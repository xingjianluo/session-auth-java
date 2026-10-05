package com.github.xingjianluo.sessionauthjava.tests.auth;

import com.github.xingjianluo.sessionauthjava.auth.config.AuthSecurityProperties;
import com.github.xingjianluo.sessionauthjava.auth.model.AuthFailureReason;
import com.github.xingjianluo.sessionauthjava.auth.model.AuthResult;
import com.github.xingjianluo.sessionauthjava.auth.model.Role;
import com.github.xingjianluo.sessionauthjava.auth.model.SessionRecord;
import com.github.xingjianluo.sessionauthjava.auth.service.SessionService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 会话签发、失效与并发上限测试。
 */
class SessionServiceTest {

    private static final Logger log = LoggerFactory.getLogger(SessionServiceTest.class);

    private MutableClock clock;
    private AuthSecurityProperties properties;
    private SessionService service;

    @BeforeEach
    void setUp() {
        clock = new MutableClock(Instant.parse("2026-09-24T00:00:00Z"));
        properties = new AuthSecurityProperties();
        properties.setSessionTtl(Duration.ofMinutes(30));
        properties.setMaxConcurrentSessions(2);
        service = new SessionService(properties, clock);
    }

    @Test
    void expiredSessionIsRejectedWithDistinguishableReason() {
        AuthResult issued = service.issue("alice", Role.USER);
        String sessionId = ((AuthResult.Success) issued).session().sessionId();
        clock.advance(Duration.ofMinutes(31));
        AuthResult result = service.validate(sessionId);
        log.info("[test] input=session expired by 1m, decision={}", result);
        AuthResult.Failure failure = assertInstanceOf(AuthResult.Failure.class, result);
        assertEquals(AuthFailureReason.SESSION_EXPIRED, failure.reason());
    }

    @Test
    void logoutRemovesSessionAndIsNotRepeatable() {
        AuthResult issued = service.issue("alice", Role.USER);
        String sessionId = ((AuthResult.Success) issued).session().sessionId();
        assertTrue(service.logout(sessionId));
        AuthResult first = service.validate(sessionId);
        boolean secondLogout = service.logout(sessionId);
        log.info("[test] input=logout twice, firstValidate={} secondLogout={}", first, secondLogout);
        AuthResult.Failure failure = assertInstanceOf(AuthResult.Failure.class, first);
        assertEquals(AuthFailureReason.SESSION_LOGGED_OUT, failure.reason());
        assertTrue(!secondLogout, "重复登出不得再次放行");
    }

    @Test
    void revokedSessionIsRejectedWithDistinguishableReason() {
        AuthResult issued = service.issue("alice", Role.USER);
        String sessionId = ((AuthResult.Success) issued).session().sessionId();
        int revoked = service.revokeAllForUser("alice");
        AuthResult result = service.validate(sessionId);
        log.info("[test] input=revokeAllForUser(alice) revoked={}, decision={}", revoked, result);
        assertEquals(1, revoked);
        AuthResult.Failure failure = assertInstanceOf(AuthResult.Failure.class, result);
        assertEquals(AuthFailureReason.SESSION_REVOKED, failure.reason());
    }

    @Test
    void concurrentSessionLimitIsEnforced() {
        service.issue("alice", Role.USER);
        service.issue("alice", Role.USER);
        AuthResult third = service.issue("alice", Role.USER);
        log.info("[test] input=3rd issue with max=2, decision={}", third);
        AuthResult.Failure failure = assertInstanceOf(AuthResult.Failure.class, third);
        assertEquals(AuthFailureReason.CONCURRENT_SESSION_LIMIT_EXCEEDED, failure.reason());
        assertEquals(2, service.activeSessionCount("alice"));
    }

    @Test
    void concurrentIssueNeverExceedsLimitAndNeverDuplicates() throws Exception {
        int threads = 32;
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        CountDownLatch start = new CountDownLatch(1);
        List<Future<AuthResult>> futures = new ArrayList<>();
        for (int i = 0; i < threads; i++) {
            futures.add(pool.submit(() -> {
                start.await();
                return service.issue("henry", Role.USER);
            }));
        }
        start.countDown();
        pool.shutdown();
        assertTrue(pool.awaitTermination(30, TimeUnit.SECONDS));

        long successes = 0;
        long limitRejections = 0;
        List<String> sessionIds = new ArrayList<>();
        for (Future<AuthResult> future : futures) {
            AuthResult result = future.get();
            if (result instanceof AuthResult.Success success) {
                successes++;
                sessionIds.add(success.session().sessionId());
            } else if (result instanceof AuthResult.Failure failure
                    && failure.reason() == AuthFailureReason.CONCURRENT_SESSION_LIMIT_EXCEEDED) {
                limitRejections++;
            }
        }
        long distinctIds = sessionIds.stream().distinct().count();
        log.info("[test] input={} concurrent issues max=2, successes={} rejected={} distinctIds={} activeCount={}",
                threads, successes, limitRejections, distinctIds, service.activeSessionCount("henry"));
        assertEquals(2, successes, "并发签发不得超过上限");
        assertEquals(threads - 2, limitRejections);
        assertEquals(successes, distinctIds, "不得重复放行同一会话");
        assertEquals(2, service.activeSessionCount("henry"));
    }

    @Test
    void concurrentValidateOfSameSessionIsConsistent() throws Exception {
        AuthResult issued = service.issue("irene", Role.USER);
        String sessionId = ((AuthResult.Success) issued).session().sessionId();
        int threads = 32;
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        CountDownLatch start = new CountDownLatch(1);
        List<Future<AuthResult>> futures = new ArrayList<>();
        for (int i = 0; i < threads; i++) {
            futures.add(pool.submit(() -> {
                start.await();
                return service.validate(sessionId);
            }));
        }
        start.countDown();
        pool.shutdown();
        assertTrue(pool.awaitTermination(30, TimeUnit.SECONDS));
        long successes = 0;
        for (Future<AuthResult> future : futures) {
            if (future.get().isSuccess()) {
                successes++;
            }
        }
        log.info("[test] input={} concurrent validates of one session, successes={}", threads, successes);
        assertEquals(threads, successes, "有效会话的并发校验应全部一致放行");
    }
}
