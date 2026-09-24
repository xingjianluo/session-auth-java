package com.github.xingjianluo.sessionauthjava.tests.auth;

import com.github.xingjianluo.sessionauthjava.auth.config.AuthSecurityProperties;
import com.github.xingjianluo.sessionauthjava.auth.model.AuthFailureReason;
import com.github.xingjianluo.sessionauthjava.auth.model.AuthResult;
import com.github.xingjianluo.sessionauthjava.auth.service.AuthService;
import com.github.xingjianluo.sessionauthjava.auth.service.LoginAttemptService;
import com.github.xingjianluo.sessionauthjava.auth.service.SessionService;
import com.github.xingjianluo.sessionauthjava.auth.service.UserStore;
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
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 并发登录测试：同一会话不得被重复放行，会话计数不得错乱。
 */
class AuthServiceConcurrencyTest {

    private static final Logger log = LoggerFactory.getLogger(AuthServiceConcurrencyTest.class);

    private AuthSecurityProperties properties;
    private SessionService sessionService;
    private AuthService authService;

    @BeforeEach
    void setUp() {
        properties = new AuthSecurityProperties();
        properties.setMaxConcurrentSessions(2);
        properties.setMaxFailedAttempts(3);
        properties.setRateLimitMaxAttempts(100);
        properties.setSessionTtl(Duration.ofMinutes(30));
        MutableClock clock = new MutableClock(Instant.parse("2026-09-24T00:00:00Z"));
        sessionService = new SessionService(properties, clock);
        authService = new AuthService(new UserStore(), new LoginAttemptService(properties, clock), sessionService);
    }

    @Test
    void concurrentLoginsRespectSessionLimitExactly() throws Exception {
        int threads = 32;
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        CountDownLatch start = new CountDownLatch(1);
        List<Future<AuthResult>> futures = new ArrayList<>();
        for (int i = 0; i < threads; i++) {
            futures.add(pool.submit(() -> {
                start.await();
                return authService.login("alice", "alice-pass");
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
        long distinct = sessionIds.stream().distinct().count();
        log.info("[test] input={} concurrent logins for alice (max=2), successes={} rejected={} distinctSessions={} activeCount={}",
                threads, successes, limitRejections, distinct, sessionService.activeSessionCount("alice"));
        assertEquals(2, successes, "成功数必须恰好等于并发会话上限");
        assertEquals(threads - 2, limitRejections, "其余请求必须因超限被拒");
        assertEquals(successes, distinct, "不得重复放行同一会话");
        assertEquals(2, sessionService.activeSessionCount("alice"), "计数不得错乱");
    }

    @Test
    void concurrentFailedLoginsLockExactlyOnce() throws Exception {
        int threads = 16;
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        CountDownLatch start = new CountDownLatch(1);
        List<Future<AuthResult>> futures = new ArrayList<>();
        for (int i = 0; i < threads; i++) {
            futures.add(pool.submit(() -> {
                start.await();
                return authService.login("bob", "wrong-pass");
            }));
        }
        start.countDown();
        pool.shutdown();
        assertTrue(pool.awaitTermination(30, TimeUnit.SECONDS));

        long invalid = 0;
        long locked = 0;
        long rateLimited = 0;
        for (Future<AuthResult> future : futures) {
            AuthResult.Failure failure = (AuthResult.Failure) future.get();
            switch (failure.reason()) {
                case INVALID_CREDENTIALS -> invalid++;
                case ACCOUNT_LOCKED -> locked++;
                case RATE_LIMITED -> rateLimited++;
                default -> throw new IllegalStateException("unexpected reason " + failure.reason());
            }
        }
        log.info("[test] input={} concurrent wrong-password logins (maxFailed=3), invalid={} locked={} rateLimited={}",
                threads, invalid, locked, rateLimited);
        // 前 3 次计为凭据错误并触发锁定，其余 13 次被锁定拦截
        assertEquals(3, invalid, "只有前 maxFailedAttempts 次计入凭据错误");
        assertEquals(threads - 3, locked, "其余请求必须返回 ACCOUNT_LOCKED");
        assertEquals(0, rateLimited);
    }

    @Test
    void failedThenSuccessfulLoginResetsCounter() {
        authService.login("bob", "bad");
        authService.login("bob", "bad");
        AuthResult ok = authService.login("bob", "bob-pass");
        assertTrue(ok.isSuccess());
        // 成功后再失败 2 次不应锁定（计数已清零）
        authService.login("bob", "bad");
        AuthResult result = authService.login("bob", "bad");
        log.info("[test] input=2fail+success+2fail (maxFailed=3), lastDecision={}", result);
        AuthResult.Failure failure = (AuthResult.Failure) result;
        assertEquals(AuthFailureReason.INVALID_CREDENTIALS, failure.reason(),
                "计数清零后不应被锁定");
    }
}
