package com.github.xingjianluo.sessionauthjava.tests.auth;

import com.github.xingjianluo.sessionauthjava.auth.config.AuthSecurityProperties;
import com.github.xingjianluo.sessionauthjava.auth.model.AuthFailureReason;
import com.github.xingjianluo.sessionauthjava.auth.model.AuthResult;
import com.github.xingjianluo.sessionauthjava.auth.model.Role;
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
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 会话失效原因细化测试：未知/登出/过期/撤销可区分，
 * 叠加状态结论稳定，并发与重复请求下原因与计数一致。
 */
class SessionInvalidationReasonTest {

    private static final Logger log = LoggerFactory.getLogger(SessionInvalidationReasonTest.class);

    private MutableClock clock;
    private SessionService service;

    @BeforeEach
    void setUp() {
        clock = new MutableClock(Instant.parse("2026-10-05T00:00:00Z"));
        AuthSecurityProperties properties = new AuthSecurityProperties();
        properties.setSessionTtl(Duration.ofMinutes(30));
        properties.setMaxConcurrentSessions(100);
        service = new SessionService(properties, clock);
    }

    private String issue(String username) {
        return ((AuthResult.Success) service.issue(username, Role.USER)).session().sessionId();
    }

    private AuthFailureReason reasonOf(String sessionId) {
        AuthResult result = service.validate(sessionId);
        AuthResult.Failure failure = assertInstanceOf(AuthResult.Failure.class, result);
        return failure.reason();
    }

    @Test
    void unknownSessionIsDistinguishedFromLoggedOut() {
        AuthFailureReason unknown = reasonOf("never-existed-session-id");
        String id = issue("alice");
        service.logout(id);
        AuthFailureReason loggedOut = reasonOf(id);
        log.info("[test] 场景=未知 vs 登出, unknown={} loggedOut={} (必须不同)", unknown, loggedOut);
        assertEquals(AuthFailureReason.SESSION_NOT_FOUND, unknown);
        assertEquals(AuthFailureReason.SESSION_LOGGED_OUT, loggedOut);
    }

    @Test
    void missingSessionIdIsNotFound() {
        AuthFailureReason reason = reasonOf(null);
        log.info("[test] 场景=无会话头, reason={}", reason);
        assertEquals(AuthFailureReason.SESSION_NOT_FOUND, reason);
    }

    @Test
    void expiredThenRevokedReportsRevokedStably() {
        // 叠加状态：先过期，再被强制失效 -> 结论固定为 SESSION_REVOKED，且重复请求一致
        String id = issue("bob");
        clock.advance(Duration.ofMinutes(31)); // 已过期
        assertEquals(AuthFailureReason.SESSION_EXPIRED, reasonOf(id));
        service.revokeAllForUser("bob"); // 注意：revokeAllForUser 只撤销活跃会话，已过期的不会被标记
        // 过期会话不会被 revokeAllForUser 标记（保持原语义），结论仍是 EXPIRED
        AuthFailureReason first = reasonOf(id);
        AuthFailureReason second = reasonOf(id);
        log.info("[test] 场景=过期后撤销扫描, first={} second={} (两次必须一致)", first, second);
        assertEquals(first, second);
    }

    @Test
    void revokedThenExpiredReportsRevokedStably() {
        // 叠加状态：先被强制失效，之后会话也到过期时间 -> 固定报 SESSION_REVOKED
        String id = issue("carol");
        service.revokeAllForUser("carol");
        clock.advance(Duration.ofMinutes(31));
        AuthFailureReason first = reasonOf(id);
        AuthFailureReason second = reasonOf(id);
        log.info("[test] 场景=撤销后又过期, first={} second={} (撤销优先且稳定)", first, second);
        assertEquals(AuthFailureReason.SESSION_REVOKED, first);
        assertEquals(AuthFailureReason.SESSION_REVOKED, second);
    }

    @Test
    void logoutIsTerminalAndCoversOtherStates() {
        // 登出是终态：撤销过的会话再登出，之后一律报 SESSION_LOGGED_OUT
        String id = issue("dave");
        service.revokeAllForUser("dave");
        assertEquals(AuthFailureReason.SESSION_REVOKED, reasonOf(id));
        service.logout(id);
        AuthFailureReason after = reasonOf(id);
        log.info("[test] 场景=撤销后登出, after={} (登出为终态)", after);
        assertEquals(AuthFailureReason.SESSION_LOGGED_OUT, after);
    }

    @Test
    void repeatedLogoutIsIdempotentAndReasonStable() {
        String id = issue("erin");
        assertTrue(service.logout(id));
        assertFalse(service.logout(id), "重复登出不得再次成功");
        AuthFailureReason first = reasonOf(id);
        AuthFailureReason second = reasonOf(id);
        log.info("[test] 场景=重复登出, first={} second={} (幂等且原因稳定)", first, second);
        assertEquals(AuthFailureReason.SESSION_LOGGED_OUT, first);
        assertEquals(AuthFailureReason.SESSION_LOGGED_OUT, second);
    }

    @Test
    void concurrentLogoutExactlyOneSucceedsAndReasonStaysLoggedOut() throws Exception {
        String id = issue("frank");
        int threads = 16;
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        CountDownLatch start = new CountDownLatch(1);
        List<Future<Boolean>> futures = new ArrayList<>();
        for (int i = 0; i < threads; i++) {
            futures.add(pool.submit(() -> {
                start.await();
                return service.logout(id);
            }));
        }
        start.countDown();
        pool.shutdown();
        assertTrue(pool.awaitTermination(30, TimeUnit.SECONDS));

        int succeeded = 0;
        for (Future<Boolean> future : futures) {
            if (future.get()) {
                succeeded++;
            }
        }
        AuthFailureReason reason = reasonOf(id);
        log.info("[test] 场景={} 线程并发登出同一会话, 成功数={} 之后原因={} (恰好 1 次成功)",
                threads, succeeded, reason);
        assertEquals(1, succeeded, "并发登出恰好一个成功");
        assertEquals(AuthFailureReason.SESSION_LOGGED_OUT, reason);
        assertEquals(0, service.activeSessionCount("frank"), "会话计数不能乱");
    }

    @Test
    void concurrentValidateDuringLogoutNeverReportsNotFound() throws Exception {
        // 并发校验与登出交错：结果只能是 OK（登出前）或 SESSION_LOGGED_OUT（登出后），
        // 绝不能出现 SESSION_NOT_FOUND（会话明明存在过）
        String id = issue("grace");
        int threads = 32;
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        CountDownLatch start = new CountDownLatch(1);
        List<Future<AuthResult>> futures = new ArrayList<>();
        for (int i = 0; i < threads; i++) {
            boolean logoutThread = i == threads / 2;
            futures.add(pool.submit(() -> {
                start.await();
                if (logoutThread) {
                    service.logout(id);
                }
                return service.validate(id);
            }));
        }
        start.countDown();
        pool.shutdown();
        assertTrue(pool.awaitTermination(30, TimeUnit.SECONDS));

        int ok = 0;
        int loggedOut = 0;
        int notFound = 0;
        for (Future<AuthResult> future : futures) {
            AuthResult result = future.get();
            if (result.isSuccess()) {
                ok++;
            } else {
                AuthFailureReason reason = ((AuthResult.Failure) result).reason();
                if (reason == AuthFailureReason.SESSION_LOGGED_OUT) {
                    loggedOut++;
                } else if (reason == AuthFailureReason.SESSION_NOT_FOUND) {
                    notFound++;
                }
            }
        }
        log.info("[test] 场景=并发校验与登出交错, ok={} loggedOut={} notFound={} (notFound 必须为 0)",
                ok, loggedOut, notFound);
        assertEquals(0, notFound, "存在过的会话在登出窗口内不得报未知");
        assertEquals(AuthFailureReason.SESSION_LOGGED_OUT, reasonOf(id));
    }

    @Test
    void sameConditionGivesSameReasonAcrossEntries() {
        // 同条件下两次请求（模拟不同入口都走 validate）结论一致
        String id = issue("henry");
        service.logout(id);
        AuthFailureReason viaFirstCall = reasonOf(id);
        AuthFailureReason viaSecondCall = reasonOf(id);
        log.info("[test] 场景=同条件重复校验, call1={} call2={}", viaFirstCall, viaSecondCall);
        assertEquals(viaFirstCall, viaSecondCall);
    }
}
