package com.github.xingjianluo.sessionauthjava.tests.auth;

import com.github.xingjianluo.sessionauthjava.auth.config.AuthSecurityProperties;
import com.github.xingjianluo.sessionauthjava.auth.model.AuthFailureReason;
import com.github.xingjianluo.sessionauthjava.auth.model.AuthResult;
import com.github.xingjianluo.sessionauthjava.auth.model.Role;
import com.github.xingjianluo.sessionauthjava.auth.policy.DecisionLog;
import com.github.xingjianluo.sessionauthjava.auth.policy.PolicyService;
import com.github.xingjianluo.sessionauthjava.auth.service.SessionService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
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
 * 会话失效原因细分与叠加状态稳定性：
 * 未知 / 主动登出 / 过期 / 强制失效四种原因可区分、跨入口一致；
 * 叠加状态（过期+撤销、重复登出、撤销后登出）结论稳定；
 * 并发或重复请求下原因与计数不乱。
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
        properties.setMaxConcurrentSessions(10);
        PolicyService policyService = new PolicyService(properties);
        service = new SessionService(policyService, new DecisionLog(policyService), clock);
    }

    private String issue(String user) {
        AuthResult result = service.issue(user, Role.USER);
        return ((AuthResult.Success) result).session().sessionId();
    }

    private AuthFailureReason reasonOf(String sessionId) {
        AuthResult result = service.validate(sessionId);
        AuthResult.Failure failure = assertInstanceOf(AuthResult.Failure.class, result);
        return failure.reason();
    }

    @Test
    void neverExistedSessionIsUnknown() {
        AuthFailureReason reason = reasonOf("no-such-session-id");
        log.info("[test] business=unknown session, input=validate(never-issued id) -> {}"
                + " (basis: no live record, no tombstone)", reason);
        assertEquals(AuthFailureReason.SESSION_UNKNOWN, reason);

        AuthFailureReason blank = reasonOf("  ");
        log.info("[test] business=missing session id, input=validate(blank) -> {}", blank);
        assertEquals(AuthFailureReason.SESSION_UNKNOWN, blank);
    }

    @Test
    void loggedOutSessionIsDistinguishableFromUnknown() {
        String id = issue("u-logout");
        assertTrue(service.logout(id));
        AuthFailureReason reason = reasonOf(id);
        log.info("[test] business=logout then validate, input=logout+validate -> {}"
                + " (basis: tombstone written at logout)", reason);
        assertEquals(AuthFailureReason.SESSION_LOGGED_OUT, reason);
    }

    @Test
    void doubleLogoutIsStableAndNotRepeatable() {
        String id = issue("u-double");
        assertTrue(service.logout(id));
        boolean second = service.logout(id);
        AuthFailureReason first = reasonOf(id);
        AuthFailureReason secondReason = reasonOf(id);
        log.info("[test] business=double logout, input=logout x2 -> secondLogout={} reasons={}/{}"
                + " (basis: tombstone idempotent)", second, first, secondReason);
        assertFalse(second, "重复登出不得再次放行");
        assertEquals(AuthFailureReason.SESSION_LOGGED_OUT, first);
        assertEquals(first, secondReason, "同样条件下两次请求原因必须一致");
    }

    @Test
    void expiredSessionReportsExpired() {
        String id = issue("u-expire");
        clock.advance(Duration.ofMinutes(31));
        AuthFailureReason reason = reasonOf(id);
        log.info("[test] business=expiry, input=advance 31m (ttl=30m) -> {}", reason);
        assertEquals(AuthFailureReason.SESSION_EXPIRED, reason);
    }

    @Test
    void revokedSessionReportsRevoked() {
        String id = issue("u-revoke");
        service.revokeAllForUser("u-revoke");
        AuthFailureReason reason = reasonOf(id);
        log.info("[test] business=force invalidate, input=revokeAllForUser -> {}", reason);
        assertEquals(AuthFailureReason.SESSION_REVOKED, reason);
    }

    @Test
    void expiredThenRevokedReportsRevoked() {
        String id = issue("u-exp-rev");
        clock.advance(Duration.ofMinutes(31)); // 先过期
        service.revokeAllForUser("u-exp-rev");   // 再强制失效
        AuthFailureReason reason = reasonOf(id);
        log.info("[test] business=overlay expired+revoked, input=expire then revoke -> {}"
                + " (basis: REVOKED has priority over EXPIRED)", reason);
        assertEquals(AuthFailureReason.SESSION_REVOKED, reason);
    }

    @Test
    void revokedThenLoggedOutReportsRevoked() {
        String id = issue("u-rev-out");
        service.revokeAllForUser("u-rev-out"); // 先强制失效
        service.logout(id);                    // 再登出
        AuthFailureReason reason = reasonOf(id);
        log.info("[test] business=overlay revoked+logout, input=revoke then logout -> {}"
                + " (basis: REVOKED has priority over LOGGED_OUT)", reason);
        assertEquals(AuthFailureReason.SESSION_REVOKED, reason);
    }

    @Test
    void tombstonePurgedAfterRetentionBecomesUnknown() {
        String id = issue("u-purge");
        service.logout(id);
        assertEquals(AuthFailureReason.SESSION_LOGGED_OUT, reasonOf(id));
        // 墓碑保留一个会话时长（30m），超过后按未知处理
        clock.advance(Duration.ofMinutes(61));
        AuthFailureReason reason = reasonOf(id);
        log.info("[test] business=tombstone retention, input=advance 61m after logout -> {}"
                + " (basis: tombstone purged after one session ttl)", reason);
        assertEquals(AuthFailureReason.SESSION_UNKNOWN, reason);
    }

    @Test
    void repeatedValidateUnderSameConditionsIsDeterministic() {
        String id = issue("u-det");
        service.revokeAllForUser("u-det");
        Set<AuthFailureReason> reasons = new HashSet<>();
        for (int i = 0; i < 50; i++) {
            reasons.add(reasonOf(id));
        }
        log.info("[test] business=determinism, input=50x validate revoked session -> distinctReasons={}"
                + " (basis: same inputs must give same reason)", reasons);
        assertEquals(Set.of(AuthFailureReason.SESSION_REVOKED), reasons);
    }

    @Test
    void concurrentLogoutAndValidateNeverReportUnknown() throws Exception {
        String id = issue("u-race");
        int threads = 32;
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        CountDownLatch start = new CountDownLatch(1);
        List<Future<AuthResult>> futures = new ArrayList<>();
        // 一半线程登出，一半线程并发校验
        for (int i = 0; i < threads; i++) {
            final boolean logout = i % 2 == 0;
            futures.add(pool.submit(() -> {
                start.await();
                if (logout) {
                    service.logout(id);
                    return null;
                }
                return service.validate(id);
            }));
        }
        start.countDown();
        pool.shutdown();
        assertTrue(pool.awaitTermination(30, TimeUnit.SECONDS));

        Set<String> outcomes = new HashSet<>();
        for (Future<AuthResult> f : futures) {
            AuthResult r = f.get();
            if (r == null) {
                continue;
            }
            outcomes.add(r.isSuccess() ? "SUCCESS"
                    : ((AuthResult.Failure) r).reason().name());
        }
        log.info("[test] business=concurrent logout+validate, input=16 logout + 16 validate -> outcomes={}"
                + " (basis: linearizable tombstone, never UNKNOWN for an issued session)", outcomes);
        assertTrue(outcomes.stream().allMatch(o -> o.equals("SUCCESS") || o.equals("SESSION_LOGGED_OUT")),
                "并发下只能看到 SUCCESS 或 LOGGED_OUT，不得出现 UNKNOWN: " + outcomes);

        // 全部落稳后：一致为 LOGGED_OUT，计数为 0
        assertEquals(AuthFailureReason.SESSION_LOGGED_OUT, reasonOf(id));
        assertEquals(0, service.activeSessionCount("u-race"));
        log.info("[test] business=post-race stability, finalReason=SESSION_LOGGED_OUT activeCount=0");
    }

    @Test
    void concurrentDoubleLogoutKeepsReasonAndCountStable() throws Exception {
        String user = "u-race-logout";
        String id = issue(user);
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

        int trues = 0;
        for (Future<Boolean> f : futures) {
            if (f.get()) {
                trues++;
            }
        }
        log.info("[test] business=concurrent double logout, input={}x logout same session"
                + " -> trueCount={} (basis: exactly one real logout)", threads, trues);
        assertEquals(1, trues, "并发登下同一会话，恰好一次真实登出");
        assertEquals(AuthFailureReason.SESSION_LOGGED_OUT, reasonOf(id));
        assertEquals(0, service.activeSessionCount(user));
    }
}
