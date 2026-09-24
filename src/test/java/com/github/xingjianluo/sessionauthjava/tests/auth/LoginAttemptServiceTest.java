package com.github.xingjianluo.sessionauthjava.tests.auth;

import com.github.xingjianluo.sessionauthjava.auth.config.AuthSecurityProperties;
import com.github.xingjianluo.sessionauthjava.auth.model.AuthFailureReason;
import com.github.xingjianluo.sessionauthjava.auth.service.LoginAttemptService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Duration;
import java.time.Instant;
import java.util.Optional;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 限流与锁定策略测试：关键输入与判定依据通过日志打印。
 */
class LoginAttemptServiceTest {

    private static final Logger log = LoggerFactory.getLogger(LoginAttemptServiceTest.class);

    private MutableClock clock;
    private AuthSecurityProperties properties;
    private LoginAttemptService service;

    @BeforeEach
    void setUp() {
        clock = new MutableClock(Instant.parse("2026-09-24T00:00:00Z"));
        properties = new AuthSecurityProperties();
        properties.setMaxFailedAttempts(3);
        properties.setLockDuration(Duration.ofMinutes(5));
        properties.setRateLimitWindow(Duration.ofMinutes(1));
        properties.setRateLimitMaxAttempts(5);
        service = new LoginAttemptService(properties, clock);
    }

    @Test
    void locksAfterConfiguredConsecutiveFailures() {
        String user = "carol";
        for (int i = 1; i <= 3; i++) {
            Optional<AuthFailureReason> before = service.checkBlocked(user);
            service.recordFailure(user);
            log.info("[test] input=failure#{} user={} blockedBefore={} lockedSecsRemaining={}",
                    i, user, before, service.lockedSecondsRemaining(user));
        }
        Optional<AuthFailureReason> blocked = service.checkBlocked(user);
        log.info("[test] decision: user={} reason={} (expected ACCOUNT_LOCKED)", user, blocked);
        assertEquals(Optional.of(AuthFailureReason.ACCOUNT_LOCKED), blocked);
    }

    @Test
    void lockExpiresAfterLockDuration() {
        String user = "dave";
        for (int i = 0; i < 3; i++) {
            service.recordFailure(user);
        }
        assertEquals(Optional.of(AuthFailureReason.ACCOUNT_LOCKED), service.checkBlocked(user));
        clock.advance(Duration.ofMinutes(6));
        Optional<AuthFailureReason> after = service.checkBlocked(user);
        log.info("[test] input=advance 6m, user={} decision={} (expected empty)", user, after);
        assertTrue(after.isEmpty());
    }

    @Test
    void rateLimitsWhenWindowAttemptsExceeded() {
        String user = "erin";
        // 连续失败上限 3 会触发锁定；为单独验证限流，把锁定阈值调高
        properties.setMaxFailedAttempts(100);
        for (int i = 0; i < 5; i++) {
            service.recordFailure(user);
        }
        Optional<AuthFailureReason> blocked = service.checkBlocked(user);
        log.info("[test] input=5 failures in 1m window, user={} decision={} (expected RATE_LIMITED)", user, blocked);
        assertEquals(Optional.of(AuthFailureReason.RATE_LIMITED), blocked);

        // 窗口滑动后放行
        clock.advance(Duration.ofMinutes(2));
        Optional<AuthFailureReason> after = service.checkBlocked(user);
        log.info("[test] input=advance 2m, user={} decision={} (expected empty)", user, after);
        assertTrue(after.isEmpty());
    }

    @Test
    void successClearsFailureState() {
        String user = "frank";
        service.recordFailure(user);
        service.recordFailure(user);
        service.recordSuccess(user);
        Optional<AuthFailureReason> blocked = service.checkBlocked(user);
        log.info("[test] input=2 failures then success, user={} decision={} (expected empty)", user, blocked);
        assertTrue(blocked.isEmpty());
    }

    @Test
    void concurrentFailuresNeverLoseCount() throws InterruptedException {
        String user = "grace";
        properties.setMaxFailedAttempts(100_000); // 关闭锁定干扰，单独验证限流计数
        properties.setRateLimitMaxAttempts(1000);
        int threads = 16;
        int failuresPerThread = 50;
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        CountDownLatch start = new CountDownLatch(1);
        for (int t = 0; t < threads; t++) {
            pool.submit(() -> {
                try {
                    start.await();
                    for (int i = 0; i < failuresPerThread; i++) {
                        service.recordFailure(user);
                    }
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            });
        }
        start.countDown();
        pool.shutdown();
        assertTrue(pool.awaitTermination(30, TimeUnit.SECONDS));

        // 总失败数 800 远超限流上限 1000？不，800 < 1000，不应被限流
        Optional<AuthFailureReason> blocked = service.checkBlocked(user);
        log.info("[test] input={} threads x {} failures, user={} decision={} (expected empty, count must be exact)",
                threads, failuresPerThread, user, blocked);
        assertTrue(blocked.isEmpty());

        // 再补 200 次，总计 1000 达到限流上限
        for (int i = 0; i < 200; i++) {
            service.recordFailure(user);
        }
        Optional<AuthFailureReason> afterTopUp = service.checkBlocked(user);
        log.info("[test] input=+200 failures (total 1000), user={} decision={} (expected RATE_LIMITED)",
                user, afterTopUp);
        assertEquals(Optional.of(AuthFailureReason.RATE_LIMITED), afterTopUp);
    }
}
