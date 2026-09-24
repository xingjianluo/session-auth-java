package com.github.xingjianluo.sessionauthjava.auth.service;

import com.github.xingjianluo.sessionauthjava.auth.config.AuthSecurityProperties;
import com.github.xingjianluo.sessionauthjava.auth.model.AuthFailureReason;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.time.Clock;
import java.time.Instant;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 登录尝试的限流与锁定管理。
 *
 * <p>规则：
 * <ul>
 *   <li>限流：同一用户在滑动窗口内失败次数达到上限 -> {@link AuthFailureReason#RATE_LIMITED}</li>
 *   <li>锁定：连续失败次数达到上限 -> 锁定一段时间，期间返回 {@link AuthFailureReason#ACCOUNT_LOCKED}</li>
 *   <li>登录成功清除全部失败状态</li>
 * </ul>
 * 判定只依赖调用时刻生效的配置快照，保证配置变更前历史判定可复现。
 */
@Service
public class LoginAttemptService {

    private static final Logger log = LoggerFactory.getLogger(LoginAttemptService.class);

    private final AuthSecurityProperties properties;
    private final Clock clock;
    private final ConcurrentHashMap<String, AttemptState> states = new ConcurrentHashMap<>();

    @org.springframework.beans.factory.annotation.Autowired
    public LoginAttemptService(AuthSecurityProperties properties) {
        this(properties, Clock.systemUTC());
    }

    /** 测试可注入固定时钟 */
    public LoginAttemptService(AuthSecurityProperties properties, Clock clock) {
        this.properties = properties;
        this.clock = clock;
    }

    private static final class AttemptState {
        /** 窗口内的失败时间戳（用于限流） */
        final Deque<Instant> failuresInWindow = new ArrayDeque<>();
        /** 连续失败次数（用于锁定） */
        int consecutiveFailures;
        /** 锁定截止时间，null 表示未锁定 */
        Instant lockedUntil;
    }

    /**
     * 若当前该用户被限流或锁定，返回对应原因；否则返回空。
     */
    public Optional<AuthFailureReason> checkBlocked(String username) {
        AttemptState state = states.get(username);
        if (state == null) {
            return Optional.empty();
        }
        synchronized (state) {
            Instant now = clock.instant();
            if (state.lockedUntil != null) {
                if (now.isBefore(state.lockedUntil)) {
                    log.info("[login-attempt] user={} blocked reason=ACCOUNT_LOCKED lockedUntil={}",
                            username, state.lockedUntil);
                    return Optional.of(AuthFailureReason.ACCOUNT_LOCKED);
                }
                // 锁定期满，重置锁定与连续计数
                state.lockedUntil = null;
                state.consecutiveFailures = 0;
            }
            pruneWindow(state, now);
            if (state.failuresInWindow.size() >= properties.getRateLimitMaxAttempts()) {
                log.info("[login-attempt] user={} blocked reason=RATE_LIMITED failuresInWindow={} max={}",
                        username, state.failuresInWindow.size(), properties.getRateLimitMaxAttempts());
                return Optional.of(AuthFailureReason.RATE_LIMITED);
            }
            return Optional.empty();
        }
    }

    /**
     * 记录一次失败尝试；达到连续失败上限时触发锁定。
     */
    public void recordFailure(String username) {
        AttemptState state = states.computeIfAbsent(username, k -> new AttemptState());
        synchronized (state) {
            Instant now = clock.instant();
            pruneWindow(state, now);
            state.failuresInWindow.addLast(now);
            state.consecutiveFailures++;
            log.info("[login-attempt] user={} failure recorded consecutive={} inWindow={}",
                    username, state.consecutiveFailures, state.failuresInWindow.size());
            if (state.consecutiveFailures >= properties.getMaxFailedAttempts()) {
                state.lockedUntil = now.plus(properties.getLockDuration());
                log.info("[login-attempt] user={} LOCKED until={} (consecutive={} >= max={})",
                        username, state.lockedUntil, state.consecutiveFailures, properties.getMaxFailedAttempts());
            }
        }
    }

    /**
     * 登录成功后清除失败计数与锁定状态。
     */
    public void recordSuccess(String username) {
        AttemptState state = states.get(username);
        if (state == null) {
            return;
        }
        synchronized (state) {
            state.failuresInWindow.clear();
            state.consecutiveFailures = 0;
            state.lockedUntil = null;
        }
    }

    private void pruneWindow(AttemptState state, Instant now) {
        Instant cutoff = now.minus(properties.getRateLimitWindow());
        while (!state.failuresInWindow.isEmpty() && state.failuresInWindow.peekFirst().isBefore(cutoff)) {
            state.failuresInWindow.pollFirst();
        }
    }

    /** 测试观测用：剩余锁定时长（秒），未锁定返回 0 */
    public long lockedSecondsRemaining(String username) {
        AttemptState state = states.get(username);
        if (state == null) {
            return 0;
        }
        synchronized (state) {
            if (state.lockedUntil == null) {
                return 0;
            }
            long secs = state.lockedUntil.getEpochSecond() - clock.instant().getEpochSecond();
            return Math.max(0, secs);
        }
    }
}
