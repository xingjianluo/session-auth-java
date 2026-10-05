package com.github.xingjianluo.sessionauthjava.auth.service;

import com.github.xingjianluo.sessionauthjava.auth.config.AuthSecurityProperties;
import com.github.xingjianluo.sessionauthjava.auth.model.AuthFailureReason;
import com.github.xingjianluo.sessionauthjava.auth.policy.AuthPolicy;
import com.github.xingjianluo.sessionauthjava.auth.policy.DecisionLog;
import com.github.xingjianluo.sessionauthjava.auth.policy.PolicyEvaluator;
import com.github.xingjianluo.sessionauthjava.auth.policy.PolicyService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.time.Clock;
import java.time.Instant;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.Map;
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
 * 每次判定读取调用时刻生效的策略快照（含版本号）并记入判定日志，
 * 历史判定可按当时策略版本回放复现。
 */
@Service
public class LoginAttemptService {

    private static final Logger log = LoggerFactory.getLogger(LoginAttemptService.class);

    private final PolicyService policyService;
    private final DecisionLog decisionLog;
    private final Clock clock;
    private final ConcurrentHashMap<String, AttemptState> states = new ConcurrentHashMap<>();

    @org.springframework.beans.factory.annotation.Autowired
    public LoginAttemptService(PolicyService policyService, DecisionLog decisionLog) {
        this(policyService, decisionLog, Clock.systemUTC());
    }

    /** 兼容旧构造：由配置项独立建一套策略服务 */
    public LoginAttemptService(AuthSecurityProperties properties, Clock clock) {
        this(defaultPolicyService(properties), clock);
    }

    public LoginAttemptService(PolicyService policyService, DecisionLog decisionLog, Clock clock) {
        this.policyService = policyService;
        this.decisionLog = decisionLog;
        this.clock = clock;
    }

    private LoginAttemptService(PolicyService policyService, Clock clock) {
        this(policyService, new DecisionLog(policyService), clock);
    }

    private static PolicyService defaultPolicyService(AuthSecurityProperties properties) {
        return new PolicyService(properties);
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
     * 判定使用当前策略版本并记录判定日志。
     */
    public Optional<AuthFailureReason> checkBlocked(String username) {
        AttemptState state = states.get(username);
        if (state == null) {
            return Optional.empty();
        }
        synchronized (state) {
            AuthPolicy policy = policyService.current();
            Instant now = clock.instant();
            if (state.lockedUntil != null && !now.isBefore(state.lockedUntil)) {
                // 锁定期满，重置锁定与连续计数
                state.lockedUntil = null;
                state.consecutiveFailures = 0;
            }
            pruneWindow(state, now, policy);
            Optional<String> blocked = PolicyEvaluator.loginBlocked(policy,
                    state.failuresInWindow.size(), state.consecutiveFailures, state.lockedUntil, now);
            decisionLog.record(DecisionLog.KIND_LOGIN_BLOCKED, policy.version(), Map.of(
                    "user", username,
                    "failuresInWindow", String.valueOf(state.failuresInWindow.size()),
                    "consecutiveFailures", String.valueOf(state.consecutiveFailures),
                    "lockedUntil", state.lockedUntil == null ? "" : state.lockedUntil.toString(),
                    "now", now.toString()), blocked.orElse("NONE"));
            if (blocked.isPresent()) {
                log.info("[login-attempt] user={} blocked reason={} policyVersion={}",
                        username, blocked.get(), policy.version());
                return Optional.of(AuthFailureReason.valueOf(blocked.get()));
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
            AuthPolicy policy = policyService.current();
            Instant now = clock.instant();
            pruneWindow(state, now, policy);
            state.failuresInWindow.addLast(now);
            state.consecutiveFailures++;
            log.info("[login-attempt] user={} failure recorded consecutive={} inWindow={} policyVersion={}",
                    username, state.consecutiveFailures, state.failuresInWindow.size(), policy.version());
            if (PolicyEvaluator.shouldLock(policy, state.consecutiveFailures)) {
                state.lockedUntil = now.plus(policy.lockDuration());
                log.info("[login-attempt] user={} LOCKED until={} (consecutive={} >= max={})",
                        username, state.lockedUntil, state.consecutiveFailures, policy.maxFailedAttempts());
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

    private void pruneWindow(AttemptState state, Instant now, AuthPolicy policy) {
        Instant cutoff = now.minus(policy.rateLimitWindow());
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
