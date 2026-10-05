package com.github.xingjianluo.sessionauthjava.auth.service;

import com.github.xingjianluo.sessionauthjava.auth.config.AuthSecurityProperties;
import com.github.xingjianluo.sessionauthjava.auth.model.AuthFailureReason;
import com.github.xingjianluo.sessionauthjava.auth.policy.DecisionLog;
import com.github.xingjianluo.sessionauthjava.auth.policy.DecisionTypes;
import com.github.xingjianluo.sessionauthjava.auth.policy.PolicyDecisions;
import com.github.xingjianluo.sessionauthjava.auth.policy.PolicyReplayService;
import com.github.xingjianluo.sessionauthjava.auth.policy.PolicyService;
import com.github.xingjianluo.sessionauthjava.auth.policy.PolicySettings;
import com.github.xingjianluo.sessionauthjava.auth.policy.PolicySnapshot;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.time.Clock;
import java.time.Instant;
import java.util.ArrayDeque;
import java.util.ArrayList;
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
 * 判定结论由 {@link PolicyDecisions#checkBlocked} 纯函数给出（与历史回放共用），
 * 判定只依赖调用时刻生效的策略快照，并写入 {@link DecisionLog} 标注策略版本。
 */
@Service
public class LoginAttemptService {

    private static final Logger log = LoggerFactory.getLogger(LoginAttemptService.class);

    private final PolicyService policyService;
    private final DecisionLog decisionLog;
    private final Clock clock;
    private final ConcurrentHashMap<String, AttemptState> states = new ConcurrentHashMap<>();

    @org.springframework.beans.factory.annotation.Autowired
    public LoginAttemptService(AuthSecurityProperties properties, PolicyService policyService,
                               DecisionLog decisionLog) {
        this(policyService, decisionLog, Clock.systemUTC());
    }

    /** 测试可注入固定时钟（沿用旧签名，策略与判定日志用默认实例） */
    public LoginAttemptService(AuthSecurityProperties properties, Clock clock) {
        this(new PolicyService(properties), new DecisionLog(), clock);
    }

    /** 测试可注入共享的策略服务/判定日志与固定时钟 */
    public LoginAttemptService(PolicyService policyService, DecisionLog decisionLog, Clock clock) {
        this.policyService = policyService;
        this.decisionLog = decisionLog;
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
            PolicySnapshot snapshot = policyService.current();
            Instant now = clock.instant();
            // 锁定期满的 bookkeeping：重置锁定与连续计数（不影响本次判定结论）
            if (state.lockedUntil != null && !now.isBefore(state.lockedUntil)) {
                state.lockedUntil = null;
                state.consecutiveFailures = 0;
            }
            pruneWindow(state, now, snapshot.settings());
            Optional<AuthFailureReason> blocked = PolicyDecisions.checkBlocked(
                    new ArrayList<>(state.failuresInWindow), state.lockedUntil, now, snapshot.settings());
            decisionLog.record(DecisionTypes.LOGIN_BLOCKED, snapshot.version(), Map.of(
                    "username", username,
                    "failures", PolicyReplayService.joinInstants(state.failuresInWindow),
                    "lockedUntil", state.lockedUntil == null ? "" : state.lockedUntil.toString(),
                    "now", now.toString()),
                    blocked.map(Enum::name).orElse("OK"));
            if (blocked.isPresent()) {
                log.info("[login-attempt] user={} blocked reason={} (policy v{})",
                        username, blocked.get(), snapshot.version());
            }
            return blocked;
        }
    }

    /**
     * 记录一次失败尝试；达到连续失败上限时触发锁定。
     */
    public void recordFailure(String username) {
        AttemptState state = states.computeIfAbsent(username, k -> new AttemptState());
        synchronized (state) {
            PolicySettings settings = policyService.current().settings();
            Instant now = clock.instant();
            pruneWindow(state, now, settings);
            state.failuresInWindow.addLast(now);
            state.consecutiveFailures++;
            log.info("[login-attempt] user={} failure recorded consecutive={} inWindow={}",
                    username, state.consecutiveFailures, state.failuresInWindow.size());
            if (state.consecutiveFailures >= settings.maxFailedAttempts()) {
                state.lockedUntil = now.plus(settings.lockDuration());
                log.info("[login-attempt] user={} LOCKED until={} (consecutive={} >= max={})",
                        username, state.lockedUntil, state.consecutiveFailures, settings.maxFailedAttempts());
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

    private void pruneWindow(AttemptState state, Instant now, PolicySettings settings) {
        Instant cutoff = now.minus(settings.rateLimitWindow());
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
