package com.github.xingjianluo.sessionauthjava.auth.policy;

import org.springframework.util.AntPathMatcher;

import java.time.Instant;
import java.util.Optional;
import java.util.Set;

/**
 * 纯函数判定逻辑：线上判定与历史回放共用同一套实现，
 * 保证"同一输入 + 同一策略版本 -> 同一结论"。
 */
public final class PolicyEvaluator {

    private static final AntPathMatcher PATH_MATCHER = new AntPathMatcher();
    private static final Set<String> SAFE_METHODS = Set.of("GET", "HEAD", "OPTIONS", "TRACE");

    private PolicyEvaluator() {
    }

    /** 路径是否无需认证。 */
    public static boolean isPublicPath(AuthPolicy policy, String path) {
        for (String pattern : policy.publicPaths()) {
            if (PATH_MATCHER.match(pattern, path)) {
                return true;
            }
        }
        return false;
    }

    /** 跨域来源是否被允许（精确匹配，不含通配）。 */
    public static boolean isOriginAllowed(AuthPolicy policy, String origin) {
        return origin != null && policy.allowedOrigins().contains(origin);
    }

    /** 是否需要对（方法, 路径）执行 CSRF 校验。 */
    public static boolean csrfCheckRequired(AuthPolicy policy, String method, boolean isPublicPath) {
        return policy.csrfEnabled() && !SAFE_METHODS.contains(method) && !isPublicPath;
    }

    /** 当前活跃会话数是否已达上限。 */
    public static boolean sessionLimitReached(AuthPolicy policy, int activeCount) {
        return activeCount >= policy.maxConcurrentSessions();
    }

    /**
     * 登录尝试是否被限流/锁定拦截。
     *
     * @return 拦截原因名（"ACCOUNT_LOCKED" / "RATE_LIMITED"），不拦截为空
     */
    public static Optional<String> loginBlocked(AuthPolicy policy, int failuresInWindow,
                                                int consecutiveFailures, Instant lockedUntil, Instant now) {
        if (lockedUntil != null && now.isBefore(lockedUntil)) {
            return Optional.of("ACCOUNT_LOCKED");
        }
        if (failuresInWindow >= policy.rateLimitMaxAttempts()) {
            return Optional.of("RATE_LIMITED");
        }
        return Optional.empty();
    }

    /** 连续失败是否达到锁定阈值（记录失败时使用）。 */
    public static boolean shouldLock(AuthPolicy policy, int consecutiveFailures) {
        return consecutiveFailures >= policy.maxFailedAttempts();
    }
}
