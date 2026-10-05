package com.github.xingjianluo.sessionauthjava.auth.policy;

import com.github.xingjianluo.sessionauthjava.auth.model.AuthFailureReason;
import org.springframework.util.AntPathMatcher;

import java.time.Instant;
import java.util.Collection;
import java.util.Optional;
import java.util.Set;

/**
 * 纯函数判定逻辑：同一份代码既用于在线判定，也用于历史回放，
 * 保证"放回当时那套策略重放，结论与当时完全一致"。
 *
 * <p>所有方法不读写任何可变状态，结论只由入参（含策略快照）决定。
 */
public final class PolicyDecisions {

    private static final AntPathMatcher PATH_MATCHER = new AntPathMatcher();
    private static final Set<String> SAFE_METHODS = Set.of("GET", "HEAD", "OPTIONS", "TRACE");

    private PolicyDecisions() {
    }

    /**
     * 会话校验：返回失败原因，空表示会话有效。
     *
     * <p>叠加状态的优先级固定（保证同条件下结论稳定）：
     * 记录不存在时区分 从未存在/未知({@code SESSION_NOT_FOUND}) 与
     * 已登出({@code SESSION_LOGGED_OUT})；记录存在时
     * 撤销({@code SESSION_REVOKED}) 优先于 过期({@code SESSION_EXPIRED})。
     */
    public static Optional<AuthFailureReason> validateSession(boolean exists, boolean loggedOut,
                                                              boolean revoked, Instant expiresAt,
                                                              Instant now) {
        if (!exists) {
            return Optional.of(loggedOut
                    ? AuthFailureReason.SESSION_LOGGED_OUT
                    : AuthFailureReason.SESSION_NOT_FOUND);
        }
        if (revoked) {
            return Optional.of(AuthFailureReason.SESSION_REVOKED);
        }
        if (expiresAt != null && !now.isBefore(expiresAt)) {
            return Optional.of(AuthFailureReason.SESSION_EXPIRED);
        }
        return Optional.empty();
    }

    /** 登录限流/锁定检查：锁定优先于限流 */
    public static Optional<AuthFailureReason> checkBlocked(Collection<Instant> failures,
                                                           Instant lockedUntil, Instant now,
                                                           PolicySettings settings) {
        if (lockedUntil != null && now.isBefore(lockedUntil)) {
            return Optional.of(AuthFailureReason.ACCOUNT_LOCKED);
        }
        Instant cutoff = now.minus(settings.rateLimitWindow());
        long inWindow = failures.stream().filter(t -> !t.isBefore(cutoff)).count();
        if (inWindow >= settings.rateLimitMaxAttempts()) {
            return Optional.of(AuthFailureReason.RATE_LIMITED);
        }
        return Optional.empty();
    }

    /** 会话签发：并发上限检查 */
    public static boolean issueAllowed(int activeCount, PolicySettings settings) {
        return activeCount < settings.maxConcurrentSessions();
    }

    /** 公开路径判定 */
    public static boolean isPublicPath(String path, PolicySettings settings) {
        for (String pattern : settings.publicPaths()) {
            if (PATH_MATCHER.match(pattern, path)) {
                return true;
            }
        }
        return false;
    }

    /** 跨域来源判定（精确匹配配置的来源列表） */
    public static boolean originAllowed(String origin, PolicySettings settings) {
        return origin != null && settings.allowedOrigins().contains(origin);
    }

    /**
     * CSRF 判定：返回可解释的结论串。
     * SKIPPED_DISABLED / SKIPPED_SAFE_METHOD / SKIPPED_PUBLIC_PATH /
     * NOT_AUTHENTICATED / PASS / REJECTED
     */
    public static String csrfOutcome(String method, String path, boolean authenticated,
                                     boolean tokenValid, PolicySettings settings) {
        if (!settings.csrfEnabled()) {
            return "SKIPPED_DISABLED";
        }
        if (SAFE_METHODS.contains(method)) {
            return "SKIPPED_SAFE_METHOD";
        }
        if (isPublicPath(path, settings)) {
            return "SKIPPED_PUBLIC_PATH";
        }
        if (!authenticated) {
            return "NOT_AUTHENTICATED";
        }
        return tokenValid ? "PASS" : "REJECTED";
    }
}
