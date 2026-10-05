package com.github.xingjianluo.sessionauthjava.auth.policy;

import com.github.xingjianluo.sessionauthjava.auth.config.AuthSecurityProperties;

import java.time.Duration;
import java.util.List;

/**
 * 一版策略的完整配置内容（不可变）。
 * 判定只依赖该快照，保证同一版本下结论可复现。
 */
public record PolicySettings(
        Duration sessionTtl,
        int maxConcurrentSessions,
        int maxFailedAttempts,
        Duration lockDuration,
        Duration rateLimitWindow,
        int rateLimitMaxAttempts,
        List<String> publicPaths,
        boolean csrfEnabled,
        List<String> allowedOrigins) {

    /** 从当前可变配置抽取一份不可变快照 */
    public static PolicySettings from(AuthSecurityProperties p) {
        return new PolicySettings(
                p.getSessionTtl(),
                p.getMaxConcurrentSessions(),
                p.getMaxFailedAttempts(),
                p.getLockDuration(),
                p.getRateLimitWindow(),
                p.getRateLimitMaxAttempts(),
                List.copyOf(p.getPublicPaths()),
                p.isCsrfEnabled(),
                List.copyOf(p.getAllowedOrigins()));
    }
}
