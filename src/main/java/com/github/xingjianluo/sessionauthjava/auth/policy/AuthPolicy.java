package com.github.xingjianluo.sessionauthjava.auth.policy;

import com.github.xingjianluo.sessionauthjava.auth.config.AuthSecurityProperties;

import java.time.Duration;
import java.util.List;

/**
 * 某一版策略的不可变快照。所有运行期判定只依赖某一份快照，
 * 保证历史判定可按当时版本回放。
 */
public record AuthPolicy(
        long version,
        Duration sessionTtl,
        int maxConcurrentSessions,
        int maxFailedAttempts,
        Duration lockDuration,
        Duration rateLimitWindow,
        int rateLimitMaxAttempts,
        List<String> publicPaths,
        boolean csrfEnabled,
        List<String> allowedOrigins) {

    /** 从配置项生成指定版本号的快照（拷贝可变集合，保证快照不可变）。 */
    public static AuthPolicy snapshot(long version, AuthSecurityProperties p) {
        return new AuthPolicy(
                version,
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

    /** 把快照内容写回配置项（供"基于当前策略修改后发布新版本"使用）。 */
    public AuthSecurityProperties toProperties() {
        AuthSecurityProperties p = new AuthSecurityProperties();
        p.setSessionTtl(sessionTtl);
        p.setMaxConcurrentSessions(maxConcurrentSessions);
        p.setMaxFailedAttempts(maxFailedAttempts);
        p.setLockDuration(lockDuration);
        p.setRateLimitWindow(rateLimitWindow);
        p.setRateLimitMaxAttempts(rateLimitMaxAttempts);
        p.setPublicPaths(new java.util.ArrayList<>(publicPaths));
        p.setCsrfEnabled(csrfEnabled);
        p.setAllowedOrigins(new java.util.ArrayList<>(allowedOrigins));
        return p;
    }
}
