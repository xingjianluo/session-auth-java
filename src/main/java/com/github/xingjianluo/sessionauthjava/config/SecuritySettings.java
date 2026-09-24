package com.github.xingjianluo.sessionauthjava.config;

/**
 * Immutable snapshot of the currently effective security settings.
 * Each runtime change produces a new snapshot with an incremented version,
 * so audit records can reference the exact configuration used for a decision.
 *
 * @param version monotonically increasing settings version
 */
public record SecuritySettings(
        long version,
        long sessionIdleTimeoutMillis,
        String sessionCookieName,
        String sessionCookiePath,
        boolean sessionCookieHttpOnly,
        String sessionCookieSameSite,
        boolean sessionCookieSecure,
        int maxSessionsPerUser,
        int lockThreshold,
        long lockMillis,
        int rateLimitAttempts,
        long rateLimitWindowMillis,
        long rateLimitBlockMillis,
        boolean csrfEnabled,
        String csrfHeaderName,
        boolean corsEnabled,
        String corsAllowedOriginPattern,
        String corsAllowedMethods,
        boolean corsAllowCredentials,
        String frameOptions,
        String contentTypeOptions,
        String referrerPolicy,
        String contentSecurityPolicy
) {
}
