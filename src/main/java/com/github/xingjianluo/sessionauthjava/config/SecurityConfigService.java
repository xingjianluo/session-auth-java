package com.github.xingjianluo.sessionauthjava.config;

import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.atomic.AtomicLong;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

/**
 * Holds the current immutable {@link SecuritySettings} snapshot and allows thread-safe
 * runtime updates. Every snapshot ever published is retained so that historical
 * authentication/authorization decisions remain reproducible from audit records.
 */
@Service
public class SecurityConfigService {

    private static final Logger log = LoggerFactory.getLogger(SecurityConfigService.class);

    private final SecurityProperties properties;
    private final AtomicLong versionSeq = new AtomicLong(0);
    private final ConcurrentMap<Long, SecuritySettings> history = new ConcurrentHashMap<>();
    private volatile SecuritySettings current;

    public SecurityConfigService(SecurityProperties properties) {
        this.properties = properties;
        reload();
    }

    /** Returns the currently effective settings snapshot. */
    public SecuritySettings current() {
        return current;
    }

    /** Rebuilds the snapshot from the bound {@link SecurityProperties} and increments the version. */
    public SecuritySettings reload() {
        long version = versionSeq.incrementAndGet();
        SecurityProperties.Session s = properties.getSession();
        SecurityProperties.Login l = properties.getLogin();
        SecurityProperties.Csrf c = properties.getCsrf();
        SecurityProperties.Cors o = properties.getCors();
        SecurityProperties.Headers h = properties.getHeaders();
        SecuritySettings settings = new SecuritySettings(
                version,
                s.getIdleTimeoutMillis(),
                s.getCookieName(),
                s.getCookiePath(),
                s.isCookieHttpOnly(),
                s.getCookieSameSite(),
                s.isCookieSecure(),
                l.getMaxSessionsPerUser(),
                l.getLockThreshold(),
                l.getLockMillis(),
                l.getRateLimitAttempts(),
                l.getRateLimitWindowMillis(),
                l.getRateLimitBlockMillis(),
                c.isEnabled(),
                c.getHeaderName(),
                o.isEnabled(),
                o.getAllowedOriginPattern(),
                o.getAllowedMethods(),
                o.isAllowCredentials(),
                h.getFrameOptions(),
                h.getContentTypeOptions(),
                h.getReferrerPolicy(),
                h.getContentSecurityPolicy()
        );
        history.put(version, settings);
        current = settings;
        log.info("Security settings reloaded -> version={} idleTimeout={}ms maxSessions={} lockThreshold={}/{}ms "
                        + "rateLimit={} per {}ms block {}ms csrf={}",
                version, s.getIdleTimeoutMillis(), l.getMaxSessionsPerUser(),
                l.getLockThreshold(), l.getLockMillis(),
                l.getRateLimitAttempts(), l.getRateLimitWindowMillis(), l.getRateLimitBlockMillis(),
                c.isEnabled());
        return settings;
    }

    /** Returns an immutable settings snapshot by version, or {@code null} when unknown. */
    public SecuritySettings version(long version) {
        return history.get(version);
    }

    /** All published version numbers in ascending order. */
    public List<Long> versions() {
        return history.keySet().stream().sorted().toList();
    }
}
