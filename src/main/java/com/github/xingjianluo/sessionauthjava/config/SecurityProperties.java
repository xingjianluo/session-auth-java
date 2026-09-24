package com.github.xingjianluo.sessionauthjava.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

/**
 * Externalized security settings (session TTL, login throttling, CSRF/CORS/headers).
 * Skeleton: mutable nested configuration holders, values populated from application.properties.
 */
@Component
@ConfigurationProperties(prefix = "app.security")
public class SecurityProperties {

    /** Session idle lifetime and cookie settings. */
    public static class Session {
        private long idleTimeoutMillis = 1800_000L;
        private String cookieName = "SID";
        private String cookiePath = "/";
        private boolean cookieHttpOnly = true;
        private String cookieSameSite = "Lax";
        private boolean cookieSecure = false;

        public long getIdleTimeoutMillis() { return idleTimeoutMillis; }
        public void setIdleTimeoutMillis(long idleTimeoutMillis) { this.idleTimeoutMillis = idleTimeoutMillis; }
        public String getCookieName() { return cookieName; }
        public void setCookieName(String cookieName) { this.cookieName = cookieName; }
        public String getCookiePath() { return cookiePath; }
        public void setCookiePath(String cookiePath) { this.cookiePath = cookiePath; }
        public boolean isCookieHttpOnly() { return cookieHttpOnly; }
        public void setCookieHttpOnly(boolean cookieHttpOnly) { this.cookieHttpOnly = cookieHttpOnly; }
        public String getCookieSameSite() { return cookieSameSite; }
        public void setCookieSameSite(String cookieSameSite) { this.cookieSameSite = cookieSameSite; }
        public boolean isCookieSecure() { return cookieSecure; }
        public void setCookieSecure(boolean cookieSecure) { this.cookieSecure = cookieSecure; }
    }

    /** Login failure throttling and account locking. */
    public static class Login {
        private int maxSessionsPerUser = 2;
        private int lockThreshold = 5;
        private long lockMillis = 300_000L;
        private int rateLimitAttempts = 10;
        private long rateLimitWindowMillis = 60_000L;
        private long rateLimitBlockMillis = 60_000L;

        public int getMaxSessionsPerUser() { return maxSessionsPerUser; }
        public void setMaxSessionsPerUser(int maxSessionsPerUser) { this.maxSessionsPerUser = maxSessionsPerUser; }
        public int getLockThreshold() { return lockThreshold; }
        public void setLockThreshold(int lockThreshold) { this.lockThreshold = lockThreshold; }
        public long getLockMillis() { return lockMillis; }
        public void setLockMillis(long lockMillis) { this.lockMillis = lockMillis; }
        public int getRateLimitAttempts() { return rateLimitAttempts; }
        public void setRateLimitAttempts(int rateLimitAttempts) { this.rateLimitAttempts = rateLimitAttempts; }
        public long getRateLimitWindowMillis() { return rateLimitWindowMillis; }
        public void setRateLimitWindowMillis(long rateLimitWindowMillis) { this.rateLimitWindowMillis = rateLimitWindowMillis; }
        public long getRateLimitBlockMillis() { return rateLimitBlockMillis; }
        public void setRateLimitBlockMillis(long rateLimitBlockMillis) { this.rateLimitBlockMillis = rateLimitBlockMillis; }
    }

    /** Cross-site request forgery protection toggles. */
    public static class Csrf {
        private boolean enabled = true;
        private String headerName = "X-CSRF-TOKEN";

        public boolean isEnabled() { return enabled; }
        public void setEnabled(boolean enabled) { this.enabled = enabled; }
        public String getHeaderName() { return headerName; }
        public void setHeaderName(String headerName) { this.headerName = headerName; }
    }

    /** Cross-origin resource sharing. */
    public static class Cors {
        private boolean enabled = true;
        private String allowedOriginPattern = "*";
        private String allowedMethods = "GET,POST,PUT,DELETE,OPTIONS";
        private boolean allowCredentials = true;

        public boolean isEnabled() { return enabled; }
        public void setEnabled(boolean enabled) { this.enabled = enabled; }
        public String getAllowedOriginPattern() { return allowedOriginPattern; }
        public void setAllowedOriginPattern(String allowedOriginPattern) { this.allowedOriginPattern = allowedOriginPattern; }
        public String getAllowedMethods() { return allowedMethods; }
        public void setAllowedMethods(String allowedMethods) { this.allowedMethods = allowedMethods; }
        public boolean isAllowCredentials() { return allowCredentials; }
        public void setAllowCredentials(boolean allowCredentials) { this.allowCredentials = allowCredentials; }
    }

    /** Static security response headers. */
    public static class Headers {
        private String frameOptions = "DENY";
        private String contentTypeOptions = "nosniff";
        private String referrerPolicy = "no-referrer";
        private String contentSecurityPolicy = "default-src 'self'";

        public String getFrameOptions() { return frameOptions; }
        public void setFrameOptions(String frameOptions) { this.frameOptions = frameOptions; }
        public String getContentTypeOptions() { return contentTypeOptions; }
        public void setContentTypeOptions(String contentTypeOptions) { this.contentTypeOptions = contentTypeOptions; }
        public String getReferrerPolicy() { return referrerPolicy; }
        public void setReferrerPolicy(String referrerPolicy) { this.referrerPolicy = referrerPolicy; }
        public String getContentSecurityPolicy() { return contentSecurityPolicy; }
        public void setContentSecurityPolicy(String contentSecurityPolicy) { this.contentSecurityPolicy = contentSecurityPolicy; }
    }

    private Session session = new Session();
    private Login login = new Login();
    private Csrf csrf = new Csrf();
    private Cors cors = new Cors();
    private Headers headers = new Headers();

    public Session getSession() { return session; }
    public void setSession(Session session) { this.session = session; }
    public Login getLogin() { return login; }
    public void setLogin(Login login) { this.login = login; }
    public Csrf getCsrf() { return csrf; }
    public void setCsrf(Csrf csrf) { this.csrf = csrf; }
    public Cors getCors() { return cors; }
    public void setCors(Cors cors) { this.cors = cors; }
    public Headers getHeaders() { return headers; }
    public void setHeaders(Headers headers) { this.headers = headers; }
}
