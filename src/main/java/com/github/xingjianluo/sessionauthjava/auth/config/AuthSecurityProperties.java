package com.github.xingjianluo.sessionauthjava.auth.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.time.Duration;
import java.util.List;

/**
 * 会话认证与访问控制的可配置项。
 * 配置变更后历史判定可复现：所有判定仅依赖当时生效的配置快照。
 */
@ConfigurationProperties(prefix = "auth.security")
public class AuthSecurityProperties {

    /** 会话有效期 */
    private Duration sessionTtl = Duration.ofMinutes(30);

    /** 每个用户允许的最大并发会话数 */
    private int maxConcurrentSessions = 2;

    /** 触发锁定的连续失败次数 */
    private int maxFailedAttempts = 3;

    /** 锁定时长 */
    private Duration lockDuration = Duration.ofMinutes(5);

    /** 限流窗口 */
    private Duration rateLimitWindow = Duration.ofMinutes(1);

    /** 限流窗口内允许的最大登录尝试次数（每用户） */
    private int rateLimitMaxAttempts = 5;

    /** 无需认证的公开路径 */
    private List<String> publicPaths = List.of("/api/public/**", "/api/auth/login");

    /** 是否启用 CSRF 校验（对非 GET 请求校验 X-CSRF-Token） */
    private boolean csrfEnabled = true;

    /** 允许的跨域来源 */
    private List<String> allowedOrigins = List.of("http://localhost:3000");

    public Duration getSessionTtl() { return sessionTtl; }
    public void setSessionTtl(Duration sessionTtl) { this.sessionTtl = sessionTtl; }

    public int getMaxConcurrentSessions() { return maxConcurrentSessions; }
    public void setMaxConcurrentSessions(int maxConcurrentSessions) { this.maxConcurrentSessions = maxConcurrentSessions; }

    public int getMaxFailedAttempts() { return maxFailedAttempts; }
    public void setMaxFailedAttempts(int maxFailedAttempts) { this.maxFailedAttempts = maxFailedAttempts; }

    public Duration getLockDuration() { return lockDuration; }
    public void setLockDuration(Duration lockDuration) { this.lockDuration = lockDuration; }

    public Duration getRateLimitWindow() { return rateLimitWindow; }
    public void setRateLimitWindow(Duration rateLimitWindow) { this.rateLimitWindow = rateLimitWindow; }

    public int getRateLimitMaxAttempts() { return rateLimitMaxAttempts; }
    public void setRateLimitMaxAttempts(int rateLimitMaxAttempts) { this.rateLimitMaxAttempts = rateLimitMaxAttempts; }

    public List<String> getPublicPaths() { return publicPaths; }
    public void setPublicPaths(List<String> publicPaths) { this.publicPaths = publicPaths; }

    public boolean isCsrfEnabled() { return csrfEnabled; }
    public void setCsrfEnabled(boolean csrfEnabled) { this.csrfEnabled = csrfEnabled; }

    public List<String> getAllowedOrigins() { return allowedOrigins; }
    public void setAllowedOrigins(List<String> allowedOrigins) { this.allowedOrigins = allowedOrigins; }
}
