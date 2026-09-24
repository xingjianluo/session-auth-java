package com.github.xingjianluo.sessionauthjava.auth.service;

import com.github.xingjianluo.sessionauthjava.auth.config.AuthSecurityProperties;
import com.github.xingjianluo.sessionauthjava.auth.model.AuthFailureReason;
import com.github.xingjianluo.sessionauthjava.auth.model.AuthResult;
import com.github.xingjianluo.sessionauthjava.auth.model.Role;
import com.github.xingjianluo.sessionauthjava.auth.model.SessionRecord;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.security.SecureRandom;
import java.time.Clock;
import java.time.Instant;
import java.util.Base64;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 会话签发、校验与失效管理（内存态）。
 *
 * <p>失效语义可区分：
 * <ul>
 *   <li>主动登出：记录移除，后续校验返回 {@link AuthFailureReason#SESSION_NOT_FOUND}</li>
 *   <li>过期：记录保留，后续校验返回 {@link AuthFailureReason#SESSION_EXPIRED}</li>
 *   <li>撤销（强制下线/降权）：记录保留并标记，后续校验返回 {@link AuthFailureReason#SESSION_REVOKED}</li>
 * </ul>
 * 并发签发通过按用户加锁保证不会超过并发会话上限，也不会重复放行。
 */
@Service
public class SessionService {

    private static final Logger log = LoggerFactory.getLogger(SessionService.class);

    private final AuthSecurityProperties properties;
    private final Clock clock;
    private final ConcurrentHashMap<String, SessionRecord> sessions = new ConcurrentHashMap<>();
    /** 按用户的签发锁，防止并发登录突破会话上限 */
    private final ConcurrentHashMap<String, Object> issueLocks = new ConcurrentHashMap<>();
    private final SecureRandom random = new SecureRandom();

    @org.springframework.beans.factory.annotation.Autowired
    public SessionService(AuthSecurityProperties properties) {
        this(properties, Clock.systemUTC());
    }

    /** 测试可注入固定时钟 */
    public SessionService(AuthSecurityProperties properties, Clock clock) {
        this.properties = properties;
        this.clock = clock;
    }

    /**
     * 校验会话 ID，返回当前有效会话或可区分的失败原因。
     */
    public AuthResult validate(String sessionId) {
        if (sessionId == null || sessionId.isBlank()) {
            log.info("[session] validate: missing session id -> SESSION_NOT_FOUND");
            return AuthResult.failure(AuthFailureReason.SESSION_NOT_FOUND, "no session id provided");
        }
        SessionRecord record = sessions.get(sessionId);
        if (record == null) {
            log.info("[session] validate: id={} unknown -> SESSION_NOT_FOUND", abbrev(sessionId));
            return AuthResult.failure(AuthFailureReason.SESSION_NOT_FOUND, "session does not exist or was logged out");
        }
        if (record.isRevoked()) {
            log.info("[session] validate: id={} user={} -> SESSION_REVOKED", abbrev(sessionId), record.username());
            return AuthResult.failure(AuthFailureReason.SESSION_REVOKED, "session was revoked");
        }
        if (record.isExpiredAt(clock.instant())) {
            log.info("[session] validate: id={} user={} expiresAt={} -> SESSION_EXPIRED",
                    abbrev(sessionId), record.username(), record.expiresAt());
            return AuthResult.failure(AuthFailureReason.SESSION_EXPIRED, "session expired at " + record.expiresAt());
        }
        return AuthResult.success(record);
    }

    /**
     * 签发新会话。并发会话数达到上限时拒绝并返回
     * {@link AuthFailureReason#CONCURRENT_SESSION_LIMIT_EXCEEDED}。
     */
    public AuthResult issue(String username, Role role) {
        Object lock = issueLocks.computeIfAbsent(username, k -> new Object());
        synchronized (lock) {
            int active = activeSessionCount(username);
            if (active >= properties.getMaxConcurrentSessions()) {
                log.info("[session] issue: user={} active={} max={} -> CONCURRENT_SESSION_LIMIT_EXCEEDED",
                        username, active, properties.getMaxConcurrentSessions());
                return AuthResult.failure(AuthFailureReason.CONCURRENT_SESSION_LIMIT_EXCEEDED,
                        "active sessions " + active + " reached limit " + properties.getMaxConcurrentSessions());
            }
            Instant now = clock.instant();
            SessionRecord record = new SessionRecord(newSessionId(), username, role, now,
                    now.plus(properties.getSessionTtl()));
            sessions.put(record.sessionId(), record);
            log.info("[session] issue: user={} id={} expiresAt={} activeNow={}",
                    username, abbrev(record.sessionId()), record.expiresAt(), active + 1);
            return AuthResult.success(record);
        }
    }

    /**
     * 主动登出：移除会话记录。返回是否真实登出了一个存在的会话。
     */
    public boolean logout(String sessionId) {
        SessionRecord removed = sessions.remove(sessionId);
        log.info("[session] logout: id={} removed={}", abbrev(sessionId), removed != null);
        return removed != null;
    }

    /**
     * 撤销某用户全部活跃会话（强制下线/降权时调用），返回撤销数量。
     */
    public int revokeAllForUser(String username) {
        int count = 0;
        for (SessionRecord record : sessions.values()) {
            if (record.username().equals(username) && !record.isRevoked()
                    && !record.isExpiredAt(clock.instant())) {
                record.revoke();
                count++;
            }
        }
        log.info("[session] revokeAllForUser: user={} revoked={}", username, count);
        return count;
    }

    /** 当前某用户的活跃（未过期且未撤销）会话数 */
    public int activeSessionCount(String username) {
        Instant now = clock.instant();
        int count = 0;
        for (SessionRecord record : sessions.values()) {
            if (record.username().equals(username) && !record.isRevoked() && !record.isExpiredAt(now)) {
                count++;
            }
        }
        return count;
    }

    public Optional<SessionRecord> find(String sessionId) {
        return Optional.ofNullable(sessions.get(sessionId));
    }

    /**
     * 派生会话对应的 CSRF 令牌（确定性、无状态，可重复校验）。
     */
    public String csrfTokenFor(String sessionId) {
        try {
            java.security.MessageDigest digest = java.security.MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest((sessionId + ".csrf").getBytes(java.nio.charset.StandardCharsets.UTF_8));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(hash);
        } catch (java.security.NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }

    /** 校验 CSRF 令牌是否匹配会话 */
    public boolean csrfTokenMatches(String sessionId, String token) {
        return token != null && csrfTokenFor(sessionId).equals(token);
    }

    private String newSessionId() {
        byte[] bytes = new byte[32];
        random.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    private static String abbrev(String sessionId) {
        if (sessionId == null) {
            return "<null>";
        }
        return sessionId.length() <= 8 ? sessionId : sessionId.substring(0, 8) + "...";
    }
}
