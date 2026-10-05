package com.github.xingjianluo.sessionauthjava.auth.service;

import com.github.xingjianluo.sessionauthjava.auth.config.AuthSecurityProperties;
import com.github.xingjianluo.sessionauthjava.auth.model.AuthFailureReason;
import com.github.xingjianluo.sessionauthjava.auth.model.AuthResult;
import com.github.xingjianluo.sessionauthjava.auth.model.Role;
import com.github.xingjianluo.sessionauthjava.auth.model.SessionRecord;
import com.github.xingjianluo.sessionauthjava.auth.policy.DecisionLog;
import com.github.xingjianluo.sessionauthjava.auth.policy.DecisionTypes;
import com.github.xingjianluo.sessionauthjava.auth.policy.PolicyDecisions;
import com.github.xingjianluo.sessionauthjava.auth.policy.PolicyService;
import com.github.xingjianluo.sessionauthjava.auth.policy.PolicySettings;
import com.github.xingjianluo.sessionauthjava.auth.policy.PolicySnapshot;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.security.SecureRandom;
import java.time.Clock;
import java.time.Instant;
import java.util.Base64;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 会话签发、校验与失效管理（内存态）。
 *
 * <p>失效语义可区分且跨入口一致（统一走 {@link PolicyDecisions#validateSession}）：
 * <ul>
 *   <li>从未存在/未知：{@link AuthFailureReason#SESSION_NOT_FOUND}</li>
 *   <li>主动登出：{@link AuthFailureReason#SESSION_LOGGED_OUT}（登出是终态，覆盖过期/撤销）</li>
 *   <li>过期：{@link AuthFailureReason#SESSION_EXPIRED}</li>
 *   <li>撤销（强制下线/降权）：{@link AuthFailureReason#SESSION_REVOKED}（与过期叠加时优先报撤销）</li>
 * </ul>
 * 登出通过有界墓碑表记录，重复登出幂等；并发登出/校验下原因与计数稳定。
 * 每条判定写入 {@link DecisionLog} 并标注策略版本，支持历史回放。
 */
@Service
public class SessionService {

    private static final Logger log = LoggerFactory.getLogger(SessionService.class);

    /** 登出墓碑保留上限，超出后最旧的墓碑被淘汰（之后按"未知"处理） */
    static final int TOMBSTONE_CAP = 10_000;

    private final PolicyService policyService;
    private final DecisionLog decisionLog;
    private final Clock clock;
    private final ConcurrentHashMap<String, SessionRecord> sessions = new ConcurrentHashMap<>();
    /** 按用户的签发锁，防止并发登录突破会话上限 */
    private final ConcurrentHashMap<String, Object> issueLocks = new ConcurrentHashMap<>();
    /** 登出墓碑（有界 LRU）：sessionId -> 占位值 */
    private final Map<String, Boolean> loggedOutTombstones = Collections.synchronizedMap(
            new LinkedHashMap<>(16, 0.75f, false) {
                @Override
                protected boolean removeEldestEntry(Map.Entry<String, Boolean> eldest) {
                    return size() > TOMBSTONE_CAP;
                }
            });
    private final SecureRandom random = new SecureRandom();

    @org.springframework.beans.factory.annotation.Autowired
    public SessionService(AuthSecurityProperties properties, PolicyService policyService,
                          DecisionLog decisionLog) {
        this(policyService, decisionLog, Clock.systemUTC());
    }

    /** 测试可注入固定时钟（沿用旧签名，策略与判定日志用默认实例） */
    public SessionService(AuthSecurityProperties properties, Clock clock) {
        this(new PolicyService(properties), new DecisionLog(), clock);
    }

    /** 测试可注入共享的策略服务/判定日志与固定时钟 */
    public SessionService(PolicyService policyService, DecisionLog decisionLog, Clock clock) {
        this.policyService = policyService;
        this.decisionLog = decisionLog;
        this.clock = clock;
    }

    /**
     * 校验会话 ID，返回当前有效会话或可区分的失败原因。
     */
    public AuthResult validate(String sessionId) {
        PolicySnapshot snapshot = policyService.current();
        Instant now = clock.instant();

        boolean blank = sessionId == null || sessionId.isBlank();
        SessionRecord record = blank ? null : sessions.get(sessionId);
        boolean exists = record != null;
        boolean loggedOut = !exists && !blank && loggedOutTombstones.containsKey(sessionId);
        boolean revoked = exists && record.isRevoked();
        Instant expiresAt = exists ? record.expiresAt() : null;

        Optional<AuthFailureReason> reason = PolicyDecisions.validateSession(
                exists, loggedOut, revoked, expiresAt, now);
        decisionLog.record(DecisionTypes.SESSION_VALIDATE, snapshot.version(), Map.of(
                "sessionId", abbrev(sessionId),
                "exists", String.valueOf(exists),
                "loggedOut", String.valueOf(loggedOut),
                "revoked", String.valueOf(revoked),
                "expiresAt", expiresAt == null ? "" : expiresAt.toString(),
                "now", now.toString()),
                reason.map(Enum::name).orElse("OK"));

        if (reason.isPresent()) {
            AuthFailureReason failure = reason.get();
            String detail = switch (failure) {
                case SESSION_NOT_FOUND -> blank
                        ? "no session id provided"
                        : "session does not exist (never existed or unknown)";
                case SESSION_LOGGED_OUT -> "session was logged out by the user";
                case SESSION_REVOKED -> "session was revoked";
                case SESSION_EXPIRED -> "session expired at " + expiresAt;
                default -> "session invalid: " + failure;
            };
            log.info("[session] validate: id={} exists={} loggedOut={} revoked={} -> {}",
                    abbrev(sessionId), exists, loggedOut, revoked, failure);
            return AuthResult.failure(failure, detail);
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
            PolicySnapshot snapshot = policyService.current();
            PolicySettings settings = snapshot.settings();
            int active = activeSessionCount(username);
            boolean allowed = PolicyDecisions.issueAllowed(active, settings);
            decisionLog.record(DecisionTypes.SESSION_ISSUE, snapshot.version(), Map.of(
                    "username", username,
                    "activeCount", String.valueOf(active)),
                    allowed ? "ISSUED" : "LIMIT_EXCEEDED");
            if (!allowed) {
                log.info("[session] issue: user={} active={} max={} -> CONCURRENT_SESSION_LIMIT_EXCEEDED",
                        username, active, settings.maxConcurrentSessions());
                return AuthResult.failure(AuthFailureReason.CONCURRENT_SESSION_LIMIT_EXCEEDED,
                        "active sessions " + active + " reached limit " + settings.maxConcurrentSessions());
            }
            Instant now = clock.instant();
            SessionRecord record = new SessionRecord(newSessionId(), username, role, now,
                    now.plus(settings.sessionTtl()));
            sessions.put(record.sessionId(), record);
            log.info("[session] issue: user={} id={} expiresAt={} activeNow={}",
                    username, abbrev(record.sessionId()), record.expiresAt(), active + 1);
            return AuthResult.success(record);
        }
    }

    /**
     * 主动登出：终止会话并留下墓碑，后续校验返回
     * {@link AuthFailureReason#SESSION_LOGGED_OUT}。
     * 重复登出幂等（返回 false），原因保持稳定。
     */
    public boolean logout(String sessionId) {
        // 先写墓碑再移除记录：并发的 validate 要么还看到记录（按记录状态判定），
        // 要么看到墓碑（SESSION_LOGGED_OUT），不会出现"刚登出却报未知会话"的窗口。
        if (sessionId != null && sessions.containsKey(sessionId)) {
            loggedOutTombstones.put(sessionId, Boolean.TRUE);
        }
        SessionRecord removed = sessions.remove(sessionId);
        log.info("[session] logout: id={} removed={} tombstoned={}",
                abbrev(sessionId), removed != null, loggedOutTombstones.containsKey(sessionId));
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
