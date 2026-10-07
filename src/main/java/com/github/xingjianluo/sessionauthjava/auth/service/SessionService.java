package com.github.xingjianluo.sessionauthjava.auth.service;

import com.github.xingjianluo.sessionauthjava.auth.config.AuthSecurityProperties;
import com.github.xingjianluo.sessionauthjava.auth.model.AuthFailureReason;
import com.github.xingjianluo.sessionauthjava.auth.model.AuthResult;
import com.github.xingjianluo.sessionauthjava.auth.model.Role;
import com.github.xingjianluo.sessionauthjava.auth.model.SessionRecord;
import com.github.xingjianluo.sessionauthjava.auth.policy.AuthPolicy;
import com.github.xingjianluo.sessionauthjava.auth.policy.DecisionLog;
import com.github.xingjianluo.sessionauthjava.auth.policy.PolicyEvaluator;
import com.github.xingjianluo.sessionauthjava.auth.policy.PolicyService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.security.SecureRandom;
import java.time.Clock;
import java.time.Instant;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 会话签发、校验与失效管理（内存态）。
 *
 * <p>失效语义可区分且各入口一致：
 * <ul>
 *   <li>从未存在/保留期外：{@link AuthFailureReason#SESSION_NOT_FOUND}</li>
 *   <li>主动登出：{@link AuthFailureReason#SESSION_LOGGED_OUT}（登出时写入墓碑，
 *       重复登出、登出后再访问结论一致）</li>
 *   <li>过期：{@link AuthFailureReason#SESSION_EXPIRED}（记录保留）</li>
 *   <li>强制失效：{@link AuthFailureReason#SESSION_REVOKED}（记录保留并标记，
 *       撤销优先于过期——一旦撤销，无论是否过期都返回 REVOKED）</li>
 * </ul>
 *
 * <p>叠加状态的稳定优先级：REVOKED &gt; LOGGED_OUT &gt; EXPIRED &gt; NOT_FOUND。
 * 失效记录（过期会话与登出墓碑）保留一个会话时长后清理，之后按 NOT_FOUND 处理，
 * 保证长时间运行占用有界。
 *
 * <p>"活动记录 + 墓碑"由同一把 {@code tombstones} 锁保护状态迁移，保证：
 * <ul>
 *   <li>登出（写墓碑 + 移除活动记录）原子：并发校验只会看到"有效"或 LOGGED_OUT，
 *       绝不会在两者之间落回 NOT_FOUND；</li>
 *   <li>撤销用户时同时把该用户已有墓碑升级为 REVOKED：已登出又被强制失效
 *       稳定为 REVOKED（撤销优先），结论与操作先后顺序无关；</li>
 *   <li>重复登出恰好一次真实生效，第二次起返回 false 且原因稳定。</li>
 * </ul>
 *
 * <p>并发签发按用户加锁，不会超过并发会话上限，也不会重复放行。
 */
@Service
public class SessionService {

    private static final Logger log = LoggerFactory.getLogger(SessionService.class);

    /** 登出墓碑保留上限（超出淘汰最旧，防止无限增长） */
    static final int TOMBSTONE_CAPACITY = 10_000;

    private final PolicyService policyService;
    private final DecisionLog decisionLog;
    private final Clock clock;
    private final ConcurrentHashMap<String, SessionRecord> sessions = new ConcurrentHashMap<>();
    /** 登出墓碑：sessionId -> 终态原因与清理时刻（插入序，容量受控） */
    private final Map<String, Tombstone> tombstones = new LinkedHashMap<>();
    /** 按用户的签发锁，防止并发登录突破会话上限 */
    private final ConcurrentHashMap<String, Object> issueLocks = new ConcurrentHashMap<>();
    private final SecureRandom random = new SecureRandom();

    /** 登出墓碑：归属用户、终态原因与清理时刻（插入序，容量受控） */
    private record Tombstone(String username, AuthFailureReason reason, Instant purgeAt) {
    }

    @org.springframework.beans.factory.annotation.Autowired
    public SessionService(PolicyService policyService, DecisionLog decisionLog) {
        this(policyService, decisionLog, Clock.systemUTC());
    }

    /** 兼容旧构造：由配置项独立建一套策略服务 */
    public SessionService(AuthSecurityProperties properties, Clock clock) {
        this(new PolicyService(properties), clock);
    }

    private SessionService(PolicyService policyService, Clock clock) {
        this(policyService, new DecisionLog(policyService), clock);
    }

    public SessionService(PolicyService policyService, DecisionLog decisionLog, Clock clock) {
        this.policyService = policyService;
        this.decisionLog = decisionLog;
        this.clock = clock;
    }

    /**
     * 校验会话 ID，返回当前有效会话或可区分的失败原因。
     * 各入口（认证过滤器、登出后访问、强制失效后访问）都经由此方法，结论一致。
     */
    public AuthResult validate(String sessionId) {
        AuthPolicy policy = policyService.current();
        Instant now = clock.instant();
        prune(now, policy);
        if (sessionId == null || sessionId.isBlank()) {
            log.info("[session] validate: missing session id -> SESSION_NOT_FOUND (policyVersion={})", policy.version());
            return AuthResult.failure(AuthFailureReason.SESSION_NOT_FOUND, "no session id provided");
        }
        SessionRecord record = sessions.get(sessionId);
        if (record != null) {
            // 撤销优先于过期：一旦强制失效，无论是否过期结论都是 REVOKED
            if (record.isRevoked()) {
                log.info("[session] validate: id={} user={} -> SESSION_REVOKED", abbrev(sessionId), record.username());
                return AuthResult.failure(AuthFailureReason.SESSION_REVOKED, "session was revoked");
            }
            if (record.isExpiredAt(now)) {
                log.info("[session] validate: id={} user={} expiresAt={} -> SESSION_EXPIRED",
                        abbrev(sessionId), record.username(), record.expiresAt());
                return AuthResult.failure(AuthFailureReason.SESSION_EXPIRED,
                        "session expired at " + record.expiresAt());
            }
            return AuthResult.success(record);
        }
        Tombstone tombstone;
        synchronized (tombstones) {
            tombstone = tombstones.get(sessionId);
        }
        if (tombstone != null) {
            log.info("[session] validate: id={} -> {} (tombstone)", abbrev(sessionId), tombstone.reason());
            return AuthResult.failure(tombstone.reason(), "session terminated: " + tombstone.reason());
        }
        log.info("[session] validate: id={} unknown -> SESSION_NOT_FOUND", abbrev(sessionId));
        return AuthResult.failure(AuthFailureReason.SESSION_NOT_FOUND, "session never existed or was purged");
    }

    /**
     * 签发新会话。并发会话数达到上限时拒绝并返回
     * {@link AuthFailureReason#CONCURRENT_SESSION_LIMIT_EXCEEDED}。
     * 上限判定使用当前策略版本并记录判定日志（可回放）。
     */
    public AuthResult issue(String username, Role role) {
        Object lock = issueLocks.computeIfAbsent(username, k -> new Object());
        synchronized (lock) {
            AuthPolicy policy = policyService.current();
            Instant now = clock.instant();
            prune(now, policy);
            int active = activeSessionCount(username);
            boolean limited = PolicyEvaluator.sessionLimitReached(policy, active);
            long decisionId = decisionLog.record(DecisionLog.KIND_SESSION_LIMIT, policy.version(),
                    Map.of("user", username, "activeCount", String.valueOf(active)),
                    limited ? "DENIED" : "ALLOWED");
            if (limited) {
                log.info("[session] issue: user={} active={} max={} policyVersion={} decisionId={}"
                                + " -> CONCURRENT_SESSION_LIMIT_EXCEEDED",
                        username, active, policy.maxConcurrentSessions(), policy.version(), decisionId);
                return AuthResult.failure(AuthFailureReason.CONCURRENT_SESSION_LIMIT_EXCEEDED,
                        "active sessions " + active + " reached limit " + policy.maxConcurrentSessions());
            }
            SessionRecord record = new SessionRecord(newSessionId(), username, role, now,
                    now.plus(policy.sessionTtl()));
            sessions.put(record.sessionId(), record);
            log.info("[session] issue: user={} id={} expiresAt={} activeNow={} policyVersion={} decisionId={}",
                    username, abbrev(record.sessionId()), record.expiresAt(), active + 1,
                    policy.version(), decisionId);
            return AuthResult.success(record);
        }
    }

    /**
     * 主动登出：在同一把锁内完成"写墓碑 + 移除活动记录"，保证并发校验要么看到
     * 有效会话、要么看到 LOGGED_OUT，不会落回 NOT_FOUND。重复登出返回 false 且
     * 原因保持 LOGGED_OUT 不变；已撤销会话登出后仍保持 REVOKED（撤销优先）。
     *
     * @return 是否真实登出了一个存在的活动会话
     */
    public boolean logout(String sessionId) {
        AuthPolicy policy = policyService.current();
        Instant now = clock.instant();
        synchronized (tombstones) {
            pruneTombstones(now);
            SessionRecord record = sessions.get(sessionId);
            if (record == null) {
                // 活动记录已不存在：墓碑存在说明是重复登出（原因维持首次终态不变），
                // 墓碑也不存在则可能是从未登录/已过保留期 -> false
                Tombstone existing = tombstones.get(sessionId);
                log.info("[session] logout: id={} no live session (tombstoneKnown={}) -> false",
                        abbrev(sessionId), existing != null);
                return false;
            }
            // 已撤销的会话登出后仍报 REVOKED（撤销优先），否则报 LOGGED_OUT
            AuthFailureReason reason = record.isRevoked()
                    ? AuthFailureReason.SESSION_REVOKED : AuthFailureReason.SESSION_LOGGED_OUT;
            tombstones.putIfAbsent(sessionId,
                    new Tombstone(record.username(), reason, now.plus(policy.sessionTtl())));
            evictTombstonesIfNeeded();
            sessions.remove(sessionId);
            log.info("[session] logout: id={} user={} tombstone={} removed=true",
                    abbrev(sessionId), record.username(), reason);
            return true;
        }
    }

    /**
     * 强制失效某用户全部会话（管理员强制下线/降权触发），返回新撤销的活动会话数量。
     * 在统一状态锁内同时：
     * <ul>
     *   <li>标记活动记录（含已过期记录）撤销——"过期+被强制失效"稳定返回 REVOKED；</li>
     *   <li>把该用户已有的登出墓碑升级为 REVOKED——"登出后又被强制失效"也稳定为
     *       REVOKED，结论与操作先后顺序无关。</li>
     * </ul>
     */
    public int revokeAllForUser(String username) {
        int count = 0;
        synchronized (tombstones) {
            for (SessionRecord record : sessions.values()) {
                if (record.username().equals(username) && !record.isRevoked()) {
                    record.revoke();
                    count++;
                }
            }
            int upgraded = 0;
            for (Map.Entry<String, Tombstone> entry : tombstones.entrySet()) {
                Tombstone t = entry.getValue();
                if (t.username().equals(username) && t.reason() != AuthFailureReason.SESSION_REVOKED) {
                    entry.setValue(new Tombstone(t.username(), AuthFailureReason.SESSION_REVOKED, t.purgeAt()));
                    upgraded++;
                }
            }
            log.info("[session] revokeAllForUser: user={} revokedLive={} upgradedTombstones={}",
                    username, count, upgraded);
        }
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

    /**
     * 清理失效记录：过期超过一个会话时长的会话记录、到期的登出墓碑。
     * 保留期内历史原因（EXPIRED/LOGGED_OUT/REVOKED）稳定可查，清理后归为 NOT_FOUND。
     * 在状态锁内执行，与登出/撤销互斥。
     */
    private void prune(Instant now, AuthPolicy policy) {
        java.time.Duration retention = policy.sessionTtl();
        synchronized (tombstones) {
            sessions.values().removeIf(r -> now.isAfter(r.expiresAt().plus(retention)));
            pruneTombstones(now);
        }
    }

    /** 清理到期墓碑并按容量淘汰最旧；调用方必须持有 tombstones 锁。 */
    private void pruneTombstones(Instant now) {
        tombstones.values().removeIf(t -> now.isAfter(t.purgeAt()));
        evictTombstonesIfNeeded();
    }

    private void evictTombstonesIfNeeded() {
        // 调用方必须持有 tombstones 锁
        java.util.Iterator<String> it = tombstones.keySet().iterator();
        while (tombstones.size() > TOMBSTONE_CAPACITY && it.hasNext()) {
            it.next();
            it.remove();
        }
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
