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
 * <p>叠加状态的稳定优先级：REVOKED &gt; LOGGED_OUT &gt; EXPIRED &gt; SESSION_NOT_FOUND。
 * 失效记录（过期会话与终态墓碑）保留一个会话时长后清理，之后按 SESSION_NOT_FOUND 处理，
 * 保证长时间运行占用有界。
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
    /** 终态墓碑：sessionId -> 终态原因/所属用户与清理时刻（插入序，容量受控） */
    private final Map<String, Tombstone> tombstones = new LinkedHashMap<>();
    /** 按用户的签发锁，防止并发登录突破会话上限 */
    private final ConcurrentHashMap<String, Object> issueLocks = new ConcurrentHashMap<>();
    private final SecureRandom random = new SecureRandom();

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
     * 主动登出：写入墓碑（先）再移除记录（后），保证并发校验要么看到有效会话、
     * 要么看到 LOGGED_OUT，不会落回 SESSION_NOT_FOUND。重复登出返回 false 且原因保持
     * LOGGED_OUT 不变；已撤销会话登出后仍保持 REVOKED。
     *
     * <p>与 {@link #revokeAllForUser(String)} 使用同一把墓碑锁串行化终态写入，
     * 保证"登出与撤销恰好并发"时结论固定：撤销优先（REVOKED &gt; LOGGED_OUT）。
     *
     * @return 是否真实登出了一个存在的会话
     */
    public boolean logout(String sessionId) {
        AuthPolicy policy = policyService.current();
        Instant now = clock.instant();
        SessionRecord record = sessions.get(sessionId);
        if (record == null) {
            boolean known;
            synchronized (tombstones) {
                known = tombstones.containsKey(sessionId);
            }
            log.info("[session] logout: id={} no live session (tombstoneKnown={}) -> false",
                    abbrev(sessionId), known);
            return false;
        }
        boolean removed;
        AuthFailureReason reason;
        synchronized (tombstones) {
            // 持锁后复查：此间若已被撤销（或墓碑已被 revoke 升级），撤销优先
            SessionRecord live = sessions.get(sessionId);
            if (live != null && live.isRevoked()) {
                reason = AuthFailureReason.SESSION_REVOKED;
            } else {
                Tombstone existing = tombstones.get(sessionId);
                reason = existing != null && existing.reason() == AuthFailureReason.SESSION_REVOKED
                        ? AuthFailureReason.SESSION_REVOKED : AuthFailureReason.SESSION_LOGGED_OUT;
            }
            tombstones.putIfAbsent(sessionId,
                    new Tombstone(record.username(), reason, now.plus(policy.sessionTtl())));
            evictTombstonesIfNeeded();
            // 墓碑落稳后再移除活动记录，并发 validate 只能看到"有效"或终态墓碑。
            // sessions 只会被本方法移除（与本方法共用同一把锁串行），故此处必能移除成功。
            removed = sessions.remove(sessionId) != null;
        }
        log.info("[session] logout: id={} user={} tombstone={} removed={}",
                abbrev(sessionId), record.username(), reason, removed);
        return removed;
    }

    /**
     * 强制失效某用户全部会话（管理员强制下线/降权触发），返回新进入 REVOKED 终态的数量：
     * 包括本次新撤销的活动会话，以及与登出并发时从 LOGGED_OUT 升级为 REVOKED 的墓碑。
     * 已过期的活动会话也一并标记，保证"过期+被强制失效"的叠加状态稳定返回 REVOKED。
     * 与 {@link #logout(String)} 共用墓碑锁，终态写入彼此线性化、同输入结论固定。
     */
    public int revokeAllForUser(String username) {
        int count = 0;
        for (SessionRecord record : sessions.values()) {
            if (record.username().equals(username) && !record.isRevoked()) {
                record.revoke();
                count++;
            }
        }
        synchronized (tombstones) {
            // 撤销优先于登出：把并发/刚发生登出写下的 LOGGED_OUT 墓碑升级为 REVOKED。
            // 已过清理时刻的墓碑不复活（留给 prune 清理，清理后按 SESSION_NOT_FOUND 处理）。
            Instant now = clock.instant();
            for (Map.Entry<String, Tombstone> entry : tombstones.entrySet()) {
                Tombstone tombstone = entry.getValue();
                if (tombstone.username().equals(username)
                        && tombstone.reason() == AuthFailureReason.SESSION_LOGGED_OUT
                        && !now.isAfter(tombstone.purgeAt())) {
                    entry.setValue(new Tombstone(tombstone.username(),
                            AuthFailureReason.SESSION_REVOKED, tombstone.purgeAt()));
                    count++;
                }
            }
        }
        log.info("[session] revokeAllForUser: user={} revokedOrUpgraded={}", username, count);
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
     * 保留期内历史原因（EXPIRED/LOGGED_OUT/REVOKED）稳定可查，清理后归为 SESSION_NOT_FOUND。
     */
    private void prune(Instant now, AuthPolicy policy) {
        java.time.Duration retention = policy.sessionTtl();
        sessions.values().removeIf(r -> now.isAfter(r.expiresAt().plus(retention)));
        synchronized (tombstones) {
            tombstones.values().removeIf(t -> now.isAfter(t.purgeAt()));
            evictTombstonesIfNeeded();
        }
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
