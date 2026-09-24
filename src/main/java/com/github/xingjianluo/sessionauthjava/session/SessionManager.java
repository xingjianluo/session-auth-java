package com.github.xingjianluo.sessionauthjava.session;

import com.github.xingjianluo.sessionauthjava.support.TimeSource;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.locks.ReentrantLock;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

/**
 * Thread-safe in-memory store and lifecycle manager for sessions.
 *
 * <p>Concurrency guarantees:
 * <ul>
 *   <li>per-user locks serialize "count active sessions + issue new session", so concurrent
 *       logins can never both pass the concurrency limit;</li>
 *   <li>per-token locks serialize "check status/expiry + slide window", so concurrent or
 *       duplicate requests on the same token are validated exactly once consistently and
 *       cannot race a logout/revoke against an in-flight request.</li>
 * </ul>
 */
@Component
public class SessionManager {

    private static final Logger log = LoggerFactory.getLogger(SessionManager.class);

    private final TimeSource timeSource;
    private final CsrfTokenService csrfTokenService;

    /** Token -> live state (including terminal records, needed to explain the rejection). */
    private final ConcurrentHashMap<String, TokenEntry> tokens = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, ReentrantLock> userLocks = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, ReentrantLock> tokenLocks = new ConcurrentHashMap<>();

    public SessionManager(TimeSource timeSource, CsrfTokenService csrfTokenService) {
        this.timeSource = timeSource;
        this.csrfTokenService = csrfTokenService;
    }

    /** Atomically issues a session for the user unless the active-session limit is reached. */
    public IssueResult issue(String username, String role, int maxActiveSessions) {
        long now = timeSource.nowMillis();
        ReentrantLock lock = userLocks.computeIfAbsent(username, k -> new ReentrantLock());
        lock.lock();
        try {
            List<TokenEntry> active = new ArrayList<>();
            for (TokenEntry entry : tokens.values()) {
                if (entry.record.username().equals(username) && isActive(entry, now)) {
                    active.add(entry);
                }
            }
            if (active.size() >= maxActiveSessions) {
                log.warn("Issue rejected for user={}: concurrency limit {} reached, activeTokens={}",
                        username, maxActiveSessions, active.stream().map(e -> e.record.token()).toList());
                return new IssueResult(IssueResult.Status.CONCURRENCY_LIMIT, null);
            }
            SessionRecord record = new SessionRecord(
                    newToken(), username, role, now, now, csrfTokenService.generate());
            tokens.put(record.token(), new TokenEntry(record, SessionStatus.ACTIVE));
            log.info("Session issued token={} user={} role={} activeCount={}/{}",
                    mask(record.token()), username, role, active.size() + 1, maxActiveSessions);
            return new IssueResult(IssueResult.Status.ISSUED, record);
        } finally {
            lock.unlock();
        }
    }

    /**
     * Atomically validates the token, enforces idle expiry and slides the idle window.
     * A terminal status (LOGGED_OUT/REVOKED) is remembered so the reason stays
     * distinguishable after the session ends.
     */
    public SessionValidationOutcome validate(String token, long idleTimeoutMillis) {
        if (token == null || token.isBlank()) {
            return new SessionValidationOutcome(SessionValidationOutcome.Status.MISSING, null);
        }
        TokenEntry entry = tokens.get(token);
        if (entry == null) {
            log.warn("Session validation failed token={}: UNKNOWN (no such token)", mask(token));
            return new SessionValidationOutcome(SessionValidationOutcome.Status.UNKNOWN, null);
        }
        ReentrantLock lock = tokenLocks.computeIfAbsent(token, k -> new ReentrantLock());
        lock.lock();
        try {
            long now = timeSource.nowMillis();
            switch (entry.status) {
                case LOGGED_OUT -> {
                    log.warn("Session validation failed token={}: LOGGED_OUT", mask(token));
                    return new SessionValidationOutcome(SessionValidationOutcome.Status.LOGGED_OUT, null);
                }
                case REVOKED -> {
                    log.warn("Session validation failed token={}: REVOKED", mask(token));
                    return new SessionValidationOutcome(SessionValidationOutcome.Status.REVOKED, null);
                }
                case EXPIRED -> {
                    log.warn("Session validation failed token={}: EXPIRED", mask(token));
                    return new SessionValidationOutcome(SessionValidationOutcome.Status.EXPIRED, null);
                }
                case ACTIVE -> {
                    long idleFor = now - entry.record.lastSeenMillis();
                    if (idleFor >= idleTimeoutMillis) {
                        entry.status = SessionStatus.EXPIRED;
                        entry.endedAtMillis = now;
                        log.warn("Session validation failed token={}: EXPIRED idle={}ms >= ttl={}ms",
                                mask(token), idleFor, idleTimeoutMillis);
                        return new SessionValidationOutcome(SessionValidationOutcome.Status.EXPIRED, null);
                    }
                    entry.record = entry.record.withLastSeen(now);
                    return new SessionValidationOutcome(SessionValidationOutcome.Status.ACTIVE, entry.record);
                }
                default -> {
                    return new SessionValidationOutcome(SessionValidationOutcome.Status.UNKNOWN, null);
                }
            }
        } finally {
            lock.unlock();
        }
    }

    /** Marks the caller's own session LOGGED_OUT. */
    public boolean logout(String token) {
        return terminate(token, SessionStatus.LOGGED_OUT);
    }

    /** Administratively marks one session REVOKED. */
    public boolean revoke(String token) {
        return terminate(token, SessionStatus.REVOKED);
    }

    /** Administratively revokes all active sessions of a user; returns the affected tokens. */
    public List<String> revokeUser(String username) {
        long now = timeSource.nowMillis();
        List<String> revoked = new ArrayList<>();
        ReentrantLock lock = userLocks.computeIfAbsent(username, k -> new ReentrantLock());
        lock.lock();
        try {
            for (TokenEntry entry : tokens.values()) {
                if (entry.record.username().equals(username) && isActive(entry, now)) {
                    ReentrantLock tokenLock = tokenLocks.computeIfAbsent(
                            entry.record.token(), k -> new ReentrantLock());
                    tokenLock.lock();
                    try {
                        if (isActive(entry, now)) {
                            entry.status = SessionStatus.REVOKED;
                            entry.endedAtMillis = now;
                            revoked.add(entry.record.token());
                        }
                    } finally {
                        tokenLock.unlock();
                    }
                }
            }
        } finally {
            lock.unlock();
        }
        log.info("Revoked all active sessions user={} count={} tokens={}",
                username, revoked.size(), revoked.stream().map(SessionManager::mask).toList());
        return revoked;
    }

    /** Active (non-expired, non-terminal) sessions for a user; expired ones are purged. */
    public List<SessionRecord> activeSessions(String username, long idleTimeoutMillis) {
        long now = timeSource.nowMillis();
        List<SessionRecord> result = new ArrayList<>();
        for (TokenEntry entry : tokens.values()) {
            if (entry.record.username().equals(username)) {
                if (entry.status == SessionStatus.ACTIVE
                        && now - entry.record.lastSeenMillis() >= idleTimeoutMillis) {
                    entry.status = SessionStatus.EXPIRED;
                    entry.endedAtMillis = now;
                }
                if (isActive(entry, now)) {
                    result.add(entry.record);
                }
            }
        }
        return result;
    }

    public int activeCount(String username, long idleTimeoutMillis) {
        return activeSessions(username, idleTimeoutMillis).size();
    }

    private boolean terminate(String token, SessionStatus target) {
        TokenEntry entry = tokens.get(token);
        if (entry == null) {
            return false;
        }
        ReentrantLock lock = tokenLocks.computeIfAbsent(token, k -> new ReentrantLock());
        lock.lock();
        try {
            if (entry.status != SessionStatus.ACTIVE) {
                return false;
            }
            entry.status = target;
            entry.endedAtMillis = timeSource.nowMillis();
            log.info("Session terminated token={} user={} newStatus={}",
                    mask(token), entry.record.username(), target);
            return true;
        } finally {
            lock.unlock();
        }
    }

    private boolean isActive(TokenEntry entry, long now) {
        if (entry.status != SessionStatus.ACTIVE) {
            return false;
        }
        return true;
    }

    private String newToken() {
        byte[] bytes = new byte[32];
        new java.security.SecureRandom().nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    /** Masks a token for logs: only the first 8 characters are shown. */
    public static String mask(String token) {
        if (token == null) {
            return "null";
        }
        return token.length() <= 8 ? "***" : token.substring(0, 8) + "***";
    }

    /** Mutable storage entry guarded by the corresponding token/user lock. */
    private static final class TokenEntry {
        private SessionRecord record;
        private volatile SessionStatus status;
        private volatile long endedAtMillis;

        private TokenEntry(SessionRecord record, SessionStatus status) {
            this.record = record;
            this.status = status;
        }
    }

    /** Result of an issuance attempt. */
    public record IssueResult(Status status, SessionRecord session) {
        public enum Status {
            ISSUED,
            CONCURRENCY_LIMIT
        }
    }
}
