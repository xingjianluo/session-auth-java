package com.github.xingjianluo.sessionauthjava.auth.model;

import java.time.Instant;

/**
 * 会话记录（内存态）。
 */
public final class SessionRecord {

    private final String sessionId;
    private final String username;
    private final Role roleAtIssue;
    private final Instant issuedAt;
    private final Instant expiresAt;
    private volatile boolean revoked;

    public SessionRecord(String sessionId, String username, Role roleAtIssue,
                         Instant issuedAt, Instant expiresAt) {
        this.sessionId = sessionId;
        this.username = username;
        this.roleAtIssue = roleAtIssue;
        this.issuedAt = issuedAt;
        this.expiresAt = expiresAt;
        this.revoked = false;
    }

    public String sessionId() { return sessionId; }
    public String username() { return username; }
    public Role roleAtIssue() { return roleAtIssue; }
    public Instant issuedAt() { return issuedAt; }
    public Instant expiresAt() { return expiresAt; }
    public boolean isRevoked() { return revoked; }
    public void revoke() { this.revoked = true; }

    public boolean isExpiredAt(Instant now) {
        return !now.isBefore(expiresAt);
    }
}
