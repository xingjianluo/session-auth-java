package com.github.xingjianluo.sessionauthjava.session;

/**
 * A single issued session.
 *
 * @param token          opaque random session id
 * @param username       owning user
 * @param roleAtIssue    role captured at login (informational only)
 * @param createdAtMillis issuance time
 * @param lastSeenMillis last authenticated request time (idle timeout reference)
 * @param csrfToken      per-session synchronizer CSRF token
 */
public record SessionRecord(
        String token,
        String username,
        String roleAtIssue,
        long createdAtMillis,
        long lastSeenMillis,
        String csrfToken
) {
    public SessionRecord withLastSeen(long millis) {
        return new SessionRecord(token, username, roleAtIssue, createdAtMillis, millis, csrfToken);
    }
}
