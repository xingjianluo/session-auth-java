package com.github.xingjianluo.sessionauthjava.session;

/**
 * Result of validating an presented session token.
 *
 * @param status  ACTIVE or the precise invalid reason
 * @param session the resolved active session, or {@code null}
 */
public record SessionValidationOutcome(Status status, SessionRecord session) {

    public enum Status {
        ACTIVE,
        MISSING,
        UNKNOWN,
        EXPIRED,
        LOGGED_OUT,
        REVOKED
    }
}
