package com.github.xingjianluo.sessionauthjava.web.security;

import com.github.xingjianluo.sessionauthjava.session.SessionValidationOutcome;

/** Thrown when authentication is missing or the session is invalid, with the precise cause. */
public class AuthenticationRequiredException extends RuntimeException {

    private final SessionValidationOutcome.Status status;

    public AuthenticationRequiredException(SessionValidationOutcome.Status status, String message) {
        super(message);
        this.status = status;
    }

    public SessionValidationOutcome.Status getStatus() {
        return status;
    }
}
