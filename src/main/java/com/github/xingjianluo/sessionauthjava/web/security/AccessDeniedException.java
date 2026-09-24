package com.github.xingjianluo.sessionauthjava.web.security;

import com.github.xingjianluo.sessionauthjava.authz.DenyReason;

/** Thrown when an authenticated request fails authorization, carrying the precise internal reason. */
public class AccessDeniedException extends RuntimeException {

    private final DenyReason reason;

    public AccessDeniedException(DenyReason reason, String message) {
        super(message);
        this.reason = reason;
    }

    public DenyReason getReason() {
        return reason;
    }
}
