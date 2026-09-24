package com.github.xingjianluo.sessionauthjava.session;

/** Terminal lifecycle states of an issued session token. */
public enum SessionStatus {
    ACTIVE,
    EXPIRED,
    LOGGED_OUT,
    REVOKED
}
