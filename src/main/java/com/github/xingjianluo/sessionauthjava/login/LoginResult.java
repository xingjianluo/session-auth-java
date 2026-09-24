package com.github.xingjianluo.sessionauthjava.login;

import com.github.xingjianluo.sessionauthjava.session.SessionRecord;

/**
 * Result of a login attempt with a machine-readable reason.
 *
 * @param reason  precise outcome reason
 * @param session issued session on success, otherwise {@code null}
 */
public record LoginResult(Reason reason, SessionRecord session) {

    public enum Reason {
        SUCCESS,
        BAD_CREDENTIALS,
        ACCOUNT_DISABLED,
        RATE_LIMITED,
        ACCOUNT_LOCKED,
        CONCURRENCY_LIMIT
    }

    public boolean success() {
        return reason == Reason.SUCCESS;
    }
}
