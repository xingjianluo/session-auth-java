package com.github.xingjianluo.sessionauthjava.web.security;

/** Raised when a state-changing request presents no valid synchronizer CSRF token. */
public class CsrfFailureException extends RuntimeException {
    public CsrfFailureException(String message) {
        super(message);
    }
}
