package com.github.xingjianluo.sessionauthjava.model;

/** Fine-grained permissions that can be granted to a role. */
public enum Permission {
    DOC_READ,
    DOC_WRITE,
    DOC_DELETE,
    SESSION_MANAGE,
    CONFIG_MANAGE,
    AUDIT_READ
}
