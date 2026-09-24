package com.github.xingjianluo.sessionauthjava.authz;

/**
 * Internally precise denial reasons. These values are written to audit logs and
 * used by tests; only a non-revealing subset is exposed in HTTP responses.
 */
public enum DenyReason {
    ROLE_DENIED,
    ATTRIBUTE_DENIED,
    RESOURCE_NOT_FOUND,
    PATH_NOT_FOUND
}
