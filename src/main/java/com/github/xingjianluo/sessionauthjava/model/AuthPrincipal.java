package com.github.xingjianluo.sessionauthjava.model;

import java.util.Map;
import java.util.Set;

/**
 * Live authentication snapshot bound to the current request.
 * Role/attributes are read from the directory on every request, so privilege
 * changes take effect on the very next request even when the session survives.
 */
public record AuthPrincipal(
        String username,
        Role role,
        Set<Permission> permissions,
        String department,
        Map<String, String> attributes,
        String sessionToken,
        String csrfToken
) {
    public boolean has(Permission permission) {
        return permissions.contains(permission);
    }
}
