package com.github.xingjianluo.sessionauthjava.model;

import java.util.Set;

/** Built-in roles and their statically granted permissions. */
public enum Role {
    ADMIN(Set.of(Permission.values())),
    MANAGER(Set.of(Permission.DOC_READ, Permission.DOC_WRITE, Permission.DOC_DELETE)),
    USER(Set.of(Permission.DOC_READ));

    private final Set<Permission> permissions;

    Role(Set<Permission> permissions) {
        this.permissions = permissions;
    }

    public Set<Permission> permissions() {
        return permissions;
    }
}
