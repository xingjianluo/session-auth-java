package com.github.xingjianluo.sessionauthjava.auth.model;

/**
 * 角色定义，权限按角色等级与属性共同判定。
 */
public enum Role {
    USER(1),
    ADMIN(2);

    private final int level;

    Role(int level) {
        this.level = level;
    }

    public int level() {
        return level;
    }

    public boolean includes(Role other) {
        return this.level >= other.level;
    }
}
