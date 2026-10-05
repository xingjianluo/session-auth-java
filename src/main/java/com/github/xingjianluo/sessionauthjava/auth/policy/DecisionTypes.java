package com.github.xingjianluo.sessionauthjava.auth.policy;

/**
 * 可回放的判定类型常量（生产方与回放方共用，避免拼写漂移）。
 */
public final class DecisionTypes {

    private DecisionTypes() {
    }

    /** 会话校验（输入：exists/loggedOut/revoked/expiresAt/now） */
    public static final String SESSION_VALIDATE = "SESSION_VALIDATE";
    /** 登录限流/锁定检查（输入：failures/lockedUntil/now） */
    public static final String LOGIN_BLOCKED = "LOGIN_BLOCKED";
    /** 会话签发并发上限（输入：activeCount） */
    public static final String SESSION_ISSUE = "SESSION_ISSUE";
    /** 公开路径判定（输入：path） */
    public static final String PUBLIC_PATH = "PUBLIC_PATH";
    /** 跨域来源判定（输入：origin） */
    public static final String CORS_ORIGIN = "CORS_ORIGIN";
    /** CSRF 判定（输入：method/path/authenticated/tokenValid） */
    public static final String CSRF = "CSRF";
}
