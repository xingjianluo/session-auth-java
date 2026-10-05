package com.github.xingjianluo.sessionauthjava.auth.model;

/**
 * 认证/会话校验失败原因，要求各入口下可区分、可解释。
 */
public enum AuthFailureReason {
    /** 用户名或密码错误 */
    INVALID_CREDENTIALS,
    /** 连续失败触发限流（单位时间尝试次数超限） */
    RATE_LIMITED,
    /** 连续失败触发账户锁定 */
    ACCOUNT_LOCKED,
    /** 会话不存在（未登录，或会话 ID 从未存在/未知） */
    SESSION_NOT_FOUND,
    /** 用户已主动登出（会话曾存在，被登出终止） */
    SESSION_LOGGED_OUT,
    /** 会话已过期 */
    SESSION_EXPIRED,
    /** 会话已被撤销（管理员强制下线/降权） */
    SESSION_REVOKED,
    /** 并发会话数超限，新登录被拒绝 */
    CONCURRENT_SESSION_LIMIT_EXCEEDED
}
