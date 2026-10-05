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
    /** 会话从未存在过，或失效记录已超过保留期被清理（未知会话） */
    SESSION_UNKNOWN,
    /** 用户已主动登出（登出后再次使用同一会话） */
    SESSION_LOGGED_OUT,
    /** 会话已过期 */
    SESSION_EXPIRED,
    /** 会话已被强制失效（管理员强制下线/降权触发） */
    SESSION_REVOKED,
    /** 并发会话数超限，新登录被拒绝 */
    CONCURRENT_SESSION_LIMIT_EXCEEDED
}
