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
    /**
     * 会话不存在：从未登录/伪造 ID，或失效记录已超过保留期被清理。
     * 注意：取值必须保持为 SESSION_NOT_FOUND（上一轮既有标识，客户端按此值做兼容判断），
     * 不得改名或被新原因顶替；登出/过期/撤销分别使用各自独立的新原因。
     */
    SESSION_NOT_FOUND,
    /** 用户已主动登出（登出后再次使用同一会话） */
    SESSION_LOGGED_OUT,
    /** 会话已过期 */
    SESSION_EXPIRED,
    /** 会话已被强制失效（管理员强制下线/降权触发） */
    SESSION_REVOKED,
    /** 并发会话数超限，新登录被拒绝 */
    CONCURRENT_SESSION_LIMIT_EXCEEDED
}
