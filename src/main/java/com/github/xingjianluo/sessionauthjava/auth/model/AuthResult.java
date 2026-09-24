package com.github.xingjianluo.sessionauthjava.auth.model;

/**
 * 认证结果：要么成功携带会话，要么失败携带可区分原因。
 */
public sealed interface AuthResult {

    record Success(SessionRecord session) implements AuthResult { }

    record Failure(AuthFailureReason reason, String detail) implements AuthResult { }

    static AuthResult success(SessionRecord session) {
        return new Success(session);
    }

    static AuthResult failure(AuthFailureReason reason, String detail) {
        return new Failure(reason, detail);
    }

    default boolean isSuccess() {
        return this instanceof Success;
    }
}
