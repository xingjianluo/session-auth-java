package com.github.xingjianluo.sessionauthjava.auth.web;

/**
 * 统一错误响应体：reason 用于区分失败原因，detail 不泄漏敏感信息。
 */
public record ApiError(String reason, String detail) {
}
