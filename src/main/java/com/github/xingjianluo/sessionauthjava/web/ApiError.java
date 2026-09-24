package com.github.xingjianluo.sessionauthjava.web;

/** Uniform JSON error body. {@code code} is machine-readable and never reveals resource existence. */
public record ApiError(String code, String message, String traceId) {
}
