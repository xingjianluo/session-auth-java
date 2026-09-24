package com.github.xingjianluo.sessionauthjava.controller.dto;

/** Successful login view. */
public record LoginResponse(String username, String role, String csrfToken, long expiresInMillis) {
}
