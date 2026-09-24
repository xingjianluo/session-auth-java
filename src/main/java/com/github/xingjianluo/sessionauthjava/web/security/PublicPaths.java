package com.github.xingjianluo.sessionauthjava.web.security;

import java.util.Set;

/**
 * Single source of truth for entries that must never be authenticated or authorized.
 * Both the authentication filter and the authorization interceptor consult it, so the
 * two layers can never disagree about what is public.
 */
public final class PublicPaths {

    private static final Set<String> PUBLIC_POST = Set.of("/api/auth/login");
    private static final Set<String> PUBLIC_SAFE = Set.of("/api/auth/csrf");

    private PublicPaths() {
    }

    /** Public API entries; everything not under {@code /api/} is not managed by this security layer. */
    public static boolean isPublicApi(String path, String method) {
        if (path == null || !path.startsWith("/api/")) {
            return true;
        }
        String m = method == null ? "" : method.toUpperCase();
        return switch (m) {
            case "GET", "HEAD", "OPTIONS" -> PUBLIC_SAFE.contains(path);
            case "POST" -> PUBLIC_POST.contains(path);
            default -> false;
        };
    }

    public static boolean isManagedApi(String path) {
        return path != null && path.startsWith("/api/");
    }
}
