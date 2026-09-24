package com.github.xingjianluo.sessionauthjava.web.security;

import com.github.xingjianluo.sessionauthjava.config.SecurityConfigService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import org.springframework.web.filter.OncePerRequestFilter;

/** Adds static security response headers from the current settings snapshot. */
public class SecurityHeadersFilter extends OncePerRequestFilter {

    private final SecurityConfigService configService;

    public SecurityHeadersFilter(SecurityConfigService configService) {
        this.configService = configService;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        var h = configService.current();
        if (notBlank(h.frameOptions())) {
            response.setHeader("X-Frame-Options", h.frameOptions());
        }
        if (notBlank(h.contentTypeOptions())) {
            response.setHeader("X-Content-Type-Options", h.contentTypeOptions());
        }
        if (notBlank(h.referrerPolicy())) {
            response.setHeader("Referrer-Policy", h.referrerPolicy());
        }
        if (notBlank(h.contentSecurityPolicy())) {
            response.setHeader("Content-Security-Policy", h.contentSecurityPolicy());
        }
        filterChain.doFilter(request, response);
    }

    private static boolean notBlank(String value) {
        return value != null && !value.isBlank() && !"-".equals(value);
    }
}
