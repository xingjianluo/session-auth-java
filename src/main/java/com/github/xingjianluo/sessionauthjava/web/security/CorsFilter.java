package com.github.xingjianluo.sessionauthjava.web.security;

import com.github.xingjianluo.sessionauthjava.config.SecurityConfigService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * Applies configurable CORS headers. Preflight requests ({@code OPTIONS} with
 * {@code Access-Control-Request-Method}) are answered and short-circuited before
 * authentication so legitimate browser handshakes are never blocked by the
 * session/CSRF layer; the actual cross-origin request still runs the full chain.
 */
public class CorsFilter extends OncePerRequestFilter {

    private final SecurityConfigService configService;

    public CorsFilter(SecurityConfigService configService) {
        this.configService = configService;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        var settings = configService.current();
        if (!settings.corsEnabled()) {
            filterChain.doFilter(request, response);
            return;
        }
        String origin = request.getHeader("Origin");
        if (origin != null) {
            response.setHeader("Access-Control-Allow-Origin", origin);
            response.setHeader("Vary", "Origin");
            response.setHeader("Access-Control-Allow-Methods", settings.corsAllowedMethods());
            response.setHeader("Access-Control-Allow-Headers",
                    "Content-Type, " + settings.csrfHeaderName());
            response.setHeader("Access-Control-Expose-Headers", settings.csrfHeaderName());
            if (settings.corsAllowCredentials()) {
                response.setHeader("Access-Control-Allow-Credentials", "true");
            }
            response.setHeader("Access-Control-Max-Age", "600");
        }
        if (isPreflight(request)) {
            response.setStatus(HttpServletResponse.SC_NO_CONTENT);
            return;
        }
        filterChain.doFilter(request, response);
    }

    private boolean isPreflight(HttpServletRequest request) {
        return "OPTIONS".equalsIgnoreCase(request.getMethod())
                && request.getHeader("Access-Control-Request-Method") != null;
    }
}
