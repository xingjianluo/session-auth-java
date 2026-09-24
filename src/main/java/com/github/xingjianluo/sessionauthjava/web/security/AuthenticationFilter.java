package com.github.xingjianluo.sessionauthjava.web.security;

import com.github.xingjianluo.sessionauthjava.config.SecurityConfigService;
import com.github.xingjianluo.sessionauthjava.config.SecuritySettings;
import com.github.xingjianluo.sessionauthjava.model.AuthPrincipal;
import com.github.xingjianluo.sessionauthjava.model.UserAccount;
import com.github.xingjianluo.sessionauthjava.model.UserDirectory;
import com.github.xingjianluo.sessionauthjava.session.CsrfTokenService;
import com.github.xingjianluo.sessionauthjava.session.SessionRecord;
import com.github.xingjianluo.sessionauthjava.session.SessionValidationOutcome;
import com.github.xingjianluo.sessionauthjava.session.SessionManager;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.servlet.HandlerExceptionResolver;

/**
 * Establishes the {@link AuthPrincipal} for protected paths and applies session +
 * CSRF controls. Unauthenticated entries never reach this gate.
 *
 * <p>Order of decision (each rejection carries a distinct, logged reason):
 * <ol>
 *   <li>session token missing / unknown / expired / logged-out / revoked -> 401;</li>
 *   <li>account removed or disabled after issuance -> 401 (effective immediately);</li>
 *   <li>state-changing request without a matching CSRF token -> 403;</li>
 *   <li>otherwise the request proceeds with a live principal.</li>
 * </ol>
 */
public class AuthenticationFilter extends OncePerRequestFilter {

    private static final Logger log = LoggerFactory.getLogger(AuthenticationFilter.class);
    public static final String PRINCIPAL_ATTRIBUTE = AuthPrincipal.class.getName();

    private final SessionManager sessionManager;
    private final UserDirectory userDirectory;
    private final CsrfTokenService csrfTokenService;
    private final SecurityConfigService configService;
    private final HandlerExceptionResolver exceptionResolver;

    public AuthenticationFilter(SessionManager sessionManager, UserDirectory userDirectory,
                                CsrfTokenService csrfTokenService,
                                SecurityConfigService configService,
                                HandlerExceptionResolver exceptionResolver) {
        this.sessionManager = sessionManager;
        this.userDirectory = userDirectory;
        this.csrfTokenService = csrfTokenService;
        this.configService = configService;
        this.exceptionResolver = exceptionResolver;
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        String path = request.getRequestURI();
        // Only the API surface is gated; all non-API entries must never be intercepted.
        return !PublicPaths.isManagedApi(path) || PublicPaths.isPublicApi(path, request.getMethod());
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        SecuritySettings settings = configService.current();
        String token = readCookie(request, settings.sessionCookieName());
        SessionValidationOutcome outcome = sessionManager.validate(
                token, settings.sessionIdleTimeoutMillis());
        if (outcome.status() != SessionValidationOutcome.Status.ACTIVE) {
            reject(request, response, new AuthenticationRequiredException(
                    outcome.status(), "Authentication required: " + outcome.status()));
            return;
        }

        SessionRecord session = outcome.session();
        UserAccount user = userDirectory.findByUsername(session.username());
        // Live directory lookup: disablement/deletion takes effect on the next request.
        if (user == null || !user.isEnabled()) {
            log.warn("Auth rejected token={} user={}: account missing or disabled",
                    SessionManager.mask(token), session.username());
            reject(request, response, new AuthenticationRequiredException(
                    SessionValidationOutcome.Status.UNKNOWN, "Account is not available"));
            return;
        }

        if (requiresCsrf(request.getMethod()) && settings.csrfEnabled()) {
            String presented = request.getHeader(settings.csrfHeaderName());
            if (!csrfTokenService.matches(presented, session.csrfToken())) {
                log.warn("CSRF rejected token={} {} {} presented={} expected={}",
                        SessionManager.mask(token), request.getMethod(), request.getRequestURI(),
                        presented == null ? "null" : "present",
                        session.csrfToken() == null ? "null" : "present");
                reject(request, response, new CsrfFailureException("CSRF token missing or invalid"));
                return;
            }
        }

        Map<String, String> attributes = Map.copyOf(user.getAttributes());
        AuthPrincipal principal = new AuthPrincipal(
                user.getUsername(),
                user.getRole(),
                Set.copyOf(user.getRole().permissions()),
                user.getDepartment(),
                attributes,
                session.token(),
                session.csrfToken());
        request.setAttribute(PRINCIPAL_ATTRIBUTE, principal);
        log.debug("Authenticated user={} role={} token={} {} {}",
                principal.username(), principal.role(), SessionManager.mask(token),
                request.getMethod(), request.getRequestURI());
        filterChain.doFilter(request, response);
    }

    private void reject(HttpServletRequest request, HttpServletResponse response, Exception ex) {
        exceptionResolver.resolveException(request, response, null, ex);
    }

    private static boolean requiresCsrf(String method) {
        Set<String> stateChanging = new HashSet<>(Set.of("POST", "PUT", "PATCH", "DELETE"));
        return stateChanging.contains(method == null ? "" : method.toUpperCase());
    }

    private String readCookie(HttpServletRequest request, String cookieName) {
        Cookie[] cookies = request.getCookies();
        if (cookies == null) {
            return null;
        }
        for (Cookie cookie : cookies) {
            if (cookieName.equals(cookie.getName())) {
                return cookie.getValue();
            }
        }
        return null;
    }
}
