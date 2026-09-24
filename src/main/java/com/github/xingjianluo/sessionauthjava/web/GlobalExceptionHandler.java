package com.github.xingjianluo.sessionauthjava.web;

import com.github.xingjianluo.sessionauthjava.session.SessionValidationOutcome;
import com.github.xingjianluo.sessionauthjava.audit.AuditService;
import com.github.xingjianluo.sessionauthjava.audit.AuthorizationEvent;
import com.github.xingjianluo.sessionauthjava.authz.AccessRuleRegistry;
import com.github.xingjianluo.sessionauthjava.authz.Decision;
import com.github.xingjianluo.sessionauthjava.config.SecurityConfigService;
import com.github.xingjianluo.sessionauthjava.model.AuthPrincipal;
import com.github.xingjianluo.sessionauthjava.support.TimeSource;
import com.github.xingjianluo.sessionauthjava.web.security.AccessDeniedException;
import com.github.xingjianluo.sessionauthjava.web.security.AuthenticationFilter;
import com.github.xingjianluo.sessionauthjava.web.security.AuthenticationRequiredException;
import com.github.xingjianluo.sessionauthjava.web.security.CsrfFailureException;
import com.github.xingjianluo.sessionauthjava.authz.DenyReason;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.web.servlet.NoHandlerFoundException;

/**
 * Translates every exception into the uniform {@link ApiError} body. Internal deny reasons
 * stay server-side (audit log); responses only carry safe codes so resource existence and
 * session validity cannot be probed beyond the intended coarse distinctions.
 */
@RestControllerAdvice
public class GlobalExceptionHandler {

    private static final Logger log = LoggerFactory.getLogger(GlobalExceptionHandler.class);

    private final AuditService auditService;
    private final AccessRuleRegistry ruleRegistry;
    private final SecurityConfigService configService;
    private final TimeSource timeSource;

    public GlobalExceptionHandler(AuditService auditService, AccessRuleRegistry ruleRegistry,
                                  SecurityConfigService configService, TimeSource timeSource) {
        this.auditService = auditService;
        this.ruleRegistry = ruleRegistry;
        this.configService = configService;
        this.timeSource = timeSource;
    }

    @ExceptionHandler(AuthenticationRequiredException.class)
    public ResponseEntity<ApiError> handleAuthentication(AuthenticationRequiredException ex) {
        HttpStatus status = switch (ex.getStatus()) {
            case MISSING, UNKNOWN, LOGGED_OUT, EXPIRED, REVOKED -> HttpStatus.UNAUTHORIZED;
            default -> HttpStatus.UNAUTHORIZED;
        };
        String code = switch (ex.getStatus()) {
            case MISSING -> "SESSION_MISSING";
            case UNKNOWN -> "SESSION_UNKNOWN";
            case EXPIRED -> "SESSION_EXPIRED";
            case LOGGED_OUT -> "SESSION_LOGGED_OUT";
            case REVOKED -> "SESSION_REVOKED";
            default -> "UNAUTHENTICATED";
        };
        return body(status, code, "Authentication is required", ex);
    }

    @ExceptionHandler(CsrfFailureException.class)
    public ResponseEntity<ApiError> handleCsrf(CsrfFailureException ex) {
        return body(HttpStatus.FORBIDDEN, "CSRF_INVALID", "Cross-site request rejected", ex);
    }

    @ExceptionHandler(AccessDeniedException.class)
    public ResponseEntity<ApiError> handleAccessDenied(AccessDeniedException ex) {
        // Role/attribute denials -> 403. Missing path/resource denials -> 404 with an
        // identical-looking body, hiding whether the resource exists.
        if (ex.getReason() == DenyReason.ROLE_DENIED) {
            return body(HttpStatus.FORBIDDEN, "ACCESS_DENIED", "Access denied", ex);
        }
        if (ex.getReason() == DenyReason.ATTRIBUTE_DENIED) {
            return body(HttpStatus.NOT_FOUND, "NOT_FOUND", "Resource not found", ex);
        }
        return body(HttpStatus.NOT_FOUND, "NOT_FOUND", "Resource not found", ex);
    }

    @ExceptionHandler(NoHandlerFoundException.class)
    public ResponseEntity<ApiError> handleNoHandler(NoHandlerFoundException ex,
                                                    HttpServletRequest request) {
        // The interceptor never runs for un-mapped paths; record the same PATH_NOT_FOUND
        // evidence here so every protected entry point has an explainable audit decision.
        String path = request.getRequestURI();
        if (path != null && path.startsWith("/api/")) {
            AuthPrincipal principal = (AuthPrincipal) request.getAttribute(
                    AuthenticationFilter.PRINCIPAL_ATTRIBUTE);
            var ruleSet = ruleRegistry.current();
            auditService.record(new AuthorizationEvent(
                    timeSource.nowMillis(),
                    principal == null ? null : principal.username(),
                    principal == null ? null : principal.sessionToken(),
                    request.getMethod(), path,
                    Decision.DENY, DenyReason.PATH_NOT_FOUND, null,
                    ruleSet.profile(), ruleSet.version(),
                    configService.current().version(),
                    principal == null ? null : principal.role().name(),
                    principal == null ? java.util.Map.of() : principal.attributes(),
                    java.util.Map.of()));
        }
        return body(HttpStatus.NOT_FOUND, "NOT_FOUND", "Resource not found", ex);
    }

    @ExceptionHandler(HttpMessageNotReadableException.class)
    public ResponseEntity<ApiError> handleBadRequest(HttpMessageNotReadableException ex) {
        return body(HttpStatus.BAD_REQUEST, "BAD_REQUEST", "Malformed request", ex);
    }

    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<ApiError> handleIllegalArgument(IllegalArgumentException ex) {
        return body(HttpStatus.BAD_REQUEST, "BAD_REQUEST", ex.getMessage(), ex);
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<ApiError> handleOther(Exception ex) {
        return body(HttpStatus.INTERNAL_SERVER_ERROR, "INTERNAL_ERROR", "Unexpected error", ex);
    }

    private ResponseEntity<ApiError> body(HttpStatus status, String code, String message, Exception ex) {
        String traceId = UUID.randomUUID().toString();
        log.warn("API error status={} code={} reason={} traceId={} msg={}",
                status.value(), code, ex.getClass().getSimpleName(), traceId, ex.getMessage());
        return ResponseEntity.status(status).body(new ApiError(code, message, traceId));
    }
}
