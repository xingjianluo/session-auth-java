package com.github.xingjianluo.sessionauthjava.auth.web;

import com.github.xingjianluo.sessionauthjava.auth.model.AuthFailureReason;
import com.github.xingjianluo.sessionauthjava.auth.model.AuthResult;
import com.github.xingjianluo.sessionauthjava.auth.model.SessionRecord;
import com.github.xingjianluo.sessionauthjava.auth.service.AuthService;
import com.github.xingjianluo.sessionauthjava.auth.service.SessionService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestAttribute;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * 登录/登出入口。失败原因通过 HTTP 状态码与 reason 字段双重区分。
 */
@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private static final Logger log = LoggerFactory.getLogger(AuthController.class);

    private final AuthService authService;
    private final SessionService sessionService;

    public AuthController(AuthService authService, SessionService sessionService) {
        this.authService = authService;
        this.sessionService = sessionService;
    }

    public record LoginRequest(String username, String password) { }

    public record LoginResponse(String sessionId, String csrfToken, String username,
                                String role, Instant expiresAt) { }

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody LoginRequest request) {
        AuthResult result = authService.login(request.username(), request.password());
        if (result instanceof AuthResult.Failure failure) {
            HttpStatus status = switch (failure.reason()) {
                case INVALID_CREDENTIALS -> HttpStatus.UNAUTHORIZED;
                case RATE_LIMITED -> HttpStatus.TOO_MANY_REQUESTS;
                case ACCOUNT_LOCKED -> HttpStatus.LOCKED;
                case CONCURRENT_SESSION_LIMIT_EXCEEDED -> HttpStatus.CONFLICT;
                default -> HttpStatus.UNAUTHORIZED;
            };
            log.info("[auth-api] login user={} -> {} reason={}", request.username(), status.value(), failure.reason());
            return ResponseEntity.status(status).body(new ApiError(failure.reason().name(), failure.detail()));
        }
        SessionRecord session = ((AuthResult.Success) result).session();
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("sessionId", session.sessionId());
        body.put("csrfToken", sessionService.csrfTokenFor(session.sessionId()));
        body.put("username", session.username());
        body.put("role", session.roleAtIssue().name());
        body.put("expiresAt", session.expiresAt().toString());
        log.info("[auth-api] login user={} -> 200", request.username());
        return ResponseEntity.ok(body);
    }

    @PostMapping("/logout")
    public ResponseEntity<?> logout(@RequestAttribute(AuthFilter.ATTR_SESSION) SessionRecord session) {
        boolean removed = authService.logout(session.sessionId());
        log.info("[auth-api] logout user={} removed={}", session.username(), removed);
        return ResponseEntity.ok(Map.of("loggedOut", String.valueOf(removed)));
    }
}
