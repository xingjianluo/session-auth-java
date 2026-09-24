package com.github.xingjianluo.sessionauthjava.controller;

import com.github.xingjianluo.sessionauthjava.config.SecurityConfigService;
import com.github.xingjianluo.sessionauthjava.controller.dto.LoginRequest;
import com.github.xingjianluo.sessionauthjava.controller.dto.LoginResponse;
import com.github.xingjianluo.sessionauthjava.login.LoginResult;
import com.github.xingjianluo.sessionauthjava.login.LoginService;
import com.github.xingjianluo.sessionauthjava.session.CsrfTokenService;
import com.github.xingjianluo.sessionauthjava.session.SessionRecord;
import com.github.xingjianluo.sessionauthjava.web.ApiError;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.util.Map;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/** Public login/logout plus a CSRF bootstrap endpoint. */
@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private static final Logger log = LoggerFactory.getLogger(AuthController.class);

    private final LoginService loginService;
    private final SecurityConfigService configService;
    private final CsrfTokenService csrfTokenService;

    public AuthController(LoginService loginService, SecurityConfigService configService,
                          CsrfTokenService csrfTokenService) {
        this.loginService = loginService;
        this.configService = configService;
        this.csrfTokenService = csrfTokenService;
    }

    /**
     * Issues a session on success. Every failure maps to a distinct safe code; unknown user
     * and wrong password share {@code BAD_CREDENTIALS} to prevent user enumeration.
     */
    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody LoginRequest body, HttpServletResponse response) {
        if (body == null || body.username() == null || body.password() == null) {
            return ResponseEntity.badRequest()
                    .body(new ApiError("BAD_REQUEST", "username and password are required", null));
        }
        LoginResult result = loginService.login(body.username(), body.password());
        if (!result.success()) {
            HttpStatus status = switch (result.reason()) {
                case RATE_LIMITED -> HttpStatus.TOO_MANY_REQUESTS;
                case ACCOUNT_LOCKED, ACCOUNT_DISABLED -> HttpStatus.LOCKED;
                case CONCURRENCY_LIMIT -> HttpStatus.CONFLICT;
                default -> HttpStatus.UNAUTHORIZED;
            };
            String code = switch (result.reason()) {
                case BAD_CREDENTIALS -> "BAD_CREDENTIALS";
                case ACCOUNT_DISABLED -> "ACCOUNT_DISABLED";
                case RATE_LIMITED -> "RATE_LIMITED";
                case ACCOUNT_LOCKED -> "ACCOUNT_LOCKED";
                case CONCURRENCY_LIMIT -> "CONCURRENCY_LIMIT";
                default -> "LOGIN_FAILED";
            };
            log.info("Login response user={} -> {} {}", body.username(), status.value(), code);
            return ResponseEntity.status(status).body(new ApiError(code, code, null));
        }

        SessionRecord session = result.session();
        addSessionCookie(response, session.token());
        LoginResponse payload = new LoginResponse(
                session.username(), session.roleAtIssue(), session.csrfToken(),
                configService.current().sessionIdleTimeoutMillis());
        return ResponseEntity.ok(payload);
    }

    @PostMapping("/logout")
    public ResponseEntity<?> logout(HttpServletRequest request) {
        String token = readCookie(request, configService.current().sessionCookieName());
        loginService.logout(token);
        return ResponseEntity.ok(Map.of("status", "LOGGED_OUT"));
    }

    /** Public helper allowing clients to obtain a fresh CSRF token before login. */
    @GetMapping("/csrf")
    public Map<String, String> csrf() {
        return Map.of("csrfToken", csrfTokenService.generate(), "headerName",
                configService.current().csrfHeaderName());
    }

    private void addSessionCookie(HttpServletResponse response, String token) {
        var s = configService.current();
        org.springframework.http.ResponseCookie springCookie = org.springframework.http.ResponseCookie
                .from(s.sessionCookieName(), token)
                .httpOnly(s.sessionCookieHttpOnly())
                .secure(s.sessionCookieSecure())
                .sameSite(s.sessionCookieSameSite())
                .path(s.sessionCookiePath())
                .build();
        response.addHeader("Set-Cookie", springCookie.toString());
    }

    private String readCookie(HttpServletRequest request, String name) {
        Cookie[] cookies = request.getCookies();
        if (cookies != null) {
            for (Cookie cookie : cookies) {
                if (name.equals(cookie.getName())) {
                    return cookie.getValue();
                }
            }
        }
        return null;
    }
}
