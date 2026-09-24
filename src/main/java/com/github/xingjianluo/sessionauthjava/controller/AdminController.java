package com.github.xingjianluo.sessionauthjava.controller;

import com.github.xingjianluo.sessionauthjava.audit.AuditService;
import com.github.xingjianluo.sessionauthjava.audit.AuthorizationEvent;
import com.github.xingjianluo.sessionauthjava.authz.AccessRuleRegistry;
import com.github.xingjianluo.sessionauthjava.authz.RuleSetVersion;
import com.github.xingjianluo.sessionauthjava.authz.RuleSetView;
import com.github.xingjianluo.sessionauthjava.config.SecurityConfigService;
import com.github.xingjianluo.sessionauthjava.config.SecurityProperties;
import com.github.xingjianluo.sessionauthjava.config.SecuritySettings;
import com.github.xingjianluo.sessionauthjava.login.LoginThrottleService;
import com.github.xingjianluo.sessionauthjava.model.Role;
import com.github.xingjianluo.sessionauthjava.model.UserAccount;
import com.github.xingjianluo.sessionauthjava.model.UserDirectory;
import com.github.xingjianluo.sessionauthjava.session.SessionManager;
import java.util.List;
import java.util.Map;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * Administrative operations. Access is restricted centrally by the authorization
 * interceptor ({@code SESSION_MANAGE}/{@code CONFIG_MANAGE}/{@code AUDIT_READ}).
 * All mutations take effect on subsequent requests immediately.
 */
@RestController
@RequestMapping("/api/admin")
public class AdminController {

    private final SessionManager sessionManager;
    private final UserDirectory userDirectory;
    private final SecurityConfigService configService;
    private final SecurityProperties properties;
    private final AccessRuleRegistry ruleRegistry;
    private final AuditService auditService;
    private final LoginThrottleService throttle;

    public AdminController(SessionManager sessionManager, UserDirectory userDirectory,
                           SecurityConfigService configService, SecurityProperties properties,
                           AccessRuleRegistry ruleRegistry, AuditService auditService,
                           LoginThrottleService throttle) {
        this.sessionManager = sessionManager;
        this.userDirectory = userDirectory;
        this.configService = configService;
        this.properties = properties;
        this.ruleRegistry = ruleRegistry;
        this.auditService = auditService;
        this.throttle = throttle;
    }

    // ---------------- sessions ----------------

    @PostMapping("/sessions/revoke")
    public Map<String, Object> revokeByToken(@RequestBody Map<String, String> body) {
        boolean revoked = sessionManager.revoke(body.get("token"));
        return Map.of("revoked", revoked);
    }

    @PostMapping("/sessions/users/{username}/revoke")
    public Map<String, Object> revokeUser(@PathVariable String username) {
        long ttl = configService.current().sessionIdleTimeoutMillis();
        List<String> revoked = sessionManager.revokeUser(username);
        return Map.of("username", username, "revokedCount", revoked.size());
    }

    @GetMapping("/sessions/users/{username}")
    public Map<String, Object> userSessions(@PathVariable String username) {
        long ttl = configService.current().sessionIdleTimeoutMillis();
        return Map.of("username", username,
                "activeCount", sessionManager.activeCount(username, ttl),
                "activeTokens", sessionManager.activeSessions(username, ttl).stream()
                        .map(s -> SessionManager.mask(s.token())).toList());
    }

    // ---------------- users ----------------

    @PostMapping("/users/{username}/role")
    public Map<String, Object> changeRole(@PathVariable String username,
                                          @RequestBody Map<String, String> body) {
        UserAccount user = requireUser(username);
        Role role = Role.valueOf(body.get("role"));
        user.setRole(role);
        // Role is read live from the directory on every request; no session invalidation needed.
        return Map.of("username", username, "role", role.name());
    }

    @PostMapping("/users/{username}/enabled")
    public Map<String, Object> setEnabled(@PathVariable String username,
                                          @RequestBody Map<String, Object> body) {
        UserAccount user = requireUser(username);
        boolean enabled = Boolean.parseBoolean(String.valueOf(body.get("enabled")));
        user.setEnabled(enabled);
        if (!enabled) {
            // Force re-login: disablement alone already blocks the next request, and existing
            // sessions are revoked so the reason presented is precisely REVOKED/UNKNOWN.
            sessionManager.revokeUser(username);
        }
        return Map.of("username", username, "enabled", enabled);
    }

    @PostMapping("/users/{username}/unlock")
    public Map<String, Object> unlock(@PathVariable String username) {
        throttle.reset(username);
        return Map.of("username", username, "unlocked", true);
    }

    @GetMapping("/users")
    public List<Map<String, Object>> users() {
        return userDirectory.all().stream()
                .map(u -> Map.<String, Object>of(
                        "username", u.getUsername(),
                        "role", u.getRole().name(),
                        "department", u.getDepartment(),
                        "enabled", u.isEnabled()))
                .toList();
    }

    // ---------------- configuration ----------------

    @GetMapping("/config")
    public SecuritySettings currentConfig() {
        return configService.current();
    }

    @GetMapping("/config/versions")
    public List<Long> configVersions() {
        return configService.versions();
    }

    @GetMapping("/config/versions/{version}")
    public SecuritySettings configVersion(@PathVariable long version) {
        return configService.version(version);
    }

    /** Updates a selection of numeric/bool security settings and publishes a new snapshot. */
    @PostMapping("/config")
    public SecuritySettings updateConfig(@RequestBody Map<String, Object> body) {
        if (body.containsKey("sessionIdleTimeoutMillis")) {
            properties.getSession().setIdleTimeoutMillis(asLong(body.get("sessionIdleTimeoutMillis")));
        }
        if (body.containsKey("maxSessionsPerUser")) {
            properties.getLogin().setMaxSessionsPerUser((int) asLong(body.get("maxSessionsPerUser")));
        }
        if (body.containsKey("lockThreshold")) {
            properties.getLogin().setLockThreshold((int) asLong(body.get("lockThreshold")));
        }
        if (body.containsKey("lockMillis")) {
            properties.getLogin().setLockMillis(asLong(body.get("lockMillis")));
        }
        if (body.containsKey("rateLimitAttempts")) {
            properties.getLogin().setRateLimitAttempts((int) asLong(body.get("rateLimitAttempts")));
        }
        if (body.containsKey("rateLimitWindowMillis")) {
            properties.getLogin().setRateLimitWindowMillis(asLong(body.get("rateLimitWindowMillis")));
        }
        if (body.containsKey("rateLimitBlockMillis")) {
            properties.getLogin().setRateLimitBlockMillis(asLong(body.get("rateLimitBlockMillis")));
        }
        if (body.containsKey("csrfEnabled")) {
            properties.getCsrf().setEnabled(Boolean.parseBoolean(String.valueOf(body.get("csrfEnabled"))));
        }
        return configService.reload();
    }

    // ---------------- rules ----------------

    @GetMapping("/rules/current")
    public RuleSetView currentRules() {
        return RuleSetView.of(ruleRegistry.current());
    }

    @GetMapping("/rules/versions")
    public List<Long> ruleVersions() {
        return ruleRegistry.versions();
    }

    @GetMapping("/rules/versions/{version}")
    public RuleSetView ruleVersion(@PathVariable long version) {
        return RuleSetView.of(ruleRegistry.version(version));
    }

    @PostMapping("/rules/switch")
    public RuleSetView switchRules(@RequestParam(defaultValue = "default") String profile) {
        return RuleSetView.of(ruleRegistry.switchProfile(profile));
    }

    // ---------------- audit ----------------

    @GetMapping("/audit/recent")
    public List<AuthorizationEvent> recent(@RequestParam(defaultValue = "50") int limit) {
        return auditService.recent(limit);
    }

    @GetMapping("/audit/by-path")
    public List<AuthorizationEvent> byPath(@RequestParam String path) {
        return auditService.findByPath(path);
    }

    // ---------------- helpers ----------------

    private UserAccount requireUser(String username) {
        UserAccount user = userDirectory.findByUsername(username);
        if (user == null) {
            throw new IllegalArgumentException("Unknown user: " + username);
        }
        return user;
    }

    private static long asLong(Object value) {
        if (value instanceof Number number) {
            return number.longValue();
        }
        return Long.parseLong(String.valueOf(value));
    }
}
