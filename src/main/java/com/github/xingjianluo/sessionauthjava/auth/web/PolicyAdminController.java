package com.github.xingjianluo.sessionauthjava.auth.web;

import com.github.xingjianluo.sessionauthjava.auth.config.AuthSecurityProperties;
import com.github.xingjianluo.sessionauthjava.auth.model.AccessDecision;
import com.github.xingjianluo.sessionauthjava.auth.model.Role;
import com.github.xingjianluo.sessionauthjava.auth.model.SessionRecord;
import com.github.xingjianluo.sessionauthjava.auth.policy.AuthPolicy;
import com.github.xingjianluo.sessionauthjava.auth.policy.DecisionLog;
import com.github.xingjianluo.sessionauthjava.auth.policy.DecisionRecord;
import com.github.xingjianluo.sessionauthjava.auth.policy.PolicyService;
import com.github.xingjianluo.sessionauthjava.auth.service.AccessControlService;
import com.github.xingjianluo.sessionauthjava.auth.service.SessionService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestAttribute;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * 运行期运维入口（本地已启动的服务上即可操作，无需进入测试或重启）：
 * <ul>
 *   <li>{@code GET  /api/admin/policy}        查看当前策略（含版本号）；</li>
 *   <li>{@code POST /api/admin/policy}        基于当前策略发布新版本，新请求立即按新版本判定；</li>
 *   <li>{@code GET  /api/admin/decisions}     列出保留的历史判定（含依据版本与输入）；</li>
 *   <li>{@code GET  /api/admin/decisions/{id}} 查看单条判定；</li>
 *   <li>{@code POST /api/admin/decisions/{id}/replay} 按记录当时的策略版本重放，
 *       结论须与当时完全一致。</li>
 * </ul>
 * 均为受保护接口：需要有效会话与 ADMIN 角色（变更接口另需 CSRF 令牌）。
 */
@RestController
@RequestMapping("/api/admin")
public class PolicyAdminController {

    private static final Logger log = LoggerFactory.getLogger(PolicyAdminController.class);

    private final PolicyService policyService;
    private final DecisionLog decisionLog;
    private final AccessControlService accessControlService;
    private final SessionService sessionService;

    public PolicyAdminController(PolicyService policyService, DecisionLog decisionLog,
                                 AccessControlService accessControlService,
                                 SessionService sessionService) {
        this.policyService = policyService;
        this.decisionLog = decisionLog;
        this.accessControlService = accessControlService;
        this.sessionService = sessionService;
    }

    /** 强制失效请求：{"username":"bob"} 把该用户全部会话（含已过期/已登出的终态记录）置为 REVOKED。 */
    public record RevokeRequest(String username) {
    }

    /** 策略修改请求：所有字段可空，非空字段覆盖当前值（基于当前版本增量修改）。 */
    public record PolicyUpdateRequest(
            String sessionTtl,
            Integer maxConcurrentSessions,
            Integer maxFailedAttempts,
            String lockDuration,
            String rateLimitWindow,
            Integer rateLimitMaxAttempts,
            List<String> publicPaths,
            Boolean csrfEnabled,
            List<String> allowedOrigins) {
    }

    @GetMapping("/policy")
    public ResponseEntity<?> currentPolicy(@RequestAttribute(AuthFilter.ATTR_SESSION) SessionRecord session) {
        ResponseEntity<?> denied = requireAdmin(session);
        if (denied != null) {
            return denied;
        }
        AuthPolicy policy = policyService.current();
        log.info("[policy-api] user={} get policy version={}", session.username(), policy.version());
        return ResponseEntity.ok(policyView(policy, policyService.historySize()));
    }

    @PostMapping("/policy")
    public ResponseEntity<?> updatePolicy(@RequestAttribute(AuthFilter.ATTR_SESSION) SessionRecord session,
                                          @RequestBody(required = false) PolicyUpdateRequest request) {
        ResponseEntity<?> denied = requireAdmin(session);
        if (denied != null) {
            return denied;
        }
        if (request == null) {
            return badRequest("request body is required");
        }
        long previousVersion = policyService.current().version();
        AuthPolicy next;
        try {
            next = policyService.update(props -> applyUpdate(props, request));
        } catch (RuntimeException e) {
            // 非法数值（<=0）或不可解析的时长（DateTimeParseException）等
            return badRequest(e.getMessage());
        }
        log.info("[policy-api] user={} published policy v{} -> v{}",
                session.username(), previousVersion, next.version());
        Map<String, Object> body = policyView(next, policyService.historySize());
        body.put("previousVersion", previousVersion);
        return ResponseEntity.ok(body);
    }

    @PostMapping("/sessions/revoke")
    public ResponseEntity<?> revokeUserSessions(
            @RequestAttribute(AuthFilter.ATTR_SESSION) SessionRecord session,
            @RequestBody RevokeRequest request) {
        ResponseEntity<?> denied = requireAdmin(session);
        if (denied != null) {
            return denied;
        }
        if (request == null || request.username() == null || request.username().isBlank()) {
            return badRequest("username is required");
        }
        int revoked = sessionService.revokeAllForUser(request.username());
        log.info("[policy-api] user={} force-invalidated sessions of target={} revokedLive={}",
                session.username(), request.username(), revoked);
        return ResponseEntity.ok(java.util.Map.of(
                "username", request.username(), "revokedLive", revoked));
    }

    @GetMapping("/decisions")
    public ResponseEntity<?> listDecisions(@RequestAttribute(AuthFilter.ATTR_SESSION) SessionRecord session) {
        ResponseEntity<?> denied = requireAdmin(session);
        if (denied != null) {
            return denied;
        }
        List<Map<String, Object>> items = new ArrayList<>();
        for (DecisionRecord record : decisionLog.all()) {
            items.add(decisionView(record, null));
        }
        log.info("[policy-api] user={} list decisions count={}", session.username(), items.size());
        return ResponseEntity.ok(Map.of("count", items.size(), "retained", decisionLog.size(),
                "decisions", items));
    }

    @GetMapping("/decisions/{id}")
    public ResponseEntity<?> getDecision(@RequestAttribute(AuthFilter.ATTR_SESSION) SessionRecord session,
                                         @PathVariable long id) {
        ResponseEntity<?> denied = requireAdmin(session);
        if (denied != null) {
            return denied;
        }
        Optional<DecisionRecord> record = decisionLog.find(id);
        if (record.isEmpty()) {
            return notFoundDecision(id);
        }
        return ResponseEntity.ok(decisionView(record.get(), null));
    }

    @PostMapping("/decisions/{id}/replay")
    public ResponseEntity<?> replayDecision(@RequestAttribute(AuthFilter.ATTR_SESSION) SessionRecord session,
                                            @PathVariable long id) {
        ResponseEntity<?> denied = requireAdmin(session);
        if (denied != null) {
            return denied;
        }
        Optional<DecisionLog.ReplayResult> replay = decisionLog.replayDetailed(id);
        if (replay.isEmpty()) {
            return notFoundDecision(id);
        }
        DecisionLog.ReplayResult result = replay.get();
        log.info("[policy-api] user={} replay id={} policyVersion={} original={} replayed={} match={}",
                session.username(), id, result.record().policyVersion(),
                result.record().outcome(), result.replayedOutcome(), result.matches());
        return ResponseEntity.ok(decisionView(result.record(), result));
    }

    private void applyUpdate(AuthSecurityProperties props, PolicyUpdateRequest req) {
        if (req.sessionTtl() != null) {
            Duration d = Duration.parse(req.sessionTtl());
            if (d.isZero() || d.isNegative()) {
                throw new IllegalArgumentException("sessionTtl must be positive");
            }
            props.setSessionTtl(d);
        }
        if (req.maxConcurrentSessions() != null) {
            if (req.maxConcurrentSessions() <= 0) {
                throw new IllegalArgumentException("maxConcurrentSessions must be positive");
            }
            props.setMaxConcurrentSessions(req.maxConcurrentSessions());
        }
        if (req.maxFailedAttempts() != null) {
            if (req.maxFailedAttempts() <= 0) {
                throw new IllegalArgumentException("maxFailedAttempts must be positive");
            }
            props.setMaxFailedAttempts(req.maxFailedAttempts());
        }
        if (req.lockDuration() != null) {
            Duration d = Duration.parse(req.lockDuration());
            if (d.isZero() || d.isNegative()) {
                throw new IllegalArgumentException("lockDuration must be positive");
            }
            props.setLockDuration(d);
        }
        if (req.rateLimitWindow() != null) {
            Duration d = Duration.parse(req.rateLimitWindow());
            if (d.isZero() || d.isNegative()) {
                throw new IllegalArgumentException("rateLimitWindow must be positive");
            }
            props.setRateLimitWindow(d);
        }
        if (req.rateLimitMaxAttempts() != null) {
            if (req.rateLimitMaxAttempts() <= 0) {
                throw new IllegalArgumentException("rateLimitMaxAttempts must be positive");
            }
            props.setRateLimitMaxAttempts(req.rateLimitMaxAttempts());
        }
        if (req.publicPaths() != null) {
            props.setPublicPaths(new ArrayList<>(req.publicPaths()));
        }
        if (req.csrfEnabled() != null) {
            props.setCsrfEnabled(req.csrfEnabled());
        }
        if (req.allowedOrigins() != null) {
            props.setAllowedOrigins(new ArrayList<>(req.allowedOrigins()));
        }
    }

    private ResponseEntity<?> requireAdmin(SessionRecord session) {
        AccessDecision decision = accessControlService.decide(session, Role.ADMIN, java.util.Set.of());
        if (!decision.granted()) {
            log.info("[policy-api] user={} -> 403 denyReason={} basis={}",
                    session.username(), decision.denyReason(), decision.basis());
            return ResponseEntity.status(HttpStatus.FORBIDDEN)
                    .body(new ApiError(decision.denyReason().name(), "admin role required"));
        }
        return null;
    }

    private ResponseEntity<ApiError> badRequest(String detail) {
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(new ApiError("INVALID_POLICY_UPDATE", detail));
    }

    private ResponseEntity<ApiError> notFoundDecision(long id) {
        return ResponseEntity.status(HttpStatus.NOT_FOUND)
                .body(new ApiError("DECISION_NOT_FOUND", "decision " + id
                        + " was evicted or never existed; only recent decisions can be replayed"));
    }

    private Map<String, Object> policyView(AuthPolicy p, int retainedVersions) {
        Map<String, Object> view = new LinkedHashMap<>();
        view.put("version", p.version());
        view.put("sessionTtl", p.sessionTtl().toString());
        view.put("maxConcurrentSessions", p.maxConcurrentSessions());
        view.put("maxFailedAttempts", p.maxFailedAttempts());
        view.put("lockDuration", p.lockDuration().toString());
        view.put("rateLimitWindow", p.rateLimitWindow().toString());
        view.put("rateLimitMaxAttempts", p.rateLimitMaxAttempts());
        view.put("publicPaths", p.publicPaths());
        view.put("csrfEnabled", p.csrfEnabled());
        view.put("allowedOrigins", p.allowedOrigins());
        view.put("retainedVersions", retainedVersions);
        return view;
    }

    private Map<String, Object> decisionView(DecisionRecord r, DecisionLog.ReplayResult replay) {
        Map<String, Object> view = new LinkedHashMap<>();
        view.put("id", r.id());
        view.put("kind", r.kind());
        view.put("policyVersion", r.policyVersion());
        view.put("inputs", r.inputs());
        view.put("outcome", r.outcome());
        view.put("decidedAt", r.decidedAt().toString());
        if (replay != null) {
            view.put("replayedOutcome", replay.replayedOutcome());
            view.put("matches", replay.matches());
        }
        return view;
    }
}
