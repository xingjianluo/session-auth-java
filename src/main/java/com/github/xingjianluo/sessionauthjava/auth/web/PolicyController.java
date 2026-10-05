package com.github.xingjianluo.sessionauthjava.auth.web;

import com.github.xingjianluo.sessionauthjava.auth.config.AuthSecurityProperties;
import com.github.xingjianluo.sessionauthjava.auth.model.AccessDecision;
import com.github.xingjianluo.sessionauthjava.auth.model.Role;
import com.github.xingjianluo.sessionauthjava.auth.model.SessionRecord;
import com.github.xingjianluo.sessionauthjava.auth.policy.DecisionLog;
import com.github.xingjianluo.sessionauthjava.auth.policy.DecisionRecord;
import com.github.xingjianluo.sessionauthjava.auth.policy.PolicyReplayService;
import com.github.xingjianluo.sessionauthjava.auth.policy.PolicyService;
import com.github.xingjianluo.sessionauthjava.auth.policy.PolicySnapshot;
import com.github.xingjianluo.sessionauthjava.auth.policy.ReplayResult;
import com.github.xingjianluo.sessionauthjava.auth.service.AccessControlService;
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
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * 策略管理与历史判定回放入口（仅 ADMIN）。
 *
 * <ul>
 *   <li>{@code GET /api/admin/policy}：查看当前策略版本与内容</li>
 *   <li>{@code POST /api/admin/policy}：运行期调整策略，立即生成新版本</li>
 *   <li>{@code GET /api/admin/decisions}：查看最近的判定记录（含策略版本）</li>
 *   <li>{@code GET /api/admin/decisions/{id}/replay}：把历史判定放回当时策略版本重放</li>
 * </ul>
 */
@RestController
@RequestMapping("/api/admin")
public class PolicyController {

    private static final Logger log = LoggerFactory.getLogger(PolicyController.class);

    private final AuthSecurityProperties properties;
    private final PolicyService policyService;
    private final DecisionLog decisionLog;
    private final PolicyReplayService replayService;
    private final AccessControlService accessControlService;

    public PolicyController(AuthSecurityProperties properties, PolicyService policyService,
                            DecisionLog decisionLog, PolicyReplayService replayService,
                            AccessControlService accessControlService) {
        this.properties = properties;
        this.policyService = policyService;
        this.decisionLog = decisionLog;
        this.replayService = replayService;
        this.accessControlService = accessControlService;
    }

    /** 策略更新请求：字段为 null 表示不修改 */
    public record PolicyUpdateRequest(
            Long sessionTtlSeconds,
            Integer maxConcurrentSessions,
            Integer maxFailedAttempts,
            Long lockDurationSeconds,
            Long rateLimitWindowSeconds,
            Integer rateLimitMaxAttempts,
            List<String> publicPaths,
            Boolean csrfEnabled,
            List<String> allowedOrigins) {
    }

    @GetMapping("/policy")
    public ResponseEntity<?> currentPolicy(@RequestAttribute(AuthFilter.ATTR_SESSION) SessionRecord session) {
        ResponseEntity<ApiError> denied = requireAdmin(session, "/api/admin/policy");
        if (denied != null) {
            return denied;
        }
        PolicySnapshot snapshot = policyService.current();
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("version", snapshot.version());
        body.put("settings", snapshot.settings());
        body.put("knownVersions", policyService.knownVersions());
        log.info("[policy-api] user={} GET policy -> version={}", session.username(), snapshot.version());
        return ResponseEntity.ok(body);
    }

    @PostMapping("/policy")
    public ResponseEntity<?> updatePolicy(@RequestAttribute(AuthFilter.ATTR_SESSION) SessionRecord session,
                                          @RequestBody PolicyUpdateRequest request) {
        ResponseEntity<ApiError> denied = requireAdmin(session, "/api/admin/policy");
        if (denied != null) {
            return denied;
        }
        if (request.sessionTtlSeconds() != null) {
            properties.setSessionTtl(Duration.ofSeconds(request.sessionTtlSeconds()));
        }
        if (request.maxConcurrentSessions() != null) {
            properties.setMaxConcurrentSessions(request.maxConcurrentSessions());
        }
        if (request.maxFailedAttempts() != null) {
            properties.setMaxFailedAttempts(request.maxFailedAttempts());
        }
        if (request.lockDurationSeconds() != null) {
            properties.setLockDuration(Duration.ofSeconds(request.lockDurationSeconds()));
        }
        if (request.rateLimitWindowSeconds() != null) {
            properties.setRateLimitWindow(Duration.ofSeconds(request.rateLimitWindowSeconds()));
        }
        if (request.rateLimitMaxAttempts() != null) {
            properties.setRateLimitMaxAttempts(request.rateLimitMaxAttempts());
        }
        if (request.publicPaths() != null) {
            properties.setPublicPaths(List.copyOf(request.publicPaths()));
        }
        if (request.csrfEnabled() != null) {
            properties.setCsrfEnabled(request.csrfEnabled());
        }
        if (request.allowedOrigins() != null) {
            properties.setAllowedOrigins(List.copyOf(request.allowedOrigins()));
        }
        PolicySnapshot snapshot = policyService.current();
        log.info("[policy-api] user={} POST policy -> new version={}", session.username(), snapshot.version());
        return ResponseEntity.ok(Map.of(
                "version", snapshot.version(),
                "settings", snapshot.settings()));
    }

    @GetMapping("/decisions")
    public ResponseEntity<?> recentDecisions(@RequestAttribute(AuthFilter.ATTR_SESSION) SessionRecord session,
                                             @RequestParam(defaultValue = "50") int limit) {
        ResponseEntity<ApiError> denied = requireAdmin(session, "/api/admin/decisions");
        if (denied != null) {
            return denied;
        }
        List<DecisionRecord> records = decisionLog.recent(Math.min(limit, 200));
        log.info("[policy-api] user={} GET decisions limit={} -> {} records",
                session.username(), limit, records.size());
        return ResponseEntity.ok(Map.of("records", records, "size", decisionLog.size()));
    }

    @GetMapping("/decisions/{id}/replay")
    public ResponseEntity<?> replay(@RequestAttribute(AuthFilter.ATTR_SESSION) SessionRecord session,
                                    @PathVariable long id) {
        ResponseEntity<ApiError> denied = requireAdmin(session, "/api/admin/decisions/" + id + "/replay");
        if (denied != null) {
            return denied;
        }
        ReplayResult result = replayService.replay(id);
        log.info("[policy-api] user={} replay decisionId={} -> status={} matches={}",
                session.username(), id, result.status(), result.matches());
        return switch (result.status()) {
            case REPLAYED -> ResponseEntity.ok(Map.of(
                    "status", result.status().name(),
                    "decisionId", id,
                    "type", result.record().type(),
                    "policyVersion", result.policyVersion(),
                    "originalOutcome", result.record().outcome(),
                    "replayedOutcome", result.replayedOutcome(),
                    "matches", result.matches()));
            case DECISION_NOT_FOUND -> ResponseEntity.status(HttpStatus.NOT_FOUND)
                    .body(new ApiError("DECISION_NOT_FOUND", "no decision record with id " + id));
            case POLICY_VERSION_EVICTED -> ResponseEntity.status(HttpStatus.GONE)
                    .body(new ApiError("POLICY_VERSION_EVICTED",
                            "policy version " + result.policyVersion() + " has been evicted from history"));
        };
    }

    private ResponseEntity<ApiError> requireAdmin(SessionRecord session, String path) {
        AccessDecision decision = accessControlService.decide(session, Role.ADMIN, Set.of());
        if (!decision.granted()) {
            log.info("[policy-api] path={} user={} -> 403 denyReason={}", path, session.username(), decision.denyReason());
            return ResponseEntity.status(HttpStatus.FORBIDDEN)
                    .body(new ApiError(decision.denyReason().name(), "access denied"));
        }
        return null;
    }
}
