package com.github.xingjianluo.sessionauthjava.auth.admin;

import com.github.xingjianluo.sessionauthjava.auth.model.AccessDecision;
import com.github.xingjianluo.sessionauthjava.auth.model.Role;
import com.github.xingjianluo.sessionauthjava.auth.model.SessionRecord;
import com.github.xingjianluo.sessionauthjava.auth.policy.AuthPolicy;
import com.github.xingjianluo.sessionauthjava.auth.policy.DecisionLog;
import com.github.xingjianluo.sessionauthjava.auth.policy.DecisionRecord;
import com.github.xingjianluo.sessionauthjava.auth.policy.PolicyService;
import com.github.xingjianluo.sessionauthjava.auth.service.AccessControlService;
import com.github.xingjianluo.sessionauthjava.auth.service.SessionService;
import com.github.xingjianluo.sessionauthjava.auth.web.ApiError;
import com.github.xingjianluo.sessionauthjava.auth.web.AuthFilter;
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
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * 运维入口（运行期，已在启动的服务上即可操作，无需进入测试/调试器）：
 *
 * <ul>
 *   <li>{@code GET  /api/admin/policy}：查看当前生效策略及版本号；</li>
 *   <li>{@code GET  /api/admin/policy/versions}：查看仍保留、可回放的版本号列表；</li>
 *   <li>{@code POST /api/admin/policy}：发布新策略版本（原子切换，新请求立即按新策略）；</li>
 *   <li>{@code GET  /api/admin/decisions[?kind=&policyVersion=]}：查看判定记录
 *       （每条含依据的策略版本与关键输入）；</li>
 *   <li>{@code GET  /api/admin/decisions/{id}}：查看单条判定记录；</li>
 *   <li>{@code POST /api/admin/decisions/{id}/replay}：按编号把该判定放回它当时那版
 *       策略重算，结论与当时一致，不受当前策略影响；</li>
 *   <li>{@code POST /api/admin/sessions/revoke?username=}：强制失效某用户全部会话。</li>
 * </ul>
 *
 * <p>安全：所有路径均非公开路径——先经认证过滤器拿到会话，再由本控制器要求 ADMIN 角色
 * （USER 访问得 403 ROLE_INSUFFICIENT，未认证得 401）；POST 入口照常经过 CSRF 过滤器。
 */
@RestController
@RequestMapping("/api/admin")
public class AdminController {

    private static final Logger log = LoggerFactory.getLogger(AdminController.class);

    /** decisions 列表最多返回的条数（有界返回，防止一次性拉取过多） */
    private static final int DECISION_LIST_LIMIT = 200;

    private final PolicyService policyService;
    private final DecisionLog decisionLog;
    private final SessionService sessionService;
    private final AccessControlService accessControlService;

    public AdminController(PolicyService policyService, DecisionLog decisionLog,
                           SessionService sessionService, AccessControlService accessControlService) {
        this.policyService = policyService;
        this.decisionLog = decisionLog;
        this.sessionService = sessionService;
        this.accessControlService = accessControlService;
    }

    /** 策略变更请求体：所有字段可空，null 表示该项保持当前策略不变（部分更新）。 */
    public record PolicyUpdateRequest(
            Long sessionTtlSeconds,
            Integer maxConcurrentSessions,
            Integer maxFailedAttempts,
            Long lockDurationSeconds,
            Long rateLimitWindowSeconds,
            Long rateLimitMaxAttempts,
            List<String> publicPaths,
            Boolean csrfEnabled,
            List<String> allowedOrigins) {
    }

    @GetMapping("/policy")
    public ResponseEntity<?> currentPolicy(@RequestAttribute(AuthFilter.ATTR_SESSION) SessionRecord session) {
        ResponseEntity<?> guard = requireAdmin(session, "GET /api/admin/policy");
        if (guard != null) {
            return guard;
        }
        return ResponseEntity.ok(policyView(policyService.current()));
    }

    @GetMapping("/policy/versions")
    public ResponseEntity<?> policyVersions(@RequestAttribute(AuthFilter.ATTR_SESSION) SessionRecord session) {
        ResponseEntity<?> guard = requireAdmin(session, "GET /api/admin/policy/versions");
        if (guard != null) {
            return guard;
        }
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("currentVersion", policyService.current().version());
        body.put("retainedVersions", policyService.versions());
        body.put("retainedCount", policyService.historySize());
        return ResponseEntity.ok(body);
    }

    @PostMapping("/policy")
    public ResponseEntity<?> updatePolicy(@RequestAttribute(AuthFilter.ATTR_SESSION) SessionRecord session,
                                          @RequestBody(required = false) PolicyUpdateRequest request) {
        ResponseEntity<?> guard = requireAdmin(session, "POST /api/admin/policy");
        if (guard != null) {
            return guard;
        }
        if (request == null) {
            return badRequest("request body is required; send {} (or fields) to publish a new version");
        }
        Optional<String> invalid = validate(request);
        if (invalid.isPresent()) {
            return badRequest(invalid.get());
        }
        long fromVersion = policyService.current().version();
        AuthPolicy next = policyService.update(draft -> {
            if (request.sessionTtlSeconds() != null) {
                draft.setSessionTtl(Duration.ofSeconds(request.sessionTtlSeconds()));
            }
            if (request.maxConcurrentSessions() != null) {
                draft.setMaxConcurrentSessions(request.maxConcurrentSessions());
            }
            if (request.maxFailedAttempts() != null) {
                draft.setMaxFailedAttempts(request.maxFailedAttempts());
            }
            if (request.lockDurationSeconds() != null) {
                draft.setLockDuration(Duration.ofSeconds(request.lockDurationSeconds()));
            }
            if (request.rateLimitWindowSeconds() != null) {
                draft.setRateLimitWindow(Duration.ofSeconds(request.rateLimitWindowSeconds()));
            }
            if (request.rateLimitMaxAttempts() != null) {
                draft.setRateLimitMaxAttempts(Math.toIntExact(request.rateLimitMaxAttempts()));
            }
            if (request.publicPaths() != null) {
                draft.setPublicPaths(new ArrayList<>(request.publicPaths()));
            }
            if (request.csrfEnabled() != null) {
                draft.setCsrfEnabled(request.csrfEnabled());
            }
            if (request.allowedOrigins() != null) {
                draft.setAllowedOrigins(new ArrayList<>(request.allowedOrigins()));
            }
        });
        log.info("[admin-api] user={} published policy v{} -> v{}", session.username(), fromVersion, next.version());
        return ResponseEntity.ok(policyView(next));
    }

    @GetMapping("/decisions")
    public ResponseEntity<?> decisions(@RequestAttribute(AuthFilter.ATTR_SESSION) SessionRecord session,
                                       @RequestParam(required = false) String kind,
                                       @RequestParam(required = false) Long policyVersion) {
        ResponseEntity<?> guard = requireAdmin(session, "GET /api/admin/decisions");
        if (guard != null) {
            return guard;
        }
        List<Map<String, Object>> items = decisionLog.snapshot().stream()
                .filter(r -> kind == null || kind.isBlank() || r.kind().equals(kind))
                .filter(r -> policyVersion == null || r.policyVersion() == policyVersion)
                .limit(DECISION_LIST_LIMIT)
                .map(AdminController::decisionView)
                .toList();
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("filter", Map.of("kind", kind == null ? "" : kind,
                "policyVersion", policyVersion == null ? "" : String.valueOf(policyVersion)));
        body.put("count", items.size());
        body.put("decisions", items);
        return ResponseEntity.ok(body);
    }

    @GetMapping("/decisions/{id}")
    public ResponseEntity<?> decision(@RequestAttribute(AuthFilter.ATTR_SESSION) SessionRecord session,
                                      @PathVariable long id) {
        ResponseEntity<?> guard = requireAdmin(session, "GET /api/admin/decisions/" + id);
        if (guard != null) {
            return guard;
        }
        return decisionLog.get(id)
                .<ResponseEntity<?>>map(record -> ResponseEntity.ok(decisionView(record)))
                .orElseGet(() -> ResponseEntity.status(HttpStatus.NOT_FOUND)
                        .body(new ApiError("DECISION_NOT_FOUND",
                                "decision " + id + " does not exist or has been evicted")));
    }

    @PostMapping("/decisions/{id}/replay")
    public ResponseEntity<?> replay(@RequestAttribute(AuthFilter.ATTR_SESSION) SessionRecord session,
                                    @PathVariable long id) {
        ResponseEntity<?> guard = requireAdmin(session, "POST /api/admin/decisions/" + id + "/replay");
        if (guard != null) {
            return guard;
        }
        DecisionRecord record = decisionLog.get(id).orElse(null);
        if (record == null) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND)
                    .body(new ApiError("DECISION_NOT_FOUND",
                            "decision " + id + " does not exist or has been evicted"));
        }
        Optional<String> replayed = decisionLog.replay(id);
        if (replayed.isEmpty()) {
            // 记录还在，但它依据的策略版本已被淘汰：明确告知，而不是给出按最新策略的错误结论
            return ResponseEntity.status(HttpStatus.GONE)
                    .body(new ApiError("POLICY_VERSION_EVICTED",
                            "policy version " + record.policyVersion()
                                    + " used by decision " + id + " has been evicted; replay unavailable"));
        }
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("decisionId", record.id());
        body.put("kind", record.kind());
        body.put("inputs", record.inputs());
        body.put("policyVersion", record.policyVersion());
        body.put("originalOutcome", record.outcome());
        body.put("replayedOutcome", replayed.get());
        body.put("matchesOriginal", record.outcome().equals(replayed.get()));
        body.put("currentVersion", policyService.current().version());
        body.put("basis", "re-evaluated under the retained policy snapshot v" + record.policyVersion()
                + ", independent of current policy v" + policyService.current().version());
        log.info("[admin-api] user={} replay decision={} v{} -> {} (original={})",
                session.username(), id, record.policyVersion(), replayed.get(), record.outcome());
        return ResponseEntity.ok(body);
    }

    @PostMapping("/sessions/revoke")
    public ResponseEntity<?> revoke(@RequestAttribute(AuthFilter.ATTR_SESSION) SessionRecord session,
                                    @RequestParam String username) {
        ResponseEntity<?> guard = requireAdmin(session, "POST /api/admin/sessions/revoke");
        if (guard != null) {
            return guard;
        }
        if (username == null || username.isBlank()) {
            return badRequest("username parameter is required");
        }
        int count = sessionService.revokeAllForUser(username);
        log.info("[admin-api] user={} force-revoked sessions for target={} count={}",
                session.username(), username, count);
        return ResponseEntity.ok(Map.of("username", username, "revokedOrUpgraded", count));
    }

    /** 统一 ADMIN 守门：判定使用用户当前角色，非 ADMIN 返回 403 ROLE_INSUFFICIENT。 */
    private ResponseEntity<?> requireAdmin(SessionRecord session, String action) {
        AccessDecision decision = accessControlService.decide(session, Role.ADMIN, java.util.Set.of());
        if (!decision.granted()) {
            log.info("[admin-api] deny action={} user={} -> 403 denyReason={} basis={}",
                    action, session.username(), decision.denyReason(), decision.basis());
            return ResponseEntity.status(HttpStatus.FORBIDDEN)
                    .body(new ApiError(decision.denyReason().name(), "access denied"));
        }
        return null;
    }

    private ResponseEntity<ApiError> badRequest(String detail) {
        return ResponseEntity.badRequest().body(new ApiError("INVALID_POLICY_UPDATE", detail));
    }

    private static Optional<String> validate(PolicyUpdateRequest r) {
        if (r.sessionTtlSeconds() != null && r.sessionTtlSeconds() <= 0) {
            return Optional.of("sessionTtlSeconds must be positive");
        }
        if (r.maxConcurrentSessions() != null && r.maxConcurrentSessions() <= 0) {
            return Optional.of("maxConcurrentSessions must be positive");
        }
        if (r.maxFailedAttempts() != null && r.maxFailedAttempts() <= 0) {
            return Optional.of("maxFailedAttempts must be positive");
        }
        if (r.lockDurationSeconds() != null && r.lockDurationSeconds() <= 0) {
            return Optional.of("lockDurationSeconds must be positive");
        }
        if (r.rateLimitWindowSeconds() != null && r.rateLimitWindowSeconds() <= 0) {
            return Optional.of("rateLimitWindowSeconds must be positive");
        }
        if (r.rateLimitMaxAttempts() != null && r.rateLimitMaxAttempts() <= 0) {
            return Optional.of("rateLimitMaxAttempts must be positive");
        }
        return Optional.empty();
    }

    private static Map<String, Object> policyView(AuthPolicy p) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("version", p.version());
        body.put("sessionTtlSeconds", p.sessionTtl().toSeconds());
        body.put("maxConcurrentSessions", p.maxConcurrentSessions());
        body.put("maxFailedAttempts", p.maxFailedAttempts());
        body.put("lockDurationSeconds", p.lockDuration().toSeconds());
        body.put("rateLimitWindowSeconds", p.rateLimitWindow().toSeconds());
        body.put("rateLimitMaxAttempts", p.rateLimitMaxAttempts());
        body.put("publicPaths", p.publicPaths());
        body.put("csrfEnabled", p.csrfEnabled());
        body.put("allowedOrigins", p.allowedOrigins());
        return body;
    }

    private static Map<String, Object> decisionView(DecisionRecord r) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("id", r.id());
        body.put("kind", r.kind());
        body.put("policyVersion", r.policyVersion());
        body.put("inputs", r.inputs());
        body.put("outcome", r.outcome());
        body.put("decidedAt", r.decidedAt());
        return body;
    }
}
