package com.github.xingjianluo.sessionauthjava.auth.web;

import com.github.xingjianluo.sessionauthjava.auth.model.AccessDecision;
import com.github.xingjianluo.sessionauthjava.auth.model.Role;
import com.github.xingjianluo.sessionauthjava.auth.model.SessionRecord;
import com.github.xingjianluo.sessionauthjava.auth.service.AccessControlService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestAttribute;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;
import java.util.Set;

/**
 * 受保护资源入口。
 *
 * <p>越权拒绝时响应体统一为 FORBIDDEN + 可区分的 denyReason，
 * 不泄漏资源是否存在（判定发生在资源加载之前，存在与否响应一致）。
 */
@RestController
@RequestMapping("/api")
public class ResourceController {

    private static final Logger log = LoggerFactory.getLogger(ResourceController.class);

    private final AccessControlService accessControlService;

    public ResourceController(AccessControlService accessControlService) {
        this.accessControlService = accessControlService;
    }

    @GetMapping("/user/profile")
    public ResponseEntity<?> profile(@RequestAttribute(AuthFilter.ATTR_SESSION) SessionRecord session) {
        AccessDecision decision = accessControlService.decide(session, Role.USER, Set.of());
        if (!decision.granted()) {
            return forbidden(session, "/api/user/profile", decision);
        }
        return ResponseEntity.ok(Map.of(
                "username", session.username(),
                "basis", decision.basis()));
    }

    @GetMapping("/admin/stats")
    public ResponseEntity<?> adminStats(@RequestAttribute(AuthFilter.ATTR_SESSION) SessionRecord session) {
        AccessDecision decision = accessControlService.decide(session, Role.ADMIN, Set.of());
        if (!decision.granted()) {
            return forbidden(session, "/api/admin/stats", decision);
        }
        return ResponseEntity.ok(Map.of("activeUsers", "2", "basis", decision.basis()));
    }

    @GetMapping("/user/eng-docs")
    public ResponseEntity<?> engDocs(@RequestAttribute(AuthFilter.ATTR_SESSION) SessionRecord session) {
        AccessDecision decision = accessControlService.decide(session, Role.USER, Set.of("dept:eng"));
        if (!decision.granted()) {
            return forbidden(session, "/api/user/eng-docs", decision);
        }
        return ResponseEntity.ok(Map.of("docs", "eng-handbook", "basis", decision.basis()));
    }

    private ResponseEntity<ApiError> forbidden(SessionRecord session, String path, AccessDecision decision) {
        log.info("[resource] path={} user={} -> 403 denyReason={} basis={}",
                path, session.username(), decision.denyReason(), decision.basis());
        return ResponseEntity.status(HttpStatus.FORBIDDEN)
                .body(new ApiError(decision.denyReason().name(), "access denied"));
    }
}
