package com.github.xingjianluo.sessionauthjava.web.security;

import com.github.xingjianluo.sessionauthjava.audit.AuditService;
import com.github.xingjianluo.sessionauthjava.audit.AuthorizationEvent;
import com.github.xingjianluo.sessionauthjava.authz.AccessRule;
import com.github.xingjianluo.sessionauthjava.authz.AccessRuleRegistry;
import com.github.xingjianluo.sessionauthjava.authz.Decision;
import com.github.xingjianluo.sessionauthjava.authz.DenyReason;
import com.github.xingjianluo.sessionauthjava.authz.ResourceAttributeProvider;
import com.github.xingjianluo.sessionauthjava.authz.RuleSetVersion;
import com.github.xingjianluo.sessionauthjava.config.SecurityConfigService;
import com.github.xingjianluo.sessionauthjava.model.AuthPrincipal;
import com.github.xingjianluo.sessionauthjava.support.TimeSource;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.util.List;
import java.util.Map;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.servlet.HandlerExceptionResolver;
import org.springframework.web.servlet.HandlerInterceptor;

/**
 * Enforces the ordered access rules on protected API paths. Every decision — allow or
 * deny — is written to the audit trail with the exact inputs and the rule/settings
 * versions used.
 *
 * <p>Resource-scoped denials are reported as {@link DenyReason#RESOURCE_NOT_FOUND} when
 * the resource is missing, and missing/unmatched paths as {@link DenyReason#PATH_NOT_FOUND}.
 * The exception handler maps both to the same external 404 body, so resource existence is
 * never leaked through the response, while logs retain the precise reason.
 */
public class AuthorizationInterceptor implements HandlerInterceptor {

    private static final Logger log = LoggerFactory.getLogger(AuthorizationInterceptor.class);

    private final AccessRuleRegistry ruleRegistry;
    private final List<ResourceAttributeProvider> attributeProviders;
    private final AuditService auditService;
    private final SecurityConfigService configService;
    private final TimeSource timeSource;
    private final HandlerExceptionResolver exceptionResolver;

    public AuthorizationInterceptor(AccessRuleRegistry ruleRegistry,
                                    List<ResourceAttributeProvider> attributeProviders,
                                    AuditService auditService,
                                    SecurityConfigService configService,
                                    TimeSource timeSource,
                                    HandlerExceptionResolver exceptionResolver) {
        this.ruleRegistry = ruleRegistry;
        this.attributeProviders = attributeProviders;
        this.auditService = auditService;
        this.configService = configService;
        this.timeSource = timeSource;
        this.exceptionResolver = exceptionResolver;
    }

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler)
            throws Exception {
        String path = request.getRequestURI();
        String method = request.getMethod();
        if (PublicPaths.isPublicApi(path, method)) {
            return true;
        }
        AuthPrincipal principal = (AuthPrincipal) request.getAttribute(
                AuthenticationFilter.PRINCIPAL_ATTRIBUTE);
        RuleSetVersion ruleSet = ruleRegistry.current();

        AccessRule matched = null;
        for (AccessRule rule : ruleSet.rules()) {
            if (rule.matches(path, method)) {
                matched = rule;
                break;
            }
        }

        Map<String, String> resourceAttributes = null;
        AccessRule.Evaluation evaluation;
        DenyReason reason;
        String ruleId;

        if (matched == null) {
            // No rule maps this protected path: hide existence uniformly.
            evaluation = null;
            reason = DenyReason.PATH_NOT_FOUND;
            ruleId = null;
        } else {
            ruleId = matched.id();
            if (matched.requiresResource()) {
                resourceAttributes = loadResourceAttributes(path, method);
            }
            evaluation = matched.evaluate(principal, resourceAttributes);
            reason = evaluation.decision() == Decision.ALLOW ? null : evaluation.denyReason();
        }

        Decision decision = (matched != null
                && evaluation != null
                && evaluation.decision() == Decision.ALLOW)
                ? Decision.ALLOW : Decision.DENY;

        AuthorizationEvent event = new AuthorizationEvent(
                timeSource.nowMillis(),
                principal == null ? null : principal.username(),
                principal == null ? null : principal.sessionToken(),
                method,
                path,
                decision,
                reason,
                ruleId,
                ruleSet.profile(),
                ruleSet.version(),
                configService.current().version(),
                principal == null ? null : principal.role().name(),
                principal == null ? Map.of() : principal.attributes(),
                resourceAttributes == null ? Map.of() : resourceAttributes);
        auditService.record(event);

        if (decision == Decision.ALLOW) {
            return true;
        }
        if (reason == DenyReason.ROLE_DENIED || reason == DenyReason.ATTRIBUTE_DENIED) {
            exceptionResolver.resolveException(request, response, handler,
                    new AccessDeniedException(reason, "Access denied: " + reason));
        } else {
            exceptionResolver.resolveException(request, response, handler,
                    new AccessDeniedException(reason, "Resource not found"));
        }
        return false;
    }

    private Map<String, String> loadResourceAttributes(String path, String method) {
        for (ResourceAttributeProvider provider : attributeProviders) {
            if (provider.supports(path, method)) {
                return provider.loadAttributes(path, method);
            }
        }
        return null;
    }
}
