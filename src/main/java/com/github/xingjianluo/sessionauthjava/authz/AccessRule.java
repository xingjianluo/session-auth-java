package com.github.xingjianluo.sessionauthjava.authz;

import com.github.xingjianluo.sessionauthjava.model.AuthPrincipal;
import com.github.xingjianluo.sessionauthjava.model.Permission;
import java.util.Map;

/**
 * One ordered access rule: path pattern + HTTP method, a permission requirement (RBAC)
 * and an optional attribute predicate (ABAC). Rules are evaluated first-match-wins by
 * {@link AccessRuleRegistry} / {@code AuthorizationInterceptor}.
 */
public class AccessRule {

    private final String id;
    private final String pathPattern;
    private final String method;
    private final Permission requiredPermission;
    private final AttributePredicate attributePredicate;
    private final DenyReason attributeDenyReason;
    private final boolean requiresResource;
    private final String description;

    public AccessRule(String id, String pathPattern, String method,
                      Permission requiredPermission, AttributePredicate attributePredicate,
                      DenyReason attributeDenyReason, boolean requiresResource,
                      String description) {
        this.id = id;
        this.pathPattern = pathPattern;
        this.method = method;
        this.requiredPermission = requiredPermission;
        this.attributePredicate = attributePredicate;
        this.attributeDenyReason = attributeDenyReason;
        this.requiresResource = requiresResource;
        this.description = description;
    }

    public boolean matches(String path, String httpMethod) {
        boolean methodOk = method == null || method.equalsIgnoreCase(httpMethod);
        return methodOk && antMatch(pathPattern, path);
    }

    /**
     * Evaluates RBAC then ABAC. {@code resourceAttributes} is {@code null} when the
     * resource does not exist; such a case is reported as RESOURCE_NOT_FOUND.
     */
    public Evaluation evaluate(AuthPrincipal principal, Map<String, String> resourceAttributes) {
        if (requiredPermission != null && !principal.has(requiredPermission)) {
            return new Evaluation(Decision.DENY, DenyReason.ROLE_DENIED, id);
        }
        if (attributePredicate != null) {
            if (resourceAttributes == null) {
                return new Evaluation(Decision.DENY, DenyReason.RESOURCE_NOT_FOUND, id);
            }
            if (!attributePredicate.test(principal, resourceAttributes)) {
                return new Evaluation(Decision.DENY,
                        attributeDenyReason != null ? attributeDenyReason : DenyReason.ATTRIBUTE_DENIED,
                        id);
            }
        }
        return Evaluation.allow(id);
    }

    public String id() { return id; }
    public String pathPattern() { return pathPattern; }
    public String method() { return method; }
    public String description() { return description; }
    public boolean requiresResource() { return requiresResource; }
    public Permission requiredPermission() { return requiredPermission; }

    /**
     * Minimal Ant-style matcher supporting {@code *} (within a segment), {@code **}
     * (any number of segments) and literal {@code ?}. Sufficient for the configured
     * rule patterns; avoids pulling in a full path-matcher dependency at this layer.
     */
    static boolean antMatch(String pattern, String path) {
        String[] p = pattern.startsWith("/") ? pattern.substring(1).split("/", -1) : new String[0];
        String[] s = path.startsWith("/") ? path.substring(1).split("/", -1) : new String[0];
        return matchSegments(p, 0, s, 0);
    }

    private static boolean matchSegments(String[] pat, int pi, String[] seg, int si) {
        while (pi < pat.length) {
            if ("**".equals(pat[pi])) {
                if (pi == pat.length - 1) {
                    return true;
                }
                for (int k = si; k <= seg.length; k++) {
                    if (matchSegments(pat, pi + 1, seg, k)) {
                        return true;
                    }
                }
                return false;
            }
            if (si >= seg.length || !segmentMatch(pat[pi], seg[si])) {
                return false;
            }
            pi++;
            si++;
        }
        return si == seg.length;
    }

    private static boolean segmentMatch(String patternSegment, String valueSegment) {
        StringBuilder regex = new StringBuilder("^");
        for (int i = 0; i < patternSegment.length(); i++) {
            char c = patternSegment.charAt(i);
            if (c == '*') {
                regex.append("[^/]*");
            } else if (c == '?') {
                regex.append('.');
            } else {
                regex.append(java.util.regex.Pattern.quote(String.valueOf(c)));
            }
        }
        regex.append('$');
        return java.util.regex.Pattern
                .compile(regex.toString())
                .matcher(valueSegment).matches();
    }

    /** Rule evaluation outcome. */
    public record Evaluation(Decision decision, DenyReason denyReason, String matchedRuleId) {
        public static Evaluation allow(String ruleId) {
            return new Evaluation(Decision.ALLOW, null, ruleId);
        }
    }

    /** ABAC predicate over principal and resource attributes. */
    @FunctionalInterface
    public interface AttributePredicate {
        boolean test(AuthPrincipal principal, Map<String, String> resourceAttributes);
    }
}
