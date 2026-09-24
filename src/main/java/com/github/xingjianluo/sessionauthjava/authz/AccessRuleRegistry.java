package com.github.xingjianluo.sessionauthjava.authz;

import com.github.xingjianluo.sessionauthjava.model.Permission;
import java.util.ArrayList;
import java.util.List;
import java.util.TreeMap;
import java.util.concurrent.atomic.AtomicLong;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

/**
 * Holds the ordered, versioned access rule set. Two profiles are provided to demonstrate
 * rule switching; every published {@link RuleSetVersion} is retained so that a decision
 * made under an older rule set can be reproduced exactly (see audit records).
 *
 * <p>Rules are evaluated first-match-wins. Rules for concrete resources carry ABAC
 * predicates; missing resources are reported as RESOURCE_NOT_FOUND so callers cannot
 * distinguish "forbidden" from "does not exist" for resource-scoped URLs.
 */
@Service
public class AccessRuleRegistry {

    private static final Logger log = LoggerFactory.getLogger(AccessRuleRegistry.class);
    public static final String PROFILE_DEFAULT = "default";
    public static final String PROFILE_STRICT = "strict";

    private final AtomicLong versionSeq = new AtomicLong(0);
    private final TreeMap<Long, RuleSetVersion> history = new TreeMap<>();
    private volatile RuleSetVersion current;

    public AccessRuleRegistry() {
        switchProfile(PROFILE_DEFAULT);
    }

    /** Returns the current ordered rule set. */
    public RuleSetVersion current() {
        return current;
    }

    /** Loads a rule set by profile name ({@code default}, {@code strict}). */
    public synchronized RuleSetVersion switchProfile(String profile) {
        List<AccessRule> rules = switch (profile) {
            case PROFILE_STRICT -> strictRules();
            case PROFILE_DEFAULT -> defaultRules();
            default -> throw new IllegalArgumentException("Unknown rule profile: " + profile);
        };
        long version = versionSeq.incrementAndGet();
        RuleSetVersion set = new RuleSetVersion(version, profile, List.copyOf(rules));
        history.put(version, set);
        current = set;
        log.info("Access rule set switched profile={} version={} rules={}",
                profile, version, rules.stream().map(AccessRule::id).toList());
        return set;
    }

    public RuleSetVersion version(long version) {
        return history.get(version);
    }

    public List<Long> versions() {
        return new ArrayList<>(history.keySet());
    }

    /**
     * Default profile: documents are readable by anyone with DOC_READ but confined to the
     * caller's department (ABAC); managers may modify within their department; admins have
     * full access. Session/config/audit management is admin-only.
     */
    private List<AccessRule> defaultRules() {
        List<AccessRule> rules = new ArrayList<>();

        // Authenticated self-service: logout needs a session but no special permission.
        rules.add(new AccessRule("auth-logout", "/api/auth/logout", "POST",
                null, null, DenyReason.ROLE_DENIED, false,
                "logout current session"));

        // Administrative API surface: admin-only, no resource attributes involved.
        rules.add(new AccessRule("admin-sessions", "/api/admin/sessions/**", null,
                Permission.SESSION_MANAGE, null, DenyReason.ROLE_DENIED, false,
                "manage sessions"));
        rules.add(new AccessRule("admin-users", "/api/admin/users/**", null,
                Permission.SESSION_MANAGE, null, DenyReason.ROLE_DENIED, false,
                "manage users"));
        rules.add(new AccessRule("admin-config", "/api/admin/config/**", null,
                Permission.CONFIG_MANAGE, null, DenyReason.ROLE_DENIED, false,
                "manage security configuration"));
        rules.add(new AccessRule("admin-rules", "/api/admin/rules/**", null,
                Permission.CONFIG_MANAGE, null, DenyReason.ROLE_DENIED, false,
                "switch access rule profiles"));
        rules.add(new AccessRule("admin-audit", "/api/admin/audit/**", null,
                Permission.AUDIT_READ, null, DenyReason.ROLE_DENIED, false,
                "read authorization audit trail"));

        // Document collection: create requires DOC_WRITE; list/read require DOC_READ.
        rules.add(new AccessRule("doc-create", "/api/documents", "POST",
                Permission.DOC_WRITE, null, DenyReason.ROLE_DENIED, false,
                "create document"));
        rules.add(new AccessRule("doc-list", "/api/documents", "GET",
                Permission.DOC_READ, null, DenyReason.ROLE_DENIED, false,
                "list documents"));

        // Document item: department must match (admins bypass by role permissions + predicate).
        AccessRule.AttributePredicate sameDepartment = (principal, resource) ->
                principal.role().name().equals("ADMIN")
                        || safeEquals(principal.department(), resource.get("department"));
        rules.add(new AccessRule("doc-read-item", "/api/documents/*", "GET",
                Permission.DOC_READ, sameDepartment, DenyReason.ATTRIBUTE_DENIED, true,
                "read a document within own department"));
        rules.add(new AccessRule("doc-update-item", "/api/documents/*", "PUT",
                Permission.DOC_WRITE, sameDepartment, DenyReason.ATTRIBUTE_DENIED, true,
                "update a document within own department"));
        rules.add(new AccessRule("doc-delete-item", "/api/documents/*", "DELETE",
                Permission.DOC_DELETE, sameDepartment, DenyReason.ATTRIBUTE_DENIED, true,
                "delete a document within own department"));
        return rules;
    }

    /**
     * Strict profile: documents can only be read by their owner in addition to admins,
     * and ordinary managers lose delete rights. Demonstrates configuration switching and
     * that historical decisions stay reproducible via retained versions.
     */
    private List<AccessRule> strictRules() {
        List<AccessRule> rules = new ArrayList<>();
        rules.add(new AccessRule("auth-logout", "/api/auth/logout", "POST",
                null, null, DenyReason.ROLE_DENIED, false,
                "logout current session"));
        rules.add(new AccessRule("admin-sessions", "/api/admin/sessions/**", null,
                Permission.SESSION_MANAGE, null, DenyReason.ROLE_DENIED, false,
                "manage sessions"));
        rules.add(new AccessRule("admin-users", "/api/admin/users/**", null,
                Permission.SESSION_MANAGE, null, DenyReason.ROLE_DENIED, false,
                "manage users"));
        rules.add(new AccessRule("admin-config", "/api/admin/config/**", null,
                Permission.CONFIG_MANAGE, null, DenyReason.ROLE_DENIED, false,
                "manage security configuration"));
        rules.add(new AccessRule("admin-rules", "/api/admin/rules/**", null,
                Permission.CONFIG_MANAGE, null, DenyReason.ROLE_DENIED, false,
                "switch access rule profiles"));
        rules.add(new AccessRule("admin-audit", "/api/admin/audit/**", null,
                Permission.AUDIT_READ, null, DenyReason.ROLE_DENIED, false,
                "read authorization audit trail"));

        rules.add(new AccessRule("doc-create", "/api/documents", "POST",
                Permission.DOC_WRITE, null, DenyReason.ROLE_DENIED, false,
                "create document"));
        rules.add(new AccessRule("doc-list", "/api/documents", "GET",
                Permission.DOC_READ, null, DenyReason.ROLE_DENIED, false,
                "list documents"));

        AccessRule.AttributePredicate ownerOrAdmin = (principal, resource) ->
                principal.role().name().equals("ADMIN")
                        || safeEquals(principal.username(), resource.get("ownerUsername"));
        rules.add(new AccessRule("doc-read-item", "/api/documents/*", "GET",
                Permission.DOC_READ, ownerOrAdmin, DenyReason.ATTRIBUTE_DENIED, true,
                "read only owned documents"));
        rules.add(new AccessRule("doc-update-item", "/api/documents/*", "PUT",
                Permission.DOC_WRITE, ownerOrAdmin, DenyReason.ATTRIBUTE_DENIED, true,
                "update only owned documents"));
        // Delete is admin-only even for managers: no DOC_DELETE rule for item paths,
        // and the rule for the collection does not match item URLs.
        return rules;
    }

    private static boolean safeEquals(String a, String b) {
        return a != null && a.equals(b);
    }
}
