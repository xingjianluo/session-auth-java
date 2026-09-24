package com.github.xingjianluo.sessionauthjava.authz;

import java.util.List;

/** JSON-safe view of a {@link RuleSetVersion} (no predicates or internal class graph). */
public record RuleSetView(long version, String profile, List<RuleView> rules) {

    public static RuleSetView of(RuleSetVersion set) {
        return new RuleSetView(set.version(), set.profile(),
                set.rules().stream().map(RuleView::of).toList());
    }

    public record RuleView(String id, String pathPattern, String method,
                           String requiredPermission, String description, boolean requiresResource) {
        static RuleView of(AccessRule rule) {
            return new RuleView(rule.id(), rule.pathPattern(), rule.method(),
                    rule.requiredPermission() == null ? null : rule.requiredPermission().name(),
                    rule.description(), rule.requiresResource());
        }
    }
}
