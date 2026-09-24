package com.github.xingjianluo.sessionauthjava.authz;

import java.util.List;

/**
 * Immutable, versioned set of access rules.
 */
public record RuleSetVersion(long version, String profile, List<AccessRule> rules) {
}
