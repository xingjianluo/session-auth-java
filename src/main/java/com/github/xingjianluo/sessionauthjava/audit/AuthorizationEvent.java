package com.github.xingjianluo.sessionauthjava.audit;

import com.github.xingjianluo.sessionauthjava.authz.Decision;
import com.github.xingjianluo.sessionauthjava.authz.DenyReason;
import java.util.Map;

/**
 * One authorization audit record capturing every input needed to reproduce the decision.
 */
public record AuthorizationEvent(
        long timestampMillis,
        String username,
        String sessionToken,
        String method,
        String path,
        Decision decision,
        DenyReason denyReason,
        String matchedRuleId,
        String ruleProfile,
        long ruleVersion,
        long settingsVersion,
        String role,
        Map<String, String> principalAttributes,
        Map<String, String> resourceAttributes
) {
}
