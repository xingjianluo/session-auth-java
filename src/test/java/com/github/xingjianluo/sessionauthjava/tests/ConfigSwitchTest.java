package com.github.xingjianluo.sessionauthjava.tests;

import com.github.xingjianluo.sessionauthjava.authz.AccessRule;
import com.github.xingjianluo.sessionauthjava.authz.RuleSetVersion;
import com.github.xingjianluo.sessionauthjava.model.AuthPrincipal;
import com.github.xingjianluo.sessionauthjava.model.Permission;
import com.github.xingjianluo.sessionauthjava.model.Role;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.web.servlet.MvcResult;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;

/**
 * Configuration/rule switching scenarios:
 * toggling CSRF changes subsequent decisions; switching the rule profile changes ABAC
 * outcomes; historical rule-set versions can be replayed and reproduce the original
 * decision; public entries stay reachable regardless of switches.
 */
class ConfigSwitchTest extends AbstractApiTest {

    @Autowired
    private com.github.xingjianluo.sessionauthjava.authz.AccessRuleRegistry registry;

    @Test
    void togglingCsrfChangesSubsequentJudgementsWithoutInvalidatingSessions() throws Exception {
        SessionTokens bob = login("bob", "bob123");
        String createBody = "{\"title\":\"t\",\"content\":\"c\",\"department\":\"ENG\"}";

        // USER lacks DOC_WRITE anyway, so use CSRF toggle on an endpoint the role may reach:
        // read is safe method, therefore test CSRF toggle through settings + login still works.
        MvcResult before = mockMvc.perform(get("/api/documents").cookie(cookie(bob))).andReturn();
        assertEquals(200, before.getResponse().getStatus());

        // Switch CSRF off: a state-changing request must skip the CSRF gate (still role-checked).
        updateConfig(adminLogin(), Map.of("csrfEnabled", false));
        MvcResult postNoToken = mockMvc.perform(post("/api/documents")
                        .cookie(cookie(bob)).contentType("application/json").content(createBody))
                .andReturn();
        testLog.info("JUDGEMENT create with csrf disabled status={} (expect ROLE 403, not CSRF 403)",
                postNoToken.getResponse().getStatus());
        assertEquals(403, postNoToken.getResponse().getStatus());
        org.junit.jupiter.api.Assertions.assertTrue(
                postNoToken.getResponse().getContentAsString().contains("ACCESS_DENIED"));

        updateConfig(adminLogin(), Map.of("csrfEnabled", true));
        MvcResult postOnAgain = mockMvc.perform(post("/api/documents")
                        .cookie(cookie(bob)).contentType("application/json").content(createBody))
                .andReturn();
        assertEquals(403, postOnAgain.getResponse().getStatus());
        org.junit.jupiter.api.Assertions.assertTrue(
                postOnAgain.getResponse().getContentAsString().contains("CSRF_INVALID"));

        // The session survived both switches.
        MvcResult read = mockMvc.perform(get("/api/documents").cookie(cookie(bob))).andReturn();
        assertEquals(200, read.getResponse().getStatus());
    }

    @Test
    void switchingToStrictRulesChangesOwnerBasedAccess() throws Exception {
        SessionTokens bob = login("bob", "bob123");

        // Default profile: same department => bob (ENG) can read the ENG document.
        MvcResult underDefault = mockMvc.perform(get("/api/documents/d-eng-1")
                .cookie(cookie(bob))).andReturn();
        testLog.info("JUDGEMENT default profile bob->d-eng-1 status={}",
                underDefault.getResponse().getStatus());
        assertEquals(200, underDefault.getResponse().getStatus());

        long defaultVersion = registry.current().version();
        switchProfile(adminLogin(), "strict");

        // Strict profile: owner-only => bob is neither owner nor admin -> hidden 404.
        MvcResult underStrict = mockMvc.perform(get("/api/documents/d-eng-1")
                .cookie(cookie(bob))).andReturn();
        testLog.info("JUDGEMENT strict profile bob->d-eng-1 status={} body={}",
                underStrict.getResponse().getStatus(), underStrict.getResponse().getContentAsString());
        assertEquals(404, underStrict.getResponse().getStatus());

        // Replay the decision against the retained historical rule set -> same old ALLOW.
        RuleSetVersion oldSet = registry.version(defaultVersion);
        RuleSetVersion newSet = registry.current();
        assertNotEquals(defaultVersion, newSet.version());
        AuthPrincipal bobPrincipal = new AuthPrincipal("bob", Role.USER,
                Set.of(Permission.DOC_READ), "ENG", Map.of(), bob.sid(), bob.csrf());
        Map<String, String> docAttrs = Map.of("id", "d-eng-1", "department", "ENG",
                "ownerUsername", "alice");

        AccessRule.Evaluation replayOld = firstMatch(oldSet, "/api/documents/d-eng-1", "GET",
                bobPrincipal, docAttrs);
        AccessRule.Evaluation replayNew = firstMatch(newSet, "/api/documents/d-eng-1", "GET",
                bobPrincipal, docAttrs);
        testLog.info("JUDGEMENT replay oldRuleVersion={} -> {} ; currentVersion={} -> {}",
                defaultVersion, replayOld.decision(), newSet.version(), replayNew.decision());
        assertEquals(com.github.xingjianluo.sessionauthjava.authz.Decision.ALLOW,
                replayOld.decision(), "historical decision must be reproducible");
        assertEquals(com.github.xingjianluo.sessionauthjava.authz.Decision.DENY,
                replayNew.decision());
        assertEquals(com.github.xingjianluo.sessionauthjava.authz.DenyReason.ATTRIBUTE_DENIED,
                replayNew.denyReason());
    }

    @Test
    void publicEntriesRemainReachableAfterSwitches() throws Exception {
        updateConfig(adminLogin(), Map.of("csrfEnabled", false));
        switchProfile(adminLogin(), "strict");

        MvcResult csrf = mockMvc.perform(get("/api/auth/csrf")).andReturn();
        testLog.info("JUDGEMENT public csrf endpoint under strict+csrf-off status={}",
                csrf.getResponse().getStatus());
        assertEquals(200, csrf.getResponse().getStatus());

        MvcResult nonApi = mockMvc.perform(get("/actuator-not-managed")).andReturn();
        // Non-API entries are not intercepted at all; the exact non-security response code is
        // irrelevant, it must never be an UNAUTHENTICATED 401 from our filter.
        assertNotEquals(401, nonApi.getResponse().getStatus());
    }

    private AccessRule.Evaluation firstMatch(RuleSetVersion set, String path, String method,
                                             AuthPrincipal principal, Map<String, String> attrs) {
        for (AccessRule rule : set.rules()) {
            if (rule.matches(path, method)) {
                return rule.evaluate(principal, attrs);
            }
        }
        return new AccessRule.Evaluation(
                com.github.xingjianluo.sessionauthjava.authz.Decision.DENY,
                com.github.xingjianluo.sessionauthjava.authz.DenyReason.PATH_NOT_FOUND, null);
    }

    private SessionTokens adminLogin() throws Exception {
        return login("admin", "admin123");
    }

    private void updateConfig(SessionTokens admin, Map<String, Object> changes) throws Exception {
        MvcResult result = mockMvc.perform(post("/api/admin/config")
                        .cookie(cookie(admin)).header("X-CSRF-TOKEN", admin.csrf())
                        .contentType("application/json")
                        .content(objectMapper.writeValueAsString(changes)))
                .andReturn();
        assertEquals(200, result.getResponse().getStatus(), result.getResponse().getContentAsString());
    }

    private void switchProfile(SessionTokens admin, String profile) throws Exception {
        MvcResult result = mockMvc.perform(post("/api/admin/rules/switch")
                        .param("profile", profile)
                        .cookie(cookie(admin)).header("X-CSRF-TOKEN", admin.csrf()))
                .andReturn();
        assertEquals(200, result.getResponse().getStatus(), result.getResponse().getContentAsString());
    }

    private jakarta.servlet.http.Cookie cookie(SessionTokens tokens) {
        return new jakarta.servlet.http.Cookie("SID", tokens.sid());
    }
}
