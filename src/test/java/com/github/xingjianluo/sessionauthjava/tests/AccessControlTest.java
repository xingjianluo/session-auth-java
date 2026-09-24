package com.github.xingjianluo.sessionauthjava.tests;

import org.junit.jupiter.api.Test;
import org.springframework.test.web.servlet.MvcResult;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;

/**
 * RBAC + ABAC denial scenarios. External responses hide resource existence:
 * attribute denial and missing resource are byte-identical 404s; the precise
 * ROLE_DENIED / ATTRIBUTE_DENIED / RESOURCE_NOT_FOUND reasons are asserted via the
 * admin audit trail instead.
 */
class AccessControlTest extends AbstractApiTest {

    @Test
    void rbacWriteDeniedToReadonlyRole() throws Exception {
        SessionTokens bob = login("bob", "bob123");
        MvcResult result = mockMvc.perform(post("/api/documents")
                        .cookie(cookie(bob)).header("X-CSRF-TOKEN", bob.csrf())
                        .contentType("application/json")
                        .content("{\"title\":\"t\",\"content\":\"c\",\"department\":\"ENG\"}"))
                .andReturn();
        testLog.info("INPUT USER create DOC; JUDGEMENT status={} body={}",
                result.getResponse().getStatus(), result.getResponse().getContentAsString());
        assertEquals(403, result.getResponse().getStatus());
        assertTrue(result.getResponse().getContentAsString().contains("ACCESS_DENIED"));
        assertEquals("ROLE_DENIED", latestDenyReason(bob, "/api/documents"));
    }

    @Test
    void abacCrossDepartmentAndMissingResourceAreIndistinguishableExternally() throws Exception {
        SessionTokens bob = login("bob", "bob123");

        MvcResult crossDept = mockMvc.perform(get("/api/documents/d-sales-1")
                .cookie(cookie(bob))).andReturn();
        MvcResult missing = mockMvc.perform(get("/api/documents/does-not-exist")
                .cookie(cookie(bob))).andReturn();
        testLog.info("JUDGEMENT crossDept status={} body={}",
                crossDept.getResponse().getStatus(), crossDept.getResponse().getContentAsString());
        testLog.info("JUDGEMENT missing   status={} body={}",
                missing.getResponse().getStatus(), missing.getResponse().getContentAsString());

        assertEquals(404, crossDept.getResponse().getStatus());
        assertEquals(404, missing.getResponse().getStatus());
        assertEquals(crossDept.getResponse().getContentAsString().replaceAll("\"traceId\":\"[^\"]+\"", ""),
                missing.getResponse().getContentAsString().replaceAll("\"traceId\":\"[^\"]+\"", ""),
                "responses must not differ between forbidden and nonexistent resources");

        assertEquals("ATTRIBUTE_DENIED", latestDenyReason(bob, "/api/documents/d-sales-1"));
        assertEquals("RESOURCE_NOT_FOUND", latestDenyReason(bob, "/api/documents/does-not-exist"));
    }

    @Test
    void unknownProtectedPathIsReportedAsNotFoundNotLeakingExistence() throws Exception {
        SessionTokens bob = login("bob", "bob123");
        MvcResult result = mockMvc.perform(get("/api/totally/unknown")
                .cookie(cookie(bob))).andReturn();
        assertEquals(404, result.getResponse().getStatus());
        assertTrue(result.getResponse().getContentAsString().contains("NOT_FOUND"));
        assertEquals("PATH_NOT_FOUND", latestDenyReason(bob, "/api/totally/unknown"));
    }

    @Test
    void managerCanWriteOwnDepartmentButNotOthers() throws Exception {
        SessionTokens alice = login("alice", "alice123");

        MvcResult own = mockMvc.perform(put("/api/documents/d-eng-1")
                        .cookie(cookie(alice)).header("X-CSRF-TOKEN", alice.csrf())
                        .contentType("application/json")
                        .content("{\"title\":\"updated\",\"content\":\"x\",\"department\":\"ENG\"}"))
                .andReturn();
        MvcResult other = mockMvc.perform(put("/api/documents/d-sales-1")
                        .cookie(cookie(alice)).header("X-CSRF-TOKEN", alice.csrf())
                        .contentType("application/json")
                        .content("{\"title\":\"x\",\"content\":\"x\",\"department\":\"SALES\"}"))
                .andReturn();
        testLog.info("JUDGEMENT manager update ownDept={} otherDept={}",
                own.getResponse().getStatus(), other.getResponse().getStatus());
        assertEquals(200, own.getResponse().getStatus());
        assertEquals(404, other.getResponse().getStatus());
    }

    @Test
    void privilegeDowngradeAppliesToTheNextRequestWithoutTouchingTheSession() throws Exception {
        SessionTokens admin = login("admin", "admin123");
        SessionTokens alice = login("alice", "alice123");

        // Initially alice (MANAGER) can create documents.
        int before = mockMvc.perform(post("/api/documents")
                        .cookie(cookie(alice)).header("X-CSRF-TOKEN", alice.csrf())
                        .contentType("application/json")
                        .content("{\"title\":\"t\",\"content\":\"c\",\"department\":\"ENG\"}"))
                .andReturn().getResponse().getStatus();
        assertEquals(201, before);

        mockMvc.perform(post("/api/admin/users/alice/role")
                        .cookie(cookie(admin)).header("X-CSRF-TOKEN", admin.csrf())
                        .contentType("application/json").content("{\"role\":\"USER\"}"))
                .andExpect(r -> assertEquals(200, r.getResponse().getStatus(),
                        r.getResponse().getContentAsString()));

        // Same session token, next request: downgrade is effective immediately.
        MvcResult after = mockMvc.perform(post("/api/documents")
                        .cookie(cookie(alice)).header("X-CSRF-TOKEN", alice.csrf())
                        .contentType("application/json")
                        .content("{\"title\":\"t2\",\"content\":\"c\",\"department\":\"ENG\"}"))
                .andReturn();
        testLog.info("JUDGEMENT post-downgrade create status={} body={} (same session={})",
                after.getResponse().getStatus(), after.getResponse().getContentAsString(),
                alice.sid().substring(0, 6));
        assertEquals(403, after.getResponse().getStatus());
        assertNotEquals("", alice.sid());
    }

    private String latestDenyReason(SessionTokens caller, String path) throws Exception {
        // Use admin to inspect the audit trail without it being affected by the caller's rights.
        SessionTokens admin = login("admin", "admin123");
        MvcResult result = mockMvc.perform(get("/api/admin/audit/by-path")
                        .param("path", path)
                        .cookie(cookie(admin)))
                .andReturn();
        assertEquals(200, result.getResponse().getStatus(), result.getResponse().getContentAsString());
        var events = objectMapper.readTree(result.getResponse().getContentAsString());
        for (int i = events.size() - 1; i >= 0; i--) {
            var event = events.get(i);
            if ("DENY".equals(event.get("decision").asText())
                    && event.get("path").asText().equals(path)) {
                return event.get("denyReason").asText();
            }
        }
        throw new IllegalStateException("no DENY audit event for " + path);
    }

    private jakarta.servlet.http.Cookie cookie(SessionTokens tokens) {
        return new jakarta.servlet.http.Cookie("SID", tokens.sid());
    }
}
