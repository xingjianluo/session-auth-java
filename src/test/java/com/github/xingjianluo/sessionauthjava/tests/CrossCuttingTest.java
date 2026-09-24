package com.github.xingjianluo.sessionauthjava.tests;

import java.util.Map;
import org.junit.jupiter.api.Test;
import org.springframework.test.web.servlet.MvcResult;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.options;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;

/**
 * Compatibility of the security outcome with cross-cutting rules:
 * CORS preflight must pass without a session; security headers must be present on both
 * successes and failures; public entries must never be intercepted; and unknown-user
 * vs wrong-password failures must be indistinguishable to prevent user enumeration.
 */
class CrossCuttingTest extends AbstractApiTest {

    @Test
    void corsPreflightIsAnsweredWithoutAuthentication() throws Exception {
        MvcResult preflight = mockMvc.perform(options("/api/documents")
                        .header("Origin", "https://example.com")
                        .header("Access-Control-Request-Method", "POST")
                        .header("Access-Control-Request-Headers", "content-type,x-csrf-token"))
                .andReturn();
        testLog.info("JUDGEMENT preflight status={} allowOrigin={} allowMethods={}",
                preflight.getResponse().getStatus(),
                preflight.getResponse().getHeader("Access-Control-Allow-Origin"),
                preflight.getResponse().getHeader("Access-Control-Allow-Methods"));
        assertEquals(204, preflight.getResponse().getStatus());
        assertEquals("https://example.com",
                preflight.getResponse().getHeader("Access-Control-Allow-Origin"));
    }

    @Test
    void securityHeadersArePresentOnAllowedAndDeniedResponses() throws Exception {
        SessionTokens bob = login("bob", "bob123");

        MvcResult allowed = mockMvc.perform(get("/api/documents").cookie(cookie(bob))).andReturn();
        MvcResult denied = mockMvc.perform(get("/api/documents/d-sales-1").cookie(cookie(bob)))
                .andReturn();
        MvcResult unauthenticated = mockMvc.perform(get("/api/documents")).andReturn();

        for (MvcResult r : new MvcResult[]{allowed, denied, unauthenticated}) {
            assertEquals("DENY", r.getResponse().getHeader("X-Frame-Options"));
            assertEquals("nosniff", r.getResponse().getHeader("X-Content-Type-Options"));
            assertTrue(r.getResponse().containsHeader("Content-Security-Policy"));
        }
        testLog.info("JUDGEMENT headers present on statuses {}/{}/{}",
                allowed.getResponse().getStatus(), denied.getResponse().getStatus(),
                unauthenticated.getResponse().getStatus());
    }

    @Test
    void publicCsrfAndLoginAreNotIntercepted() throws Exception {
        MvcResult csrf = mockMvc.perform(get("/api/auth/csrf")).andReturn();
        assertEquals(200, csrf.getResponse().getStatus());

        MvcResult login = mockMvc.perform(post("/api/auth/login")
                        .contentType("application/json")
                        .content(objectMapper.writeValueAsString(Map.of("username", "bob", "password", "bob123"))))
                .andReturn();
        assertEquals(200, login.getResponse().getStatus());
        testLog.info("JUDGEMENT public entries csrf={} login={}",
                csrf.getResponse().getStatus(), login.getResponse().getStatus());
    }

    @Test
    void unknownUserAndWrongPasswordReturnIdenticalCode() throws Exception {
        MvcResult unknownUser = loginAttempt("ghost", "whatever");
        MvcResult wrongPassword = loginAttempt("bob", "WRONG");
        testLog.info("JUDGEMENT unknownUser={} wrongPassword={}",
                unknownUser.getResponse().getStatus(), wrongPassword.getResponse().getStatus());
        assertEquals(401, unknownUser.getResponse().getStatus());
        assertEquals(401, wrongPassword.getResponse().getStatus());
        assertEquals(
                unknownUser.getResponse().getContentAsString()
                        .replaceAll("\"traceId\":\"[^\"]+\"", ""),
                wrongPassword.getResponse().getContentAsString()
                        .replaceAll("\"traceId\":\"[^\"]+\"", ""));
        assertTrue(unknownUser.getResponse().getContentAsString().contains("BAD_CREDENTIALS"));
    }

    @Test
    void disabledAccountIsRejectedAtLoginAndExistingSessionStopsWorkingImmediately() throws Exception {
        SessionTokens victim = login("bob", "bob123");
        assertEquals(200, mockMvc.perform(get("/api/documents").cookie(cookie(victim)))
                .andReturn().getResponse().getStatus());

        SessionTokens admin = login("admin", "admin123");
        mockMvc.perform(post("/api/admin/users/bob/enabled")
                        .cookie(cookie(admin)).header("X-CSRF-TOKEN", admin.csrf())
                        .contentType("application/json").content("{\"enabled\":false}"))
                .andExpect(r -> assertEquals(200, r.getResponse().getStatus(),
                        r.getResponse().getContentAsString()));

        MvcResult existing = mockMvc.perform(get("/api/documents").cookie(cookie(victim))).andReturn();
        testLog.info("JUDGEMENT existing session after disable status={} body={}",
                existing.getResponse().getStatus(), existing.getResponse().getContentAsString());
        assertEquals(401, existing.getResponse().getStatus());

        MvcResult relogin = loginAttempt("bob", "bob123");
        assertEquals(423, relogin.getResponse().getStatus());
        assertTrue(relogin.getResponse().getContentAsString().contains("ACCOUNT_DISABLED"));
    }

    private MvcResult loginAttempt(String username, String password) throws Exception {
        return mockMvc.perform(post("/api/auth/login")
                .contentType("application/json")
                .content(objectMapper.writeValueAsString(Map.of("username", username, "password", password))))
                .andReturn();
    }

    private jakarta.servlet.http.Cookie cookie(SessionTokens tokens) {
        return new jakarta.servlet.http.Cookie("SID", tokens.sid());
    }
}
