package com.github.xingjianluo.sessionauthjava.tests;

import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.test.web.servlet.MvcResult;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;

/**
 * Session expiry, logout, administrative revocation and concurrent duplicate-request
 * consistency. Each case logs the presented token state and the exact rejection code.
 */
class SessionLifecycleTest extends AbstractApiTest {

    @Test
    void idleSessionExpiresWithDistinctCode() throws Exception {
        adminConfig(Map.of("sessionIdleTimeoutMillis", 1000L));
        SessionTokens tokens = login("bob", "bob123");

        clock.advanceMillis(500);
        MvcResult alive = callDocs(tokens);
        assertEquals(200, alive.getResponse().getStatus());

        clock.advanceMillis(1001); // sliding window expired
        MvcResult expired = callDocs(tokens);
        testLog.info("JUDGEMENT expired session status={} body={}",
                expired.getResponse().getStatus(), expired.getResponse().getContentAsString());
        assertEquals(401, expired.getResponse().getStatus());
        assertTrue(expired.getResponse().getContentAsString().contains("SESSION_EXPIRED"));
    }

    @Test
    void logoutMakesNextRequestDistinctlyRejected() throws Exception {
        SessionTokens tokens = login("bob", "bob123");
        mockMvc.perform(post("/api/auth/logout")
                        .cookie(cookie(tokens))
                        .header("X-CSRF-TOKEN", tokens.csrf()))
                .andExpect(r -> assertEquals(200, r.getResponse().getStatus()));

        MvcResult result = callDocs(tokens);
        testLog.info("JUDGEMENT after logout status={} body={}",
                result.getResponse().getStatus(), result.getResponse().getContentAsString());
        assertEquals(401, result.getResponse().getStatus());
        assertTrue(result.getResponse().getContentAsString().contains("SESSION_LOGGED_OUT"));
    }

    @Test
    void adminRevocationTakesEffectOnTheNextRequest() throws Exception {
        SessionTokens victim = login("bob", "bob123");
        assertEquals(200, callDocs(victim).getResponse().getStatus());

        SessionTokens admin = login("admin", "admin123");
        mockMvc.perform(post("/api/admin/sessions/users/bob/revoke")
                        .cookie(cookie(admin))
                        .header("X-CSRF-TOKEN", admin.csrf()))
                .andExpect(r -> assertEquals(200, r.getResponse().getStatus(),
                        r.getResponse().getContentAsString()));

        MvcResult result = callDocs(victim);
        testLog.info("JUDGEMENT after admin revoke status={} body={}",
                result.getResponse().getStatus(), result.getResponse().getContentAsString());
        assertEquals(401, result.getResponse().getStatus());
        assertTrue(result.getResponse().getContentAsString().contains("SESSION_REVOKED"));
    }

    @Test
    void missingAndUnknownCookiesAreDistinguishable() throws Exception {
        MvcResult missing = mockMvc.perform(get("/api/documents")).andReturn();
        testLog.info("JUDGEMENT no cookie status={} body={}",
                missing.getResponse().getStatus(), missing.getResponse().getContentAsString());
        assertEquals(401, missing.getResponse().getStatus());
        assertTrue(missing.getResponse().getContentAsString().contains("SESSION_MISSING"));

        MvcResult unknown = mockMvc.perform(get("/api/documents")
                .cookie(new jakarta.servlet.http.Cookie("SID", "does-not-exist"))).andReturn();
        assertEquals(401, unknown.getResponse().getStatus());
        assertTrue(unknown.getResponse().getContentAsString().contains("SESSION_UNKNOWN"));
    }

    @Test
    void duplicateConcurrentRequestsOnRevokedTokenCannotSlipThrough() throws Exception {
        SessionTokens victim = login("bob", "bob123");
        SessionTokens admin = login("admin", "admin123");
        mockMvc.perform(post("/api/admin/sessions/revoke")
                        .cookie(cookie(admin))
                        .header("X-CSRF-TOKEN", admin.csrf())
                        .contentType("application/json")
                        .content(objectMapper.writeValueAsString(Map.of("token", victim.sid()))))
                .andExpect(r -> assertEquals(200, r.getResponse().getStatus(),
                        r.getResponse().getContentAsString()));

        int threads = 16;
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        List<? extends Future<MvcResult>> futures = pool.invokeAll(
                java.util.Collections.nCopies(threads, (java.util.concurrent.Callable<MvcResult>)
                        () -> callDocs(victim)));
        pool.shutdown();
        assertTrue(pool.awaitTermination(30, TimeUnit.SECONDS));
        int revoked = 0;
        for (Future<MvcResult> future : futures) {
            MockHttpServletResponse response = future.get().getResponse();
            if (response.getStatus() == 401
                    && response.getContentAsString().contains("SESSION_REVOKED")) {
                revoked++;
            }
        }
        testLog.info("JUDGEMENT 16 duplicate requests after revoke revokedCount={}", revoked);
        assertEquals(threads, revoked, "no duplicate request may be admitted after revocation");
    }

    private MvcResult callDocs(SessionTokens tokens) throws Exception {
        return mockMvc.perform(get("/api/documents").cookie(cookie(tokens))).andReturn();
    }

    private jakarta.servlet.http.Cookie cookie(SessionTokens tokens) {
        return new jakarta.servlet.http.Cookie("SID", tokens.sid());
    }

    private void adminConfig(Map<String, Object> changes) throws Exception {
        SessionTokens admin = login("admin", "admin123");
        mockMvc.perform(post("/api/admin/config")
                        .cookie(cookie(admin))
                        .header("X-CSRF-TOKEN", admin.csrf())
                        .contentType("application/json")
                        .content(objectMapper.writeValueAsString(changes)))
                .andExpect(r -> assertEquals(200, r.getResponse().getStatus(),
                        r.getResponse().getContentAsString()));
    }
}
