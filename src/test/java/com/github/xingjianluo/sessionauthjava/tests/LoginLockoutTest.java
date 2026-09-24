package com.github.xingjianluo.sessionauthjava.tests;

import java.util.Map;
import org.junit.jupiter.api.Test;
import org.springframework.test.web.servlet.MvcResult;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;

/**
 * Failed-login rate limiting and account locking.
 *
 * <p>Configured for the test: 3 consecutive failures lock for 1000ms; 5 failures per
 * 60s window trigger a 500ms rate-limit block. Each judgement logs counters and time.
 */
class LoginLockoutTest extends AbstractApiTest {

    /** lockThreshold=3 -> crossing attempt and following attempts are ACCOUNT_LOCKED. */
    @Test
    void consecutiveFailuresLockAccountAndUnlockAfterDuration() throws Exception {
        adminConfig(Map.of(
                "lockThreshold", 3,
                "lockMillis", 1000L,
                "rateLimitAttempts", 100,
                "rateLimitWindowMillis", 60000L,
                "rateLimitBlockMillis", 500L));

        MvcResult r1 = badLogin("bob");
        MvcResult r2 = badLogin("bob");
        MvcResult r3 = badLogin("bob");
        testLog.info("JUDGEMENT failures 1-3 statuses={}/{} bodies={}|{}|{}",
                r1.getResponse().getStatus(), r2.getResponse().getStatus(), r3.getResponse().getStatus(),
                r1.getResponse().getContentAsString(), r2.getResponse().getContentAsString(),
                r3.getResponse().getContentAsString());
        assertEquals(401, r1.getResponse().getStatus());
        assertTrue(r1.getResponse().getContentAsString().contains("BAD_CREDENTIALS"));
        // Crossing attempt is reported as ACCOUNT_LOCKED immediately.
        assertEquals(423, r3.getResponse().getStatus());
        assertTrue(r3.getResponse().getContentAsString().contains("ACCOUNT_LOCKED"));

        // Even with the correct password, a locked account cannot log in.
        MvcResult locked = loginAttempt("bob", "bob123");
        testLog.info("INPUT correct password while locked -> status={} body={}",
                locked.getResponse().getStatus(), locked.getResponse().getContentAsString());
        assertEquals(423, locked.getResponse().getStatus());

        clock.advanceMillis(1001);
        MvcResult after = loginAttempt("bob", "bob123");
        testLog.info("JUDGEMENT after lock TTL elapsed status={} body={}",
                after.getResponse().getStatus(), after.getResponse().getContentAsString());
        assertEquals(200, after.getResponse().getStatus(), "lock expiry must restore login");
    }

    /** 5 failures per window -> RATE_LIMITED (429), independently of the 3-strike lock. */
    @Test
    void slidingWindowTriggersDistinctRateLimit() throws Exception {
        adminConfig(Map.of(
                "lockThreshold", 100,
                "lockMillis", 1000L,
                "rateLimitAttempts", 5,
                "rateLimitWindowMillis", 60000L,
                "rateLimitBlockMillis", 500L));

        MvcResult crossing = null;
        for (int i = 0; i < 5; i++) {
            crossing = badLogin("carol");
        }
        testLog.info("JUDGEMENT 5th failure status={} body={} (rateLimitAttempts=5)",
                crossing.getResponse().getStatus(), crossing.getResponse().getContentAsString());
        assertEquals(429, crossing.getResponse().getStatus());
        assertTrue(crossing.getResponse().getContentAsString().contains("RATE_LIMITED"));

        MvcResult blocked = loginAttempt("carol", "carol123");
        assertEquals(429, blocked.getResponse().getStatus());
        assertTrue(blocked.getResponse().getContentAsString().contains("RATE_LIMITED"));

        clock.advanceMillis(501);
        // Rate-limit block elapsed, but the window still holds 5 failures -> next failure
        // starts a fresh decision; correct password now succeeds because lock never engaged.
        MvcResult ok = loginAttempt("carol", "carol123");
        testLog.info("JUDGEMENT after rate-limit block elapsed status={}", ok.getResponse().getStatus());
        assertEquals(200, ok.getResponse().getStatus());
    }

    @Test
    void adminUnlockClearsFailureStateImmediately() throws Exception {
        adminConfig(Map.of(
                "lockThreshold", 2,
                "lockMillis", 100000L,
                "rateLimitAttempts", 100,
                "rateLimitWindowMillis", 60000L,
                "rateLimitBlockMillis", 500L));
        badLogin("bob");
        badLogin("bob");

        SessionTokens admin = login("admin", "admin123");
        mockMvc.perform(post("/api/admin/users/bob/unlock")
                        .cookie(new jakarta.servlet.http.Cookie("SID", admin.sid()))
                        .header("X-CSRF-TOKEN", admin.csrf()))
                .andExpect(r -> assertEquals(200, r.getResponse().getStatus()));

        MvcResult ok = loginAttempt("bob", "bob123");
        testLog.info("JUDGEMENT post-unlock login status={}", ok.getResponse().getStatus());
        assertEquals(200, ok.getResponse().getStatus());
    }

    private MvcResult badLogin(String username) throws Exception {
        return loginAttempt(username, "wrong-password");
    }

    private MvcResult loginAttempt(String username, String password) throws Exception {
        String body = objectMapper.writeValueAsString(Map.of("username", username, "password", password));
        MvcResult result = mockMvc.perform(post("/api/auth/login")
                .contentType("application/json").content(body)).andReturn();
        testLog.info("INPUT login user={} correct={} -> status={}",
                username, !"wrong-password".equals(password), result.getResponse().getStatus());
        return result;
    }

    private void adminConfig(Map<String, Object> changes) throws Exception {
        SessionTokens admin = login("admin", "admin123");
        mockMvc.perform(post("/api/admin/config")
                        .cookie(new jakarta.servlet.http.Cookie("SID", admin.sid()))
                        .header("X-CSRF-TOKEN", admin.csrf())
                        .contentType("application/json")
                        .content(objectMapper.writeValueAsString(changes)))
                .andExpect(r -> assertEquals(200, r.getResponse().getStatus(),
                        r.getResponse().getContentAsString()));
    }
}
