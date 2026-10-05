package com.github.xingjianluo.sessionauthjava.tests.auth;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.xingjianluo.sessionauthjava.auth.service.SessionService;
import com.github.xingjianluo.sessionauthjava.auth.service.UserStore;
import com.github.xingjianluo.sessionauthjava.auth.model.Role;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * 全链路集成测试：登录 -> 访问 -> 登出 -> 失效，横切规则（安全头/CSRF/公开路径）组合验证。
 */
@SpringBootTest
@AutoConfigureMockMvc
class AuthFlowWebTest {

    private static final Logger log = LoggerFactory.getLogger(AuthFlowWebTest.class);

    @Autowired
    private MockMvc mockMvc;
    @Autowired
    private SessionService sessionService;
    @Autowired
    private UserStore userStore;

    private final ObjectMapper om = new ObjectMapper();

    private JsonNode login(String username, String password) throws Exception {
        return login(username, password, true);
    }

    private JsonNode login(String username, String password, boolean revokeExisting) throws Exception {
        if (revokeExisting) {
            // 测试隔离：清掉该用户在其他用例中遗留的会话
            sessionService.revokeAllForUser(username);
        }
        MvcResult result = mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"" + username + "\",\"password\":\"" + password + "\"}"))
                .andExpect(status().isOk())
                .andReturn();
        JsonNode body = om.readTree(result.getResponse().getContentAsString());
        log.info("[test] login user={} -> 200, sessionId={}...", username,
                body.get("sessionId").asText().substring(0, 8));
        return body;
    }

    @Test
    void publicPathIsNeverIntercepted() throws Exception {
        MvcResult result = mockMvc.perform(get("/api/public/health"))
                .andExpect(status().isOk())
                .andExpect(header().string("X-Content-Type-Options", "nosniff"))
                .andExpect(header().string("X-Frame-Options", "DENY"))
                .andReturn();
        log.info("[test] input=GET /api/public/health without session -> {} (must not be intercepted)",
                result.getResponse().getStatus());
    }

    @Test
    void protectedPathWithoutSessionIs401WithReason() throws Exception {
        MvcResult result = mockMvc.perform(get("/api/user/profile"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.reason").value("SESSION_UNKNOWN"))
                .andExpect(header().string("X-Content-Type-Options", "nosniff"))
                .andReturn();
        log.info("[test] input=GET /api/user/profile without session -> 401 body={}",
                result.getResponse().getContentAsString());
    }

    @Test
    void loginThenAccessThenLogoutThenRejected() throws Exception {
        JsonNode login = login("bob", "bob-pass");
        String sessionId = login.get("sessionId").asText();

        mockMvc.perform(get("/api/user/profile").header("X-Session-Id", sessionId))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.username").value("bob"));

        String csrf = login.get("csrfToken").asText();
        mockMvc.perform(post("/api/auth/logout")
                        .header("X-Session-Id", sessionId)
                        .header("X-CSRF-Token", csrf))
                .andExpect(status().isOk());

        MvcResult after = mockMvc.perform(get("/api/user/profile").header("X-Session-Id", sessionId))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.reason").value("SESSION_LOGGED_OUT"))
                .andReturn();
        log.info("[test] input=reuse session after logout -> 401 body={}",
                after.getResponse().getContentAsString());
    }

    @Test
    void revokedSessionIsRejectedWithDistinguishableReason() throws Exception {
        JsonNode login = login("alice", "alice-pass");
        String sessionId = login.get("sessionId").asText();
        sessionService.revokeAllForUser("alice");
        MvcResult result = mockMvc.perform(get("/api/user/profile").header("X-Session-Id", sessionId))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.reason").value("SESSION_REVOKED"))
                .andReturn();
        log.info("[test] input=access with revoked session -> 401 body={}",
                result.getResponse().getContentAsString());
    }

    @Test
    void userRoleCannotAccessAdminResource() throws Exception {
        JsonNode login = login("bob", "bob-pass");
        String sessionId = login.get("sessionId").asText();
        MvcResult result = mockMvc.perform(get("/api/admin/stats").header("X-Session-Id", sessionId))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.reason").value("ROLE_INSUFFICIENT"))
                .andReturn();
        log.info("[test] input=bob(USER) -> /api/admin/stats -> 403 body={}",
                result.getResponse().getContentAsString());
    }

    @Test
    void attributeBasedDenialIsDistinguishable() throws Exception {
        JsonNode login = login("bob", "bob-pass"); // bob 只有 dept:ops
        String sessionId = login.get("sessionId").asText();
        MvcResult result = mockMvc.perform(get("/api/user/eng-docs").header("X-Session-Id", sessionId))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.reason").value("ATTRIBUTE_MISSING"))
                .andReturn();
        log.info("[test] input=bob(dept:ops) -> /api/user/eng-docs (needs dept:eng) -> 403 body={}",
                result.getResponse().getContentAsString());
    }

    @Test
    void demotionTakesEffectImmediatelyOnNextRequest() throws Exception {
        JsonNode login = login("alice", "alice-pass");
        String sessionId = login.get("sessionId").asText();
        mockMvc.perform(get("/api/admin/stats").header("X-Session-Id", sessionId))
                .andExpect(status().isOk());

        userStore.updateRole("alice", Role.USER); // 降权
        try {
            MvcResult result = mockMvc.perform(get("/api/admin/stats").header("X-Session-Id", sessionId))
                    .andExpect(status().isForbidden())
                    .andExpect(jsonPath("$.reason").value("ROLE_INSUFFICIENT"))
                    .andReturn();
            log.info("[test] input=alice demoted to USER, reuse live session on /api/admin/stats -> 403 body={}",
                    result.getResponse().getContentAsString());
        } finally {
            userStore.updateRole("alice", Role.ADMIN); // 还原，避免影响其他测试
        }
    }

    @Test
    void stateChangingRequestWithoutCsrfTokenIsRejected() throws Exception {
        JsonNode login = login("bob", "bob-pass");
        String sessionId = login.get("sessionId").asText();
        MvcResult result = mockMvc.perform(post("/api/auth/logout")
                        .header("X-Session-Id", sessionId))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.reason").value("CSRF_TOKEN_MISMATCH"))
                .andReturn();
        log.info("[test] input=POST /api/auth/logout without CSRF token -> 403 body={}",
                result.getResponse().getContentAsString());
        // 会话未被登出，仍可使用
        mockMvc.perform(get("/api/user/profile").header("X-Session-Id", sessionId))
                .andExpect(status().isOk());
    }

    @Test
    void wrongPasswordIs401AndLockKicksIn() throws Exception {
        for (int i = 1; i <= 3; i++) {
            MvcResult r = mockMvc.perform(post("/api/auth/login")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content("{\"username\":\"carol-web\",\"password\":\"bad\"}"))
                    .andExpect(status().isUnauthorized())
                    .andExpect(jsonPath("$.reason").value("INVALID_CREDENTIALS"))
                    .andReturn();
            log.info("[test] input=wrong password attempt #{} -> {}", i, r.getResponse().getContentAsString());
        }
        MvcResult locked = mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"carol-web\",\"password\":\"bad\"}"))
                .andExpect(status().isLocked())
                .andExpect(jsonPath("$.reason").value("ACCOUNT_LOCKED"))
                .andReturn();
        log.info("[test] input=4th attempt after 3 failures -> 423 body={}",
                locked.getResponse().getContentAsString());
    }

    @Test
    void concurrentSessionLimitIsEnforcedOverHttp() throws Exception {
        String u = "dave-web";
        userStore.save(new com.github.xingjianluo.sessionauthjava.auth.model.UserAccount(
                u, "pass", Role.USER, java.util.Set.of()));
        login(u, "pass", false);
        login(u, "pass", false);
        MvcResult third = mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"" + u + "\",\"password\":\"pass\"}"))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.reason").value("CONCURRENT_SESSION_LIMIT_EXCEEDED"))
                .andReturn();
        log.info("[test] input=3rd login with maxConcurrentSessions=2 -> 409 body={}",
                third.getResponse().getContentAsString());
        assertEquals(2, sessionService.activeSessionCount(u));
        assertTrue(sessionService.activeSessionCount(u) <= 2);
    }
}
