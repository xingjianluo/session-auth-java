package com.github.xingjianluo.sessionauthjava.tests.auth;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.xingjianluo.sessionauthjava.auth.config.AuthSecurityProperties;
import com.github.xingjianluo.sessionauthjava.auth.service.SessionService;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.options;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * 策略运行期调整与历史判定回放的全链路测试：
 * 通过管理端点改策略 -> 新请求按新策略 -> 历史判定按旧版本回放且结论一致。
 */
@SpringBootTest
@AutoConfigureMockMvc
class PolicyReplayWebTest {

    private static final Logger log = LoggerFactory.getLogger(PolicyReplayWebTest.class);

    private static final String ALLOWED_ORIGIN = "http://localhost:3000";
    private static final String NEW_ORIGIN = "http://evil.example";

    @Autowired
    private MockMvc mockMvc;
    @Autowired
    private AuthSecurityProperties properties;
    @Autowired
    private SessionService sessionService;

    private final ObjectMapper om = new ObjectMapper();

    private JsonNode login(String username, String password) throws Exception {
        // 测试隔离：清掉该用户在其他用例中遗留的会话，避免触发并发上限
        sessionService.revokeAllForUser(username);
        MvcResult result = mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"" + username + "\",\"password\":\"" + password + "\"}"))
                .andExpect(status().isOk())
                .andReturn();
        return om.readTree(result.getResponse().getContentAsString());
    }

    @Test
    void policyChangeTakesEffectAndOldDecisionReplaysIdentically() throws Exception {
        JsonNode admin = login("alice", "alice-pass");
        String sessionId = admin.get("sessionId").asText();
        String csrf = admin.get("csrfToken").asText();

        // 1. 当前策略版本
        MvcResult policyBefore = mockMvc.perform(get("/api/admin/policy").header("X-Session-Id", sessionId))
                .andExpect(status().isOk())
                .andReturn();
        long versionBefore = om.readTree(policyBefore.getResponse().getContentAsString()).get("version").asLong();
        log.info("[test] 步骤1 当前策略 version={}", versionBefore);

        // 2. 在旧策略下制造一条 CORS 判定：NEW_ORIGIN 被拒绝
        mockMvc.perform(options("/api/user/profile")
                        .header("Origin", NEW_ORIGIN)
                        .header("Access-Control-Request-Method", "GET"))
                .andExpect(status().isForbidden());

        // 3. 找到这条判定记录
        MvcResult decisions = mockMvc.perform(get("/api/admin/decisions").header("X-Session-Id", sessionId))
                .andExpect(status().isOk())
                .andReturn();
        JsonNode records = om.readTree(decisions.getResponse().getContentAsString()).get("records");
        JsonNode corsRecord = null;
        for (JsonNode record : records) {
            if ("CORS_ORIGIN".equals(record.get("type").asText())
                    && NEW_ORIGIN.equals(record.get("inputs").get("origin").asText())) {
                corsRecord = record;
                break;
            }
        }
        assertTrue(corsRecord != null, "必须能找到刚才的 CORS 判定记录");
        long decisionId = corsRecord.get("id").asLong();
        assertEquals("DENIED", corsRecord.get("outcome").asText());
        assertEquals(versionBefore, corsRecord.get("policyVersion").asLong(), "判定必须标注当时策略版本");
        log.info("[test] 步骤2-3 旧策略下判定 decisionId={} policyVersion={} outcome=DENIED",
                decisionId, versionBefore);

        // 4. 运行期调整策略：允许 NEW_ORIGIN
        List<String> original = properties.getAllowedOrigins();
        try {
            MvcResult updated = mockMvc.perform(post("/api/admin/policy")
                            .header("X-Session-Id", sessionId)
                            .header("X-CSRF-Token", csrf)
                            .contentType(MediaType.APPLICATION_JSON)
                            .content("{\"allowedOrigins\":[\"" + ALLOWED_ORIGIN + "\",\"" + NEW_ORIGIN + "\"]}"))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.version").value(versionBefore + 1))
                    .andReturn();
            long newVersion = om.readTree(updated.getResponse().getContentAsString()).get("version").asLong();
            log.info("[test] 步骤4 策略调整 allowedOrigins+={}, 新版本={}", NEW_ORIGIN, newVersion);

            // 5. 新请求立即按新策略放行
            mockMvc.perform(options("/api/user/profile")
                            .header("Origin", NEW_ORIGIN)
                            .header("Access-Control-Request-Method", "GET"))
                    .andExpect(status().isOk());
            log.info("[test] 步骤5 新策略下同一 Origin 预检 -> 200 (新请求用新策略)");

            // 6. 回放旧判定：必须仍按旧版本得出 DENIED
            MvcResult replay = mockMvc.perform(get("/api/admin/decisions/" + decisionId + "/replay")
                            .header("X-Session-Id", sessionId))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.status").value("REPLAYED"))
                    .andExpect(jsonPath("$.policyVersion").value(versionBefore))
                    .andExpect(jsonPath("$.originalOutcome").value("DENIED"))
                    .andExpect(jsonPath("$.replayedOutcome").value("DENIED"))
                    .andExpect(jsonPath("$.matches").value(true))
                    .andReturn();
            log.info("[test] 步骤6 回放 decisionId={} -> {}", decisionId, replay.getResponse().getContentAsString());
        } finally {
            properties.setAllowedOrigins(original);
        }
    }

    @Test
    void sessionLimitChangeAppliesToNewLoginsImmediately() throws Exception {
        JsonNode admin = login("alice", "alice-pass");
        String sessionId = admin.get("sessionId").asText();
        String csrf = admin.get("csrfToken").asText();
        int originalLimit = properties.getMaxConcurrentSessions();
        try {
            mockMvc.perform(post("/api/admin/policy")
                            .header("X-Session-Id", sessionId)
                            .header("X-CSRF-Token", csrf)
                            .contentType(MediaType.APPLICATION_JSON)
                            .content("{\"maxConcurrentSessions\":1}"))
                    .andExpect(status().isOk());

            // bob 第一个登录成功，第二个立即被新上限拒绝
            login("bob", "bob-pass");
            MvcResult second = mockMvc.perform(post("/api/auth/login")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content("{\"username\":\"bob\",\"password\":\"bob-pass\"}"))
                    .andExpect(status().isConflict())
                    .andExpect(jsonPath("$.reason").value("CONCURRENT_SESSION_LIMIT_EXCEEDED"))
                    .andReturn();
            log.info("[test] 场景=上限调为1后第二次登录 -> {} body={}",
                    second.getResponse().getStatus(), second.getResponse().getContentAsString());
        } finally {
            properties.setMaxConcurrentSessions(originalLimit);
            // 清理 bob 会话，避免影响其他用例
            sessionService.revokeAllForUser("bob");
        }
    }

    @Test
    void nonAdminCannotViewOrChangePolicy() throws Exception {
        JsonNode bob = login("bob", "bob-pass");
        String sessionId = bob.get("sessionId").asText();
        String csrf = bob.get("csrfToken").asText();
        MvcResult get = mockMvc.perform(get("/api/admin/policy").header("X-Session-Id", sessionId))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.reason").value("ROLE_INSUFFICIENT"))
                .andReturn();
        MvcResult post = mockMvc.perform(post("/api/admin/policy")
                        .header("X-Session-Id", sessionId)
                        .header("X-CSRF-Token", csrf)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"maxConcurrentSessions\":9}"))
                .andExpect(status().isForbidden())
                .andReturn();
        log.info("[test] 场景=非管理员访问策略端点, GET -> {} POST -> {}",
                get.getResponse().getStatus(), post.getResponse().getStatus());
    }

    @Test
    void replayOfUnknownDecisionReturns404() throws Exception {
        JsonNode admin = login("alice", "alice-pass");
        String sessionId = admin.get("sessionId").asText();
        MvcResult result = mockMvc.perform(get("/api/admin/decisions/99999999/replay")
                        .header("X-Session-Id", sessionId))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.reason").value("DECISION_NOT_FOUND"))
                .andReturn();
        log.info("[test] 场景=回放不存在的判定 -> {} body={}",
                result.getResponse().getStatus(), result.getResponse().getContentAsString());
    }
}
