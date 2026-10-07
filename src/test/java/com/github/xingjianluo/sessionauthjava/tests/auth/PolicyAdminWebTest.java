package com.github.xingjianluo.sessionauthjava.tests.auth;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.xingjianluo.sessionauthjava.auth.policy.DecisionLog;
import com.github.xingjianluo.sessionauthjava.auth.policy.DecisionRecord;
import com.github.xingjianluo.sessionauthjava.auth.policy.PolicyService;
import com.github.xingjianluo.sessionauthjava.auth.service.SessionService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * 运维 HTTP 入口（本地已启动的服务上直接操作）：
 * 查看/修改策略、列出与按编号回放判定。验证：
 * <ul>
 *   <li>POST /api/admin/policy 发布新版本后，下一个业务请求立即按新版本判定；</li>
 *   <li>每条判定带 policyVersion；POST .../replay 按当时版本重算，与当时一致；</li>
 *   <li>反复切换后新请求不串旧策略、回放不串最新策略；</li>
 *   <li>仅 ADMIN 可用；变更接口需要 CSRF 令牌；非法修改 400 且不产生新版本。</li>
 * </ul>
 * 会修改共享策略，使用独立 Spring 上下文。
 */
@SpringBootTest
@AutoConfigureMockMvc
@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_CLASS)
class PolicyAdminWebTest {

    private static final Logger log = LoggerFactory.getLogger(PolicyAdminWebTest.class);

    @Autowired
    private MockMvc mockMvc;
    @Autowired
    private PolicyService policyService;
    @Autowired
    private DecisionLog decisionLog;
    @Autowired
    private SessionService sessionService;

    private final ObjectMapper om = new ObjectMapper();

    /** 每个用例前：收敛到已知基线（上限 2、开启 CSRF、清空 alice 残留会话）。 */
    @BeforeEach
    void resetBaseline() {
        policyService.update(p -> {
            p.setMaxConcurrentSessions(2);
            p.setCsrfEnabled(true);
        });
        sessionService.revokeAllForUser("alice");
        sessionService.revokeAllForUser("bob");
    }

    private JsonNode loginAdmin() throws Exception {
        MvcResult result = mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"alice\",\"password\":\"alice-pass\"}"))
                .andExpect(status().isOk()).andReturn();
        return om.readTree(result.getResponse().getContentAsString());
    }

    @Test
    void runtimePolicyChangeViaHttpTakesEffectImmediatelyAndDecisionShowsVersion() throws Exception {
        JsonNode admin = loginAdmin();
        String sid = admin.get("sessionId").asText();
        String csrf = admin.get("csrfToken").asText();

        // 1. 查看当前策略版本
        long versionBefore = policyService.current().version();
        MvcResult got = mockMvc.perform(get("/api/admin/policy").header("X-Session-Id", sid))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.version").value((int) versionBefore))
                .andExpect(jsonPath("$.maxConcurrentSessions").value(2))
                .andReturn();
        log.info("[test] business=http get policy, input=GET /api/admin/policy -> {}",
                got.getResponse().getContentAsString());

        // 2. 运行期把并发上限改为 5，返回新版本号
        String body = "{\"maxConcurrentSessions\":5}";
        MvcResult updated = mockMvc.perform(post("/api/admin/policy")
                        .header("X-Session-Id", sid).header("X-CSRF-Token", csrf)
                        .contentType(MediaType.APPLICATION_JSON).content(body))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.version").value((int) (versionBefore + 1)))
                .andExpect(jsonPath("$.previousVersion").value((int) versionBefore))
                .andExpect(jsonPath("$.maxConcurrentSessions").value(5))
                .andReturn();
        log.info("[test] business=http policy switch, input=POST policy {} -> {}",
                body, updated.getResponse().getContentAsString());

        // 3. 新版本立即生效：alice 再登录到第 3 个会话不再 409（原上限 2）
        MvcResult extra = mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"alice\",\"password\":\"alice-pass\"}"))
                .andExpect(status().isOk()).andReturn();
        log.info("[test] business=new policy effective immediately, input=3rd alice login under"
                + " limit=5 -> status={}", extra.getResponse().getStatus());

        // 4. 该判定记录携带新版本号
        DecisionRecord latest = decisionLog.latestOfKind(DecisionLog.KIND_SESSION_LIMIT).orElseThrow();
        assertEquals(versionBefore + 1, latest.policyVersion());
        log.info("[test] business=decision basis visible, decisionId={} policyVersion={} inputs={} -> {}",
                latest.id(), latest.policyVersion(), latest.inputs(), latest.outcome());

    }

    @Test
    void replayByDecisionIdOverHttpUsesThePolicyVersionAtDecisionTime() throws Exception {
        JsonNode admin = loginAdmin();
        String sid = admin.get("sessionId").asText();
        String csrf = admin.get("csrfToken").asText();

        // v1：上限 2，制造一次 DENIED 判定
        loginAdmin();
        mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"alice\",\"password\":\"alice-pass\"}"))
                .andExpect(status().isConflict());
        DecisionRecord denied = decisionLog.latestOfKind(DecisionLog.KIND_SESSION_LIMIT).orElseThrow();
        assertEquals("DENIED", denied.outcome());
        long oldVersion = denied.policyVersion();

        // 通过 HTTP 把策略切到上限 5
        mockMvc.perform(post("/api/admin/policy")
                        .header("X-Session-Id", sid).header("X-CSRF-Token", csrf)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"maxConcurrentSessions\":5}"))
                .andExpect(status().isOk());
        long newVersion = policyService.current().version();
        assertTrue(newVersion > oldVersion);

        // 新请求按最新策略：第 3 次登录（activeCount=2，limit=5）现在 ALLOWED
        mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"alice\",\"password\":\"alice-pass\"}"))
                .andExpect(status().isOk());
        DecisionRecord allowed = decisionLog.latestOfKind(DecisionLog.KIND_SESSION_LIMIT).orElseThrow();
        assertEquals("ALLOWED", allowed.outcome());
        assertEquals(newVersion, allowed.policyVersion());

        // HTTP 按编号回放旧判定：必须按 oldVersion 重算，结论仍 DENIED 且 matches=true
        MvcResult replay = mockMvc.perform(post("/api/admin/decisions/" + denied.id() + "/replay")
                        .header("X-Session-Id", sid).header("X-CSRF-Token", csrf))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.id").value((int) denied.id()))
                .andExpect(jsonPath("$.policyVersion").value((int) oldVersion))
                .andExpect(jsonPath("$.outcome").value("DENIED"))
                .andExpect(jsonPath("$.replayedOutcome").value("DENIED"))
                .andExpect(jsonPath("$.matches").value(true))
                .andReturn();
        log.info("[test] business=http replay old decision, input=replay id={} -> {} (basis: recomputed"
                + " under policy v{}, current is v{})",
                denied.id(), replay.getResponse().getContentAsString(), oldVersion, newVersion);

        // 服务层回放结论一致（双重确认）
        assertEquals(Optional.of("DENIED"), decisionLog.replay(denied.id()));

        // 列表接口能看到每条判定及其依据版本
        mockMvc.perform(get("/api/admin/decisions").header("X-Session-Id", sid))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.count").isNumber())
                .andExpect(jsonPath("$.retained").isNumber());

        // 不存在/已淘汰编号 -> 404
        mockMvc.perform(post("/api/admin/decisions/999999999/replay")
                        .header("X-Session-Id", sid).header("X-CSRF-Token", csrf))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.reason").value("DECISION_NOT_FOUND"));

    }

    @Test
    void adminEndpointsRequireAdminRoleAndCsrf() throws Exception {
        // bob 是 USER：查看策略 -> 403 ROLE_INSUFFICIENT
        MvcResult bob = mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"bob\",\"password\":\"bob-pass\"}"))
                .andExpect(status().isOk()).andReturn();
        JsonNode bobNode = om.readTree(bob.getResponse().getContentAsString());
        String bobSid = bobNode.get("sessionId").asText();
        mockMvc.perform(get("/api/admin/policy").header("X-Session-Id", bobSid))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.reason").value("ROLE_INSUFFICIENT"));
        log.info("[test] business=admin endpoint RBAC, input=bob(USER) GET policy -> 403");

        // 无会话 -> 401 且保持旧标识
        mockMvc.perform(get("/api/admin/policy"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.reason").value("SESSION_NOT_FOUND"));

        // alice(ADMIN) 变更策略但缺少 CSRF 令牌 -> 403 CSRF_TOKEN_MISMATCH，策略版本不变
        JsonNode admin = loginAdmin();
        String sid = admin.get("sessionId").asText();
        long version = policyService.current().version();
        mockMvc.perform(post("/api/admin/policy").header("X-Session-Id", sid)
                        .contentType(MediaType.APPLICATION_JSON).content("{\"csrfEnabled\":false}"))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.reason").value("CSRF_TOKEN_MISMATCH"));
        assertEquals(version, policyService.current().version());
        log.info("[test] business=admin mutation CSRF, input=POST policy without token -> 403,"
                + " version unchanged={}", policyService.current().version());
    }

    @Test
    void invalidPolicyUpdateIsRejectedWith400AndNoNewVersion() throws Exception {
        JsonNode admin = loginAdmin();
        String sid = admin.get("sessionId").asText();
        String csrf = admin.get("csrfToken").asText();
        long version = policyService.current().version();

        mockMvc.perform(post("/api/admin/policy")
                        .header("X-Session-Id", sid).header("X-CSRF-Token", csrf)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"maxConcurrentSessions\":0}"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.reason").value("INVALID_POLICY_UPDATE"));
        assertEquals(version, policyService.current().version());

        mockMvc.perform(post("/api/admin/policy")
                        .header("X-Session-Id", sid).header("X-CSRF-Token", csrf)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"sessionTtl\":\"not-a-duration\"}"))
                .andExpect(status().isBadRequest());
        assertEquals(version, policyService.current().version());
        log.info("[test] business=invalid policy update, input=limit=0 / bad duration -> 400,"
                + " version stays {}", version);
    }
}
