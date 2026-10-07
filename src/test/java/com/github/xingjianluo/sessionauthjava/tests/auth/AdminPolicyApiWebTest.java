package com.github.xingjianluo.sessionauthjava.tests.auth;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.xingjianluo.sessionauthjava.auth.model.Role;
import com.github.xingjianluo.sessionauthjava.auth.model.UserAccount;
import com.github.xingjianluo.sessionauthjava.auth.policy.DecisionLog;
import com.github.xingjianluo.sessionauthjava.auth.policy.DecisionRecord;
import com.github.xingjianluo.sessionauthjava.auth.policy.PolicyService;
import com.github.xingjianluo.sessionauthjava.auth.service.SessionService;
import com.github.xingjianluo.sessionauthjava.auth.service.UserStore;
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

import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * 运行期策略运维入口（HTTP，服务已启动即可操作，无需进入测试/调试器）：
 * 查看/切换策略、切换后新请求立即生效、查看判定记录、按编号按当时版本回放、
 * 强制失效、鉴权与 CSRF、非法参数、反复切换有界。
 * 会修改共享策略，使用独立 Spring 上下文。
 */
@SpringBootTest
@AutoConfigureMockMvc
@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_CLASS)
class AdminPolicyApiWebTest {

    private static final Logger log = LoggerFactory.getLogger(AdminPolicyApiWebTest.class);

    @Autowired
    private MockMvc mockMvc;
    @Autowired
    private PolicyService policyService;
    @Autowired
    private DecisionLog decisionLog;
    @Autowired
    private SessionService sessionService;
    @Autowired
    private UserStore userStore;

    private final ObjectMapper om = new ObjectMapper();

    /** 以管理员 alice 登录并返回 {sessionId, csrfToken} */
    private JsonNode adminLogin() throws Exception {
        sessionService.revokeAllForUser("alice");
        MvcResult result = mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"alice\",\"password\":\"alice-pass\"}"))
                .andExpect(status().isOk())
                .andReturn();
        return om.readTree(result.getResponse().getContentAsString());
    }

    private JsonNode userLogin(String username) throws Exception {
        userStore.save(new UserAccount(username, "pass", Role.USER, Set.of()));
        sessionService.revokeAllForUser(username);
        MvcResult result = mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"" + username + "\",\"password\":\"pass\"}"))
                .andExpect(status().isOk())
                .andReturn();
        return om.readTree(result.getResponse().getContentAsString());
    }

    private MvcResult publishPolicy(String sessionId, String csrf, String json) throws Exception {
        return mockMvc.perform(post("/api/admin/policy")
                        .header("X-Session-Id", sessionId)
                        .header("X-CSRF-Token", csrf)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json))
                .andReturn();
    }

    @Test
    void adminEndpointsRequireAuthentication() throws Exception {
        MvcResult result = mockMvc.perform(get("/api/admin/policy"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.reason").value("SESSION_NOT_FOUND"))
                .andReturn();
        log.info("[test] business=admin auth, input=GET /api/admin/policy without session -> 401 body={}"
                + " (basis: non-public path goes through AuthFilter)", result.getResponse().getContentAsString());
    }

    @Test
    void nonAdminUserIsForbidden() throws Exception {
        JsonNode bob = userLogin("api-user-bob");
        MvcResult result = mockMvc.perform(get("/api/admin/policy")
                        .header("X-Session-Id", bob.get("sessionId").asText()))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.reason").value("ROLE_INSUFFICIENT"))
                .andReturn();
        log.info("[test] business=admin authorization, input=USER role GET /api/admin/policy -> 403 body={}"
                + " (basis: AccessControlService requires ADMIN using current role)",
                result.getResponse().getContentAsString());
    }

    @Test
    void policyMutationRequiresCsrfToken() throws Exception {
        JsonNode alice = adminLogin();
        MvcResult result = publishPolicy(alice.get("sessionId").asText(), "",
                "{\"maxConcurrentSessions\":1}");
        assertEquals(403, result.getResponse().getStatus());
        log.info("[test] business=admin csrf, input=POST /api/admin/policy without CSRF -> {} body={}"
                        + " (basis: mutating request still passes CsrfFilter)",
                result.getResponse().getStatus(), result.getResponse().getContentAsString());
    }

    @Test
    void currentAndVersionHistoryAreReadable() throws Exception {
        JsonNode alice = adminLogin();
        long before = policyService.current().version();
        MvcResult current = mockMvc.perform(get("/api/admin/policy")
                        .header("X-Session-Id", alice.get("sessionId").asText()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.version").value((int) before))
                .andExpect(jsonPath("$.maxConcurrentSessions").value(2))
                .andReturn();
        log.info("[test] business=read current policy, input=GET /api/admin/policy -> body={}"
                        + " (basis: current immutable snapshot)",
                current.getResponse().getContentAsString());

        MvcResult versions = mockMvc.perform(get("/api/admin/policy/versions")
                        .header("X-Session-Id", alice.get("sessionId").asText()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.currentVersion").value((int) before))
                .andReturn();
        log.info("[test] business=read version history, input=GET /api/admin/policy/versions -> body={}",
                versions.getResponse().getContentAsString());
    }

    @Test
    void policyPublishedAtRuntimeTakesEffectImmediately() throws Exception {
        JsonNode alice = adminLogin();
        String sid = alice.get("sessionId").asText();
        String csrf = alice.get("csrfToken").asText();

        String user = "api-live-switch";
        userStore.save(new UserAccount(user, "pass", Role.USER, Set.of()));
        sessionService.revokeAllForUser(user);

        // 发布新版本：并发上限 1（部分更新，其它字段沿用当前策略）
        long from = policyService.current().version();
        MvcResult published = publishPolicy(sid, csrf, "{\"maxConcurrentSessions\":1}");
        JsonNode body = om.readTree(published.getResponse().getContentAsString());
        assertEquals(200, published.getResponse().getStatus());
        assertEquals(from + 1, body.get("version").asLong());
        assertEquals(1, body.get("maxConcurrentSessions").asInt());
        log.info("[test] business=publish policy at runtime, input=POST policy {{maxConcurrentSessions:1}}"
                + " -> v{} body={} (basis: atomic snapshot switch)", body.get("version").asLong(),
                published.getResponse().getContentAsString());

        // 新请求立即按新策略：第一次登录成功，第二次 409（直接登录，不走会撤销存量的 helper）
        mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"" + user + "\",\"password\":\"pass\"}"))
                .andExpect(status().isOk());
        mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"" + user + "\",\"password\":\"pass\"}"))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.reason").value("CONCURRENT_SESSION_LIMIT_EXCEEDED"));
        log.info("[test] business=new requests use new policy, input=2nd login under limit=1 -> 409"
                + " (basis: SessionService reads latest snapshot)");

        // 再放宽到 3：同样的登录立即成功，且依据版本是最新版
        MvcResult relaxed = publishPolicy(sid, csrf, "{\"maxConcurrentSessions\":3}");
        long v3 = om.readTree(relaxed.getResponse().getContentAsString()).get("version").asLong();
        mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"" + user + "\",\"password\":\"pass\"}"))
                .andExpect(status().isOk());
        DecisionRecord latest = decisionLog.latestOfKind(DecisionLog.KIND_SESSION_LIMIT).orElseThrow();
        assertEquals(v3, latest.policyVersion());
        assertEquals("ALLOWED", latest.outcome());
        log.info("[test] business=relax then immediate allow, input=login under limit=3 -> 200"
                + " decisionId={} policyVersion={} (== latest)", latest.id(), latest.policyVersion());

        publishPolicy(sid, csrf, "{\"maxConcurrentSessions\":2}"); // 还原
    }

    @Test
    void invalidPolicyUpdateIsRejectedWithoutPublishing() throws Exception {
        JsonNode alice = adminLogin();
        long before = policyService.current().version();
        MvcResult result = publishPolicy(alice.get("sessionId").asText(),
                alice.get("csrfToken").asText(), "{\"maxConcurrentSessions\":0}");
        assertEquals(400, result.getResponse().getStatus());
        JsonNode body = om.readTree(result.getResponse().getContentAsString());
        assertEquals("INVALID_POLICY_UPDATE", body.get("reason").asText());
        assertEquals(before, policyService.current().version(), "非法更新不得发布新版本");
        log.info("[test] business=invalid update rejected, input=maxConcurrentSessions=0 -> 400 body={}"
                + " (basis: validated before publish, version unchanged v{})",
                result.getResponse().getContentAsString(), before);
    }

    @Test
    void decisionsAreListableFilterableAndFetchableById() throws Exception {
        JsonNode alice = adminLogin();
        String sid = alice.get("sessionId").asText();
        // 制造一条 CORS 预检判定
        mockMvc.perform(org.springframework.test.web.servlet.request.MockMvcRequestBuilders
                        .options("/api/user/profile")
                        .header("Origin", "http://localhost:3000")
                        .header("Access-Control-Request-Method", "GET"))
                .andExpect(status().isOk());

        MvcResult list = mockMvc.perform(get("/api/admin/decisions")
                        .header("X-Session-Id", sid)
                        .param("kind", DecisionLog.KIND_CORS_ORIGIN))
                .andExpect(status().isOk())
                .andReturn();
        JsonNode body = om.readTree(list.getResponse().getContentAsString());
        assertTrue(body.get("count").asInt() >= 1);
        long id = body.get("decisions").get(0).get("id").asLong();
        log.info("[test] business=list decisions, input=kind=CORS_ORIGIN -> count={} firstId={}"
                + " (basis: retained decision records with inputs/policyVersion)",
                body.get("count").asInt(), id);

        mockMvc.perform(get("/api/admin/decisions/" + id).header("X-Session-Id", sid))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.id").value((int) id))
                .andExpect(jsonPath("$.kind").value("CORS_ORIGIN"))
                .andExpect(jsonPath("$.policyVersion").exists())
                .andExpect(jsonPath("$.inputs.origin").value("http://localhost:3000"));

        MvcResult missing = mockMvc.perform(get("/api/admin/decisions/999999999").header("X-Session-Id", sid))
                .andExpect(status().isNotFound())
                .andReturn();
        log.info("[test] business=fetch unknown decision, input=GET decisions/999999999 -> 404 body={}",
                missing.getResponse().getContentAsString());
    }

    @Test
    void replayByNumberUsesDecisionOwnPolicyVersion() throws Exception {
        JsonNode alice = adminLogin();
        String sid = alice.get("sessionId").asText();
        String csrf = alice.get("csrfToken").asText();

        String user = "api-replay";
        userStore.save(new UserAccount(user, "pass", Role.USER, Set.of()));
        sessionService.revokeAllForUser(user);

        // 在上限 2 下制造一条 DENIED 的 SESSION_LIMIT 判定
        publishPolicy(sid, csrf, "{\"maxConcurrentSessions\":2}");
        sessionService.revokeAllForUser(user);
        mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"" + user + "\",\"password\":\"pass\"}"))
                .andExpect(status().isOk());
        mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"" + user + "\",\"password\":\"pass\"}"))
                .andExpect(status().isOk());
        mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"" + user + "\",\"password\":\"pass\"}"))
                .andExpect(status().isConflict());
        DecisionRecord denied = decisionLog.latestOfKind(DecisionLog.KIND_SESSION_LIMIT).orElseThrow();
        assertEquals("DENIED", denied.outcome());
        long deniedVersion = denied.policyVersion();

        // 运行期放宽到 5：新判定 ALLOWED 且依据新版本
        MvcResult relaxed = publishPolicy(sid, csrf, "{\"maxConcurrentSessions\":5}");
        long latestVersion = om.readTree(relaxed.getResponse().getContentAsString()).get("version").asLong();
        assertNotEquals(deniedVersion, latestVersion);

        // 按编号回放历史判定：必须按它当时那版重算 -> 仍 DENIED，与当时一致，不受当前策略影响
        MvcResult replay = mockMvc.perform(post("/api/admin/decisions/" + denied.id() + "/replay")
                        .header("X-Session-Id", sid)
                        .header("X-CSRF-Token", csrf))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.replayedOutcome").value("DENIED"))
                .andExpect(jsonPath("$.originalOutcome").value("DENIED"))
                .andExpect(jsonPath("$.matchesOriginal").value(true))
                .andExpect(jsonPath("$.policyVersion").value((int) deniedVersion))
                .andReturn();
        JsonNode replayBody = om.readTree(replay.getResponse().getContentAsString());
        assertEquals(latestVersion, replayBody.get("currentVersion").asLong(),
                "回放时当前策略已是新版本，但结论仍取自历史版本");
        log.info("[test] business=replay by number, input=replay decisionId={} under current v{} -> {}"
                + " (basis: replayed with its own policyVersion={}, identical to original)",
                denied.id(), latestVersion, replayBody.get("replayedOutcome").asText(), deniedVersion);

        publishPolicy(sid, csrf, "{\"maxConcurrentSessions\":2}"); // 还原
    }

    @Test
    void replayOfDecisionWhosePolicyVersionWasEvictedReturnsGone() throws Exception {
        JsonNode alice = adminLogin();
        String sid = alice.get("sessionId").asText();
        String csrf = alice.get("csrfToken").asText();

        // 用另一个普通用户制造"上限 2、第三次被拒"的判定，避免发布用的管理员会话
        // 受会话上限切换影响（发布者必须在整轮切换中始终有效）。
        String victim = "api-evicted-victim";
        userStore.save(new UserAccount(victim, "pass", Role.USER, Set.of()));
        publishPolicy(sid, csrf, "{\"maxConcurrentSessions\":2}");
        sessionService.revokeAllForUser(victim);
        mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"" + victim + "\",\"password\":\"pass\"}"))
                .andExpect(status().isOk());
        mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"" + victim + "\",\"password\":\"pass\"}"))
                .andExpect(status().isOk());
        mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"" + victim + "\",\"password\":\"pass\"}"))
                .andExpect(status().isConflict());
        DecisionRecord v1Decision = decisionLog.latestOfKind(DecisionLog.KIND_SESSION_LIMIT).orElseThrow();
        long decisionId = v1Decision.id();
        long deniedVersion = v1Decision.policyVersion();

        // 用运维入口持续发布新版本，直到该判定依据的版本被淘汰出 64 版历史窗口。
        // 版本号是进程内全局单调递增的（其它用例也会发布），故不写死次数，直接轮询。
        int switchesNeeded = 0;
        while (policyService.version(deniedVersion).isPresent() && switchesNeeded < 1000) {
            int limit = (switchesNeeded % 2 == 0) ? 1 : 2;
            publishPolicy(sid, csrf, "{\"maxConcurrentSessions\":" + limit + "}");
            switchesNeeded++;
        }
        assertTrue(policyService.historySize() <= 64);
        assertTrue(policyService.version(deniedVersion).isEmpty(),
                "被回放判定依据的 v" + deniedVersion + " 应已被淘汰");

        MvcResult gone = mockMvc.perform(post("/api/admin/decisions/" + decisionId + "/replay")
                        .header("X-Session-Id", sid)
                        .header("X-CSRF-Token", csrf))
                .andExpect(status().isGone())
                .andExpect(jsonPath("$.reason").value("POLICY_VERSION_EVICTED"))
                .andReturn();
        log.info("[test] business=replay evicted version, input=replay v{} decisionId={} after {} switches"
                + " -> 410 body={} (basis: record retained but its policy snapshot evicted,"
                + " never falls back to newest policy)", deniedVersion, decisionId, switchesNeeded,
                gone.getResponse().getContentAsString());

        publishPolicy(sid, csrf, "{\"maxConcurrentSessions\":2}"); // 还原
    }

    @Test
    void revokeEndpointForceInvalidatesAndReasonIsStable() throws Exception {
        JsonNode admin = adminLogin();
        String sid = admin.get("sessionId").asText();
        String csrf = admin.get("csrfToken").asText();

        JsonNode victim = userLogin("api-revoke-victim");
        String victimSid = victim.get("sessionId").asText();
        mockMvc.perform(get("/api/user/profile").header("X-Session-Id", victimSid))
                .andExpect(status().isOk());

        MvcResult revoked = mockMvc.perform(post("/api/admin/sessions/revoke")
                        .header("X-Session-Id", sid).header("X-CSRF-Token", csrf)
                        .param("username", "api-revoke-victim"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.revokedOrUpgraded").value(1))
                .andReturn();
        log.info("[test] business=force revoke via runtime endpoint, input=POST revoke?username=..."
                + " -> body={}", revoked.getResponse().getContentAsString());

        for (int i = 0; i < 3; i++) {
            mockMvc.perform(get("/api/user/profile").header("X-Session-Id", victimSid))
                    .andExpect(status().isUnauthorized())
                    .andExpect(jsonPath("$.reason").value("SESSION_REVOKED"));
        }
        log.info("[test] business=post-revoke stable reason, input=3x GET profile with revoked session"
                + " -> SESSION_REVOKED every time");
    }

    @Test
    void repeatedRuntimeSwitchingStaysBoundedAndReplayStaysCorrect() throws Exception {
        JsonNode alice = adminLogin();
        String sid = alice.get("sessionId").asText();
        String csrf = alice.get("csrfToken").asText();

        // 先在 limit=2 策略下留一条锚点判定：取一个干净用户制造一次被拒登录
        String anchorUser = "api-anchor";
        userStore.save(new UserAccount(anchorUser, "pass", Role.USER, Set.of()));
        sessionService.revokeAllForUser(anchorUser);
        publishPolicy(sid, csrf, "{\"maxConcurrentSessions\":2}");
        mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"" + anchorUser + "\",\"password\":\"pass\"}"))
                .andExpect(status().isOk());
        mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"" + anchorUser + "\",\"password\":\"pass\"}"))
                .andExpect(status().isOk());
        mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"" + anchorUser + "\",\"password\":\"pass\"}"))
                .andExpect(status().isConflict());
        DecisionRecord anchor = decisionLog.latestOfKind(DecisionLog.KIND_SESSION_LIMIT).orElseThrow();
        assertEquals("DENIED", anchor.outcome());
        long anchorVersion = anchor.policyVersion();

        long versionBeforeChurn = policyService.current().version();
        for (int i = 0; i < 130; i++) {
            publishPolicy(sid, csrf, "{\"maxConcurrentSessions\":" + ((i % 2 == 0) ? 1 : 2) + "}");
        }
        assertEquals(versionBeforeChurn + 130, policyService.current().version(),
                "版本号必须单调递增，每次发布恰好 +1");
        MvcResult versions = mockMvc.perform(get("/api/admin/policy/versions").header("X-Session-Id", sid))
                .andExpect(status().isOk())
                .andReturn();
        int retained = om.readTree(versions.getResponse().getContentAsString())
                .get("retainedCount").asInt();
        assertTrue(retained <= 64, "版本历史必须有界，实际=" + retained);

        // 新请求始终依据最新策略，不会用到旧策略：再发一次登录，其判定版本必须等于当前版本
        String fresh = "api-fresh";
        userStore.save(new UserAccount(fresh, "pass", Role.USER, Set.of()));
        mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"" + fresh + "\",\"password\":\"pass\"}"))
                .andExpect(status().isOk());
        long currentVersion = policyService.current().version();
        DecisionRecord newest = decisionLog.latestOfKind(DecisionLog.KIND_SESSION_LIMIT).orElseThrow();
        assertEquals(currentVersion, newest.policyVersion());
        log.info("[test] business=bounded runtime switching, input=130 switches -> retained={} current=v{}"
                + " newest decision policyVersion={} (basis: newest policy wins, history capped at 64)",
                retained, currentVersion, newest.policyVersion());

        // 锚点判定若其版本仍保留，回放结论必须与当时一致（DENIED）；若已被淘汰则明确 410，
        // 绝不串到最新策略
        MvcResult replay = mockMvc.perform(post("/api/admin/decisions/" + anchor.id() + "/replay")
                        .header("X-Session-Id", sid).header("X-CSRF-Token", csrf))
                .andReturn();
        int status = replay.getResponse().getStatus();
        JsonNode replayBody = om.readTree(replay.getResponse().getContentAsString());
        assertTrue(status == 200 || status == 410);
        if (status == 200) {
            assertEquals(anchor.outcome(), replayBody.get("replayedOutcome").asText());
            assertEquals(anchorVersion, replayBody.get("policyVersion").asLong());
        } else {
            assertEquals("POLICY_VERSION_EVICTED", replayBody.get("reason").asText());
        }
        log.info("[test] business=replay isolation after churn, input=replay anchor v{} decisionId={} -> {}"
                + " (200: DENIED under its own version; 410: its version evicted)",
                anchorVersion, anchor.id(), replay.getResponse().getContentAsString());

        publishPolicy(sid, csrf, "{\"maxConcurrentSessions\":2}"); // 还原
    }
}
