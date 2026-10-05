package com.github.xingjianluo.sessionauthjava.tests.auth;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
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

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.options;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * 运行期策略切换与历史判定回放：
 * 新请求立即按新策略判定；每条判定记录所依据的策略版本；
 * 历史判定放回当时版本重放，结论与当时一致；反复切换占用有界。
 * 本类会修改共享策略，使用独立 Spring 上下文避免影响其他测试。
 */
@SpringBootTest
@AutoConfigureMockMvc
@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_CLASS)
class PolicySwitchTest {

    private static final Logger log = LoggerFactory.getLogger(PolicySwitchTest.class);

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

    private JsonNode login(String username, String password) throws Exception {
        MvcResult result = mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"" + username + "\",\"password\":\"" + password + "\"}"))
                .andExpect(status().isOk())
                .andReturn();
        return om.readTree(result.getResponse().getContentAsString());
    }

    @Test
    void sessionLimitChangeTakesEffectImmediately() throws Exception {
        String u = "policy-user-1";
        userStore.save(new com.github.xingjianluo.sessionauthjava.auth.model.UserAccount(
                u, "pass", com.github.xingjianluo.sessionauthjava.auth.model.Role.USER, java.util.Set.of()));
        policyService.update(p -> p.setMaxConcurrentSessions(2));
        sessionService.revokeAllForUser(u);

        // 上限 2：前两次登录成功，第三次 409
        login(u, "pass");
        login(u, "pass");
        mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"" + u + "\",\"password\":\"pass\"}"))
                .andExpect(status().isConflict());

        // 运行期放宽到 3：同样的请求立即放行
        long v = policyService.update(p -> p.setMaxConcurrentSessions(3)).version();
        MvcResult third = mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"" + u + "\",\"password\":\"pass\"}"))
                .andExpect(status().isOk())
                .andReturn();
        log.info("[test] business=session limit switch, input=3rd login under policy v{} (limit=3)"
                + " -> {} (basis: new limit effective immediately)", v, third.getResponse().getStatus());

        // 运行期收紧到 1：新登录立即被拒
        long v2 = policyService.update(p -> p.setMaxConcurrentSessions(1)).version();
        mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"" + u + "\",\"password\":\"pass\"}"))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.reason").value("CONCURRENT_SESSION_LIMIT_EXCEEDED"));
        log.info("[test] business=session limit tighten, input=new login under policy v{} (limit=1)"
                + " -> 409 (basis: tightened limit effective immediately)", v2);

        policyService.update(p -> p.setMaxConcurrentSessions(2)); // 还原
    }

    @Test
    void csrfToggleTakesEffectImmediatelyOnNextRequest() throws Exception {
        JsonNode login = login("bob", "bob-pass");
        String sessionId = login.get("sessionId").asText();

        // 策略开启时：无令牌 -> 403
        mockMvc.perform(post("/api/auth/logout").header("X-Session-Id", sessionId))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.reason").value("CSRF_TOKEN_MISMATCH"));

        // 运行期关闭 CSRF：同一会话无令牌 -> 200
        long v = policyService.update(p -> p.setCsrfEnabled(false)).version();
        MvcResult off = mockMvc.perform(post("/api/auth/logout").header("X-Session-Id", sessionId))
                .andExpect(status().isOk())
                .andReturn();
        log.info("[test] business=csrf toggle off, input=POST logout without token under policy v{}"
                        + " -> {} (basis: csrfEnabled=false in new policy)", v, off.getResponse().getStatus());

        // 运行期重新开启：无令牌 -> 403
        JsonNode relogin = login("bob", "bob-pass");
        String session2 = relogin.get("sessionId").asText();
        long v2 = policyService.update(p -> p.setCsrfEnabled(true)).version();
        mockMvc.perform(post("/api/auth/logout").header("X-Session-Id", session2))
                .andExpect(status().isForbidden());
        log.info("[test] business=csrf toggle on, input=POST logout without token under policy v{}"
                + " -> 403 (basis: csrfEnabled=true restored)", v2);
    }

    @Test
    void publicPathsChangeTakesEffectImmediately() throws Exception {
        // 默认配置下 /api/open/** 不是公开路径 -> 401
        mockMvc.perform(get("/api/open/anything")).andExpect(status().isUnauthorized());

        long v = policyService.update(p -> p.setPublicPaths(
                List.of("/api/public/**", "/api/auth/login", "/api/open/**"))).version();
        // 新策略下不再被认证拦截（无控制器 -> 404 而非 401）
        MvcResult result = mockMvc.perform(get("/api/open/anything"))
                .andExpect(status().isNotFound())
                .andReturn();
        log.info("[test] business=publicPaths switch, input=GET /api/open/anything under policy v{}"
                + " -> {} (basis: /api/open/** added to publicPaths)", v, result.getResponse().getStatus());
    }

    @Test
    void allowedOriginsChangeTakesEffectImmediately() throws Exception {
        String newOrigin = "http://new-frontend.example.com";
        // 默认仅允许 http://localhost:3000
        mockMvc.perform(options("/api/user/profile")
                        .header("Origin", newOrigin)
                        .header("Access-Control-Request-Method", "GET"))
                .andExpect(header().doesNotExist("Access-Control-Allow-Origin"));

        long v = policyService.update(p -> p.setAllowedOrigins(
                List.of("http://localhost:3000", newOrigin))).version();
        MvcResult result = mockMvc.perform(options("/api/user/profile")
                        .header("Origin", newOrigin)
                        .header("Access-Control-Request-Method", "GET"))
                .andExpect(status().isOk())
                .andExpect(header().string("Access-Control-Allow-Origin", newOrigin))
                .andReturn();
        log.info("[test] business=allowedOrigins switch, input=preflight origin={} under policy v{}"
                        + " -> {} allowOrigin={} (basis: origin added to allowedOrigins)",
                newOrigin, v, result.getResponse().getStatus(),
                result.getResponse().getHeader("Access-Control-Allow-Origin"));
    }

    @Test
    void historicalDecisionReplaysAgainstItsOwnPolicyVersion() throws Exception {
        // v1：上限 2。alice 登录两次后第三次被拒，产生一条 DENIED 的 SESSION_LIMIT 判定
        policyService.update(p -> p.setMaxConcurrentSessions(2));
        sessionService.revokeAllForUser("alice");
        login("alice", "alice-pass");
        login("alice", "alice-pass");
        mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"alice\",\"password\":\"alice-pass\"}"))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.reason").value("CONCURRENT_SESSION_LIMIT_EXCEEDED"));
        DecisionRecord denied = decisionLog.latestOfKind(DecisionLog.KIND_SESSION_LIMIT).orElseThrow();
        assertEquals("DENIED", denied.outcome());
        long deniedVersion = denied.policyVersion();
        log.info("[test] business=record decision, input=3rd login with limit=2 -> decisionId={}"
                        + " policyVersion={} outcome={} inputs={}",
                denied.id(), deniedVersion, denied.outcome(), denied.inputs());

        // 切换策略：上限调到 5。同样的活跃数（2）在新策略下应放行
        policyService.update(p -> p.setMaxConcurrentSessions(5));
        JsonNode third = login("alice", "alice-pass");
        DecisionRecord allowed = decisionLog.latestOfKind(DecisionLog.KIND_SESSION_LIMIT).orElseThrow();
        assertEquals("ALLOWED", allowed.outcome());
        assertTrue(allowed.policyVersion() > deniedVersion);
        log.info("[test] business=policy switched, input=3rd login with limit=5 -> decisionId={}"
                        + " policyVersion={} outcome={} (new requests use new policy)",
                allowed.id(), allowed.policyVersion(), allowed.outcome());

        // 回放历史判定：必须仍按 v1 得出 DENIED，不受最新策略影响
        Optional<String> replayed = decisionLog.replay(denied.id());
        assertEquals(Optional.of("DENIED"), replayed);
        log.info("[test] business=replay, input=replay decisionId={} -> outcome={} (basis: replayed under"
                        + " policy v{}, identical to original)", denied.id(), replayed, deniedVersion);

        // 新判定回放也得到自己的结论
        assertEquals(Optional.of("ALLOWED"), decisionLog.replay(allowed.id()));
    }

    @Test
    void repeatedSwitchingStaysBoundedAndConsistent() throws Exception {
        int switches = 200;
        long baseVersion = policyService.current().version();
        for (int i = 0; i < switches; i++) {
            final int limit = (i % 2 == 0) ? 1 : 2;
            policyService.update(p -> p.setMaxConcurrentSessions(limit));
        }
        // 版本号单调递增
        assertEquals(baseVersion + switches, policyService.current().version());
        // 历史版本有界：不会随切换次数无限增长
        assertTrue(policyService.historySize() <= 64,
                "history must be bounded, actual=" + policyService.historySize());
        log.info("[test] business=bounded history, input={} consecutive switches -> historySize={}"
                        + " currentVersion={} (basis: capacity 64, oldest evicted)",
                switches, policyService.historySize(), policyService.current().version());

        // 最后一次切换 i=199（奇数）-> limit=2：新请求必须按最新策略判定
        String u = "policy-user-bound";
        userStore.save(new com.github.xingjianluo.sessionauthjava.auth.model.UserAccount(
                u, "pass", com.github.xingjianluo.sessionauthjava.auth.model.Role.USER, java.util.Set.of()));
        login(u, "pass");
        login(u, "pass");
        mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"" + u + "\",\"password\":\"pass\"}"))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.reason").value("CONCURRENT_SESSION_LIMIT_EXCEEDED"));
        DecisionRecord latest = decisionLog.latestOfKind(DecisionLog.KIND_SESSION_LIMIT).orElseThrow();
        assertEquals(policyService.current().version(), latest.policyVersion());
        log.info("[test] business=latest policy wins, input=3rd login after {} switches -> 409,"
                        + " decision used policyVersion={} (== current)",
                switches, latest.policyVersion());

        // 判定日志同样有界
        assertTrue(decisionLog.size() <= 1000,
                "decision log must be bounded, actual=" + decisionLog.size());
        log.info("[test] business=bounded decision log, decisionLogSize={} (basis: capacity 1000,"
                + " oldest evicted)", decisionLog.size());

        policyService.update(p -> p.setMaxConcurrentSessions(2)); // 还原
    }
}
