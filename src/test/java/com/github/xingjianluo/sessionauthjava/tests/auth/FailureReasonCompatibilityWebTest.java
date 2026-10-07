package com.github.xingjianluo.sessionauthjava.tests.auth;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
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

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * 失效原因标识的兼容性与跨入口一致性（HTTP 层）：
 * <ul>
 *   <li>无会话/无法识别的会话 ID 必须沿用历轮标识 SESSION_NOT_FOUND（旧客户端兼容）；</li>
 *   <li>登出后再访问 -> SESSION_LOGGED_OUT；被强制失效后再访问 -> SESSION_REVOKED，
 *       与 SESSION_NOT_FOUND 并存、互不顶替；</li>
 *   <li>同一未知 ID 重复请求结论固定。</li>
 * </ul>
 */
@SpringBootTest
@AutoConfigureMockMvc
class FailureReasonCompatibilityWebTest {

    private static final Logger log = LoggerFactory.getLogger(FailureReasonCompatibilityWebTest.class);

    @Autowired
    private MockMvc mockMvc;
    @Autowired
    private SessionService sessionService;

    private final ObjectMapper om = new ObjectMapper();

    @Test
    void missingAndUnknownSessionUseLegacyReasonAtAuthEntry() throws Exception {
        // 入口 1：不带会话头（无会话）
        MvcResult noHeader = mockMvc.perform(get("/api/user/profile"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.reason").value("SESSION_NOT_FOUND"))
                .andReturn();
        log.info("[test] business=legacy unknown reason compatibility, input=GET profile without header"
                + " -> 401 body={} (basis: AuthFilter -> SessionService.validate)",
                noHeader.getResponse().getContentAsString());

        // 入口 1：伪造/无法识别的会话 ID
        MvcResult forged = mockMvc.perform(get("/api/user/profile").header("X-Session-Id", "totally-unknown-id"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.reason").value("SESSION_NOT_FOUND"))
                .andReturn();
        log.info("[test] business=legacy unknown reason compatibility, input=GET profile with forged id"
                + " -> 401 body={}", forged.getResponse().getContentAsString());

        // 旧标识不得被本轮新值顶替：登出原因必须是独立的新值
        MvcResult second = mockMvc.perform(get("/api/user/profile").header("X-Session-Id", "totally-unknown-id"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.reason").value("SESSION_NOT_FOUND"))
                .andReturn();
        log.info("[test] business=determinism, input=same forged id again -> body={} (identical input,"
                + " identical reason)", second.getResponse().getContentAsString());
    }

    @Test
    void logoutAndRevokeEntryPointsGiveDistinctNewReasons() throws Exception {
        // 登录 -> 登出 -> 再访问：SESSION_LOGGED_OUT（新值，不顶替旧值）
        MvcResult login = mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"bob\",\"password\":\"bob-pass\"}"))
                .andExpect(status().isOk())
                .andReturn();
        JsonNode session = om.readTree(login.getResponse().getContentAsString());
        String id = session.get("sessionId").asText();
        String csrf = session.get("csrfToken").asText();

        mockMvc.perform(post("/api/auth/logout")
                        .header("X-Session-Id", id).header("X-CSRF-Token", csrf))
                .andExpect(status().isOk());
        MvcResult afterLogout = mockMvc.perform(get("/api/user/profile").header("X-Session-Id", id))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.reason").value("SESSION_LOGGED_OUT"))
                .andReturn();
        log.info("[test] business=logout entry, input=logout then GET profile with same id -> 401 body={}"
                + " (basis: logout tombstone, distinct new reason)", afterLogout.getResponse().getContentAsString());

        // 再登录一个会话 -> 强制失效 -> 再访问：SESSION_REVOKED（新值）
        MvcResult login2 = mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"bob\",\"password\":\"bob-pass\"}"))
                .andExpect(status().isOk())
                .andReturn();
        JsonNode session2 = om.readTree(login2.getResponse().getContentAsString());
        String id2 = session2.get("sessionId").asText();
        sessionService.revokeAllForUser("bob");
        MvcResult afterRevoke = mockMvc.perform(get("/api/user/profile").header("X-Session-Id", id2))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.reason").value("SESSION_REVOKED"))
                .andReturn();
        log.info("[test] business=force-invalidate entry, input=revokeAllForUser(bob) then GET profile"
                + " -> 401 body={} (basis: revoked record, distinct new reason)",
                afterRevoke.getResponse().getContentAsString());
    }
}
