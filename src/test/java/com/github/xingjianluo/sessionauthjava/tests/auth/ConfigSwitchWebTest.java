package com.github.xingjianluo.sessionauthjava.tests.auth;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * 配置切换场景：CSRF 关闭、并发会话上限调为 1、公开路径变更。
 * 验证判定仅依赖当时生效的配置快照，规则变更后结论一致且可复现。
 */
@SpringBootTest
@AutoConfigureMockMvc
@TestPropertySource(properties = {
        "auth.security.csrf-enabled=false",
        "auth.security.max-concurrent-sessions=1",
        "auth.security.public-paths=/api/public/**,/api/auth/login,/api/open/**"
})
class ConfigSwitchWebTest {

    private static final Logger log = LoggerFactory.getLogger(ConfigSwitchWebTest.class);

    @Autowired
    private MockMvc mockMvc;

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
    void csrfDisabledAllowsStateChangingRequestWithoutToken() throws Exception {
        JsonNode login = login("bob", "bob-pass");
        String sessionId = login.get("sessionId").asText();
        MvcResult result = mockMvc.perform(post("/api/auth/logout")
                        .header("X-Session-Id", sessionId))
                .andExpect(status().isOk())
                .andReturn();
        log.info("[test] config csrf-enabled=false, input=POST logout without token -> {}",
                result.getResponse().getStatus());
    }

    @Test
    void sessionLimitOfOneRejectsSecondLogin() throws Exception {
        login("alice", "alice-pass");
        MvcResult second = mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"alice\",\"password\":\"alice-pass\"}"))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.reason").value("CONCURRENT_SESSION_LIMIT_EXCEEDED"))
                .andReturn();
        log.info("[test] config max-concurrent-sessions=1, input=2nd login -> 409 body={}",
                second.getResponse().getContentAsString());
    }

    @Test
    void newlyAddedPublicPathIsNotIntercepted() throws Exception {
        // /api/open/** 在本配置中为公开路径；该路径无控制器，期望 404 而非 401，
        // 以此证明认证过滤器未拦截（401 才表示被误拦截）
        MvcResult result = mockMvc.perform(get("/api/open/anything"))
                .andExpect(status().isNotFound())
                .andReturn();
        log.info("[test] config public-paths+=/api/open/**, input=GET /api/open/anything -> {} (404=未被误拦截)",
                result.getResponse().getStatus());
    }

    @Test
    void protectedPathStillRequiresSessionUnderNewConfig() throws Exception {
        MvcResult result = mockMvc.perform(get("/api/user/profile"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.reason").value("SESSION_UNKNOWN"))
                .andReturn();
        log.info("[test] config switched, input=GET /api/user/profile without session -> 401 body={}",
                result.getResponse().getContentAsString());
    }
}
