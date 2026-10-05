package com.github.xingjianluo.sessionauthjava.tests.auth;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.xingjianluo.sessionauthjava.auth.config.AuthSecurityProperties;
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

import static org.junit.jupiter.api.Assertions.assertNull;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.options;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * 跨域真实调用链路：预检（OPTIONS）+ 带会话的真实请求。
 * 验证允许来源拿到正确跨域响应头、预检不被认证拦截、
 * 不允许来源被拒绝、安全响应头在预检与真实请求上都保留。
 */
@SpringBootTest
@AutoConfigureMockMvc
class CorsWebTest {

    private static final Logger log = LoggerFactory.getLogger(CorsWebTest.class);

    private static final String ALLOWED_ORIGIN = "http://localhost:3000";
    private static final String DENIED_ORIGIN = "http://evil.example";

    @Autowired
    private MockMvc mockMvc;
    @Autowired
    private AuthSecurityProperties properties;

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
    void preflightOnProtectedPathPassesWithCorsAndSecurityHeaders() throws Exception {
        // 业务：浏览器跨域访问受保护资源前先发预检；预检不带会话，不能被认证拦截（401 则浏览器直接失败）
        MvcResult result = mockMvc.perform(options("/api/user/profile")
                        .header("Origin", ALLOWED_ORIGIN)
                        .header("Access-Control-Request-Method", "GET")
                        .header("Access-Control-Request-Headers", "X-Session-Id"))
                .andExpect(status().isOk())
                .andExpect(header().string("Access-Control-Allow-Origin", ALLOWED_ORIGIN))
                .andExpect(header().string("Access-Control-Allow-Methods", org.hamcrest.Matchers.containsString("GET")))
                .andExpect(header().string("Access-Control-Allow-Headers", org.hamcrest.Matchers.containsString("X-Session-Id")))
                .andExpect(header().string("X-Content-Type-Options", "nosniff"))
                .andExpect(header().string("X-Frame-Options", "DENY"))
                .andReturn();
        log.info("[test] 场景=预检放行, input=OPTIONS /api/user/profile Origin={} -> {} allowOrigin={} allowHeaders={}",
                ALLOWED_ORIGIN, result.getResponse().getStatus(),
                result.getResponse().getHeader("Access-Control-Allow-Origin"),
                result.getResponse().getHeader("Access-Control-Allow-Headers"));
    }

    @Test
    void preflightFromDisallowedOriginIsRejected() throws Exception {
        // 业务：不在允许列表里的来源，预检直接拒绝
        MvcResult result = mockMvc.perform(options("/api/user/profile")
                        .header("Origin", DENIED_ORIGIN)
                        .header("Access-Control-Request-Method", "GET"))
                .andExpect(status().isForbidden())
                .andExpect(header().doesNotExist("Access-Control-Allow-Origin"))
                .andExpect(header().string("X-Content-Type-Options", "nosniff"))
                .andReturn();
        log.info("[test] 场景=预检拒绝, input=OPTIONS Origin={} -> {} (无 ACAO 头)",
                DENIED_ORIGIN, result.getResponse().getStatus());
    }

    @Test
    void actualRequestWithSessionAndTokenFlowsAfterPreflight() throws Exception {
        // 业务：预检通过后，真实请求带会话与 CSRF 令牌访问受保护资源
        JsonNode login = login("alice", "alice-pass");
        String sessionId = login.get("sessionId").asText();

        mockMvc.perform(options("/api/user/profile")
                        .header("Origin", ALLOWED_ORIGIN)
                        .header("Access-Control-Request-Method", "GET")
                        .header("Access-Control-Request-Headers", "X-Session-Id"))
                .andExpect(status().isOk());

        MvcResult actual = mockMvc.perform(get("/api/user/profile")
                        .header("Origin", ALLOWED_ORIGIN)
                        .header("X-Session-Id", sessionId))
                .andExpect(status().isOk())
                .andExpect(header().string("Access-Control-Allow-Origin", ALLOWED_ORIGIN))
                .andExpect(header().string("X-Content-Type-Options", "nosniff"))
                .andExpect(header().string("X-Frame-Options", "DENY"))
                .andReturn();
        log.info("[test] 场景=预检+真实请求, input=GET /api/user/profile Origin={} + session -> {} body={}",
                ALLOWED_ORIGIN, actual.getResponse().getStatus(), actual.getResponse().getContentAsString());
    }

    @Test
    void actualRequestFromDisallowedOriginIsRejected() throws Exception {
        // 业务：不允许来源的真实请求按规则拒绝（403，不下发跨域头）
        JsonNode login = login("bob", "bob-pass");
        String sessionId = login.get("sessionId").asText();
        MvcResult result = mockMvc.perform(get("/api/user/profile")
                        .header("Origin", DENIED_ORIGIN)
                        .header("X-Session-Id", sessionId))
                .andExpect(status().isForbidden())
                .andExpect(header().doesNotExist("Access-Control-Allow-Origin"))
                .andReturn();
        log.info("[test] 场景=真实请求拒绝, input=GET /api/user/profile Origin={} -> {}",
                DENIED_ORIGIN, result.getResponse().getStatus());
    }

    @Test
    void publicPathKeepsWorkingWithCors() throws Exception {
        // 业务：无需认证的入口在跨域下行为不变
        MvcResult result = mockMvc.perform(get("/api/public/health")
                        .header("Origin", ALLOWED_ORIGIN))
                .andExpect(status().isOk())
                .andExpect(header().string("Access-Control-Allow-Origin", ALLOWED_ORIGIN))
                .andExpect(header().string("X-Content-Type-Options", "nosniff"))
                .andReturn();
        log.info("[test] 场景=公开入口跨域, input=GET /api/public/health Origin={} -> {} body={}",
                ALLOWED_ORIGIN, result.getResponse().getStatus(), result.getResponse().getContentAsString());
    }

    @Test
    void requestWithoutOriginIsTreatedAsSameOriginAndUnchanged() throws Exception {
        // 业务：非跨域请求（无 Origin 头）不受 CORS 过滤器影响
        MvcResult result = mockMvc.perform(get("/api/public/health"))
                .andExpect(status().isOk())
                .andReturn();
        assertNull(result.getResponse().getHeader("Access-Control-Allow-Origin"));
        log.info("[test] 场景=无 Origin 请求, input=GET /api/public/health -> {} (无跨域头)",
                result.getResponse().getStatus());
    }

    @Test
    void runtimeOriginChangeTakesEffectImmediately() throws Exception {
        // 业务：运行期把新来源加入允许列表后，新预检立即放行；还原后恢复拒绝
        List<String> original = properties.getAllowedOrigins();
        String newOrigin = "https://console.example.com";
        try {
            properties.setAllowedOrigins(List.of(ALLOWED_ORIGIN, newOrigin));
            MvcResult allowed = mockMvc.perform(options("/api/user/profile")
                            .header("Origin", newOrigin)
                            .header("Access-Control-Request-Method", "GET"))
                    .andExpect(status().isOk())
                    .andExpect(header().string("Access-Control-Allow-Origin", newOrigin))
                    .andReturn();
            log.info("[test] 场景=运行期新增来源, input=OPTIONS Origin={} (策略变更后) -> {}",
                    newOrigin, allowed.getResponse().getStatus());
        } finally {
            properties.setAllowedOrigins(original);
        }
        MvcResult denied = mockMvc.perform(options("/api/user/profile")
                        .header("Origin", newOrigin)
                        .header("Access-Control-Request-Method", "GET"))
                .andExpect(status().isForbidden())
                .andReturn();
        log.info("[test] 场景=来源还原后, input=OPTIONS Origin={} -> {}", newOrigin, denied.getResponse().getStatus());
    }
}
