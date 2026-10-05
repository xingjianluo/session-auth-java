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
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.options;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * 跨域真实调用链路：预检（OPTIONS）-> 带会话与令牌的真实请求。
 * 允许来源拿到完整跨域响应头与安全响应头；不允许的来源不附加跨域头，
 * 服务端仍按原有认证/授权规则处理。
 */
@SpringBootTest
@AutoConfigureMockMvc
class CorsWebTest {

    private static final Logger log = LoggerFactory.getLogger(CorsWebTest.class);

    private static final String ALLOWED_ORIGIN = "http://localhost:3000";
    private static final String DENIED_ORIGIN = "http://evil.example.com";

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
    void preflightFromAllowedOriginPassesWithCorsAndSecurityHeaders() throws Exception {
        MvcResult result = mockMvc.perform(options("/api/user/profile")
                        .header("Origin", ALLOWED_ORIGIN)
                        .header("Access-Control-Request-Method", "GET")
                        .header("Access-Control-Request-Headers", "X-Session-Id, X-CSRF-Token"))
                .andExpect(status().isOk())
                .andExpect(header().string("Access-Control-Allow-Origin", ALLOWED_ORIGIN))
                .andExpect(header().string("Access-Control-Allow-Methods", org.hamcrest.Matchers.containsString("GET")))
                .andExpect(header().string("Access-Control-Allow-Headers",
                        org.hamcrest.Matchers.containsString("X-Session-Id")))
                .andExpect(header().string("Access-Control-Allow-Headers",
                        org.hamcrest.Matchers.containsString("X-CSRF-Token")))
                // 预检响应同样保留安全响应头
                .andExpect(header().string("X-Content-Type-Options", "nosniff"))
                .andExpect(header().string("X-Frame-Options", "DENY"))
                .andReturn();
        log.info("[test] business=CORS preflight, input=OPTIONS /api/user/profile origin={} acrm=GET"
                        + " -> status={} allowOrigin={} allowMethods={} allowHeaders={} (basis: origin in policy"
                        + " allowedOrigins, preflight answered before auth)",
                ALLOWED_ORIGIN, result.getResponse().getStatus(),
                result.getResponse().getHeader("Access-Control-Allow-Origin"),
                result.getResponse().getHeader("Access-Control-Allow-Methods"),
                result.getResponse().getHeader("Access-Control-Allow-Headers"));
    }

    @Test
    void preflightThenRealRequestWithSessionAndCsrfTokenWorks() throws Exception {
        JsonNode login = login("bob", "bob-pass");
        String sessionId = login.get("sessionId").asText();
        String csrf = login.get("csrfToken").asText();

        // 1. 预检：受保护路径也不应被认证拦截
        mockMvc.perform(options("/api/user/profile")
                        .header("Origin", ALLOWED_ORIGIN)
                        .header("Access-Control-Request-Method", "GET"))
                .andExpect(status().isOk())
                .andExpect(header().string("Access-Control-Allow-Origin", ALLOWED_ORIGIN));

        // 2. 真实 GET：带会话，跨域头与业务响应同时正确
        MvcResult real = mockMvc.perform(get("/api/user/profile")
                        .header("Origin", ALLOWED_ORIGIN)
                        .header("X-Session-Id", sessionId))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.username").value("bob"))
                .andExpect(header().string("Access-Control-Allow-Origin", ALLOWED_ORIGIN))
                .andExpect(header().string("X-Content-Type-Options", "nosniff"))
                .andReturn();
        log.info("[test] business=CORS real GET, input=GET /api/user/profile origin={} with session"
                        + " -> status={} body={} (basis: preflight passed, session valid)",
                ALLOWED_ORIGIN, real.getResponse().getStatus(), real.getResponse().getContentAsString());

        // 3. 真实 POST（变更类）：带会话 + CSRF 令牌
        MvcResult post = mockMvc.perform(post("/api/auth/logout")
                        .header("Origin", ALLOWED_ORIGIN)
                        .header("X-Session-Id", sessionId)
                        .header("X-CSRF-Token", csrf))
                .andExpect(status().isOk())
                .andExpect(header().string("Access-Control-Allow-Origin", ALLOWED_ORIGIN))
                .andReturn();
        log.info("[test] business=CORS real POST, input=POST /api/auth/logout origin={} with session+csrf"
                        + " -> status={} body={} (basis: session valid, csrf token matches)",
                ALLOWED_ORIGIN, post.getResponse().getStatus(), post.getResponse().getContentAsString());
    }

    @Test
    void preflightFromDisallowedOriginGetsNoCorsHeaders() throws Exception {
        MvcResult result = mockMvc.perform(options("/api/user/profile")
                        .header("Origin", DENIED_ORIGIN)
                        .header("Access-Control-Request-Method", "GET"))
                .andExpect(header().doesNotExist("Access-Control-Allow-Origin"))
                // 服务端仍按现有规则处理：受保护路径无会话 -> 401
                .andExpect(status().isUnauthorized())
                .andExpect(header().string("X-Content-Type-Options", "nosniff"))
                .andReturn();
        log.info("[test] business=CORS preflight denied, input=OPTIONS /api/user/profile origin={}"
                        + " -> status={} allowOrigin={} (basis: origin NOT in allowedOrigins,"
                        + " falls through to existing auth rules)",
                DENIED_ORIGIN, result.getResponse().getStatus(),
                result.getResponse().getHeader("Access-Control-Allow-Origin"));
    }

    @Test
    void realRequestFromDisallowedOriginProcessedByExistingRulesWithoutCorsHeaders() throws Exception {
        JsonNode login = login("alice", "alice-pass");
        String sessionId = login.get("sessionId").asText();
        MvcResult result = mockMvc.perform(get("/api/user/profile")
                        .header("Origin", DENIED_ORIGIN)
                        .header("X-Session-Id", sessionId))
                // 现有规则（认证）照常生效，但不附加跨域头，浏览器侧会拦截
                .andExpect(status().isOk())
                .andExpect(header().doesNotExist("Access-Control-Allow-Origin"))
                .andReturn();
        log.info("[test] business=CORS real request denied origin, input=GET /api/user/profile origin={}"
                        + " valid session -> status={} allowOrigin={} (basis: auth rules apply, no CORS grant)",
                DENIED_ORIGIN, result.getResponse().getStatus(),
                result.getResponse().getHeader("Access-Control-Allow-Origin"));
    }

    @Test
    void publicPathAndSafeMethodsUnaffectedByCors() throws Exception {
        // 公开路径不需要预检也能直接访问；带允许来源时附加跨域头
        MvcResult result = mockMvc.perform(get("/api/public/health")
                        .header("Origin", ALLOWED_ORIGIN))
                .andExpect(status().isOk())
                .andExpect(header().string("Access-Control-Allow-Origin", ALLOWED_ORIGIN))
                .andExpect(header().string("X-Content-Type-Options", "nosniff"))
                .andReturn();
        log.info("[test] business=public path with CORS, input=GET /api/public/health origin={}"
                        + " -> status={} (basis: public path never intercepted, CORS header attached)",
                ALLOWED_ORIGIN, result.getResponse().getStatus());

        // 无 Origin 头的普通请求完全不受 CORS 过滤器影响
        mockMvc.perform(get("/api/public/health"))
                .andExpect(status().isOk())
                .andExpect(header().doesNotExist("Access-Control-Allow-Origin"));
    }
}
