package com.github.xingjianluo.sessionauthjava.auth.web;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.xingjianluo.sessionauthjava.auth.model.SessionRecord;
import com.github.xingjianluo.sessionauthjava.auth.policy.AuthPolicy;
import com.github.xingjianluo.sessionauthjava.auth.policy.DecisionLog;
import com.github.xingjianluo.sessionauthjava.auth.policy.PolicyEvaluator;
import com.github.xingjianluo.sessionauthjava.auth.policy.PolicyService;
import com.github.xingjianluo.sessionauthjava.auth.service.SessionService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Map;

/**
 * CSRF 防护过滤器（在 AuthFilter 之后执行）：
 * 对已认证的变更类请求（POST/PUT/DELETE/PATCH）校验 X-CSRF-Token。
 * 公开路径与安全方法不校验；策略关闭时整体跳过。
 * 是否需要校验由当前策略版本决定并记录判定日志（可回放）。
 */
@Component
public class CsrfFilter extends OncePerRequestFilter {

    private static final Logger log = LoggerFactory.getLogger(CsrfFilter.class);

    public static final String CSRF_HEADER = "X-CSRF-Token";

    private final PolicyService policyService;
    private final DecisionLog decisionLog;
    private final SessionService sessionService;
    private final AuthFilter authFilter;
    private final ObjectMapper objectMapper = new ObjectMapper();

    public CsrfFilter(PolicyService policyService, DecisionLog decisionLog,
                      SessionService sessionService, AuthFilter authFilter) {
        this.policyService = policyService;
        this.decisionLog = decisionLog;
        this.sessionService = sessionService;
        this.authFilter = authFilter;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        AuthPolicy policy = policyService.current();
        boolean isPublic = authFilter.isPublicPath(request.getRequestURI());
        boolean required = PolicyEvaluator.csrfCheckRequired(policy, request.getMethod(), isPublic);
        long decisionId = decisionLog.record(DecisionLog.KIND_CSRF_REQUIRED, policy.version(),
                Map.of("method", request.getMethod(), "path", request.getRequestURI(),
                        "publicPath", String.valueOf(isPublic)),
                required ? "REQUIRED" : "SKIPPED");
        if (!required) {
            filterChain.doFilter(request, response);
            return;
        }

        Object sessionAttr = request.getAttribute(AuthFilter.ATTR_SESSION);
        if (sessionAttr instanceof SessionRecord session) {
            String token = request.getHeader(CSRF_HEADER);
            if (!sessionService.csrfTokenMatches(session.sessionId(), token)) {
                log.info("[csrf] path={} method={} user={} -> 403 CSRF_TOKEN_MISMATCH"
                                + " (policyVersion={} decisionId={})",
                        request.getRequestURI(), request.getMethod(), session.username(),
                        policy.version(), decisionId);
                response.setStatus(HttpServletResponse.SC_FORBIDDEN);
                response.setContentType(MediaType.APPLICATION_JSON_VALUE);
                response.setCharacterEncoding(StandardCharsets.UTF_8.name());
                response.getWriter().write(objectMapper.writeValueAsString(
                        new ApiError("CSRF_TOKEN_MISMATCH", "missing or invalid CSRF token")));
                return;
            }
        }
        filterChain.doFilter(request, response);
    }
}
