package com.github.xingjianluo.sessionauthjava.auth.web;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.xingjianluo.sessionauthjava.auth.model.SessionRecord;
import com.github.xingjianluo.sessionauthjava.auth.policy.DecisionLog;
import com.github.xingjianluo.sessionauthjava.auth.policy.DecisionTypes;
import com.github.xingjianluo.sessionauthjava.auth.policy.PolicyDecisions;
import com.github.xingjianluo.sessionauthjava.auth.policy.PolicyService;
import com.github.xingjianluo.sessionauthjava.auth.policy.PolicySnapshot;
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
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * CSRF 防护过滤器（在 AuthFilter 之后执行）：
 * 对已认证的变更类请求（POST/PUT/DELETE/PATCH）校验 X-CSRF-Token。
 * 公开路径与安全方法不校验；策略关闭时整体跳过。
 *
 * <p>判定结论由 {@link PolicyDecisions#csrfOutcome} 纯函数给出（与历史回放共用），
 * 每条判定写入判定日志并标注策略版本。
 */
@Component
public class CsrfFilter extends OncePerRequestFilter {

    private static final Logger log = LoggerFactory.getLogger(CsrfFilter.class);

    public static final String CSRF_HEADER = "X-CSRF-Token";

    private final PolicyService policyService;
    private final DecisionLog decisionLog;
    private final SessionService sessionService;
    private final ObjectMapper objectMapper = new ObjectMapper();

    public CsrfFilter(PolicyService policyService, DecisionLog decisionLog, SessionService sessionService) {
        this.policyService = policyService;
        this.decisionLog = decisionLog;
        this.sessionService = sessionService;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        PolicySnapshot snapshot = policyService.current();
        Object sessionAttr = request.getAttribute(AuthFilter.ATTR_SESSION);
        boolean authenticated = sessionAttr instanceof SessionRecord;
        boolean tokenValid = false;
        if (authenticated) {
            SessionRecord session = (SessionRecord) sessionAttr;
            tokenValid = sessionService.csrfTokenMatches(session.sessionId(), request.getHeader(CSRF_HEADER));
        }
        String path = request.getRequestURI();
        String outcome = PolicyDecisions.csrfOutcome(request.getMethod(), path, authenticated,
                tokenValid, snapshot.settings());
        Map<String, String> inputs = new LinkedHashMap<>();
        inputs.put("method", request.getMethod());
        inputs.put("path", path);
        inputs.put("authenticated", String.valueOf(authenticated));
        inputs.put("tokenValid", String.valueOf(tokenValid));
        decisionLog.record(DecisionTypes.CSRF, snapshot.version(), inputs, outcome);

        if ("REJECTED".equals(outcome)) {
            SessionRecord session = (SessionRecord) sessionAttr;
            log.info("[csrf] path={} method={} user={} -> 403 CSRF_TOKEN_MISMATCH (policy v{})",
                    path, request.getMethod(), session.username(), snapshot.version());
            response.setStatus(HttpServletResponse.SC_FORBIDDEN);
            response.setContentType(MediaType.APPLICATION_JSON_VALUE);
            response.setCharacterEncoding(StandardCharsets.UTF_8.name());
            response.getWriter().write(objectMapper.writeValueAsString(
                    new ApiError("CSRF_TOKEN_MISMATCH", "missing or invalid CSRF token")));
            return;
        }
        filterChain.doFilter(request, response);
    }
}
