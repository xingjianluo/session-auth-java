package com.github.xingjianluo.sessionauthjava.auth.web;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.xingjianluo.sessionauthjava.auth.model.AuthResult;
import com.github.xingjianluo.sessionauthjava.auth.policy.AuthPolicy;
import com.github.xingjianluo.sessionauthjava.auth.policy.DecisionLog;
import com.github.xingjianluo.sessionauthjava.auth.policy.PolicyEvaluator;
import com.github.xingjianluo.sessionauthjava.auth.policy.PolicyService;
import com.github.xingjianluo.sessionauthjava.auth.service.AccessControlService;
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
 * 认证过滤器：
 * <ul>
 *   <li>公开路径（当前策略版本）直接放行，绝不误拦截</li>
 *   <li>受保护路径校验 X-Session-Id，失败返回 401 且原因可区分</li>
 *   <li>校验通过将会话挂到请求属性，供后续过滤器与控制器使用</li>
 *   <li>公开路径判定记录判定日志（含策略版本），可按当时版本回放</li>
 * </ul>
 */
@Component
public class AuthFilter extends OncePerRequestFilter {

    private static final Logger log = LoggerFactory.getLogger(AuthFilter.class);

    public static final String ATTR_SESSION = "auth.session";
    public static final String SESSION_HEADER = "X-Session-Id";

    private final SessionService sessionService;
    private final AccessControlService accessControlService;
    private final PolicyService policyService;
    private final DecisionLog decisionLog;
    private final ObjectMapper objectMapper = new ObjectMapper();

    public AuthFilter(SessionService sessionService, AccessControlService accessControlService,
                      PolicyService policyService, DecisionLog decisionLog) {
        this.sessionService = sessionService;
        this.accessControlService = accessControlService;
        this.policyService = policyService;
        this.decisionLog = decisionLog;
    }

    /** 按当前生效策略判断路径是否公开 */
    public boolean isPublicPath(String path) {
        return PolicyEvaluator.isPublicPath(policyService.current(), path);
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        String path = request.getRequestURI();
        AuthPolicy policy = policyService.current();
        boolean isPublic = PolicyEvaluator.isPublicPath(policy, path);
        long decisionId = decisionLog.record(DecisionLog.KIND_PUBLIC_PATH, policy.version(),
                Map.of("path", path), String.valueOf(isPublic));
        if (isPublic) {
            log.info("[auth-filter] path={} is public -> skip auth (policyVersion={} decisionId={})",
                    path, policy.version(), decisionId);
            filterChain.doFilter(request, response);
            return;
        }

        String sessionId = request.getHeader(SESSION_HEADER);
        AuthResult result = sessionService.validate(sessionId);
        if (result instanceof AuthResult.Failure failure) {
            log.info("[auth-filter] path={} method={} -> 401 reason={} (policyVersion={})",
                    path, request.getMethod(), failure.reason(), policy.version());
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            response.setContentType(MediaType.APPLICATION_JSON_VALUE);
            response.setCharacterEncoding(StandardCharsets.UTF_8.name());
            response.getWriter().write(objectMapper.writeValueAsString(
                    new ApiError(failure.reason().name(), failure.detail())));
            return;
        }

        AuthResult.Success success = (AuthResult.Success) result;
        request.setAttribute(ATTR_SESSION, success.session());
        log.info("[auth-filter] path={} method={} user={} -> authenticated (policyVersion={})",
                path, request.getMethod(), success.session().username(), policy.version());
        filterChain.doFilter(request, response);
    }
}
