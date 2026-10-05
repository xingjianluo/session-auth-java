package com.github.xingjianluo.sessionauthjava.auth.web;

import com.github.xingjianluo.sessionauthjava.auth.policy.AuthPolicy;
import com.github.xingjianluo.sessionauthjava.auth.policy.DecisionLog;
import com.github.xingjianluo.sessionauthjava.auth.policy.PolicyEvaluator;
import com.github.xingjianluo.sessionauthjava.auth.policy.PolicyService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * CORS 过滤器（在安全响应头之后、认证之前执行）。
 *
 * <ul>
 *   <li>预检（OPTIONS + Access-Control-Request-Method）：来源被当前策略允许时
 *       直接应答 200 并附加允许来源/方法/请求头，终止链路（不进入认证）；
 *       来源不被允许时不附加任何跨域头，继续走原有链路规则。</li>
 *   <li>真实请求：来源被允许时附加 Access-Control-Allow-Origin 后继续链路，
 *       会话与 CSRF 校验由后续过滤器按原规则执行。</li>
 *   <li>允许来源读取当前策略版本，运行期调整立即生效；每次判定记录判定日志。</li>
 * </ul>
 */
@Component
public class CorsFilter extends OncePerRequestFilter {

    private static final Logger log = LoggerFactory.getLogger(CorsFilter.class);

    /** 预检中允许的方法（静态能力声明，与策略无关） */
    private static final String ALLOW_METHODS = "GET, POST, PUT, DELETE, PATCH, OPTIONS";
    /** 预检结果缓存时间（秒） */
    private static final String MAX_AGE = "600";

    private final PolicyService policyService;
    private final DecisionLog decisionLog;

    public CorsFilter(PolicyService policyService, DecisionLog decisionLog) {
        this.policyService = policyService;
        this.decisionLog = decisionLog;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        String origin = request.getHeader("Origin");
        if (origin == null) {
            // 非跨域请求，不干预
            filterChain.doFilter(request, response);
            return;
        }

        AuthPolicy policy = policyService.current();
        boolean allowed = PolicyEvaluator.isOriginAllowed(policy, origin);
        boolean preflight = isPreflight(request);
        Map<String, String> inputs = new LinkedHashMap<>();
        inputs.put("origin", origin);
        inputs.put("method", request.getMethod());
        inputs.put("path", request.getRequestURI());
        inputs.put("preflight", String.valueOf(preflight));
        long decisionId = decisionLog.record(DecisionLog.KIND_CORS_ORIGIN, policy.version(),
                inputs, allowed ? "ALLOWED" : "DENIED");

        if (!allowed) {
            // 不附加任何跨域头，浏览器将拦截；服务端仍按原有规则处理
            log.info("[cors] origin={} path={} preflight={} -> DENIED by policy v{} (decisionId={})",
                    origin, request.getRequestURI(), preflight, policy.version(), decisionId);
            filterChain.doFilter(request, response);
            return;
        }

        response.setHeader("Access-Control-Allow-Origin", origin);
        response.setHeader("Vary", "Origin");
        if (preflight) {
            // 预检直接应答，不进入认证链路（预检不携带会话凭据）
            response.setHeader("Access-Control-Allow-Methods", ALLOW_METHODS);
            String requestedHeaders = request.getHeader("Access-Control-Request-Headers");
            response.setHeader("Access-Control-Allow-Headers",
                    requestedHeaders != null && !requestedHeaders.isBlank() ? requestedHeaders : "*");
            response.setHeader("Access-Control-Max-Age", MAX_AGE);
            response.setStatus(HttpServletResponse.SC_OK);
            log.info("[cors] preflight origin={} path={} requestMethod={} -> 200 ALLOWED by policy v{}"
                            + " (decisionId={})",
                    origin, request.getRequestURI(), request.getHeader("Access-Control-Request-Method"),
                    policy.version(), decisionId);
            return;
        }

        log.info("[cors] origin={} path={} method={} -> ALLOWED by policy v{} (decisionId={})",
                origin, request.getRequestURI(), request.getMethod(), policy.version(), decisionId);
        filterChain.doFilter(request, response);
    }

    private static boolean isPreflight(HttpServletRequest request) {
        return "OPTIONS".equals(request.getMethod())
                && request.getHeader("Access-Control-Request-Method") != null;
    }
}
