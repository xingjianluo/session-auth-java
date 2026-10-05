package com.github.xingjianluo.sessionauthjava.auth.web;

import com.github.xingjianluo.sessionauthjava.auth.policy.DecisionLog;
import com.github.xingjianluo.sessionauthjava.auth.policy.DecisionTypes;
import com.github.xingjianluo.sessionauthjava.auth.policy.PolicyDecisions;
import com.github.xingjianluo.sessionauthjava.auth.policy.PolicyService;
import com.github.xingjianluo.sessionauthjava.auth.policy.PolicySettings;
import com.github.xingjianluo.sessionauthjava.auth.policy.PolicySnapshot;
import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * 动态 CORS 配置源：每次请求从当前策略快照读取允许来源，
 * 运行期调整 allowed-origins 后新请求立即按新策略判定；
 * 每条来源判定写入判定日志并标注策略版本，支持历史回放。
 */
public class DynamicCorsConfigurationSource implements CorsConfigurationSource {

    private static final Logger log = LoggerFactory.getLogger(DynamicCorsConfigurationSource.class);

    /** 允许跨域携带的方法 */
    private static final List<String> ALLOWED_METHODS = List.of("GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS");
    /** 允许跨域携带的请求头（会话与 CSRF 令牌） */
    private static final List<String> ALLOWED_HEADERS = List.of("X-Session-Id", "X-CSRF-Token", "Content-Type");

    private final PolicyService policyService;
    private final DecisionLog decisionLog;

    public DynamicCorsConfigurationSource(PolicyService policyService, DecisionLog decisionLog) {
        this.policyService = policyService;
        this.decisionLog = decisionLog;
    }

    @Override
    public CorsConfiguration getCorsConfiguration(HttpServletRequest request) {
        PolicySnapshot snapshot = policyService.current();
        PolicySettings settings = snapshot.settings();

        String origin = request.getHeader("Origin");
        if (origin != null) {
            boolean allowed = PolicyDecisions.originAllowed(origin, settings);
            Map<String, String> inputs = new LinkedHashMap<>();
            inputs.put("origin", origin);
            inputs.put("method", request.getMethod());
            decisionLog.record(DecisionTypes.CORS_ORIGIN, snapshot.version(), inputs,
                    allowed ? "ALLOWED" : "DENIED");
            log.info("[cors] origin={} method={} -> {} (policy v{})",
                    origin, request.getMethod(), allowed ? "ALLOWED" : "DENIED", snapshot.version());
        }

        CorsConfiguration config = new CorsConfiguration();
        config.setAllowedOrigins(settings.allowedOrigins());
        config.setAllowedMethods(ALLOWED_METHODS);
        config.setAllowedHeaders(ALLOWED_HEADERS);
        config.setAllowCredentials(true);
        config.setMaxAge(1800L);
        return config;
    }
}
