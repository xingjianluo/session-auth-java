package com.github.xingjianluo.sessionauthjava.auth.web;

import com.github.xingjianluo.sessionauthjava.auth.config.AuthSecurityProperties;
import com.github.xingjianluo.sessionauthjava.auth.policy.DecisionLog;
import com.github.xingjianluo.sessionauthjava.auth.policy.PolicyService;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.filter.CorsFilter;

/**
 * 过滤器链装配。
 *
 * <p>执行顺序固定为：安全响应头(1) -> CORS(2) -> 认证(3) -> CSRF(4)。
 * CORS 过滤器在认证之前处理预检（OPTIONS）请求并直接应答，
 * 保证跨域预检不会被认证拦截；真实请求则先挂上跨域响应头再进入认证链。
 * 安全响应头在最外层，预检与真实请求的响应（含拒绝响应）都带安全头。
 */
@Configuration
@EnableConfigurationProperties(AuthSecurityProperties.class)
public class WebSecurityConfig {

    @Bean
    public FilterRegistrationBean<SecurityHeadersFilter> securityHeadersFilterRegistration(SecurityHeadersFilter filter) {
        FilterRegistrationBean<SecurityHeadersFilter> bean = new FilterRegistrationBean<>(filter);
        bean.setOrder(1);
        bean.addUrlPatterns("/api/*");
        return bean;
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource(PolicyService policyService, DecisionLog decisionLog) {
        return new DynamicCorsConfigurationSource(policyService, decisionLog);
    }

    @Bean
    public FilterRegistrationBean<CorsFilter> corsFilterRegistration(CorsConfigurationSource corsConfigurationSource) {
        FilterRegistrationBean<CorsFilter> bean = new FilterRegistrationBean<>(new CorsFilter(corsConfigurationSource));
        bean.setOrder(2);
        bean.addUrlPatterns("/api/*");
        return bean;
    }

    @Bean
    public FilterRegistrationBean<AuthFilter> authFilterRegistration(AuthFilter filter) {
        FilterRegistrationBean<AuthFilter> bean = new FilterRegistrationBean<>(filter);
        bean.setOrder(3);
        bean.addUrlPatterns("/api/*");
        return bean;
    }

    @Bean
    public FilterRegistrationBean<CsrfFilter> csrfFilterRegistration(CsrfFilter filter) {
        FilterRegistrationBean<CsrfFilter> bean = new FilterRegistrationBean<>(filter);
        bean.setOrder(4);
        bean.addUrlPatterns("/api/*");
        return bean;
    }
}
