package com.github.xingjianluo.sessionauthjava.auth.web;

import com.github.xingjianluo.sessionauthjava.auth.config.AuthSecurityProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * 过滤器链装配。
 *
 * <p>执行顺序固定为：安全响应头(1) -> CORS(2) -> 认证(3) -> CSRF(4)，
 * 保证横切规则与认证结论组合后一致：
 * 预检在安全头之后被 CORS 过滤器直接应答（带安全头），不进入认证；
 * 真实跨域请求先附加跨域头，再按原规则认证与 CSRF 校验。
 *
 * <p>允许来源由 CorsFilter 按当前策略版本动态判定（运行期可调），
 * 因此不再使用 Spring MVC 的静态 CORS 映射。
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
    public FilterRegistrationBean<CorsFilter> corsFilterRegistration(CorsFilter filter) {
        FilterRegistrationBean<CorsFilter> bean = new FilterRegistrationBean<>(filter);
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
