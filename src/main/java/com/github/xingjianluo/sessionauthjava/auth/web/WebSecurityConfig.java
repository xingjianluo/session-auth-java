package com.github.xingjianluo.sessionauthjava.auth.web;

import com.github.xingjianluo.sessionauthjava.auth.config.AuthSecurityProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

/**
 * 过滤器链与 CORS 装配。
 *
 * <p>执行顺序固定为：安全响应头(1) -> 认证(2) -> CSRF(3)，
 * 保证横切规则与认证结论组合后一致。
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
    public FilterRegistrationBean<AuthFilter> authFilterRegistration(AuthFilter filter) {
        FilterRegistrationBean<AuthFilter> bean = new FilterRegistrationBean<>(filter);
        bean.setOrder(2);
        bean.addUrlPatterns("/api/*");
        return bean;
    }

    @Bean
    public FilterRegistrationBean<CsrfFilter> csrfFilterRegistration(CsrfFilter filter) {
        FilterRegistrationBean<CsrfFilter> bean = new FilterRegistrationBean<>(filter);
        bean.setOrder(3);
        bean.addUrlPatterns("/api/*");
        return bean;
    }

    @Bean
    public WebMvcConfigurer corsConfigurer(AuthSecurityProperties properties) {
        return new WebMvcConfigurer() {
            @Override
            public void addCorsMappings(CorsRegistry registry) {
                registry.addMapping("/api/**")
                        .allowedOrigins(properties.getAllowedOrigins().toArray(new String[0]))
                        .allowedMethods("GET", "POST", "PUT", "DELETE", "OPTIONS")
                        .allowedHeaders("*");
            }
        };
    }
}
