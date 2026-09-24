package com.github.xingjianluo.sessionauthjava.web.security;

import com.github.xingjianluo.sessionauthjava.audit.AuditService;
import com.github.xingjianluo.sessionauthjava.authz.AccessRuleRegistry;
import com.github.xingjianluo.sessionauthjava.authz.ResourceAttributeProvider;
import com.github.xingjianluo.sessionauthjava.config.SecurityConfigService;
import com.github.xingjianluo.sessionauthjava.model.UserDirectory;
import com.github.xingjianluo.sessionauthjava.session.CsrfTokenService;
import com.github.xingjianluo.sessionauthjava.session.SessionManager;
import com.github.xingjianluo.sessionauthjava.support.TimeSource;
import com.github.xingjianluo.sessionauthjava.web.CurrentUserArgumentResolver;
import java.util.List;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Lazy;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.HandlerExceptionResolver;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

/**
 * Wires the security chain: CORS -> security headers -> session/CSRF authentication,
 * followed by the authorization interceptor on {@code /api/**}.
 */
@Configuration
public class WebSecurityConfig implements WebMvcConfigurer {

    private final SessionManager sessionManager;
    private final UserDirectory userDirectory;
    private final CsrfTokenService csrfTokenService;
    private final SecurityConfigService configService;
    private final AccessRuleRegistry ruleRegistry;
    private final List<ResourceAttributeProvider> attributeProviders;
    private final AuditService auditService;
    private final TimeSource timeSource;
    private final HandlerExceptionResolver handlerExceptionResolver;

    public WebSecurityConfig(SessionManager sessionManager, UserDirectory userDirectory,
                             CsrfTokenService csrfTokenService, SecurityConfigService configService,
                             AccessRuleRegistry ruleRegistry,
                             List<ResourceAttributeProvider> attributeProviders,
                             AuditService auditService, TimeSource timeSource,
                             @Lazy HandlerExceptionResolver handlerExceptionResolver) {
        this.sessionManager = sessionManager;
        this.userDirectory = userDirectory;
        this.csrfTokenService = csrfTokenService;
        this.configService = configService;
        this.ruleRegistry = ruleRegistry;
        this.attributeProviders = attributeProviders;
        this.auditService = auditService;
        this.timeSource = timeSource;
        this.handlerExceptionResolver = handlerExceptionResolver;
    }

    @Bean
    FilterRegistrationBean<CorsFilter> corsFilter() {
        FilterRegistrationBean<CorsFilter> bean = new FilterRegistrationBean<>(new CorsFilter(configService));
        bean.setOrder(10);
        bean.addUrlPatterns("/*");
        return bean;
    }

    @Bean
    FilterRegistrationBean<SecurityHeadersFilter> headersFilter() {
        FilterRegistrationBean<SecurityHeadersFilter> bean =
                new FilterRegistrationBean<>(new SecurityHeadersFilter(configService));
        bean.setOrder(20);
        bean.addUrlPatterns("/*");
        return bean;
    }

    @Bean
    FilterRegistrationBean<AuthenticationFilter> authenticationFilter() {
        AuthenticationFilter filter = new AuthenticationFilter(
                sessionManager, userDirectory, csrfTokenService, configService,
                handlerExceptionResolver);
        FilterRegistrationBean<AuthenticationFilter> bean = new FilterRegistrationBean<>(filter);
        bean.setOrder(30);
        bean.addUrlPatterns("/api/*");
        return bean;
    }

    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        registry.addInterceptor(new AuthorizationInterceptor(
                        ruleRegistry, attributeProviders, auditService, configService,
                        timeSource, handlerExceptionResolver))
                .addPathPatterns("/api/**");
    }

    @Override
    public void addArgumentResolvers(List<org.springframework.web.method.support.HandlerMethodArgumentResolver> resolvers) {
        resolvers.add(new CurrentUserArgumentResolver());
    }
}
