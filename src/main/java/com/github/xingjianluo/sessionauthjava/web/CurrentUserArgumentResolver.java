package com.github.xingjianluo.sessionauthjava.web;

import com.github.xingjianluo.sessionauthjava.model.AuthPrincipal;
import com.github.xingjianluo.sessionauthjava.web.security.AuthenticationRequiredException;
import com.github.xingjianluo.sessionauthjava.session.SessionValidationOutcome;
import org.springframework.core.MethodParameter;
import org.springframework.web.bind.support.WebDataBinderFactory;
import org.springframework.web.context.request.NativeWebRequest;
import org.springframework.web.method.support.HandlerMethodArgumentResolver;
import org.springframework.web.method.support.ModelAndViewContainer;

/** Injects the {@link AuthPrincipal} placed on the request by the authentication filter. */
public class CurrentUserArgumentResolver implements HandlerMethodArgumentResolver {

    @Override
    public boolean supportsParameter(MethodParameter parameter) {
        return parameter.hasParameterAnnotation(CurrentUser.class)
                && AuthPrincipal.class.isAssignableFrom(parameter.getParameterType());
    }

    @Override
    public Object resolveArgument(MethodParameter parameter, ModelAndViewContainer mavContainer,
                                  NativeWebRequest webRequest, WebDataBinderFactory binderFactory) {
        AuthPrincipal principal = (AuthPrincipal) webRequest.getAttribute(
                com.github.xingjianluo.sessionauthjava.web.security.AuthenticationFilter.PRINCIPAL_ATTRIBUTE,
                NativeWebRequest.SCOPE_REQUEST);
        if (principal == null) {
            throw new AuthenticationRequiredException(
                    SessionValidationOutcome.Status.MISSING, "No authenticated principal");
        }
        return principal;
    }
}
