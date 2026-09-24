package com.github.xingjianluo.sessionauthjava.web;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/** Resolves the authenticated {@link com.github.xingjianluo.sessionauthjava.model.AuthPrincipal}. */
@Target(ElementType.PARAMETER)
@Retention(RetentionPolicy.RUNTIME)
public @interface CurrentUser {
}
