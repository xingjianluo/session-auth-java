package com.github.xingjianluo.sessionauthjava.authz;

import java.util.Map;

/**
 * Loads resource attributes for ABAC evaluation. Returning {@code null} means the
 * resource does not exist, which the authorization layer must hide identically to
 * an attribute denial when the caller could otherwise know the path pattern.
 */
public interface ResourceAttributeProvider {

    boolean supports(String path, String method);

    Map<String, String> loadAttributes(String path, String method);
}
