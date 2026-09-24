package com.github.xingjianluo.sessionauthjava.auth.model;

/**
 * 访问控制判定结果。
 */
public record AccessDecision(boolean granted, DenyReason denyReason, String basis) {

    public enum DenyReason {
        NONE,
        /** 未认证（无会话或会话无效） */
        UNAUTHENTICATED,
        /** 角色不足 */
        ROLE_INSUFFICIENT,
        /** 缺少必需属性 */
        ATTRIBUTE_MISSING
    }

    public static AccessDecision grant(String basis) {
        return new AccessDecision(true, DenyReason.NONE, basis);
    }

    public static AccessDecision deny(DenyReason reason, String basis) {
        return new AccessDecision(false, reason, basis);
    }
}
