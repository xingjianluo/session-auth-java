package com.github.xingjianluo.sessionauthjava.auth.service;

import com.github.xingjianluo.sessionauthjava.auth.model.AccessDecision;
import com.github.xingjianluo.sessionauthjava.auth.model.Role;
import com.github.xingjianluo.sessionauthjava.auth.model.SessionRecord;
import com.github.xingjianluo.sessionauthjava.auth.model.UserAccount;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.util.Optional;
import java.util.Set;

/**
 * 基于角色与属性的访问控制。
 *
 * <p>判定使用用户的<b>当前</b>角色与属性（而非会话签发时的快照），
 * 因此降权/升权后后续请求立即按新状态判定。
 */
@Service
public class AccessControlService {

    private static final Logger log = LoggerFactory.getLogger(AccessControlService.class);

    private final UserStore userStore;

    public AccessControlService(UserStore userStore) {
        this.userStore = userStore;
    }

    /**
     * 判定会话是否可访问受保护资源。
     *
     * @param session            已验证的会话（null 表示未认证）
     * @param requiredRole       所需最低角色
     * @param requiredAttributes 所需属性集合（可为空）
     */
    public AccessDecision decide(SessionRecord session, Role requiredRole, Set<String> requiredAttributes) {
        if (session == null) {
            log.info("[access] deny reason=UNAUTHENTICATED requiredRole={}", requiredRole);
            return AccessDecision.deny(AccessDecision.DenyReason.UNAUTHENTICATED,
                    "no valid session attached to request");
        }
        Optional<UserAccount> account = userStore.findByUsername(session.username());
        if (account.isEmpty()) {
            log.info("[access] deny reason=UNAUTHENTICATED user={} (account no longer exists)", session.username());
            return AccessDecision.deny(AccessDecision.DenyReason.UNAUTHENTICATED,
                    "account for session no longer exists");
        }
        UserAccount user = account.get();
        Role currentRole = user.role();
        if (!currentRole.includes(requiredRole)) {
            log.info("[access] deny reason=ROLE_INSUFFICIENT user={} currentRole={} requiredRole={}",
                    user.username(), currentRole, requiredRole);
            return AccessDecision.deny(AccessDecision.DenyReason.ROLE_INSUFFICIENT,
                    "current role " + currentRole + " does not include required role " + requiredRole);
        }
        Set<String> required = requiredAttributes == null ? Set.of() : requiredAttributes;
        if (!required.isEmpty() && !user.attributes().containsAll(required)) {
            log.info("[access] deny reason=ATTRIBUTE_MISSING user={} required={} actual={}",
                    user.username(), required, user.attributes());
            return AccessDecision.deny(AccessDecision.DenyReason.ATTRIBUTE_MISSING,
                    "missing required attributes " + required);
        }
        log.info("[access] grant user={} role={} requiredRole={} requiredAttrs={}",
                user.username(), currentRole, requiredRole, required);
        return AccessDecision.grant("role " + currentRole + " satisfies " + requiredRole
                + (required.isEmpty() ? "" : " and attributes " + required));
    }
}
