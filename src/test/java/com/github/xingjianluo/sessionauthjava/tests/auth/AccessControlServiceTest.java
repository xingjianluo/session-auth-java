package com.github.xingjianluo.sessionauthjava.tests.auth;

import com.github.xingjianluo.sessionauthjava.auth.config.AuthSecurityProperties;
import com.github.xingjianluo.sessionauthjava.auth.model.AccessDecision;
import com.github.xingjianluo.sessionauthjava.auth.model.AuthResult;
import com.github.xingjianluo.sessionauthjava.auth.model.Role;
import com.github.xingjianluo.sessionauthjava.auth.model.SessionRecord;
import com.github.xingjianluo.sessionauthjava.auth.model.UserAccount;
import com.github.xingjianluo.sessionauthjava.auth.service.AccessControlService;
import com.github.xingjianluo.sessionauthjava.auth.service.SessionService;
import com.github.xingjianluo.sessionauthjava.auth.service.UserStore;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Instant;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 角色/属性访问控制测试：降权立即生效、越权原因可区分。
 */
class AccessControlServiceTest {

    private static final Logger log = LoggerFactory.getLogger(AccessControlServiceTest.class);

    private UserStore userStore;
    private SessionService sessionService;
    private AccessControlService accessControl;

    @BeforeEach
    void setUp() {
        userStore = new UserStore();
        sessionService = new SessionService(new AuthSecurityProperties(),
                new MutableClock(Instant.parse("2026-09-24T00:00:00Z")));
        accessControl = new AccessControlService(userStore);
    }

    private SessionRecord sessionOf(String username) {
        Role role = userStore.findByUsername(username).map(UserAccount::role).orElse(Role.USER);
        return ((AuthResult.Success) sessionService.issue(username, role)).session();
    }

    @Test
    void unauthenticatedIsDenied() {
        AccessDecision decision = accessControl.decide(null, Role.USER, Set.of());
        log.info("[test] input=no session requiredRole=USER, decision={}", decision);
        assertFalse(decision.granted());
        assertEquals(AccessDecision.DenyReason.UNAUTHENTICATED, decision.denyReason());
    }

    @Test
    void userCannotAccessAdminResource() {
        SessionRecord bobSession = sessionOf("bob"); // USER 角色
        AccessDecision decision = accessControl.decide(bobSession, Role.ADMIN, Set.of());
        log.info("[test] input=bob(USER) -> admin resource, decision={}", decision);
        assertFalse(decision.granted());
        assertEquals(AccessDecision.DenyReason.ROLE_INSUFFICIENT, decision.denyReason());
    }

    @Test
    void adminCanAccessAdminResource() {
        SessionRecord aliceSession = sessionOf("alice"); // ADMIN 角色
        AccessDecision decision = accessControl.decide(aliceSession, Role.ADMIN, Set.of());
        log.info("[test] input=alice(ADMIN) -> admin resource, decision={}", decision);
        assertTrue(decision.granted());
    }

    @Test
    void missingAttributeIsDeniedWithDistinguishableReason() {
        SessionRecord bobSession = sessionOf("bob"); // 只有 dept:ops
        AccessDecision decision = accessControl.decide(bobSession, Role.USER, Set.of("dept:eng"));
        log.info("[test] input=bob(attrs=dept:ops) -> resource requiring dept:eng, decision={}", decision);
        assertFalse(decision.granted());
        assertEquals(AccessDecision.DenyReason.ATTRIBUTE_MISSING, decision.denyReason());
    }

    @Test
    void demotionTakesEffectImmediatelyForExistingSession() {
        SessionRecord aliceSession = sessionOf("alice"); // 签发时为 ADMIN
        AccessDecision before = accessControl.decide(aliceSession, Role.ADMIN, Set.of());
        assertTrue(before.granted());

        userStore.updateRole("alice", Role.USER); // 降权
        AccessDecision after = accessControl.decide(aliceSession, Role.ADMIN, Set.of());
        log.info("[test] input=alice demoted ADMIN->USER with live session, before={} after={}", before, after);
        assertFalse(after.granted());
        assertEquals(AccessDecision.DenyReason.ROLE_INSUFFICIENT, after.denyReason());
    }

    @Test
    void revokedSessionFailsValidationBeforeAccessCheck() {
        SessionRecord aliceSession = sessionOf("alice");
        sessionService.revokeAllForUser("alice");
        AuthResult validated = sessionService.validate(aliceSession.sessionId());
        log.info("[test] input=validate revoked session, decision={}", validated);
        assertFalse(validated.isSuccess());
    }
}
