package com.github.xingjianluo.sessionauthjava.auth.service;

import com.github.xingjianluo.sessionauthjava.auth.model.AuthFailureReason;
import com.github.xingjianluo.sessionauthjava.auth.model.AuthResult;
import com.github.xingjianluo.sessionauthjava.auth.model.UserAccount;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.util.Optional;

/**
 * 登录编排：限流/锁定检查 -> 凭据校验 -> 会话签发。
 *
 * <p>失败计数只在"通过限流/锁定检查但凭据错误"时累计，
 * 避免被锁定期间的请求继续放大计数。
 */
@Service
public class AuthService {

    private static final Logger log = LoggerFactory.getLogger(AuthService.class);

    private final UserStore userStore;
    private final LoginAttemptService attemptService;
    private final SessionService sessionService;
    /** 按用户的登录串行化锁：保证"检查-计数-签发"原子，并发下计数不错乱 */
    private final java.util.concurrent.ConcurrentHashMap<String, Object> loginLocks =
            new java.util.concurrent.ConcurrentHashMap<>();

    public AuthService(UserStore userStore, LoginAttemptService attemptService, SessionService sessionService) {
        this.userStore = userStore;
        this.attemptService = attemptService;
        this.sessionService = sessionService;
    }

    public AuthResult login(String username, String password) {
        Object lock = loginLocks.computeIfAbsent(username, k -> new Object());
        synchronized (lock) {
            return doLogin(username, password);
        }
    }

    private AuthResult doLogin(String username, String password) {
        // 1. 限流与锁定检查（优先于凭据校验，防止锁定期间被继续探测）
        Optional<AuthFailureReason> blocked = attemptService.checkBlocked(username);
        if (blocked.isPresent()) {
            log.info("[auth] login user={} blocked reason={}", username, blocked.get());
            return AuthResult.failure(blocked.get(), "login temporarily blocked: " + blocked.get());
        }

        // 2. 凭据校验（用户不存在与密码错误统一为 INVALID_CREDENTIALS，不泄漏用户是否存在）
        Optional<UserAccount> account = userStore.findByUsername(username);
        if (account.isEmpty() || !account.get().password().equals(password)) {
            attemptService.recordFailure(username);
            log.info("[auth] login user={} -> INVALID_CREDENTIALS (userExists={})",
                    username, account.isPresent());
            return AuthResult.failure(AuthFailureReason.INVALID_CREDENTIALS, "invalid username or password");
        }

        // 3. 会话签发（可能因并发会话超限被拒）
        AuthResult issued = sessionService.issue(username, account.get().role());
        if (issued instanceof AuthResult.Failure failure) {
            log.info("[auth] login user={} session issue failed reason={}", username, failure.reason());
            return issued;
        }

        // 4. 成功，清除失败计数
        attemptService.recordSuccess(username);
        log.info("[auth] login user={} -> SUCCESS", username);
        return issued;
    }

    public boolean logout(String sessionId) {
        return sessionService.logout(sessionId);
    }
}
