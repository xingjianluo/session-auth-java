package com.github.xingjianluo.sessionauthjava.login;

import com.github.xingjianluo.sessionauthjava.config.SecurityConfigService;
import com.github.xingjianluo.sessionauthjava.config.SecuritySettings;
import com.github.xingjianluo.sessionauthjava.model.UserAccount;
import com.github.xingjianluo.sessionauthjava.model.UserDirectory;
import com.github.xingjianluo.sessionauthjava.session.SessionManager;
import com.github.xingjianluo.sessionauthjava.session.SessionRecord;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

/**
 * Orchestrates the full login flow: throttle/lock check, credential verification,
 * failure accounting and atomic session issuance. All failure reasons are distinct so
 * callers can explain every rejection precisely.
 */
@Service
public class LoginService {

    private static final Logger log = LoggerFactory.getLogger(LoginService.class);

    private final LoginThrottleService throttle;
    private final UserDirectory userDirectory;
    private final SessionManager sessionManager;
    private final SecurityConfigService configService;

    public LoginService(LoginThrottleService throttle, UserDirectory userDirectory,
                        SessionManager sessionManager, SecurityConfigService configService) {
        this.throttle = throttle;
        this.userDirectory = userDirectory;
        this.sessionManager = sessionManager;
        this.configService = configService;
    }

    /** Performs a full login flow and returns a precisely classified result. */
    public LoginResult login(String username, String password) {
        SecuritySettings settings = configService.current();
        log.info("Login attempt user={} settingsVersion={}", username, settings.version());

        LoginThrottleService.BlockReason block = throttle.check(username);
        if (block == LoginThrottleService.BlockReason.ACCOUNT_LOCKED) {
            return new LoginResult(LoginResult.Reason.ACCOUNT_LOCKED, null);
        }
        if (block == LoginThrottleService.BlockReason.RATE_LIMITED) {
            return new LoginResult(LoginResult.Reason.RATE_LIMITED, null);
        }

        UserAccount user = userDirectory.findByUsername(username);
        // Same BAD_CREDENTIALS reason for unknown user and wrong password: no user enumeration.
        if (user == null || !passwordMatches(password, user.getPassword())) {
            LoginThrottleService.FailureReport report = throttle.recordFailure(username);
            log.info("Login failed user={} reason=BAD_CREDENTIALS evidence={}", username, report);
            LoginResult.Reason reason = switch (report.reason()) {
                case ACCOUNT_LOCKED -> LoginResult.Reason.ACCOUNT_LOCKED;
                case RATE_LIMITED -> LoginResult.Reason.RATE_LIMITED;
                case NONE -> LoginResult.Reason.BAD_CREDENTIALS;
            };
            return new LoginResult(reason, null);
        }
        if (!user.isEnabled()) {
            log.info("Login rejected user={} reason=ACCOUNT_DISABLED", username);
            return new LoginResult(LoginResult.Reason.ACCOUNT_DISABLED, null);
        }

        SessionManager.IssueResult issue = sessionManager.issue(
                username, user.getRole().name(), settings.maxSessionsPerUser());
        if (issue.status() == SessionManager.IssueResult.Status.CONCURRENCY_LIMIT) {
            log.info("Login rejected user={} reason=CONCURRENCY_LIMIT maxSessions={}",
                    username, settings.maxSessionsPerUser());
            return new LoginResult(LoginResult.Reason.CONCURRENCY_LIMIT, null);
        }
        throttle.reset(username);
        log.info("Login success user={} role={} token={} settingsVersion={}",
                username, user.getRole(), SessionManager.mask(issue.session().token()),
                settings.version());
        return new LoginResult(LoginResult.Reason.SUCCESS, issue.session());
    }

    /** Logs out the presented session token. */
    public boolean logout(String token) {
        boolean done = sessionManager.logout(token);
        log.info("Logout token={} result={}", SessionManager.mask(token), done);
        return done;
    }

    private boolean passwordMatches(String presented, String stored) {
        if (presented == null) {
            return false;
        }
        // Demo project stores plaintext; compare in constant time.
        return MessageDigest.isEqual(
                presented.getBytes(StandardCharsets.UTF_8), stored.getBytes(StandardCharsets.UTF_8));
    }
}
