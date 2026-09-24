package com.github.xingjianluo.sessionauthjava.login;

import com.github.xingjianluo.sessionauthjava.config.SecurityConfigService;
import com.github.xingjianluo.sessionauthjava.config.SecuritySettings;
import com.github.xingjianluo.sessionauthjava.support.TimeSource;
import java.util.concurrent.ConcurrentHashMap;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

/**
 * Tracks failed login attempts per username and distinguishes two independent mechanisms:
 * <ul>
 *   <li><b>rate limiting</b>: more than {@code rateLimitAttempts} failures inside a sliding
 *       window produce a short block ({@link BlockReason#RATE_LIMITED});</li>
 *   <li><b>account locking</b>: {@code lockThreshold} consecutive failures produce a longer
 *       block ({@link BlockReason#ACCOUNT_LOCKED}).</li>
 * </ul>
 * All checks and mutations for one username are serialized on its state object so that
 * concurrent failed logins cannot miscount.
 */
@Service
public class LoginThrottleService {

    private static final Logger log = LoggerFactory.getLogger(LoginThrottleService.class);

    /** Reasons a request may be refused before credential checking. */
    public enum BlockReason {
        NONE,
        RATE_LIMITED,
        ACCOUNT_LOCKED
    }

    private final TimeSource timeSource;
    private final SecurityConfigService configService;
    private final ConcurrentHashMap<String, State> states = new ConcurrentHashMap<>();

    public LoginThrottleService(TimeSource timeSource, SecurityConfigService configService) {
        this.timeSource = timeSource;
        this.configService = configService;
    }

    /** Returns whether a login attempt for the user is currently blocked and why. */
    public BlockReason check(String username) {
        State state = states.get(username);
        if (state == null) {
            return BlockReason.NONE;
        }
        synchronized (state) {
            long now = timeSource.nowMillis();
            if (now < state.lockUntilMillis) {
                log.debug("Throttle check user={}: ACCOUNT_LOCKED for another {}ms",
                        username, state.lockUntilMillis - now);
                return BlockReason.ACCOUNT_LOCKED;
            }
            if (now < state.rateLimitUntilMillis) {
                log.debug("Throttle check user={}: RATE_LIMITED for another {}ms",
                        username, state.rateLimitUntilMillis - now);
                return BlockReason.RATE_LIMITED;
            }
            return BlockReason.NONE;
        }
    }

    /**
     * Records one failed password attempt against the currently effective settings and
     * returns the resulting block (if any) plus the counter evidence. The crossing attempt
     * itself is reported as blocked so callers can return the correct reason immediately.
     */
    public FailureReport recordFailure(String username) {
        SecuritySettings settings = configService.current();
        State state = states.computeIfAbsent(username, k -> new State());
        synchronized (state) {
            long now = timeSource.nowMillis();

            if (now - state.windowStartMillis >= settings.rateLimitWindowMillis()) {
                state.windowStartMillis = now;
                state.windowFailures = 0;
            }
            state.windowFailures++;
            state.consecutiveFailures++;

            boolean locked = false;
            boolean limited = false;
            if (state.consecutiveFailures >= settings.lockThreshold()
                    && state.lockUntilMillis <= now) {
                state.lockUntilMillis = now + settings.lockMillis();
                locked = true;
            }
            if (state.windowFailures >= settings.rateLimitAttempts()
                    && state.rateLimitUntilMillis <= now) {
                state.rateLimitUntilMillis = now + settings.rateLimitBlockMillis();
                limited = true;
            }
            BlockReason reason = locked ? BlockReason.ACCOUNT_LOCKED
                    : limited ? BlockReason.RATE_LIMITED : BlockReason.NONE;
            log.warn("Login failure recorded user={} consecutive={}/{} windowFailures={}/{} -> {}",
                    username, state.consecutiveFailures, settings.lockThreshold(),
                    state.windowFailures, settings.rateLimitAttempts(), reason);
            return new FailureReport(reason, state.consecutiveFailures, state.windowFailures,
                    state.lockUntilMillis, state.rateLimitUntilMillis);
        }
    }

    /** Clears all failure state after a successful login (also used as manual unlock). */
    public void reset(String username) {
        states.remove(username);
        log.info("Throttle state reset user={}", username);
    }

    /** Counter snapshot for tests and admin inspection. */
    public FailureReport snapshot(String username) {
        State state = states.get(username);
        if (state == null) {
            return new FailureReport(BlockReason.NONE, 0, 0, 0L, 0L);
        }
        synchronized (state) {
            return new FailureReport(check(username), state.consecutiveFailures,
                    state.windowFailures, state.lockUntilMillis, state.rateLimitUntilMillis);
        }
    }

    /** Per-user mutable counters; every access is guarded by {@code synchronized(this)}. */
    private static final class State {
        private int consecutiveFailures;
        private int windowFailures;
        private long windowStartMillis;
        private long lockUntilMillis;
        private long rateLimitUntilMillis;
    }

    /** Report snapshot for logging/tests. */
    public record FailureReport(BlockReason reason, int consecutiveFailures, int windowFailures,
                                long lockUntilMillis, long rateLimitUntilMillis) {
    }
}
