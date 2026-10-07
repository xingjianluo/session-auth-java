package com.github.xingjianluo.sessionauthjava.auth.policy;

import com.github.xingjianluo.sessionauthjava.auth.config.AuthSecurityProperties;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Consumer;

/**
 * 策略版本管理。
 *
 * <ul>
 *   <li>当前策略放在 {@link AtomicReference} 中，读取无锁、切换原子，
 *       新请求立即看到新版本，不会读到"半个"策略。</li>
 *   <li>历史版本有界保留（默认最近 64 版），供历史判定回放；
 *       超出容量淘汰最旧版本，反复切换不会无限占用内存。</li>
 *   <li>版本号单调递增，每条判定记录所依据的版本号。</li>
 * </ul>
 */
@Service
public class PolicyService {

    private static final Logger log = LoggerFactory.getLogger(PolicyService.class);

    /** 历史版本保留上限（含当前版本） */
    static final int HISTORY_CAPACITY = 64;

    private final AtomicReference<AuthPolicy> current;
    /**
     * version -> 快照；必须用<b>插入序</b>（accessOrder=false）：淘汰只按版本新旧，
     * 回放时的 {@link #version(long)} 读取不能把老版本"刷新"成最近使用而导致它永不淘汰。
     */
    private final Map<Long, AuthPolicy> history;

    public PolicyService(AuthSecurityProperties properties) {
        AuthPolicy initial = AuthPolicy.snapshot(1, properties);
        this.current = new AtomicReference<>(initial);
        this.history = new LinkedHashMap<>() {
            @Override
            protected boolean removeEldestEntry(Map.Entry<Long, AuthPolicy> eldest) {
                return size() > HISTORY_CAPACITY;
            }
        };
        this.history.put(initial.version(), initial);
        log.info("[policy] initialized version={} {}", initial.version(), describe(initial));
    }

    /** 当前生效策略（每次调用读到同一时刻的一致快照）。 */
    public AuthPolicy current() {
        return current.get();
    }

    /**
     * 运行期调整策略：基于当前快照应用修改并发布新版本，发布后新请求立即按新策略判定。
     * 同步保证连续切换时版本号与历史登记不交错。
     */
    public synchronized AuthPolicy update(Consumer<AuthSecurityProperties> mutation) {
        AuthPolicy base = current.get();
        AuthSecurityProperties draft = base.toProperties();
        mutation.accept(draft);
        AuthPolicy next = AuthPolicy.snapshot(base.version() + 1, draft);
        current.set(next);
        history.put(next.version(), next);
        log.info("[policy] switched v{} -> v{} {}", base.version(), next.version(), describe(next));
        return next;
    }

    /** 按版本号取历史策略（用于回放）；已被淘汰则返回空。 */
    public Optional<AuthPolicy> version(long version) {
        synchronized (this) {
            return Optional.ofNullable(history.get(version));
        }
    }

    /** 当前仍保留（可回放）的策略版本号列表，按版本升序。 */
    public java.util.List<Long> versions() {
        synchronized (this) {
            return history.keySet().stream().sorted().toList();
        }
    }

    /** 观测用：当前保留的历史版本数（验证有界性）。 */
    public synchronized int historySize() {
        return history.size();
    }

    private static String describe(AuthPolicy p) {
        return "{sessionTtl=" + p.sessionTtl()
                + ", maxConcurrentSessions=" + p.maxConcurrentSessions()
                + ", maxFailedAttempts=" + p.maxFailedAttempts()
                + ", lockDuration=" + p.lockDuration()
                + ", rateLimitWindow=" + p.rateLimitWindow()
                + ", rateLimitMaxAttempts=" + p.rateLimitMaxAttempts()
                + ", publicPaths=" + p.publicPaths()
                + ", csrfEnabled=" + p.csrfEnabled()
                + ", allowedOrigins=" + p.allowedOrigins() + "}";
    }
}
