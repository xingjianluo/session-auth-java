package com.github.xingjianluo.sessionauthjava.auth.policy;

import com.github.xingjianluo.sessionauthjava.auth.config.AuthSecurityProperties;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * 策略版本管理：运行期配置变更自动生成新版本快照，
 * 历史版本有界保留，供判定记录标注与历史回放使用。
 *
 * <p>工作方式：底层 {@link AuthSecurityProperties} 仍是唯一的可变配置入口
 * （配置文件、测试直接改、管理端点改都一样）。每次取当前快照时与上一版比对，
 * 内容有变化则单调递增版本号并归档旧版。历史容量有界（{@link #HISTORY_CAP}），
 * 反复切换不会无限占用内存，也不会越跑越慢。
 */
@Service
public class PolicyService {

    private static final Logger log = LoggerFactory.getLogger(PolicyService.class);

    /** 历史版本保留上限，超出后淘汰最旧版本 */
    public static final int HISTORY_CAP = 64;

    private final AuthSecurityProperties properties;
    private final Object lock = new Object();

    private PolicySnapshot current;
    private final LinkedHashMap<Long, PolicySnapshot> history = new LinkedHashMap<>() {
        @Override
        protected boolean removeEldestEntry(Map.Entry<Long, PolicySnapshot> eldest) {
            return size() > HISTORY_CAP;
        }
    };

    public PolicyService(AuthSecurityProperties properties) {
        this.properties = properties;
    }

    /**
     * 当前生效的策略快照；配置自上次调用后有变化时生成新版本。
     * 同一配置内容下反复调用返回同一版本，不会产生新版本。
     */
    public PolicySnapshot current() {
        synchronized (lock) {
            PolicySettings settings = PolicySettings.from(properties);
            if (current != null && current.settings().equals(settings)) {
                return current;
            }
            long version = current == null ? 1 : current.version() + 1;
            current = new PolicySnapshot(version, settings);
            history.put(version, current);
            log.info("[policy] new snapshot version={} settings={}", version, settings);
            return current;
        }
    }

    /** 取某个历史版本的快照（可能已被淘汰） */
    public Optional<PolicySnapshot> snapshot(long version) {
        synchronized (lock) {
            return Optional.ofNullable(history.get(version));
        }
    }

    /** 当前保留的历史版本数（有界） */
    public int historySize() {
        synchronized (lock) {
            return history.size();
        }
    }

    /** 当前保留的所有版本号（升序） */
    public List<Long> knownVersions() {
        synchronized (lock) {
            return new ArrayList<>(history.keySet());
        }
    }
}
