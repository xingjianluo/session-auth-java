package com.github.xingjianluo.sessionauthjava.auth.policy;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicLong;

/**
 * 判定日志：每条判定记录其依据的策略版本与关键输入，结论可回放。
 *
 * <ul>
 *   <li>容量有界（默认保留最近 1000 条），超限淘汰最旧记录，
 *       长时间运行/反复切换策略不会无限增长。</li>
 *   <li>回放使用记录中保存的策略版本与输入，经 {@link PolicyEvaluator}
 *       重算，与当前策略无关，保证结论与当时一致。</li>
 * </ul>
 */
@Component
public class DecisionLog {

    private static final Logger log = LoggerFactory.getLogger(DecisionLog.class);

    /** 判定记录保留上限 */
    static final int CAPACITY = 1000;

    // 判定种类
    public static final String KIND_PUBLIC_PATH = "PUBLIC_PATH";
    public static final String KIND_CORS_ORIGIN = "CORS_ORIGIN";
    public static final String KIND_CSRF_REQUIRED = "CSRF_REQUIRED";
    public static final String KIND_SESSION_LIMIT = "SESSION_LIMIT";
    public static final String KIND_LOGIN_BLOCKED = "LOGIN_BLOCKED";

    private final PolicyService policyService;
    private final AtomicLong idSequence = new AtomicLong(0);
    private final Map<Long, DecisionRecord> records = new LinkedHashMap<>();
    private final Deque<Long> insertionOrder = new ArrayDeque<>();

    public DecisionLog(PolicyService policyService) {
        this.policyService = policyService;
    }

    /** 记录一条判定，返回判定 ID。 */
    public long record(String kind, long policyVersion, Map<String, String> inputs, String outcome) {
        long id = idSequence.incrementAndGet();
        DecisionRecord record = new DecisionRecord(id, kind, policyVersion,
                Map.copyOf(inputs), outcome, Instant.now());
        synchronized (this) {
            records.put(id, record);
            insertionOrder.addLast(id);
            while (records.size() > CAPACITY) {
                Long evicted = insertionOrder.pollFirst();
                if (evicted != null) {
                    records.remove(evicted);
                }
            }
        }
        log.info("[decision] id={} kind={} policyVersion={} inputs={} -> outcome={}",
                id, kind, policyVersion, inputs, outcome);
        return id;
    }

    /** 按编号取原始判定记录（运维查询用）；已被淘汰返回空。 */
    public Optional<DecisionRecord> find(long decisionId) {
        synchronized (this) {
            return Optional.ofNullable(records.get(decisionId));
        }
    }

    /** 当前保留的判定记录，按编号升序（运维列表用，有界拷贝）。 */
    public java.util.List<DecisionRecord> all() {
        synchronized (this) {
            return insertionOrder.stream().map(records::get).toList();
        }
    }

    /** 回放结果：原记录结论与按当时策略重算的结论（两者一致即回放吻合）。 */
    public record ReplayResult(DecisionRecord record, String replayedOutcome) {
        public boolean matches() {
            return record.outcome().equals(replayedOutcome);
        }
    }

    /**
     * 回放历史判定：取记录当时的策略版本与输入重算结论，连同原结论一起返回。
     * 记录或对应策略版本已被淘汰时返回空。
     */
    public Optional<ReplayResult> replayDetailed(long decisionId) {
        Optional<DecisionRecord> found = find(decisionId);
        if (found.isEmpty()) {
            log.info("[decision] replay id={} -> record evicted", decisionId);
            return Optional.empty();
        }
        DecisionRecord record = found.get();
        Optional<AuthPolicy> policy = policyService.version(record.policyVersion());
        if (policy.isEmpty()) {
            log.info("[decision] replay id={} -> policy version={} evicted", decisionId, record.policyVersion());
            return Optional.empty();
        }
        String outcome = evaluate(record.kind(), policy.get(), record.inputs());
        log.info("[decision] replay id={} kind={} policyVersion={} -> outcome={} (original={})",
                decisionId, record.kind(), record.policyVersion(), outcome, record.outcome());
        return Optional.of(new ReplayResult(record, outcome));
    }

    /**
     * 回放历史判定：取记录当时的策略版本与输入重算结论。
     * 记录或对应策略版本已被淘汰时返回空。
     */
    public Optional<String> replay(long decisionId) {
        return replayDetailed(decisionId).map(ReplayResult::replayedOutcome);
    }

    /** 用指定策略与输入重算某类判定的结论（线上与回放共用）。 */
    /**
     * 用指定策略与输入重算某类判定的结论（线上与回放共用）。
     * 返回的结论词表与线上记录时完全一致。
     */
    static String evaluate(String kind, AuthPolicy policy, Map<String, String> inputs) {
        return switch (kind) {
            case KIND_PUBLIC_PATH -> String.valueOf(
                    PolicyEvaluator.isPublicPath(policy, inputs.get("path")));
            case KIND_CORS_ORIGIN -> PolicyEvaluator.isOriginAllowed(policy, inputs.get("origin"))
                    ? "ALLOWED" : "DENIED";
            case KIND_CSRF_REQUIRED -> PolicyEvaluator.csrfCheckRequired(policy, inputs.get("method"),
                    Boolean.parseBoolean(inputs.get("publicPath"))) ? "REQUIRED" : "SKIPPED";
            case KIND_SESSION_LIMIT -> PolicyEvaluator.sessionLimitReached(policy,
                    Integer.parseInt(inputs.get("activeCount"))) ? "DENIED" : "ALLOWED";
            case KIND_LOGIN_BLOCKED -> PolicyEvaluator.loginBlocked(policy,
                    Integer.parseInt(inputs.get("failuresInWindow")),
                    Integer.parseInt(inputs.get("consecutiveFailures")),
                    inputs.get("lockedUntil").isEmpty() ? null : Instant.parse(inputs.get("lockedUntil")),
                    Instant.parse(inputs.get("now"))).orElse("NONE");
            default -> throw new IllegalArgumentException("unknown decision kind: " + kind);
        };
    }

    /** 观测用：当前保留的记录数（验证有界性）。 */
    public synchronized int size() {
        return records.size();
    }

    /** 取某类判定中最新的一条（测试与排障观测用）。 */
    public Optional<DecisionRecord> latestOfKind(String kind) {
        synchronized (this) {
            var it = insertionOrder.descendingIterator();
            while (it.hasNext()) {
                DecisionRecord record = records.get(it.next());
                if (record != null && record.kind().equals(kind)) {
                    return Optional.of(record);
                }
            }
            return Optional.empty();
        }
    }
}
