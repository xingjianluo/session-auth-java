package com.github.xingjianluo.sessionauthjava.auth.policy;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * 历史判定回放：把一条历史判定放回它当时那版策略里重算，
 * 结论必须与当时完全一致。
 *
 * <p>回放与在线判定共用 {@link PolicyDecisions} 的纯函数，
 * 输入来自判定记录，策略来自该记录标注的历史版本，
 * 与当前生效策略完全隔离（不会串到最新策略）。
 */
@Service
public class PolicyReplayService {

    private static final Logger log = LoggerFactory.getLogger(PolicyReplayService.class);

    private final DecisionLog decisionLog;
    private final PolicyService policyService;

    public PolicyReplayService(DecisionLog decisionLog, PolicyService policyService) {
        this.decisionLog = decisionLog;
        this.policyService = policyService;
    }

    /** 回放指定 ID 的历史判定 */
    public ReplayResult replay(long decisionId) {
        Optional<DecisionRecord> found = decisionLog.find(decisionId);
        if (found.isEmpty()) {
            log.info("[replay] decisionId={} -> DECISION_NOT_FOUND", decisionId);
            return ReplayResult.decisionNotFound();
        }
        DecisionRecord record = found.get();
        Optional<PolicySnapshot> snapshot = policyService.snapshot(record.policyVersion());
        if (snapshot.isEmpty()) {
            log.info("[replay] decisionId={} policyVersion={} -> POLICY_VERSION_EVICTED",
                    decisionId, record.policyVersion());
            return ReplayResult.policyEvicted(record);
        }
        PolicySettings settings = snapshot.get().settings();
        String replayed = evaluate(record, settings);
        boolean matches = replayed.equals(record.outcome());
        log.info("[replay] decisionId={} type={} policyVersion={} original={} replayed={} matches={}",
                decisionId, record.type(), record.policyVersion(), record.outcome(), replayed, matches);
        return ReplayResult.replayed(record, record.policyVersion(), replayed, matches);
    }

    /** 用历史策略快照对记录的输入重算结论 */
    private String evaluate(DecisionRecord record, PolicySettings settings) {
        Map<String, String> in = record.inputs();
        return switch (record.type()) {
            case DecisionTypes.SESSION_VALIDATE -> {
                var reason = PolicyDecisions.validateSession(
                        bool(in, "exists"), bool(in, "loggedOut"), bool(in, "revoked"),
                        instantOrNull(in.get("expiresAt")), Instant.parse(in.get("now")));
                yield reason.map(Enum::name).orElse("OK");
            }
            case DecisionTypes.LOGIN_BLOCKED -> {
                var reason = PolicyDecisions.checkBlocked(
                        parseInstants(in.get("failures")), instantOrNull(in.get("lockedUntil")),
                        Instant.parse(in.get("now")), settings);
                yield reason.map(Enum::name).orElse("OK");
            }
            case DecisionTypes.SESSION_ISSUE ->
                    PolicyDecisions.issueAllowed(Integer.parseInt(in.get("activeCount")), settings)
                            ? "ISSUED" : "LIMIT_EXCEEDED";
            case DecisionTypes.PUBLIC_PATH ->
                    PolicyDecisions.isPublicPath(in.get("path"), settings) ? "PUBLIC" : "PROTECTED";
            case DecisionTypes.CORS_ORIGIN ->
                    PolicyDecisions.originAllowed(in.get("origin"), settings) ? "ALLOWED" : "DENIED";
            case DecisionTypes.CSRF -> PolicyDecisions.csrfOutcome(
                    in.get("method"), in.get("path"),
                    bool(in, "authenticated"), bool(in, "tokenValid"), settings);
            default -> throw new IllegalArgumentException("unknown decision type: " + record.type());
        };
    }

    private static boolean bool(Map<String, String> in, String key) {
        return Boolean.parseBoolean(in.get(key));
    }

    private static Instant instantOrNull(String value) {
        return (value == null || value.isEmpty()) ? null : Instant.parse(value);
    }

    private static List<Instant> parseInstants(String joined) {
        List<Instant> result = new ArrayList<>();
        if (joined == null || joined.isEmpty()) {
            return result;
        }
        for (String token : joined.split(",")) {
            result.add(Instant.ofEpochMilli(Long.parseLong(token)));
        }
        return result;
    }

    /** 生产方工具：把时间集合编码进判定记录输入 */
    public static String joinInstants(Iterable<Instant> instants) {
        StringBuilder sb = new StringBuilder();
        for (Instant instant : instants) {
            if (sb.length() > 0) {
                sb.append(',');
            }
            sb.append(instant.toEpochMilli());
        }
        return sb.toString();
    }
}
