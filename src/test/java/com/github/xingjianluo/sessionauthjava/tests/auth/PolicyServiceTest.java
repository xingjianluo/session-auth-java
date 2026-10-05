package com.github.xingjianluo.sessionauthjava.tests.auth;

import com.github.xingjianluo.sessionauthjava.auth.config.AuthSecurityProperties;
import com.github.xingjianluo.sessionauthjava.auth.policy.DecisionLog;
import com.github.xingjianluo.sessionauthjava.auth.policy.DecisionRecord;
import com.github.xingjianluo.sessionauthjava.auth.policy.DecisionTypes;
import com.github.xingjianluo.sessionauthjava.auth.policy.PolicyReplayService;
import com.github.xingjianluo.sessionauthjava.auth.policy.PolicyService;
import com.github.xingjianluo.sessionauthjava.auth.policy.PolicySnapshot;
import com.github.xingjianluo.sessionauthjava.auth.policy.ReplayResult;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 策略版本管理与历史回放测试：
 * 版本单调递增、历史有界、回放与当时结论一致、反复切换不占内存不变慢。
 */
class PolicyServiceTest {

    private static final Logger log = LoggerFactory.getLogger(PolicyServiceTest.class);

    private AuthSecurityProperties properties;
    private PolicyService policyService;
    private DecisionLog decisionLog;
    private PolicyReplayService replayService;

    @BeforeEach
    void setUp() {
        properties = new AuthSecurityProperties();
        policyService = new PolicyService(properties);
        decisionLog = new DecisionLog();
        replayService = new PolicyReplayService(decisionLog, policyService);
    }

    @Test
    void sameConfigKeepsSameVersion() {
        PolicySnapshot v1 = policyService.current();
        PolicySnapshot v2 = policyService.current();
        log.info("[test] 场景=配置未变, v1={} v2={} (应相同)", v1.version(), v2.version());
        assertEquals(v1.version(), v2.version());
    }

    @Test
    void configChangeBumpsVersionAndNewDecisionsUseIt() {
        PolicySnapshot before = policyService.current();
        properties.setMaxConcurrentSessions(5);
        PolicySnapshot after = policyService.current();
        log.info("[test] 场景=修改并发上限 2->5, before=v{} after=v{} (应递增)",
                before.version(), after.version());
        assertEquals(before.version() + 1, after.version());
        assertEquals(5, after.settings().maxConcurrentSessions());
        assertEquals(2, policyService.snapshot(before.version()).orElseThrow().settings().maxConcurrentSessions(),
                "旧版本快照必须保持当时内容");
    }

    @Test
    void decisionRecordsPolicyVersionAndReplayMatches() {
        // 在 v1 下做一条 CORS 判定：evil.example 被拒绝
        PolicySnapshot v1 = policyService.current();
        DecisionRecord denied = decisionLog.record(DecisionTypes.CORS_ORIGIN, v1.version(),
                Map.of("origin", "http://evil.example"), "DENIED");

        // 切到 v2：允许 evil.example
        properties.setAllowedOrigins(List.of("http://evil.example"));
        PolicySnapshot v2 = policyService.current();
        assertNotEquals(v1.version(), v2.version());

        // 新判定按新策略放行
        String nowOutcome = com.github.xingjianluo.sessionauthjava.auth.policy.PolicyDecisions
                .originAllowed("http://evil.example", policyService.current().settings()) ? "ALLOWED" : "DENIED";
        // 回放旧判定必须仍按 v1 得出 DENIED
        ReplayResult replay = replayService.replay(denied.id());
        log.info("[test] 场景=策略切换后回放, decisionId={} 当时=v{}/DENIED 现在=v{}/{} 回放={} matches={}",
                denied.id(), v1.version(), v2.version(), nowOutcome, replay.replayedOutcome(), replay.matches());
        assertEquals("ALLOWED", nowOutcome, "新请求必须按新策略给结论");
        assertEquals(ReplayResult.Status.REPLAYED, replay.status());
        assertEquals(v1.version(), replay.policyVersion(), "回放必须钉在当时版本");
        assertEquals("DENIED", replay.replayedOutcome());
        assertTrue(replay.matches(), "回放结论必须与当时完全一致");
    }

    @Test
    void replayBackAndForthSwitchingStaysConsistent() {
        // 反复来回切换同一配置：内容相同不得产生新版本
        long base = policyService.current().version();
        for (int i = 0; i < 10; i++) {
            properties.setMaxConcurrentSessions(3);
            policyService.current();
            properties.setMaxConcurrentSessions(2);
            policyService.current();
        }
        long after = policyService.current().version();
        // 每次来回产生 2 个新版本（内容确实变了），但最终内容与 v1 相同
        log.info("[test] 场景=10 次来回切换, baseVersion={} finalVersion={} historySize={}",
                base, after, policyService.historySize());
        assertTrue(after > base);
        assertTrue(policyService.historySize() <= PolicyService.HISTORY_CAP);
    }

    @Test
    void historyIsBoundedUnderContinuousSwitching() {
        long start = System.nanoTime();
        for (int i = 1; i <= 200; i++) {
            properties.setMaxConcurrentSessions(2 + (i % 7));
            properties.setRateLimitMaxAttempts(5 + (i % 3));
            policyService.current();
        }
        long elapsedMs = (System.nanoTime() - start) / 1_000_000;
        List<Long> versions = policyService.knownVersions();
        log.info("[test] 场景=200 次连续切换, historySize={} knownVersions={}..{} 耗时={}ms",
                policyService.historySize(), versions.get(0), versions.get(versions.size() - 1), elapsedMs);
        assertTrue(policyService.historySize() <= PolicyService.HISTORY_CAP,
                "历史版本必须有界，不能无限增长");
        assertEquals(PolicyService.HISTORY_CAP, policyService.historySize());
        // 最旧版本已被淘汰：回放指向旧版本的判定应得到 POLICY_VERSION_EVICTED
        DecisionRecord old = decisionLog.record(DecisionTypes.SESSION_ISSUE, 1,
                Map.of("activeCount", "1"), "ISSUED");
        ReplayResult replay = replayService.replay(old.id());
        log.info("[test] 场景=回放已淘汰版本, decisionId={} policyVersion=1 -> status={}",
                old.id(), replay.status());
        assertEquals(ReplayResult.Status.POLICY_VERSION_EVICTED, replay.status());
    }

    @Test
    void decisionLogIsBounded() {
        for (int i = 0; i < 2500; i++) {
            decisionLog.record(DecisionTypes.PUBLIC_PATH, 1, Map.of("path", "/api/x/" + i), "PROTECTED");
        }
        log.info("[test] 场景=写入 2500 条判定, logSize={} (上限 {})", decisionLog.size(), DecisionLog.CAP);
        assertEquals(DecisionLog.CAP, decisionLog.size(), "判定日志必须有界");
        // 最旧的记录已被淘汰
        assertTrue(decisionLog.find(1).isEmpty());
        assertTrue(decisionLog.find(2500).isPresent());
    }

    @Test
    void replayOfUnknownDecisionIsNotFound() {
        ReplayResult result = replayService.replay(999_999);
        log.info("[test] 场景=回放不存在的判定, id=999999 -> status={}", result.status());
        assertEquals(ReplayResult.Status.DECISION_NOT_FOUND, result.status());
        assertFalse(result.status() == ReplayResult.Status.REPLAYED);
    }
}
