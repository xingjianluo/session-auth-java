package com.github.xingjianluo.sessionauthjava.auth.policy;

/**
 * 历史判定回放结果。
 */
public record ReplayResult(Status status, DecisionRecord record, Long policyVersion,
                           String replayedOutcome, Boolean matches) {

    public enum Status {
        /** 回放完成 */
        REPLAYED,
        /** 判定记录不存在（或已被淘汰） */
        DECISION_NOT_FOUND,
        /** 判定记录存在，但对应策略版本已被淘汰 */
        POLICY_VERSION_EVICTED
    }

    public static ReplayResult replayed(DecisionRecord record, long policyVersion,
                                        String replayedOutcome, boolean matches) {
        return new ReplayResult(Status.REPLAYED, record, policyVersion, replayedOutcome, matches);
    }

    public static ReplayResult decisionNotFound() {
        return new ReplayResult(Status.DECISION_NOT_FOUND, null, null, null, null);
    }

    public static ReplayResult policyEvicted(DecisionRecord record) {
        return new ReplayResult(Status.POLICY_VERSION_EVICTED, record, record.policyVersion(), null, null);
    }
}
