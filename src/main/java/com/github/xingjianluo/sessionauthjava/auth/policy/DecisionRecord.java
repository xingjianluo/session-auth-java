package com.github.xingjianluo.sessionauthjava.auth.policy;

import java.time.Instant;
import java.util.Map;

/**
 * 一条历史判定记录：判定类型、依据的策略版本、关键输入与结论。
 *
 * @param id            单调递增的判定 ID
 * @param at            判定时间
 * @param type          判定类型（如 SESSION_VALIDATE / LOGIN_BLOCKED / CORS_ORIGIN 等）
 * @param policyVersion 判定时生效的策略版本
 * @param inputs        关键输入（用于回放）
 * @param outcome       判定结论
 */
public record DecisionRecord(long id, Instant at, String type, long policyVersion,
                             Map<String, String> inputs, String outcome) {
}
