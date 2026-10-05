package com.github.xingjianluo.sessionauthjava.auth.policy;

import java.time.Instant;
import java.util.Map;

/**
 * 一条策略判定的历史记录：判定种类、关键输入、结论、依据的策略版本。
 *
 * @param id            判定 ID（单调递增）
 * @param kind          判定种类（如 PUBLIC_PATH / CORS_ORIGIN / CSRF_REQUIRED / SESSION_LIMIT / LOGIN_BLOCKED）
 * @param policyVersion 判定时生效的策略版本
 * @param inputs        关键输入（回放时原样使用）
 * @param outcome       当时结论
 * @param decidedAt     判定时刻
 */
public record DecisionRecord(long id, String kind, long policyVersion,
                             Map<String, String> inputs, String outcome, Instant decidedAt) {
}
