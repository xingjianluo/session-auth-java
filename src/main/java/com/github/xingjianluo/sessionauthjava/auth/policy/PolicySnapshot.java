package com.github.xingjianluo.sessionauthjava.auth.policy;

/**
 * 带版本号的策略快照。版本号单调递增。
 */
public record PolicySnapshot(long version, PolicySettings settings) {
}
