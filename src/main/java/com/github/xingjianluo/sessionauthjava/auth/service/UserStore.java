package com.github.xingjianluo.sessionauthjava.auth.service;

import com.github.xingjianluo.sessionauthjava.auth.model.UserAccount;
import org.springframework.stereotype.Component;

import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 内存用户存储（模拟真实登录链路中的用户目录）。
 */
@Component
public class UserStore {

    private final Map<String, UserAccount> users = new ConcurrentHashMap<>();

    public UserStore() {
        // 预置演示用户
        save(new UserAccount("alice", "alice-pass", com.github.xingjianluo.sessionauthjava.auth.model.Role.ADMIN, Set.of("dept:eng")));
        save(new UserAccount("bob", "bob-pass", com.github.xingjianluo.sessionauthjava.auth.model.Role.USER, Set.of("dept:ops")));
    }

    public Optional<UserAccount> findByUsername(String username) {
        return Optional.ofNullable(users.get(username));
    }

    public void save(UserAccount account) {
        users.put(account.username(), account);
    }

    /** 变更角色（模拟降权/升权），后续判定立即按新角色执行 */
    public void updateRole(String username, com.github.xingjianluo.sessionauthjava.auth.model.Role role) {
        users.computeIfPresent(username, (k, u) -> u.withRole(role));
    }
}
