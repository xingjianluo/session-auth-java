package com.github.xingjianluo.sessionauthjava.model;

import java.util.Collection;
import java.util.concurrent.ConcurrentHashMap;
import org.springframework.stereotype.Component;

/**
 * In-memory user directory. Lookups return the live account instance so that
 * privilege changes (role downgrade, disablement) apply to the very next request
 * without touching existing sessions.
 */
@Component
public class UserDirectory {

    private final ConcurrentHashMap<String, UserAccount> users = new ConcurrentHashMap<>();

    public UserAccount findByUsername(String username) {
        if (username == null) {
            return null;
        }
        return users.get(username);
    }

    public UserAccount save(UserAccount user) {
        users.put(user.getUsername(), user);
        return user;
    }

    public boolean delete(String username) {
        return users.remove(username) != null;
    }

    public Collection<UserAccount> all() {
        return users.values();
    }
}
