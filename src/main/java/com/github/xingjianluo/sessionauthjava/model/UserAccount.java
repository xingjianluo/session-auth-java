package com.github.xingjianluo.sessionauthjava.model;

import java.util.HashMap;
import java.util.Map;

/** A user account as stored in the in-memory directory. */
public class UserAccount {

    private final String username;
    private String password;
    private boolean enabled = true;
    private Role role = Role.USER;
    private String department = "";
    private final Map<String, String> attributes = new HashMap<>();

    public UserAccount(String username, String password) {
        this.username = username;
        this.password = password;
    }

    public String getUsername() { return username; }
    public String getPassword() { return password; }
    public void setPassword(String password) { this.password = password; }
    public boolean isEnabled() { return enabled; }
    public void setEnabled(boolean enabled) { this.enabled = enabled; }
    public Role getRole() { return role; }
    public void setRole(Role role) { this.role = role; }
    public String getDepartment() { return department; }
    public void setDepartment(String department) { this.department = department; }
    public Map<String, String> getAttributes() { return attributes; }
}
