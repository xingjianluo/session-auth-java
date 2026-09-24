package com.github.xingjianluo.sessionauthjava.auth.model;

import java.util.Set;

/**
 * 内存用户账户模型。
 *
 * @param username   用户名（唯一）
 * @param password   明文密码（本地模拟，不用于生产）
 * @param role       角色
 * @param attributes 属性集合（如部门、标签），供属性级访问控制使用
 */
public record UserAccount(String username, String password, Role role, Set<String> attributes) {

    public UserAccount withRole(Role newRole) {
        return new UserAccount(username, password, newRole, attributes);
    }
}
