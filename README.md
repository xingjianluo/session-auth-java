# session-auth-java-bootstrap-a

基于 Spring Boot 3 / Java 21 的**本地会话认证与访问控制**示例。使用内存状态模拟真实登录链路，
覆盖并发登录、会话失效、基于角色（RBAC）与属性（ABAC）的访问控制，以及与 CSRF / CORS /
安全响应头等横切规则的组合判定。所有关键判定都会打印“输入 + 依据”，失败原因可区分且可复现。

## 快速开始

```bash
mvn spring-boot:run          # 启动服务（默认端口 8080）
mvn test                     # 运行全部 26 个测试
```

启动后内置账号与文档资源：

| 账号 | 密码 | 角色 | 部门 |
|---|---|---|---|
| admin | admin123 | ADMIN | HQ |
| alice | alice123 | MANAGER | ENG |
| bob   | bob123   | USER | ENG |
| carol | carol123 | USER | SALES |

| 文档 ID | 部门 | 所有者 |
|---|---|---|
| d-eng-1 | ENG | alice |
| d-sales-1 | SALES | carol |

## 最小调用链

```bash
# 1) 登录（公开入口），Set-Cookie: SID=...，响应体含 csrfToken
curl -i -c cookies.txt -X POST http://localhost:8080/api/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"bob","password":"bob123"}'

# 2) 安全方法（GET）只带 Cookie
curl -b cookies.txt http://localhost:8080/api/documents/d-eng-1

# 3) 状态变更（POST/PUT/DELETE）必须同时带 Cookie 与 CSRF 头
curl -b cookies.txt -X POST http://localhost:8080/api/documents \
  -H "X-CSRF-TOKEN: <登录返回的 csrfToken>" -H 'Content-Type: application/json' \
  -d '{"title":"t","content":"c","department":"ENG"}'

# 4) 登出
curl -b cookies.txt -X POST http://localhost:8080/api/auth/logout \
  -H "X-CSRF-TOKEN: <csrfToken>"
```

详细设计见 [`docs/SECURITY.md`](docs/SECURITY.md)，接口清单与错误码见
[`docs/API.md`](docs/API.md)，验证方法见 [`docs/VERIFICATION.md`](docs/VERIFICATION.md)。
