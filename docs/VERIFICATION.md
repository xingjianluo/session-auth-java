# 验证方法

## 一键运行

```bash
mvn test
```

测试使用 `MutableTimeSource` 替换系统时钟（`TestSecurityConfiguration` 中 `@Primary`），
时间只有用例显式推进时才前进，因此过期/锁定/限流窗口的测试都是确定性的、无需真实等待。
每个用例在每个关键步骤都会通过日志打印 **关键输入（INPUT）与判定依据（JUDGEMENT）**，
鉴权判定另由 `AUTHZ_AUDIT` logger 以结构化方式输出（主体、资源属性、命中规则、
规则/设置版本）。

## 测试与需求点对照

| 测试类 | 覆盖场景 |
|---|---|
| `LoginSmokeTest` | 登录 → 会话/CSRF 基本链路；跨部门文档返回与不存在一致的 404；无 CSRF 的写操作被拒；安全响应头 |
| `ConcurrentLoginTest` | 第三次登录返回 `409 CONCURRENCY_LIMIT`；20 线程并发登录恰好只有 `maxSessions` 个成功，其余全部得到可区分的拒绝 |
| `LoginLockoutTest` | 连续 3 次失败锁定（当次即 423）、锁定期内正确密码也拒绝、TTL 后恢复；滑动窗口超限返回独立的 `429 RATE_LIMITED`；管理员解锁立即生效 |
| `SessionLifecycleTest` | 空闲过期 `SESSION_EXPIRED`（滑动窗口验证）；登出 `SESSION_LOGGED_OUT`；管理员撤销 `SESSION_REVOKED`；无 Cookie/未知 token 的区分；撤销后 16 个重复并发请求无一漏放 |
| `AccessControlTest` | USER 写文档被 `ROLE_DENIED`（403）；跨部门与不存在资源对外逐字节一致、审计中分别为 `ATTRIBUTE_DENIED`/`RESOURCE_NOT_FOUND`；未知受保护路径为 `PATH_NOT_FOUND`；MANAGER 同部门可写、跨部门 404；**同一 Session 内降权后下一个请求立即按新角色判定** |
| `ConfigSwitchTest` | 运行时关闭/开启 CSRF 后后续结论随之变化且会话不失效；`default`→`strict` 规则切换改变 ABAC 结论；用保留的历史规则版本重放得到与历史一致的 ALLOW；切换后公开入口仍可访问 |
| `CrossCuttingTest` | CORS 预检无会话返回 204；成功/401/404 响应均带安全头；公开入口不被拦截；用户名不存在与密码错误响应一致；禁用用户后其现有会话立即失效且无法再登录 |

## 手工验证示例

```bash
# 并发登录上限（上限为 2）
for i in 1 2 3; do
  curl -s -o /dev/null -w "%{http_code} " -X POST localhost:8080/api/auth/login \
    -H 'Content-Type: application/json' -d '{"username":"bob","password":"bob123"}'
done; echo   # 期望: 200 200 409

# 触发连续失败锁定（默认阈值 5）
for i in $(seq 1 6); do
  curl -s -X POST localhost:8080/api/auth/login -H 'Content-Type: application/json' \
    -d '{"username":"carol","password":"bad"}' | head -c 200; echo
done   # 前 4 次 BAD_CREDENTIALS，第 5 次起 ACCOUNT_LOCKED

# 越权与资源存在性隐藏（bob=ENG/USER 访问 SALES 文档 vs 不存在文档）
curl -s -b cookies.txt localhost:8080/api/documents/d-sales-1
curl -s -b cookies.txt localhost:8080/api/documents/no-such-doc
# 两者均为 {"code":"NOT_FOUND",...}；精确原因仅在 /api/admin/audit/by-path 中可查

# 规则切换（需 ADMIN 的会话与 CSRF 头）
curl -b admin.txt -X POST "localhost:8080/api/admin/rules/switch?profile=strict" \
  -H "X-CSRF-TOKEN: <admin csrf>"

# 降权即时生效：把 alice 降为 USER 后，用她原来的会话再发写请求立即变 403
curl -b admin.txt -X POST localhost:8080/api/admin/users/alice/role \
  -H "X-CSRF-TOKEN: <admin csrf>" -H 'Content-Type: application/json' -d '{"role":"USER"}'
```

## 配置项（application.properties）

```properties
app.security.session.idle-timeout-millis=1800000   # 空闲过期
app.security.login.max-sessions-per-user=2         # 每用户并发会话上限
app.security.login.lock-threshold=5                # 连续失败锁定阈值
app.security.login.lock-millis=300000
app.security.login.rate-limit-attempts=10          # 滑动窗口限流
app.security.login.rate-limit-window-millis=60000
app.security.login.rate-limit-block-millis=60000
app.security.csrf.enabled=true
app.security.cors.enabled=true
```

所有配置项均可通过 `POST /api/admin/config` 在运行时修改并立即生效，且每次修改产生新的
设置版本号写入审计，便于对照复现。
