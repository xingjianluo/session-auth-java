# session-auth-java：本地会话认证与访问控制

基于 Spring Boot 3.4 / Java 21 的内存态会话认证与访问控制实现，模拟真实登录链路，
保证并发登录、会话失效与权限判定在各入口下结论一致且可解释。

## 1. 会话模型

- **签发**：`POST /api/auth/login` 校验凭据后签发会话，返回 `sessionId` 与 `csrfToken`。
  会话记录包含：`sessionId`、`username`、签发时角色、签发时间、过期时间、撤销标记。
- **校验**：受保护请求携带 `X-Session-Id` 头，`AuthFilter` 校验后将会话挂到请求属性。
- **失效语义（可区分）**：

  | 失效方式 | 触发 | 后续请求的判定结果 |
  |---|---|---|
  | 主动登出 | `POST /api/auth/logout` | `401 SESSION_NOT_FOUND`（记录已移除） |
  | 过期 | 超过 `auth.security.session-ttl` | `401 SESSION_EXPIRED`（记录保留） |
  | 撤销 | 强制下线/降权时 `revokeAllForUser` | `401 SESSION_REVOKED`（记录保留并标记） |
  | 并发超限 | 第 N+1 次登录 | `409 CONCURRENT_SESSION_LIMIT_EXCEEDED` |

- **并发一致性**：登录按用户串行化（检查-计数-签发原子化），签发按用户加锁，
  并发登录下成功数恰好等于 `max-concurrent-sessions`，不会重复放行同一会话、计数不错乱。

## 2. 权限规则

- **角色**：`ADMIN` 包含 `USER`（等级制）。判定使用用户**当前**角色而非会话签发时快照，
  降权/升权后下一个请求立即按新状态判定。
- **属性**：用户携带属性集合（如 `dept:eng`），资源可要求必需属性。
- **判定结果可区分**：`401 UNAUTHENTICATED`（未认证）/ `403 ROLE_INSUFFICIENT`（角色不足）/
  `403 ATTRIBUTE_MISSING`（缺少属性）。
- **不泄漏资源存在性**：访问控制判定发生在资源加载之前，越权时无论资源是否存在，
  响应均为统一的 `403` 错误体。

预置用户：`alice/alice-pass`（ADMIN, dept:eng）、`bob/bob-pass`（USER, dept:ops）。

资源入口：

| 路径 | 要求 |
|---|---|
| `GET /api/public/health` | 公开 |
| `GET /api/user/profile` | 任意已认证用户 |
| `GET /api/user/eng-docs` | USER 角色 + 属性 `dept:eng` |
| `GET /api/admin/stats` | ADMIN 角色 |

## 3. 限流与锁定策略

- **限流**：同一用户在滑动窗口（`rate-limit-window`，默认 1 分钟）内失败次数达到
  `rate-limit-max-attempts`（默认 5）→ `429 RATE_LIMITED`。
- **锁定**：连续失败达到 `max-failed-attempts`（默认 3）→ 锁定 `lock-duration`
  （默认 5 分钟），期间所有登录返回 `423 ACCOUNT_LOCKED`；期满自动解锁。
- 登录成功清除全部失败计数；锁定/限流期间的请求不再放大计数。
- 用户不存在与密码错误统一返回 `401 INVALID_CREDENTIALS`，不泄漏用户是否存在。

## 4. 横切规则组合

过滤器顺序固定：**安全响应头(1) → 认证(2) → CSRF(3)**。

- **安全响应头**：所有 `/api/*` 响应（含拒绝响应）统一附加
  `X-Content-Type-Options: nosniff`、`X-Frame-Options: DENY` 等。
- **CSRF**：对已认证的变更类请求（POST/PUT/DELETE/PATCH）校验 `X-CSRF-Token`
  （登录响应中下发，由会话 ID 确定性派生）；公开路径与安全方法不校验；
  `auth.security.csrf-enabled=false` 可整体关闭。
- **CORS**：仅允许 `auth.security.allowed-origins` 配置的来源。
- **公开路径**：`auth.security.public-paths` 中的路径绝不进入认证逻辑，不会被误拦截。
- **可复现性**：所有判定仅依赖请求时刻生效的配置快照；配置变更（如上限、公开路径、
  CSRF 开关）后新判定按新配置执行，历史判定结论可由当时配置复现。

## 5. 配置项（application.properties）

```properties
auth.security.session-ttl=30m              # 会话有效期
auth.security.max-concurrent-sessions=2    # 每用户最大并发会话数
auth.security.max-failed-attempts=3        # 连续失败锁定阈值
auth.security.lock-duration=5m             # 锁定时长
auth.security.rate-limit-window=1m         # 限流滑动窗口
auth.security.rate-limit-max-attempts=5    # 窗口内最大失败次数
auth.security.public-paths=/api/public/**,/api/auth/login
auth.security.csrf-enabled=true
auth.security.allowed-origins=http://localhost:3000
```

## 6. 验证方法

```bash
mvn test          # 全部 35 个测试
mvn spring-boot:run   # 本地启动后手工验证
```

手工验证示例：

```bash
# 登录
curl -s -X POST localhost:8080/api/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"alice","password":"alice-pass"}'
# -> {"sessionId":"...","csrfToken":"...",...}

# 访问受保护资源
curl -s localhost:8080/api/admin/stats -H "X-Session-Id: <sessionId>"

# 登出（需 CSRF 令牌）
curl -s -X POST localhost:8080/api/auth/logout \
  -H "X-Session-Id: <sessionId>" -H "X-CSRF-Token: <csrfToken>"

# 登出后再访问 -> 401 SESSION_NOT_FOUND
curl -s localhost:8080/api/admin/stats -H "X-Session-Id: <sessionId>"
```

测试覆盖（日志均打印关键输入与判定依据）：

| 测试类 | 覆盖场景 |
|---|---|
| `LoginAttemptServiceTest` | 限流窗口、锁定触发/期满、成功清零、并发失败计数精确性 |
| `SessionServiceTest` | 过期/登出/撤销原因区分、并发签发不超上限不重复、并发校验一致性 |
| `AuthServiceConcurrencyTest` | 32 线程并发登录恰好 2 个成功、16 线程并发失败恰好锁定一次 |
| `AccessControlServiceTest` | 角色/属性判定、降权立即生效、越权原因可区分 |
| `AuthFlowWebTest` | 全链路：登录→访问→登出→失效、CSRF、安全头、公开路径、越权、锁定 |
| `ConfigSwitchWebTest` | 配置切换（CSRF 关闭、上限=1、公开路径变更）后判定一致 |
