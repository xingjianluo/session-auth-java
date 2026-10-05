# session-auth-java：本地会话认证与访问控制

基于 Spring Boot 3.4 / Java 21 的内存态会话认证与访问控制实现，模拟真实登录链路，
保证并发登录、会话失效与权限判定在各入口下结论一致且可解释。

## 1. 会话模型

- **签发**：`POST /api/auth/login` 校验凭据后签发会话，返回 `sessionId` 与 `csrfToken`。
  会话记录包含：`sessionId`、`username`、签发时角色、签发时间、过期时间、撤销标记。
- **校验**：受保护请求携带 `X-Session-Id` 头，`AuthFilter` 校验后将会话挂到请求属性。
- **失效语义（细分、跨入口一致）**：所有入口（认证过滤器、登出后访问、强制失效后访问）
  都经 `SessionService.validate` 判定，结论一致、可解释。

  | 原因 | 含义 | 触发 |
  |---|---|---|
  | `401 SESSION_UNKNOWN` | 会话从未存在，或失效记录已过保留期被清理 | 未登录/伪造 ID |
  | `401 SESSION_LOGGED_OUT` | 用户已主动登出 | `POST /api/auth/logout`（登出时写墓碑） |
  | `401 SESSION_EXPIRED` | 会话已过期 | 超过 `auth.security.session-ttl` |
  | `401 SESSION_REVOKED` | 会话被强制失效 | 管理员强制下线/降权 `revokeAllForUser` |
  | `409 CONCURRENT_SESSION_LIMIT_EXCEEDED` | 并发会话数超限 | 第 N+1 次登录 |

  叠加状态的稳定优先级：**REVOKED > LOGGED_OUT > EXPIRED > UNKNOWN**：
  - 已过期又被强制失效 -> `SESSION_REVOKED`（撤销优先于过期）；
  - 已撤销再登出 -> 仍为 `SESSION_REVOKED`；
  - 重复登出 -> 第二次登出返回 `loggedOut=false`，原因稳定为 `SESSION_LOGGED_OUT`；
  - 登出墓碑与过期记录保留一个会话时长后清理，之后归为 `SESSION_UNKNOWN`
    （保留期内原因稳定，占用有界）。
  - 并发登出/校验下，已签发的会话只会看到"有效"或 `SESSION_LOGGED_OUT`，
    不会落回 `SESSION_UNKNOWN`；并发登出恰好一次真实生效，计数不乱。

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

过滤器顺序固定：**安全响应头(1) → CORS(2) → 认证(3) → CSRF(4)**。

- **安全响应头**：所有 `/api/*` 响应（含预检与拒绝响应）统一附加
  `X-Content-Type-Options: nosniff`、`X-Frame-Options: DENY` 等。
- **CORS（真实跨域调用）**：
  - 预检（`OPTIONS` + `Access-Control-Request-Method`）：来源在当前策略的
    `allowed-origins` 中时，直接应答 `200` 并带 `Access-Control-Allow-Origin`
    （回显来源）、`Access-Control-Allow-Methods`、`Access-Control-Allow-Headers`
    （回显请求头）、`Access-Control-Max-Age`，不进入认证链路（预检不带凭据）；
  - 真实请求：来源被允许时附加 `Access-Control-Allow-Origin` 后继续原链路，
    会话（`X-Session-Id`）与 CSRF（`X-CSRF-Token`）校验按原规则执行；
  - 来源不被允许时不附加任何跨域头（浏览器侧拦截），服务端仍按现有规则处理；
  - 允许来源读取当前策略版本，运行期调整立即生效。
- **CSRF**：对已认证的变更类请求（POST/PUT/DELETE/PATCH）校验 `X-CSRF-Token`
  （登录响应中下发，由会话 ID 确定性派生）；公开路径与安全方法不校验；
  `auth.security.csrf-enabled=false` 可整体关闭。
- **公开路径**：`auth.security.public-paths` 中的路径绝不进入认证逻辑，不会被误拦截。

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

## 6. 策略版本与历史判定回放

- **策略快照**：`PolicyService` 持有当前生效的不可变策略快照（`AuthPolicy`），
  版本号单调递增。运行期通过 `PolicyService.update(修改器)` 发布新版本，
  原子切换，新请求立即按新策略判定（可调整：会话时长、并发会话上限、限流/锁定参数、
  公开路径、CSRF 开关、允许跨域来源）。
- **判定日志**：每个策略相关判定（公开路径、跨域来源、CSRF 是否需要、会话上限、
  登录限流/锁定）都记录 `DecisionRecord`：判定 ID、种类、关键输入、结论、
  **所依据的策略版本**。日志打印形如
  `[decision] id=4 kind=CORS_ORIGIN policyVersion=1 inputs={...} -> outcome=ALLOWED`。
- **回放**：`DecisionLog.replay(decisionId)` 用记录中的策略版本与输入，
  经与线上同一套纯函数（`PolicyEvaluator`）重算结论，与当前策略无关，
  结论与当时完全一致，用于排障与审计。
- **有界性**：历史策略版本最多保留 64 版、判定记录最多保留 1000 条，
  超限淘汰最旧；反复切换策略不会越跑越慢、占用不会失控
  （被淘汰的版本/记录回放时返回空）。

## 7. 验证方法

```bash
mvn test          # 全部 57 个测试
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

# 登出后再访问 -> 401 SESSION_LOGGED_OUT
curl -s localhost:8080/api/admin/stats -H "X-Session-Id: <sessionId>"

# 从未存在的会话 -> 401 SESSION_UNKNOWN
curl -s localhost:8080/api/admin/stats -H "X-Session-Id: no-such-id"
```

跨域预检与真实请求验证：

```bash
# 预检：允许来源 -> 200 + 跨域头 + 安全头
curl -si -X OPTIONS localhost:8080/api/user/profile   -H "Origin: http://localhost:3000"   -H "Access-Control-Request-Method: GET"   -H "Access-Control-Request-Headers: X-Session-Id, X-CSRF-Token"
# -> 200, Access-Control-Allow-Origin: http://localhost:3000,
#    Access-Control-Allow-Methods / Allow-Headers / Max-Age, X-Content-Type-Options: nosniff

# 预检：不允许的来源 -> 无 Access-Control-Allow-Origin，按现有规则处理
curl -si -X OPTIONS localhost:8080/api/user/profile   -H "Origin: http://evil.example.com"   -H "Access-Control-Request-Method: GET"

# 真实请求：带会话与允许来源 -> 业务响应 + Access-Control-Allow-Origin
curl -s localhost:8080/api/user/profile   -H "Origin: http://localhost:3000" -H "X-Session-Id: <sessionId>"
```

历史判定复现（回放）：

```bash
# 1. 运行时在日志中找到目标判定，例如：
#    [decision] id=12 kind=SESSION_LIMIT policyVersion=1 inputs={activeCount=2, user=alice} -> outcome=DENIED
# 2. 调整策略（如把并发上限从 2 调到 5），新请求立即按新版本判定；
# 3. 在测试或调试入口中调用 DecisionLog.replay(12)，
#    重放仍按 policyVersion=1 计算 -> 结论仍为 DENIED，与当时一致。
#    可参考 PolicySwitchTest#historicalDecisionReplaysAgainstItsOwnPolicyVersion。
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
| `CorsWebTest` | 跨域预检+真实请求组合：允许来源拿全跨域头与安全头、不允许来源无跨域头且按现有规则处理、公开路径与安全方法不受影响 |
| `PolicySwitchTest` | 运行期策略切换（上限/CSRF/公开路径/允许来源）立即生效、历史判定按当时版本回放结论一致、反复切换后版本历史与判定日志有界 |
| `SessionInvalidationReasonTest` | 失效原因细分（未知/登出/过期/撤销）、叠加状态优先级、墓碑保留期、并发登出+校验下原因与计数稳定 |
