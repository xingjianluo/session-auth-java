# session-auth-java：本地会话认证与访问控制

基于 Spring Boot 3.4 / Java 21 的内存态会话认证与访问控制实现，模拟真实登录链路，
保证并发登录、会话失效与权限判定在各入口下结论一致且可解释。

## 1. 会话模型

- **签发**：`POST /api/auth/login` 校验凭据后签发会话，返回 `sessionId` 与 `csrfToken`。
  会话记录包含：`sessionId`、`username`、签发时角色、签发时间、过期时间、撤销标记。
- **校验**：受保护请求携带 `X-Session-Id` 头，`AuthFilter` 校验后将会话挂到请求属性。
- **失效语义（细分、跨入口一致）**：所有入口（认证过滤器、登出后访问、强制失效后访问）
  都经 `SessionService.validate` 判定，结论一致、可解释。

  | 原因（HTTP 401，响应体 `reason` 取值） | 含义 | 触发 |
  |---|---|---|
  | `SESSION_NOT_FOUND` | **上一轮既有标识（兼容红线，不得改名/改义）**：会话从未存在、未带头/空 ID、伪造 ID，或失效记录已过保留期被清理 | 未登录/伪造 ID/墓碑已清理 |
  | `SESSION_LOGGED_OUT`（本轮新增） | 用户已主动登出 | `POST /api/auth/logout`（登出时写墓碑） |
  | `SESSION_EXPIRED`（本轮新增） | 会话已过期 | 超过 `auth.security.session-ttl` |
  | `SESSION_REVOKED`（本轮新增） | 会话被强制失效 | 管理员强制下线/降权（`revokeAllForUser` / `POST /api/admin/sessions/revoke`） |
  | `409 CONCURRENT_SESSION_LIMIT_EXCEEDED` | 并发会话数超限 | 第 N+1 次登录 |

  > 兼容性说明：本轮新增的三个原因与旧标识**并存**，未知/没见过的会话一律仍是
  > `SESSION_NOT_FOUND`，没有被任何新原因顶替。客户端上一轮按 `"SESSION_NOT_FOUND"`
  > 写的兼容判断继续有效。

  **各入口对同一会话的结论一致**（过滤器校验、登出后再访问、强制失效后再访问都走
  `SessionService.validate` 这一条判定路径）。叠加状态的稳定优先级：
  **REVOKED > LOGGED_OUT > EXPIRED > NOT_FOUND**：
  - 已过期又被强制失效 -> `SESSION_REVOKED`（撤销优先于过期）；
  - 已登出又被强制失效（管理员强制下线会把已登出墓碑升级）-> `SESSION_REVOKED`
    （撤销优先于登出），与两个操作的先后顺序无关；
  - 已撤销再登出 -> 仍为 `SESSION_REVOKED`；
  - 已过期再登出 -> `SESSION_LOGGED_OUT`（登出优先于过期）；
  - 重复登出 -> 只有第一次返回 `loggedOut=true`，之后返回 false；该会话在校验入口
    稳定为 `SESSION_LOGGED_OUT`，同样输入重复请求结论固定；
  - 登出墓碑与终态记录保留一个会话时长后清理，之后归为 `SESSION_NOT_FOUND`
    （保留期内原因稳定，占用有界）。
  - 并发登出/校验下，已签发的会话只会看到"有效"或 `SESSION_LOGGED_OUT`，
    不会落回 `SESSION_NOT_FOUND`；并发登出恰好一次真实生效；撤销与登出并发时
    落稳结论固定为 `SESSION_REVOKED`，会话计数不乱。

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

## 6. 策略版本与历史判定回放（服务运行期可操作）

- **策略快照**：`PolicyService` 持有当前生效的不可变策略快照（`AuthPolicy`），
  版本号单调递增。运行期通过 `PolicyService.update(修改器)` 或
  **HTTP 运维入口**发布新版本，原子切换，新请求立即按新策略判定（可调整：会话时长、
  并发会话上限、限流/锁定参数、公开路径、CSRF 开关、允许跨域来源）。
- **判定日志**：每个策略相关判定（公开路径、跨域来源、CSRF 是否需要、会话上限、
  登录限流/锁定）都记录 `DecisionRecord`：判定 ID、种类、关键输入、结论、
  **所依据的策略版本**。日志打印形如
  `[decision] id=4 kind=CORS_ORIGIN policyVersion=1 inputs={...} -> outcome=ALLOWED`。
- **回放**：`DecisionLog.replay(decisionId)`（或 HTTP 回放入口）用记录中的策略版本与
  输入，经与线上同一套纯函数（`PolicyEvaluator`）重算结论，与当前策略无关，
  结论与当时完全一致，用于排障与审计。
- **有界性**：历史策略版本最多保留 64 版、判定记录最多保留 1000 条，
  超限淘汰最旧；反复切换策略不会越跑越慢、占用不会失控
  （被淘汰的版本/记录回放时返回空 / HTTP 404 `DECISION_NOT_FOUND`）。

### 6.1 运行期运维 HTTP 入口（本地服务已启动即可用，无需测试或重启）

均需有效会话；变更类（POST）另需登录下发的 `X-CSRF-Token`。
除强制下线外仅 **ADMIN** 可用（alice 为 ADMIN；bob 等普通用户得到 `403 ROLE_INSUFFICIENT`）。

| 方法与路径 | 作用 |
|---|---|
| `GET  /api/admin/policy` | 查看当前策略全文与 `version` |
| `POST /api/admin/policy` | 基于当前版本发布新版本；请求体只传需要改的字段，响应回显 `version` 与 `previousVersion`；非法取值返回 `400 INVALID_POLICY_UPDATE` 且不产生新版本 |
| `GET  /api/admin/decisions` | 列出保留的判定（每条含 `id/kind/policyVersion/inputs/outcome/decidedAt`） |
| `GET  /api/admin/decisions/{id}` | 查看单条判定 |
| `POST /api/admin/decisions/{id}/replay` | 按该记录**当时的策略版本**重放，返回原结论 `outcome`、重算结论 `replayedOutcome` 与 `matches` |
| `POST /api/admin/sessions/revoke` | 强制失效某用户全部会话：`{"username":"bob"}`，返回 `revokedLive`；已登出/已过期的终态记录同步升级为 `SESSION_REVOKED` |

`POST /api/admin/policy` 请求体字段（全部可选，只传要改的）：

```json
{
  "sessionTtl": "PT30M",
  "maxConcurrentSessions": 5,
  "maxFailedAttempts": 3,
  "lockDuration": "PT5M",
  "rateLimitWindow": "PT1M",
  "rateLimitMaxAttempts": 5,
  "publicPaths": ["/api/public/**", "/api/auth/login"],
  "csrfEnabled": true,
  "allowedOrigins": ["http://localhost:3000"]
}
```

时长使用 ISO-8601（`PT30M`/`PT5M`/`PT1H`）；数值类必须为正数。

## 7. 验证方法

```bash
mvn test          # 全部 65 个测试
mvn spring-boot:run   # 本地启动后手工验证（默认 8080）
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

# 登出后再访问 -> 401 SESSION_LOGGED_OUT（重复访问结论固定）
curl -s localhost:8080/api/admin/stats -H "X-Session-Id: <sessionId>"

# 从未存在/伪造/空会话 -> 401 SESSION_NOT_FOUND（上一轮旧标识，保持不变）
curl -s localhost:8080/api/admin/stats -H "X-Session-Id: no-such-id"
curl -s localhost:8080/api/admin/stats
```

叠加状态验证（需要两个终端的会话，或先登录 alice 做管理员）：

```bash
# 1) bob 登录后主动登出 -> 401 SESSION_LOGGED_OUT
# 2) 管理员强制下线 bob（会把已登出墓碑升级为撤销）
curl -s -X POST localhost:8080/api/admin/sessions/revoke \
  -H "X-Session-Id: <aliceSessionId>" -H "X-CSRF-Token: <aliceCsrf>" \
  -H 'Content-Type: application/json' -d '{"username":"bob"}'
# 3) bob 再用原会话访问 -> 401 SESSION_REVOKED（撤销优先于登出，重复请求结论一致）
curl -s localhost:8080/api/user/profile -H "X-Session-Id: <bobOldSessionId>"
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

运行期改策略与按编号复现历史判定（HTTP 实操）：

```bash
# 管理员登录，拿到 sessionId/csrfToken
ALICE=$(curl -s -X POST localhost:8080/api/auth/login -H 'Content-Type: application/json' \
  -d '{"username":"alice","password":"alice-pass"}')
SID=$(echo "$ALICE" | python3 -c 'import sys,json;print(json.load(sys.stdin)["sessionId"])')
TOK=$(echo "$ALICE" | python3 -c 'import sys,json;print(json.load(sys.stdin)["csrfToken"])')

# 1. 查看当前策略版本
curl -s localhost:8080/api/admin/policy -H "X-Session-Id: $SID" | python3 -m json.tool

# 2. 运行期把并发会话上限从 2 改为 5（立刻对下一个请求生效，返回新旧版本号）
curl -s -X POST localhost:8080/api/admin/policy \
  -H "X-Session-Id: $SID" -H "X-CSRF-Token: $TOK" -H 'Content-Type: application/json' \
  -d '{"maxConcurrentSessions":5}'

# 3. 列出判定，找到一条改策略前的 SESSION_LIMIT 记录（含 id/policyVersion/inputs/outcome）
curl -s localhost:8080/api/admin/decisions -H "X-Session-Id: $SID" | python3 -m json.tool

# 4. 按编号回放：即使当前上限已是 5，旧记录仍按它当时的版本重算
curl -s -X POST localhost:8080/api/admin/decisions/<id>/replay \
  -H "X-Session-Id: $SID" -H "X-CSRF-Token: $TOK" | python3 -m json.tool
# -> {"policyVersion":<当时版本>, "outcome":"DENIED",
#     "replayedOutcome":"DENIED", "matches":true, ...}
# 编号已被淘汰或不存在 -> 404 DECISION_NOT_FOUND
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
| `PolicyAdminWebTest` | 已启动服务上经 HTTP 查看/修改策略（立即生效、判定带版本号）、按编号回放锁定当时版本（matches=true）、新请求不串旧策略/回放不串新策略、仅 ADMIN 可用、变更需 CSRF、非法修改 400 且不产生新版本、淘汰编号 404 |
| `SessionInvalidationReasonTest` | 旧标识 `SESSION_NOT_FOUND` 兼容、失效原因细分（未知/登出/过期/撤销）、叠加状态优先级（过期+撤销、登出+撤销、撤销+登出、过期+登出）、墓碑保留期、并发登出+校验下原因与计数稳定、并发重复登出恰好一次、撤销+登出并发落稳固定为 REVOKED |
