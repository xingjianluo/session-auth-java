# session-auth-java：本地会话认证与访问控制

基于 Spring Boot 3.4 / Java 21 的内存态会话认证与访问控制实现，模拟真实登录链路，
保证并发登录、会话失效与权限判定在各入口下结论一致且可解释。

## 1. 会话模型

- **签发**：`POST /api/auth/login` 校验凭据后签发会话，返回 `sessionId` 与 `csrfToken`。
  会话记录包含：`sessionId`、`username`、签发时角色、签发时间、过期时间、撤销标记。
- **校验**：受保护请求携带 `X-Session-Id` 头，`AuthFilter` 校验后将会话挂到请求属性。
- **失效语义（细分、跨入口一致）**：所有入口（认证过滤器、登出后访问、强制失效后访问）
  都经 `SessionService.validate` 判定，结论一致、可解释。

  | 原因（线上取值） | HTTP | 含义 | 触发 |
  |---|---|---|---|
  | `SESSION_NOT_FOUND` | 401 | **历轮沿用的旧标识**：会话从未存在、ID 无法识别，或失效记录已过保留期被清理 | 未登录/伪造 ID |
  | `SESSION_LOGGED_OUT` | 401 | 用户已主动登出（本轮新增，独立取值，不顶替旧标识） | `POST /api/auth/logout`（登出时写墓碑） |
  | `SESSION_EXPIRED` | 401 | 会话已过期 | 超过 `auth.security.session-ttl` |
  | `SESSION_REVOKED` | 401 | 会话被强制失效 | 管理员强制下线/降权 `revokeAllForUser` |
  | `CONCURRENT_SESSION_LIMIT_EXCEEDED` | 409 | 并发会话数超限 | 第 N+1 次登录 |

  > 兼容性说明：无会话 / 会话 ID 认不出来时，失败原因一律使用历轮既有的
  > `SESSION_NOT_FOUND`，**不改名、不换新值**。本轮新区分的
  > `SESSION_LOGGED_OUT` / `SESSION_EXPIRED` / `SESSION_REVOKED` 均为新增的、
  > 彼此不同的取值，与 `SESSION_NOT_FOUND` 并存，不会顶替它原来的含义。

  叠加状态的稳定优先级：**REVOKED > LOGGED_OUT > EXPIRED > SESSION_NOT_FOUND**：
  - 已过期又被强制失效 -> `SESSION_REVOKED`（撤销优先于过期）；
  - 已撤销再登出 -> 仍为 `SESSION_REVOKED`；
  - 已登出后又被强制失效（含登出与撤销恰好并发）-> 终态升级为 `SESSION_REVOKED`；
  - 重复登出 -> 第二次登出返回 `loggedOut=false`，原因稳定为 `SESSION_LOGGED_OUT`；
  - 登出墓碑与过期记录保留一个会话时长后清理，之后归为 `SESSION_NOT_FOUND`
    （保留期内原因稳定，占用有界）。
  - 并发登出/校验下，已签发的会话只会看到"有效"或 `SESSION_LOGGED_OUT`，
    不会落回 `SESSION_NOT_FOUND`；并发登出恰好一次真实生效，计数不乱；
    并发登出/撤销的终态写入彼此线性化，同输入重复请求结论固定。

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

## 6. 策略版本、运行期调整与历史判定回放

### 6.1 模型

- **策略快照**：`PolicyService` 持有当前生效的不可变策略快照（`AuthPolicy`），
  版本号单调递增。发布新版本原子切换，新请求立即按新策略判定（可调整：会话时长、
  并发会话上限、限流/锁定参数、公开路径、CSRF 开关、允许跨域来源）。
- **判定日志**：每个策略相关判定（公开路径、跨域来源、CSRF 是否需要、会话上限、
  登录限流/锁定）都记录 `DecisionRecord`：判定 ID、种类、关键输入、结论、
  **所依据的策略版本**。日志打印形如
  `[decision] id=4 kind=CORS_ORIGIN policyVersion=1 inputs={...} -> outcome=ALLOWED`。
- **回放**：按判定编号取记录当时的策略版本与输入，经与线上同一套纯函数
  （`PolicyEvaluator`）重算结论，与当前策略无关，结论与当时完全一致。
  若记录还在但它依据的策略版本已被淘汰，HTTP 回放返回 `410 POLICY_VERSION_EVICTED`，
  **不会退回用最新策略重算**（避免"回放串到最新策略"）。
- **有界性**：历史策略版本最多保留 64 版、判定记录最多保留 1000 条，
  **按版本新旧（插入序）淘汰最旧**——回放/查看等只读访问不会把老版本"刷新"成
  最近使用，反复切换策略不会越跑越慢、占用不会失控；被淘汰的版本/记录不可回放。

### 6.2 运行期运维入口（服务启动后即可直接 HTTP 调用）

所有 `/api/admin/**` 均为非公开路径：先经认证（401），再要求 **ADMIN** 角色
（USER 访问为 `403 ROLE_INSUFFICIENT`）；POST 请求照常需要 `X-CSRF-Token`。

| 方法与路径 | 作用 |
|---|---|
| `GET  /api/admin/policy` | 查看当前生效策略及版本号 |
| `GET  /api/admin/policy/versions` | 查看仍保留、可回放的版本号列表与当前版本 |
| `POST /api/admin/policy` | 发布新策略版本（部分更新；字段为 null 表示沿用当前值） |
| `GET  /api/admin/decisions?kind=&policyVersion=` | 查看判定记录（可按种类/版本过滤） |
| `GET  /api/admin/decisions/{id}` | 查看单条判定（输入、结论、依据版本） |
| `POST /api/admin/decisions/{id}/replay` | 按编号回放：用它当时那版策略重算 |
| `POST /api/admin/sessions/revoke?username=` | 强制失效某用户全部会话（含并发登出墓碑升级） |

`POST /api/admin/policy` 请求体（所有字段均可省略；时长字段单位为秒）：

```json
{
  "sessionTtlSeconds": 1800,
  "maxConcurrentSessions": 2,
  "maxFailedAttempts": 3,
  "lockDurationSeconds": 300,
  "rateLimitWindowSeconds": 60,
  "rateLimitMaxAttempts": 5,
  "publicPaths": ["/api/public/**", "/api/auth/login"],
  "csrfEnabled": true,
  "allowedOrigins": ["http://localhost:3000"]
}
```

非法参数（如 `maxConcurrentSessions=0`）返回 `400 INVALID_POLICY_UPDATE` 且**不发布**
新版本。回放响应示例：

```json
{
  "decisionId": 25, "kind": "SESSION_LIMIT",
  "inputs": {"user": "bob", "activeCount": "1"},
  "policyVersion": 2, "originalOutcome": "DENIED",
  "replayedOutcome": "DENIED", "matchesOriginal": true,
  "currentVersion": 3,
  "basis": "re-evaluated under the retained policy snapshot v2, independent of current policy v3"
}
```

## 7. 验证方法

```bash
mvn test               # 全部 74 个测试
mvn spring-boot:run    # 本地启动后手工验证（默认端口 8080）
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

# 从未存在/认不出来的会话 -> 401 SESSION_NOT_FOUND（历轮旧标识，保持不变）
curl -s localhost:8080/api/admin/stats -H "X-Session-Id: no-such-id"
```

运行期改策略 + 按编号回放（全程在已启动的服务上用 HTTP 完成）：

```bash
# 1. 管理员登录，取会话与 CSRF 令牌
ADMIN=$(curl -s -X POST localhost:8080/api/auth/login -H 'Content-Type: application/json' \
  -d '{"username":"alice","password":"alice-pass"}')
SID=$(echo "$ADMIN" | python3 -c 'import sys,json;print(json.load(sys.stdin)["sessionId"])')
TOK=$(echo "$ADMIN" | python3 -c 'import sys,json;print(json.load(sys.stdin)["csrfToken"])')

# 2. 查看当前策略与版本
curl -s localhost:8080/api/admin/policy -H "X-Session-Id: $SID"

# 3. 运行期把并发上限改为 1（部分更新，发布后新请求立即按新版本判定）
curl -s -X POST localhost:8080/api/admin/policy \
  -H "X-Session-Id: $SID" -H "X-CSRF-Token: $TOK" -H 'Content-Type: application/json' \
  -d '{"maxConcurrentSessions":1}'
# 此后 bob 第二次登录立即 409 CONCURRENT_SESSION_LIMIT_EXCEEDED

# 4. 查看刚产生的判定记录（可按种类/版本过滤）
curl -s "localhost:8080/api/admin/decisions?kind=SESSION_LIMIT" -H "X-Session-Id: $SID"

# 5. 再把上限放宽到 5，新请求立即放行
curl -s -X POST localhost:8080/api/admin/policy \
  -H "X-Session-Id: $SID" -H "X-CSRF-Token: $TOK" -H 'Content-Type: application/json' \
  -d '{"maxConcurrentSessions":5}'

# 6. 按编号回放第 4 步那条 DENIED 判定：仍按它当时的版本重算，
#    replayedOutcome=DENIED、matchesOriginal=true，即使当前策略已是上限 5
curl -s -X POST localhost:8080/api/admin/decisions/<id>/replay \
  -H "X-Session-Id: $SID" -H "X-CSRF-Token: $TOK"
# 若该判定依据的版本已被淘汰 -> 410 POLICY_VERSION_EVICTED（绝不串到最新策略）

# 7. 运行期强制某用户全部会话失效
curl -s -X POST "localhost:8080/api/admin/sessions/revoke?username=bob" \
  -H "X-Session-Id: $SID" -H "X-CSRF-Token: $TOK"
# bob 再用旧会话访问 -> 401 SESSION_REVOKED；过期会话被撤销同样稳定为 REVOKED
```

鉴权与 CSRF 验证：

```bash
# 不带会话访问运维入口 -> 401 SESSION_NOT_FOUND
curl -s localhost:8080/api/admin/policy
# USER（bob）访问运维入口 -> 403 ROLE_INSUFFICIENT
curl -s localhost:8080/api/admin/policy -H "X-Session-Id: <bob-session>"
# POST 改策略不带 CSRF 令牌 -> 403 CSRF_TOKEN_MISMATCH
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

测试覆盖（日志均打印每条用例的业务场景、关键输入与判定依据）：

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
| `SessionInvalidationReasonTest` | 旧标识 `SESSION_NOT_FOUND` 兼容与四种原因取值互不相同、登出/过期/撤销区分、叠加优先级（过期+撤销、撤销+登出、登出+撤销）、重复登出幂等、墓碑保留期、并发登出+校验、并发登出+撤销下原因与计数稳定 |
| `FailureReasonCompatibilityWebTest` | HTTP 层旧标识兼容（无会话/伪造 ID/重复请求）、登出入口与强制失效入口给出彼此不同的新原因 |
| `AdminPolicyApiWebTest` | 运维 HTTP 入口：鉴权/ADMIN 授权/CSRF、查看当前策略与版本历史、运行期发布部分更新并对新请求立即生效、非法参数 400 不发布、判定记录列表/过滤/按编号查、按编号按当时版本回放且不串最新策略、版本淘汰后回放 410、运行期强制失效原因稳定、反复切换版本历史有界且版本号严格 +1 |

观察测试日志：每个测试类用 `[test] business=..., input=... -> ... (basis: ...)`
打印该用例覆盖的业务、关键输入、实际结论与判定依据；线上判定则用
`[decision] id=.. kind=.. policyVersion=.. inputs=.. -> outcome=..` 打印依据的策略版本。
