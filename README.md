# session-auth-java：本地会话认证与访问控制

基于 Spring Boot 3.4 / Java 21 的内存态会话认证与访问控制实现，模拟真实登录链路，
保证并发登录、会话失效与权限判定在各入口下结论一致且可解释；
支持跨域真实调用、运行期策略版本化与历史判定回放。

## 1. 会话模型

- **签发**：`POST /api/auth/login` 校验凭据后签发会话，返回 `sessionId` 与 `csrfToken`。
  会话记录包含：`sessionId`、`username`、签发时角色、签发时间、过期时间、撤销标记。
- **校验**：受保护请求携带 `X-Session-Id` 头，`AuthFilter` 校验后将会话挂到请求属性。
- **失效语义（细化、可区分、跨入口一致）**：所有入口（校验、登出后再访问、强制失效后访问）
  统一走同一个纯函数判定（`PolicyDecisions.validateSession`），同条件下结论必然一致。

  | 失效方式 | 触发 | 后续请求的判定结果 |
  |---|---|---|
  | 从未存在/未知 | 会话 ID 从未签发（或墓碑已淘汰） | `401 SESSION_NOT_FOUND` |
  | 主动登出 | `POST /api/auth/logout` | `401 SESSION_LOGGED_OUT`（登出是终态） |
  | 过期 | 超过 `auth.security.session-ttl` | `401 SESSION_EXPIRED`（记录保留） |
  | 撤销 | 强制下线/降权时 `revokeAllForUser` | `401 SESSION_REVOKED`（记录保留并标记） |
  | 并发超限 | 第 N+1 次登录 | `409 CONCURRENT_SESSION_LIMIT_EXCEEDED` |

- **叠加状态的稳定结论**：
  - 撤销 + 过期叠加 → 固定报 `SESSION_REVOKED`（撤销优先于过期）；
  - 登出是终态：已撤销/已过期的会话再登出，之后一律报 `SESSION_LOGGED_OUT`；
  - 重复登出幂等：第二次登出返回 `loggedOut=false`，原因保持 `SESSION_LOGGED_OUT`；
  - 登出通过**有界墓碑表**（上限 1 万条）记录，先写墓碑再移除记录，
    并发登出/校验下不会出现"刚登出却报未知会话"的窗口；并发登出恰好一个成功，会话计数不乱。
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
| `GET/POST /api/admin/policy`、`GET /api/admin/decisions*` | ADMIN 角色（策略管理与回放，见第 5 节） |

## 3. 限流与锁定策略

- **限流**：同一用户在滑动窗口（`rate-limit-window`，默认 1 分钟）内失败次数达到
  `rate-limit-max-attempts`（默认 5）→ `429 RATE_LIMITED`。
- **锁定**：连续失败达到 `max-failed-attempts`（默认 3）→ 锁定 `lock-duration`
  （默认 5 分钟），期间所有登录返回 `423 ACCOUNT_LOCKED`；期满自动解锁。
- 登录成功清除全部失败计数；锁定/限流期间的请求不再放大计数。
- 用户不存在与密码错误统一返回 `401 INVALID_CREDENTIALS`，不泄漏用户是否存在。

## 4. 横切规则组合与跨域（CORS）

过滤器顺序固定：**安全响应头(1) → CORS(2) → 认证(3) → CSRF(4)**。

- **安全响应头**：所有 `/api/*` 响应（含预检与拒绝响应）统一附加
  `X-Content-Type-Options: nosniff`、`X-Frame-Options: DENY` 等。
- **CORS**：`CorsFilter` 在认证**之前**运行，配置来自当前策略快照（`allowed-origins`）：
  - **预检**（`OPTIONS` + `Origin` + `Access-Control-Request-Method`）：允许来源 →
    `200` 并返回 `Access-Control-Allow-Origin`（回显来源）、`Access-Control-Allow-Methods`、
    `Access-Control-Allow-Headers`（含 `X-Session-Id`、`X-CSRF-Token`、`Content-Type`），
    预检不会被认证拦截；不允许来源 → `403` 且不下发跨域头；
  - **真实请求**：允许来源 → 正常进入认证链并附带 `Access-Control-Allow-Origin`；
    不允许来源 → `403`；
  - 允许携带凭据（`Access-Control-Allow-Credentials: true`），无 `Origin` 头的请求
    视为同源，行为与之前完全一致；
  - 公开入口、安全方法等原有行为不受影响。
- **CSRF**：对已认证的变更类请求（POST/PUT/DELETE/PATCH）校验 `X-CSRF-Token`
  （登录响应中下发，由会话 ID 确定性派生）；公开路径与安全方法不校验；
  `auth.security.csrf-enabled=false` 可整体关闭。
- **公开路径**：`auth.security.public-paths` 中的路径绝不进入认证逻辑，不会被误拦截。

## 5. 策略版本与历史判定回放

- **策略版本化**：`PolicyService` 把当前配置（`AuthSecurityProperties`）抽取为不可变快照，
  内容变化即生成单调递增的新版本。所有判定（会话校验、签发上限、限流/锁定、公开路径、
  CSRF、CORS 来源）都只依赖**判定时刻的策略快照**，配置变更后新请求立即按新策略给结论。
- **判定日志**：每条判定写入有界日志（上限 1000 条），记录判定 ID、类型、策略版本、
  关键输入与结论 —— 每条判定都能看出它依据的是哪一版策略。
- **历史回放**：`GET /api/admin/decisions/{id}/replay` 把该条判定放回它当时那版策略，
  用与在线判定**同一份纯函数**（`PolicyDecisions`）重算，结论与当时完全一致
  （响应中 `matches=true`）。回放与当前策略完全隔离，不会串到最新策略。
- **资源占用有界**：策略历史最多保留 64 版（超出淘汰最旧，回放返回 `410 POLICY_VERSION_EVICTED`）、
  判定日志最多 1000 条、登出墓碑最多 1 万条。反复/连续切换策略不会越跑越慢、占用不失控。

管理端点（均需 ADMIN 会话；POST 需 CSRF 令牌）：

| 端点 | 说明 |
|---|---|
| `GET /api/admin/policy` | 当前策略版本、内容与保留的版本列表 |
| `POST /api/admin/policy` | 运行期调整策略（字段缺省即不修改），返回新版本号 |
| `GET /api/admin/decisions?limit=50` | 最近的判定记录（含策略版本与关键输入） |
| `GET /api/admin/decisions/{id}/replay` | 回放指定判定；记录不存在 `404`，策略版本已淘汰 `410` |

`POST /api/admin/policy` 请求体示例（全部字段可选）：

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

## 6. 配置项（application.properties）

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

## 7. 验证方法

```bash
mvn test          # 全部 62 个测试
mvn spring-boot:run   # 本地启动后手工验证
```

### 7.1 基本链路

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

# 登出后再访问 -> 401 SESSION_LOGGED_OUT（与"从未存在"的 SESSION_NOT_FOUND 可区分）
curl -s localhost:8080/api/admin/stats -H "X-Session-Id: <sessionId>"

# 从未存在的会话 -> 401 SESSION_NOT_FOUND
curl -s localhost:8080/api/admin/stats -H "X-Session-Id: no-such-session"
```

### 7.2 验证跨域预检与真实请求

```bash
# 预检：允许来源 -> 200 + 跨域响应头（且带安全响应头）
curl -s -i -X OPTIONS localhost:8080/api/user/profile \
  -H 'Origin: http://localhost:3000' \
  -H 'Access-Control-Request-Method: GET' \
  -H 'Access-Control-Request-Headers: X-Session-Id'
# -> 200, Access-Control-Allow-Origin: http://localhost:3000
#    Access-Control-Allow-Methods: GET,POST,...  Access-Control-Allow-Headers: X-Session-Id,...

# 预检：不允许来源 -> 403，无 Access-Control-Allow-Origin
curl -s -i -X OPTIONS localhost:8080/api/user/profile \
  -H 'Origin: http://evil.example' -H 'Access-Control-Request-Method: GET'

# 真实请求：允许来源 + 会话 -> 200 且带 Access-Control-Allow-Origin
curl -s -i localhost:8080/api/user/profile \
  -H 'Origin: http://localhost:3000' -H "X-Session-Id: <sessionId>"
```

### 7.3 复现历史判定（策略版本与回放）

```bash
# 1. 查看当前策略版本（需 ADMIN 会话）
curl -s localhost:8080/api/admin/policy -H "X-Session-Id: <adminSessionId>"

# 2. 制造一条判定，例如用不允许的来源发预检（被拒绝 403）
curl -s -i -X OPTIONS localhost:8080/api/user/profile \
  -H 'Origin: http://evil.example' -H 'Access-Control-Request-Method: GET'

# 3. 查看判定日志，找到这条 CORS_ORIGIN 记录的 id 与 policyVersion
curl -s "localhost:8080/api/admin/decisions?limit=20" -H "X-Session-Id: <adminSessionId>"

# 4. 运行期调整策略：允许该来源（立即生效，生成新版本）
curl -s -X POST localhost:8080/api/admin/policy \
  -H "X-Session-Id: <adminSessionId>" -H "X-CSRF-Token: <csrfToken>" \
  -H 'Content-Type: application/json' \
  -d '{"allowedOrigins":["http://localhost:3000","http://evil.example"]}'

# 5. 新请求按新策略放行（同一 Origin 预检现在 200）
curl -s -i -X OPTIONS localhost:8080/api/user/profile \
  -H 'Origin: http://evil.example' -H 'Access-Control-Request-Method: GET'

# 6. 回放第 3 步的历史判定：仍按当时版本得出 DENIED，matches=true
curl -s localhost:8080/api/admin/decisions/<decisionId>/replay -H "X-Session-Id: <adminSessionId>"
```

## 8. 测试覆盖

测试覆盖（日志均打印场景、关键输入与判定依据）：

| 测试类 | 覆盖场景 |
|---|---|
| `LoginAttemptServiceTest` | 限流窗口、锁定触发/期满、成功清零、并发失败计数精确性 |
| `SessionServiceTest` | 过期/登出/撤销原因区分、并发签发不超上限不重复、并发校验一致性 |
| `SessionInvalidationReasonTest` | 未知/登出/过期/撤销可区分、叠加状态稳定结论、重复登出幂等、并发登出恰一次成功、并发校验不报未知 |
| `AuthServiceConcurrencyTest` | 32 线程并发登录恰好 2 个成功、16 线程并发失败恰好锁定一次 |
| `AccessControlServiceTest` | 角色/属性判定、降权立即生效、越权原因可区分 |
| `AuthFlowWebTest` | 全链路：登录→访问→登出→失效、CSRF、安全头、公开路径、越权、锁定 |
| `ConfigSwitchWebTest` | 配置切换（CSRF 关闭、上限=1、公开路径变更）后判定一致 |
| `CorsWebTest` | 预检放行/拒绝、预检+真实请求组合、安全头保留、公开入口跨域、运行期新增来源立即生效 |
| `PolicyServiceTest` | 版本单调递增、判定标注版本、回放一致、历史/日志有界、200 次连续切换不占内存 |
| `PolicyReplayWebTest` | 管理端点改策略立即生效、旧判定按旧版本回放 matches=true、非管理员 403、回放未知判定 404 |
