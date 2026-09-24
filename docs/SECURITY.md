# 安全模型说明

## 1. 会话模型

- 登录成功后由 `SessionManager` 签发 256 位随机、不透明的 `SID`，通过 `HttpOnly` Cookie
  下发；同一会话绑定一个独立的 CSRF 同步令牌（登录响应体返回，后续通过 `X-CSRF-TOKEN` 头提交）。
- 会话采用**空闲过期（idle timeout）**：每次通过认证的请求都会原子地滑动
  `lastSeen`；距上次访问超过 `app.security.session.idle-timeout-millis` 即判为过期。
- 会话状态机：`ACTIVE -> EXPIRED | LOGGED_OUT | REVOKED`。终态被保留，因此同一个令牌在
  “过期 / 主动登出 / 被管理员撤销”三种情况下会给出**可区分**的错误码，而不是笼统的 401。
- 每个用户允许的最大并发会话数可配置（`max-sessions-per-user`）。“统计有效会话 + 创建新会话”
  在**每用户锁**内原子完成，因此并发登录不可能两个请求同时越过上限；失败的竞争者统一得到
  `409 CONCURRENCY_LIMIT`。
- 每个令牌的“检查状态/过期 + 滑动窗口”在**每令牌锁**内原子完成，重复或并发请求不会出现
  重复放行，也不会与登出/撤销产生竞态（已由 16 并发请求撤销测试验证）。
- 角色与属性在**每次请求**时从 `UserDirectory` 实时读取，会话中只缓存用户名：
  降权、禁用、删除账户在**下一个请求立即生效**，无需等待会话过期。

### 会话失败原因（HTTP 401，code 可区分）

| code | 触发条件 |
|---|---|
| `SESSION_MISSING` | 请求未携带会话 Cookie |
| `SESSION_UNKNOWN` | Cookie 中的令牌不存在（或账户已被删除/禁用） |
| `SESSION_EXPIRED` | 空闲时间超过 TTL |
| `SESSION_LOGGED_OUT` | 该令牌已被本人主动登出 |
| `SESSION_REVOKED` | 该令牌已被管理员撤销 |

## 2. 访问控制（RBAC + ABAC）

规则由有序的 `AccessRule` 列表组成，**首条匹配生效**，保存在带版本号的
`AccessRuleRegistry` 中。内置两套规则集，可在运行时切换：

- `default`：文档按“同部门”可见（ABAC：principal.department == resource.department），
  MANAGER 可在本部门内读写删，ADMIN 全权；
- `strict`：文档仅“所有者本人或 ADMIN”可见可改，普通 MANAGER 失去删除权限。

权限（RBAC）：

| 权限 | 含义 |
|---|---|
| `DOC_READ` / `DOC_WRITE` / `DOC_DELETE` | 文档读/写/删 |
| `SESSION_MANAGE` | 会话与用户管理 |
| `CONFIG_MANAGE` | 安全配置与规则集切换 |
| `AUDIT_READ` | 查看审计记录 |

角色授权：`ADMIN` 拥有全部权限，`MANAGER = {DOC_READ, DOC_WRITE, DOC_DELETE}`，
`USER = {DOC_READ}`。

### 判定结果与“不泄漏资源是否存在”

内部保留四种精确拒绝原因（写入审计日志）：

| 内部 DenyReason | 含义 | 对外响应 |
|---|---|---|
| `ROLE_DENIED` | 角色/权限不足 | `403 ACCESS_DENIED` |
| `ATTRIBUTE_DENIED` | 有权限但 ABAC 属性不满足（如跨部门） | `404 NOT_FOUND` |
| `RESOURCE_NOT_FOUND` | 路径匹配但资源不存在 | `404 NOT_FOUND` |
| `PATH_NOT_FOUND` | 受保护 API 下没有任何规则匹配该路径 | `404 NOT_FOUND` |

即：**跨部门访问与访问不存在的资源，响应体除 traceId 外逐字节一致**，调用方无法据此探测
资源是否存在；真正的区分依据只出现在服务端审计记录中（`/api/admin/audit/**`）。

### 配置变更后历史判定可复现

- 每次规则集切换 / 安全配置更新都会产生单调递增的新版本（`RuleSetVersion` /
  `SecuritySettings`），历史版本全部保留。
- 每条审计事件都记录：用户名、角色、principal 属性、资源属性、命中规则 ID、
  `ruleProfile`、`ruleVersion`、`settingsVersion`、时间戳。
- 用旧版本规则集 + 当时的输入重放即可得到与历史一致的结论（见
  `ConfigSwitchTest#switchingToStrictRulesChangesOwnerBasedAccess`）。

## 3. 限流与锁定策略

登录失败在 `LoginThrottleService` 中**按用户名**串行计数，两套相互独立的机制：

1. **连续失败锁定**：连续错误密码达到 `lock-threshold`（默认 5）次，账户锁定
   `lock-millis`（默认 5 分钟）。触发锁定的当次尝试即返回锁定结论；成功登录会清零连续计数；
   管理员可通过 `/api/admin/users/{user}/unlock` 立即解锁。
2. **滑动窗口限流**：在 `rate-limit-window-millis`（默认 60s）窗口内失败次数达到
   `rate-limit-attempts`（默认 10），短时间阻断 `rate-limit-block-millis`（默认 60s）。

对外原因可区分：`429 RATE_LIMITED` vs `423 ACCOUNT_LOCKED`。凭证错误（用户不存在与
密码错误）统一为 `401 BAD_CREDENTIALS`，防止枚举用户名。账户禁用为
`423 ACCOUNT_DISABLED`，并发会话超限为 `409 CONCURRENCY_LIMIT`。

## 4. 横切规则的组合顺序

过滤器链（按 order）与拦截器：

1. `CorsFilter`（order 10）：写 CORS 头；合法 **预检 OPTIONS 直接返回 204 并短路**，
   不进入会话/CSRF 判定；真实跨域请求仍走完整链路。
2. `SecurityHeadersFilter`（order 20）：在所有响应（成功与各类失败）上附加
   `X-Frame-Options`、`X-Content-Type-Options`、`Referrer-Policy`、`Content-Security-Policy`。
3. `AuthenticationFilter`（order 30，仅 `/api/*`）：
   - 公开入口（`POST /api/auth/login`、`GET /api/auth/csrf`）与所有非 `/api/` 路径直接放行，
     公开路径判定由 `PublicPaths` 统一维护，认证过滤器与授权拦截器共用；
   - 校验会话（含过期/终态的精确原因）；
   - 对 POST/PUT/PATCH/DELETE 校验 CSRF 同步令牌（可通过配置关闭），失败为
     `403 CSRF_INVALID`。
4. `AuthorizationInterceptor`（仅 `/api/**`）：按有序规则做 RBAC+ABAC 判定、隐藏不存在资源，
   并对每次判定写审计。未匹配到任何处理器的受保护路径由 `GlobalExceptionHandler` 补记
   `PATH_NOT_FOUND` 审计后返回统一 404。

所有安全异常最终由 `GlobalExceptionHandler` 转成统一 `{code,message,traceId}` 错误体。
