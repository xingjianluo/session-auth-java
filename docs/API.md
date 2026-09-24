# 接口与错误码清单

所有响应（含错误）带安全响应头。错误体统一为：

```json
{ "code": "STRING_CODE", "message": "human readable", "traceId": "uuid" }
```

## 公开入口（无需会话）

| 方法 | 路径 | 说明 |
|---|---|---|
| POST | `/api/auth/login` | 登录；成功时 `Set-Cookie: SID=...`，返回 `{username,role,csrfToken,expiresInMillis}` |
| GET  | `/api/auth/csrf` | 获取一个新的 CSRF 令牌（返回 `{csrfToken,headerName}`） |

## 认证后的自助入口

| 方法 | 路径 | 所需权限 | 说明 |
|---|---|---|---|
| POST | `/api/auth/logout` | 仅需有效会话 + CSRF | 登出当前令牌（置为 LOGGED_OUT） |
| GET  | `/api/documents` | `DOC_READ` | 文档列表 |
| POST | `/api/documents` | `DOC_WRITE` + CSRF | 新建文档（默认归属本部门） |
| GET  | `/api/documents/{id}` | `DOC_READ` + ABAC | 跨部门/不存在均为 `404 NOT_FOUND` |
| PUT  | `/api/documents/{id}` | `DOC_WRITE` + ABAC + CSRF | 更新文档 |
| DELETE | `/api/documents/{id}` | `DOC_DELETE` + ABAC + CSRF | 删除文档 |

## 管理入口（ADMIN）

| 方法 | 路径 | 说明 |
|---|---|---|
| POST | `/api/admin/sessions/revoke` | 按 token 撤销单个会话（body: `{"token":"..."}`） |
| POST | `/api/admin/sessions/users/{username}/revoke` | 撤销某用户全部有效会话 |
| GET  | `/api/admin/sessions/users/{username}` | 查看有效会话数量与脱敏 token |
| POST | `/api/admin/users/{username}/role` | 修改角色，下一次请求立即生效（body: `{"role":"USER"}`） |
| POST | `/api/admin/users/{username}/enabled` | 启用/禁用用户；禁用时同时撤销其会话 |
| POST | `/api/admin/users/{username}/unlock` | 清除失败计数并解除锁定 |
| GET  | `/api/admin/users` | 用户列表 |
| GET  | `/api/admin/config` | 当前安全设置快照（含版本号） |
| POST | `/api/admin/config` | 更新设置并发布新版本（字段名见下） |
| GET  | `/api/admin/config/versions` / `/versions/{v}` | 历史设置版本 |
| GET  | `/api/admin/rules/current` | 当前规则集视图 |
| POST | `/api/admin/rules/switch?profile=default|strict` | 切换规则集 |
| GET  | `/api/admin/rules/versions` / `/versions/{v}` | 历史规则集版本 |
| GET  | `/api/admin/audit/recent?limit=N` | 最近的判定审计 |
| GET  | `/api/admin/audit/by-path?path=/api/...` | 按路径查询审计（含精确 denyReason） |

`POST /api/admin/config` 支持的字段：`sessionIdleTimeoutMillis`、`maxSessionsPerUser`、
`lockThreshold`、`lockMillis`、`rateLimitAttempts`、`rateLimitWindowMillis`、
`rateLimitBlockMillis`、`csrfEnabled`。

## 错误码汇总

| HTTP | code | 含义 |
|---|---|---|
| 400 | `BAD_REQUEST` | 请求体缺失/格式错误 |
| 401 | `BAD_CREDENTIALS` | 用户名不存在或密码错误（两者不可区分） |
| 401 | `SESSION_MISSING` / `SESSION_UNKNOWN` / `SESSION_EXPIRED` / `SESSION_LOGGED_OUT` / `SESSION_REVOKED` | 会话校验的五种精确原因 |
| 403 | `CSRF_INVALID` | 状态变更请求缺少/错误的 CSRF 令牌 |
| 403 | `ACCESS_DENIED` | RBAC 权限不足（`ROLE_DENIED`） |
| 404 | `NOT_FOUND` | 路径不存在、资源不存在，或 ABAC 拒绝（对外不可区分） |
| 409 | `CONCURRENCY_LIMIT` | 并发会话数超过上限 |
| 423 | `ACCOUNT_LOCKED` / `ACCOUNT_DISABLED` | 连续失败锁定 / 账户被禁用 |
| 429 | `RATE_LIMITED` | 滑动窗口失败次数过多 |
| 500 | `INTERNAL_ERROR` | 未预期的服务端错误 |

## CORS 行为

- 携带 `Origin` 的响应会回写 `Access-Control-Allow-Origin`（与请求 Origin 一致）、
  `Allow-Methods`、`Allow-Headers`（含 CSRF 头名）、`Allow-Credentials`。
- 带 `Access-Control-Request-Method` 的 `OPTIONS` 预检返回 `204` 并短路，不要求会话。
