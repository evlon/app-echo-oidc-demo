# app-echo-oidc-demo —— 企业业务应用接入统一认证的标准示例

> 这是一份**给业务开发人员照抄的模板项目**：把一个普通 HTTP 业务服务，做成
> **Docker 镜像 → 上公司内网网关（Higress）→ 接公司统一认证（Keycloak OIDC /
> JWT/JWKS）**，总共分几步、代码怎么写、踩过哪些坑。

**线上体验**：<https://echo.ai.example.com>（登录后回显你的身份；「开发指导」按钮指向门户认证页）。

**开发指导页（门户）**：<https://portal.example.com/auth.html> —— 完整接入文档（架构图 / 时序图 / 运维配置 / 开发指南 / 经验坑）。

---

## 一、这个 demo 解决什么问题

公司要求：业务应用要上内网网关，**登录走公司统一 SSO（Keycloak）**，不许每个应用
自己弹登录框、自己存密码。那么——

- 用户的登录（OIDC 授权码流程）由 **Higress oidc 插件** + **Keycloak** 在网关层完成，
  应用**不用自己写登录页**；
- 应用后端拿到的不是密码，而是**网关注入的身份请求头**（`X-User-*`），直接读「当前是谁」；
- 机器对机器（API 调用）则用 **JWT + JWKS 验签**，应用后端同样读身份头，不自己验。

本 demo 的 `echo-server.mjs` 就是一个「最小业务后端」：接收身份头、渲染页面/JSON 回显。
它演示了上面两条链路都怎么对接。

---

## 二、代码里哪些是「业务」，哪些是「对接」？

打开 `echo-server.mjs`，每个函数顶部都标了 `【业务代码】` / `【对接代码】`。

| 代码块 | 类型 | 说明 |
|---|---|---|
| `http.createServer` / 路由 / `/health` | **业务** | 任何 Web 应用都有 |
| `renderJson` | **业务** | 返回 JSON |
| `renderPage` | **业务** | 渲染 HTML 页面 |
| `collectIdentity`（读 `X-User-*` 头 + 调 UserInfo） | **对接** | 读 ASCII 身份头 + 中文走 UserInfo |
| `userinfo.js`（`fetchUserInfo` / `extractAccessToken`） | **对接** | 调 Keycloak UserInfo 拿全量身份的标准模块 |
| 退出登录链接 | **对接** | 真正登出 Keycloak SSO |
| `Cache-Control: no-store` | **对接** | 防缓存导致「假登录」 |

> 一句话：**业务代码 = 你的服务本来要写的；对接代码 = 为了接认证/网关额外加的几小块。**

---

## 三、把这个服务做成镜像、上网关、接认证 —— 分几步

### 第 1 步：打专属镜像

见 `Dockerfile` + `build.sh`（在 K8S 节点原生构建 arm64、推送内网镜像仓库）：

```bash
cd /e/ai-works/app-echo-oidc-demo
bash build.sh 20260919        # 默认 tag 是当天日期
```

产物：`registry.example.com/library/echo-oidc-demo:20260919`

### 第 2 步：部署到 K8S

见 `deploy/echo-server.yaml`（Deployment + Service）。关键点：

- 引用**自己的专属镜像**（不是 `node:22-slim + ConfigMap` 挂源码）；
- 所有 Pod 加 `tolerations: [{operator: Exists}]`（集群无 worker 节点）。

```bash
kubectl -n default apply -f deploy/echo-server.yaml
```

### 第 3 步：在 Higress 建路由（对外暴露域名）

域名 `echo.ai.example.com` 的 Ingress 见 `k8s/business-services/echo-server/echo-ingress.yaml`，
或直接用 higress-cli / MCP：

```bash
higress-cli create --name echo --domains echo.ai.example.com \
    --service k8s-echo.default.dns:80 --cert im-ai-tls
```

### 第 4 步：接认证（网关侧配置）

这一步是**网关/运维**做的，业务开发把需求提交给运维即可。两种方式：

1. **浏览器登录（OIDC）**：Higress `oidc` 插件 → Keycloak，配置见
   `docs/认证接入/01-运维-配置手册.md`；
2. **后端 API（JWT）**：Higress `jwt-auth` 插件（JWKS 验签）+ `claims_to_headers`。

配置好后，应用后端**自动**收到 `X-User-*` 身份头 —— 代码不用改。

---

## 四、给业务开发的常见 Q&A

- **Q：我后端要不要自己存 token/密码？** 不需要。身份由网关校验后以请求头传给你。
- **Q：用户登出怎么做？** 浏览器场景由网关 `rd` 指向 Keycloak `end_session`（见
  `02-开发-接入指南.md`）；后端 API 无状态，不涉及登出。
- **Q：我后端要校验 token 吗？** 在网关后面不用（网关已验）。若你的服务要**绕过网关**
  或**被外部直接访问**，才需要在应用内用 JWKS 自验（`02` 有示例说明）。
- **Q：中文姓名乱码？** 不再用 `unMojibake`。ASCII 字段读 `X-User-*` 头，中文姓名
  用 access token 调 UserInfo 拿干净 UTF-8（见 `userinfo.js` 与
  `docs/认证接入/07-身份透传-第二跳.md` 第九章）。
- **Q：手机号（phone_number）能拿到吗？** 能。`phone` 是 realm 默认 scope，`phone_number`
  claim 已配好、数据已落本地表，网关也已注入 `X-User-Phone` 头；UserInfo 里也有
  `phone_number`（实测 `niukunliang` 手机号数据在位）。

---

## 五、进阶：身份透传（第二跳 + 链式多跳）

上面讲的是**单跳**——客户端直接调你的服务。真实业务常有**服务间调用**：
`客户端 → 网关 → 服务 A → 服务 B → 服务 C`，此时 B、C 怎么知道「你是谁」？

**正确姿势**：每一跳都把原始 JWT 透传给网关，由网关对下一跳重新验签注入身份（**不是** 手动复制身份头）。跳数再多规则不变。

> **/aiapi 路径约定**：所有「可能有 AI 参与」的 API 统一 `/aiapi` 前缀、只挂 jwt-auth；传统 `/api` 留给普通后端接口，避免冲突。

| 服务 | 文件 | 说明 |
|---|---|---|
| 第一跳（入口） | `echo-a.mjs` | 读原始 JWT（`keep_token: true`）→ 透传 JWT 调网关的下游域名；另有浏览器 OIDC 登录页 + S1/S2 按钮 + header 回显 |
| 第二跳（中间跳） | `echo-b.mjs` | 读网关注入的 `X-User-*` 头 + 透传 JWT 调 echo-c（`keep_token: true`）|
| 第三跳（链式末端） | `echo-c.mjs` | = 单跳 echo-server，只读网关注入的 `X-User-*` 头 |

每个服务都暴露 `/aiapi/echo-headers` 端点，回显**实际收到的 HTTP 请求头**（token 脱敏），供「点击即测」直观展示。

完整讲解见 `docs/认证接入/07-身份透传-第二跳.md`（含架构图、逐行注释、踩坑记录）。

**线上体验**：
- **浏览器（系统 A 登录页）**：<https://demo-a.example.com> —— 经公司统一认证（OIDC）登录后，
  看到「我是谁」页面 + S1/S2 按钮 + 「查看 A/B/C 实际收到的请求头」按钮。
- **API（纯 JWT）**：<https://demo-a.example.com/aiapi/call-b> —— 带 JWT 访问，返回 A→B→C 三跳身份透传 JSON。

### 系统 A 的「有状态前端」形态（OIDC 登录页 + 按钮）

`echo-a.mjs` 除了 API 透传，还提供**浏览器登录页**：

| 路由 | 行为 |
|---|---|
| `/` | 渲染 HTML 页面：显示「我是谁」+ S1/S2 按钮 + header 回显按钮 + 退出登录 |
| `/aiapi/whoami` | 回显第一跳身份（`emp_no` / `name` / `email` / `sub`）|
| `/aiapi/call-b` | S1 API 直调（带 Bearer JWT），透传调 echo-b → B 再调 echo-c，返回三跳 JSON |
| `/aiapi/echo-headers` | 回显第一跳实际收到的请求头（token 脱敏）|
| `/ui/call-b` | S2 浏览器按钮（oidc 会话），后端取 access token 透传 |
| `/health` | K8S 探针 |

网关侧配套：demo-a 域名同时挂 **oidc**（浏览器登录，`client_id=demo-a`）+ **jwt-auth**（API 验签）。
两者靠 oidc 的 `match_list` 豁免 `/aiapi`、`/health` 分流。

---

## 六、目录结构

```
app-echo-oidc-demo/
├── echo-server.mjs        # 单跳身份回显（业务 + 对接，已逐块标注）
├── echo-a.mjs             # 身份透传第一跳（透传 JWT 调下游）
├── echo-b.mjs             # 身份透传第二跳（中间跳，透传 JWT 调 echo-c）
├── echo-c.mjs             # 身份透传第三跳（链式末端，读网关注入身份）
├── userinfo.js            # ⭐ 身份获取标准模块（ASCII 读头 + 中文调 UserInfo）
├── verify-transit.mjs     # 两跳端到端验证脚本（本机运行）
├── verify-3hop.mjs        # 三跳端到端验证脚本（本机运行）
├── package.json
├── Dockerfile             # 打镜像（一个镜像承载四个服务）
├── build.sh               # 构建 + 推送镜像仓库
└── deploy/
    ├── echo-server.yaml   # 单跳 K8S Deployment + Service
    ├── echo-a.yaml        # 第一跳（含 hostAliases 坑）
    ├── echo-b.yaml        # 第二跳（中间跳，含 ECHO_C_URL + hostAliases）
    └── demo-c.yaml        # 第三跳（链式末端）
```

> 网关插件配置（jwt-auth-demo-a/b/c、oidc-demo-a）不在本仓库——它们含真实密钥/域名，
> 由 `k8s/scripts/deploy-demo-aiapi-3hop.py` 在节点上经 apiserver CRD 生成。

配套文档（上级目录）：
- `docs/认证接入/00-总览-整体情况.md` —— 架构图 / 时序图 / 价值
- `docs/认证接入/01-运维-配置手册.md` —— 网关/Keycloak 一步步配置
- `docs/认证接入/02-开发-接入指南.md` —— 业务开发怎么接
- `docs/认证接入/03-领导-价值说明.md`
- `docs/认证接入/04-经验与坑.md`
- `docs/认证接入/07-身份透传-第二跳.md` —— ⭐ 服务间调用身份不衰减（本示例新增）
