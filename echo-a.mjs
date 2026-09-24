#!/usr/bin/env node
/**
 * ============================================================================
 * echo-a.mjs —— 「身份透传」链路的【第一跳：入口服务】
 * ============================================================================
 *
 * 这是「身份透传」标准示例的第一跳。它演示的核心命题是：
 *
 *   ★ 一个服务（echo-a）在收到请求后，要调用另一个服务（echo-b），
 *     而「echo-b 知道我是谁」这件事，不是由 echo-a 手动把身份字段复制过去，
 *     而是由 echo-a 把【原始 JWT】原样透传给网关，让网关在 echo-b 这一跳
 *     【重新验签 + 重新注入身份头】。
 *
 * ── 完整链路 ────────────────────────────────────────────────────────────────
 *   客户端(带 JWT)
 *      │ ① 发到网关 demo-a 域名
 *      ▼
 *   网关 jwt-auth-a（验签 → 注入 X-User-* → keep_token:true 把 JWT 也透传）
 *      │
 *      ▼
 *   echo-a（本文件）
 *      │ ② 拿到「原始 JWT」（Authorization 头，因为 keep_token:true）
 *      │    调用 echo-b 时，把请求发到【网关的 demo-b 域名】（不是集群内 DNS）
 *      │    并把原始 JWT 放回 Authorization 头
 *      ▼
 *   网关 jwt-auth-b（对 demo-b 这一跳【重新验签】→ 重新注入 X-User-*）
 *      │
 *      ▼
 *   echo-b（读 X-User-* → 返回「我知道你是谁：牛昆亮」）
 *      │
 *      ▼
 *   echo-a 把 echo-b 的返回值打印出来（回给最初客户端）
 *
 * ── 关键点（对比旧 Java demo 的反面教材）───────────────────────────────────
 *   旧 DemoA.java 的第二跳是「手动复制 X-User-* 头 + 走集群内 DNS 直连 demo-b」，
 *   绕过了网关。这有两个坏处：
 *     1. 身份是 echo-a 自己转传的，echo-b 无法确认它真来自网关验签；
 *     2. 一旦 echo-a 被攻破 / 有 bug，可以伪造任意 X-User-* 头骗过 echo-b。
 *   本文件演示的正确做法是：echo-a 只透传【原始 JWT】，身份由网关重新验签，
 *   这样身份在任何一跳都可信，且「身份不随调用跳数衰减」。
 *
 * ── 代码如何划分（关键）────────────────────────────────────────────────────
 *   【业务代码】  ：HTTP 服务器、路由、调用下游、拼响应。
 *   【对接代码】  ：(a) 读 Authorization 头 / X-Forwarded-Access-Token 拿原始 JWT
 *                  (b) 透传 JWT 到下一跳（发到网关域名而非集群内）
 *   每个函数顶部都标注了它是【业务】还是【对接】。
 *
 * ── 单域名两种认证路径分流（S1 / S2）───────────────────────────────────────
 *   同一个 demo-a.example.com 域名，靠网关插件 match_list 按路径分流：
 *
 *     /             → oidc 插件（浏览器登录页，展示「我是谁」+ 按钮）
 *     /ui/call-b    → oidc 插件（S2 浏览器按钮：oidc 会话 → 后端拿 access token 透传）
 *     /aiapi/*      → jwt-auth 插件（S1 API 直调：调用方自带 Bearer JWT）
 *
 *   S1 与 S2 的本质区别：
 *     - S1 无状态：token 由调用方自己带（Authorization: Bearer），走 jwt-auth 验签；
 *       适合「系统/程序间调用」。点击即测的实现=先经 /api/token（oidc 会话）拿到
 *       access token，再带 Bearer 直调 /aiapi/call-b（jwt-auth 验签）。
 *     - S2 有状态：token 在 oidc 服务端 cookie，前端 JS 拿不到明文，靠 oidc 插件把
 *       access token 放到 X-Forwarded-Access-Token 头，后端取出透传；适合「人在浏览器点按钮」。
 *
 * ── /aiapi 路径约定 ────────────────────────────────────────────────────────
 *   为避免与「传统 API」路径冲突，所有「可能有 AI 参与」的 API 统一规划成
 *   /aiapi 前缀，且 /aiapi 只挂 jwt-auth（验签）。传统 /api 留给普通后端接口。
 *   本示例的 /aiapi/* 端点：/aiapi/call-b（透传调 B）、/aiapi/whoami、/aiapi/echo-headers。
 *
 * ── 链式透传（A → B → C 三跳）──────────────────────────────────────────────
 *   echo-a 只透传 JWT 调 echo-b；echo-b 作为中间跳，内部再透传 JWT 调 echo-c。
 *   每一跳都由网关重新验签注入身份，身份不随跳数衰减。
 *
 * 运行：node echo-a.mjs（PORT 默认 8080；ECHO_B_URL 指向 demo-b 的网关域名）
 * ============================================================================
 */
import http from 'node:http'

const PORT = Number(process.env.PORT || 8080)

/* ═══════════════════════════════════════════════════════════════════════
 * 【对接代码】(a) 读取「原始 JWT」（供透传到下一跳）
 * ───────────────────────────────────────────────────────────────────────
 * 要让第二跳 echo-b 也「由网关重新验签」，echo-a 必须能拿到客户端带来的
 * 原始 JWT。这依赖网关 jwt-auth-a 插件配置了 keep_token: true ——
 * 否则网关验签后会把 Authorization 头剥掉，echo-a 就拿不到 token 了。
 *
 * 这里取出「下一跳要透传的 JWT」。它可能在：
 *   1. X-Forwarded-Access-Token 头（【优先】浏览器 OIDC 链路：oidc 插件
 *      把 access token 放这里，这正是第二跳 jwt-auth-b 要验签的 token）；
 *   2. Authorization 头（keep_token:true 时网关原样透传原始 JWT —— API/Bearer
 *      直调场景）。
 *
 * ⚠️ 顺序很关键：浏览器 OIDC 登录后，oidc 插件会【同时】放两个头——
 *   - Authorization: Bearer <ID Token>   （pass_authorization_header）
 *   - X-Forwarded-Access-Token: <Access Token>（pass_access_token）
 * 第二跳 demo-b 的 jwt-auth 要验签的是 Access Token（受众正确、含必要 claim），
 * 不是 ID Token。所以必须【优先取 X-Forwarded-Access-Token】，Authorization
 * 里的 ID Token 只作 API/Bearer 直调场景的兜底。
 * ═══════════════════════════════════════════════════════════════════════ */
function extractJwt(req) {
  // 浏览器 OIDC 链路：oidc 插件把 access token 放在这个头（优先，第二跳要验签它）
  const fwd = req.headers['x-forwarded-access-token']
  if (fwd) return String(fwd).trim()
  // API/Bearer 直调：keep_token:true 时网关把原始 JWT 原样透传在 Authorization
  const auth = req.headers['authorization'] || ''
  if (auth.startsWith('Bearer ')) return auth.slice(7).trim()
  return null
}

/* ═══════════════════════════════════════════════════════════════════════
 * 【对接代码】(b) 透传原始 JWT 调用下一跳（走网关，而非集群内 DNS）
 * ───────────────────────────────────────────────────────────────────────
 * 这是本示例的【核心】。注意两点，缺一不可：
 *
 *   1. 目标地址是【网关的 demo-b 域名】（ECHO_B_URL，如
 *      https://demo-b.example.com/aiapi/me），不是
 *      http://demo-b.default.svc.cluster.local —— 后者会绕过网关，
 *      第二跳就不会被重新验签，身份就丢了（旧 Java demo 就是这么错的）。
 *
 *   2. 把【原始 JWT】放回 Authorization: Bearer 头透传，而不是手动复制
 *      X-User-* 身份头。因为身份要由网关对 demo-b 这一跳重新验签注入，
 *      echo-a 不「替」下游做身份判断。
 *
 *   补充：因为第二跳也走网关（https），网关证书是内网自签，Node 内置 CA
 *   不含它，所以要挂企业根证书 + NODE_EXTRA_CA_CERTS（见 deploy yaml）。
 * ═══════════════════════════════════════════════════════════════════════ */
async function callEchoB(jwt) {
  const url = process.env.ECHO_B_URL || 'https://demo-b.example.com/aiapi/me'
  const res = await fetch(url, {
    headers: {
      Authorization: `Bearer ${jwt}`,
    },
  })
  const body = await res.text()
  return { status: res.status, url, body }
}

/* ═══════════════════════════════════════════════════════════════════════
 * 【对接代码】读网关注入的身份头（本跳自己的身份，用于展示第一跳结果）
 * 与 echo-server.mjs 的 collectIdentity 同源 —— 中文乱码用 unMojibake 修。
 * ═══════════════════════════════════════════════════════════════════════ */
function unMojibake(v) {
  if (v == null) return null
  try {
    return Buffer.from(String(v), 'latin1').toString('utf8')
  } catch {
    return v
  }
}

/* 【对接代码】从 JWT payload 段解析 claims（仅 base64 解码，不验签——信任已过
 * 网关认证的 token）。oidc 路径下网关注入的是 ID Token（Authorization）/ Access
 * Token（X-Forwarded-Access-Token），不一定有 X-User-* 头，所以这里兜底解 claims。 */
function decodeJwtPayload(v) {
  if (!v) return null
  const parts = String(v).split('.')
  if (parts.length !== 3) return null
  try {
    let b64 = parts[1].replace(/-/g, '+').replace(/_/g, '/')
    while (b64.length % 4) b64 += '='
    return JSON.parse(Buffer.from(b64, 'base64').toString('utf8'))
  } catch {
    return null
  }
}

function collectIdentity(req) {
  // X-User-* 头由 jwt-auth claims_to_headers 注入（API/Bearer 路径）
  const fromHeaders = {
    username: req.headers['x-user-username'] ?? null,
    name: unMojibake(req.headers['x-user-name']),
    email: req.headers['x-user-email'] ?? null,
    phone: req.headers['x-user-phone'] ?? null,
    employeeNo: req.headers['x-user-employee-no'] ?? null,
    sub: req.headers['x-user-sub'] ?? null,
  }

  // oidc（浏览器）路径：优先从 token 兜底解 claims（X-User-* 头不一定在）
  const accessTok = req.headers['x-forwarded-access-token'] || null
  const authHdr = req.headers['authorization'] || ''
  const idTok = authHdr.startsWith('Bearer ') ? authHdr.slice(7).trim() : null
  const payload = decodeJwtPayload(accessTok) || decodeJwtPayload(idTok)

  return {
    username: fromHeaders.username ?? payload?.preferred_username ?? null,
    name: fromHeaders.name ?? payload?.name ?? null,
    email: fromHeaders.email ?? payload?.email ?? null,
    phone: fromHeaders.phone ?? payload?.phone_number ?? null,
    employeeNo: fromHeaders.employeeNo ?? payload?.new_emp_no ?? null,
    sub: fromHeaders.sub ?? payload?.sub ?? null,
  }
}

/* ═══════════════════════════════════════════════════════════════════════
 * 【对接代码】完整回显「实际收到的 HTTP 请求头」（token 脱敏）
 * ───────────────────────────────────────────────────────────────────────
 * 给页面「点击即测」展示：A 这一跳实际收到了哪些头 —— Authorization /
 * X-Forwarded-Access-Token / X-User-*（网关注入身份）等。
 * ⚠️ 安全：token 只回显前缀，绝不回显完整 token。
 * ═══════════════════════════════════════════════════════════════════════ */
function maskToken(v) {
  if (v == null) return null
  const s = String(v)
  if (s.length <= 24) return s.slice(0, 8) + '...'
  return s.slice(0, 20) + '...' + s.slice(-6)
}

const SENSITIVE_HEADERS = new Set(['authorization', 'x-forwarded-access-token'])

function collectHeaders(req) {
  const headers = {}
  for (const [k, v] of Object.entries(req.headers)) {
    if (SENSITIVE_HEADERS.has(k)) {
      headers[k] = Array.isArray(v) ? v.map(maskToken) : maskToken(v)
    } else {
      headers[k] = v
    }
  }
  return headers
}

/* ═══════════════════════════════════════════════════════════════════════
 * 【业务代码】JSON 回显：把「第一跳身份」+「第二跳 echo-b 的返回」一起给出
 * 这是本示例的「业务结果」——调用方一眼看到：A 知道我是谁，B 也知道我是谁。
 * （echo-b 的返回里会嵌套第三跳 echo-c 的结果，构成 A → B → C 三跳链。）
 * ═══════════════════════════════════════════════════════════════════════ */
function renderJson(identity, jwtPresent, bResult) {
  return JSON.stringify({
    service: 'echo-a',
    hop: 1,
    // 第一跳：echo-a 自己从网关注入头读到「我是谁」
    myIdentity: identity,
    // 关键：echo-a 是否拿到了原始 JWT（keep_token / pass_access_token 是否生效）
    jwtForNextHop: jwtPresent ? '透传中（keep_token=true / pass_access_token 生效）' : '缺失（第二跳会失败）',
    // 第二跳：echo-b 经网关重新验签后返回的结果
    downstream: bResult
      ? {
          target: bResult.url,
          status: bResult.status,
          echoBResponse: (() => {
            try { return JSON.parse(bResult.body) } catch { return bResult.body }
          })(),
        }
      : null,
  }, null, 2)
}

/* ═══════════════════════════════════════════════════════════════════════
 * 【业务代码】HTML 登录页（浏览器 OIDC 登录后的首页）
 * ───────────────────────────────────────────────────────────────────────
 * 这是「系统 A = 有状态前端」的形态：浏览器经网关 oidc 插件登录后，
 * 访问 / 时看到「我是谁」+ 按钮。S1 按钮走 /aiapi/call-b（jwt-auth 验签），
 * 由 echo-a 后台持用户 token 经网关调 demo-b（B 再透传调 demo-c）。
 *
 * ⚠️ 退出登录链接指向 /oauth2/sign_out —— 这是 oidc 插件（oauth2-proxy
 * 兼容）预留的登出端点，插件会清会话 cookie 并（配合 rd 参数）跳转
 * Keycloak 真正登出 SSO。这里 rd 指向 echo 域名兜底（demo 简化）。
 * ═══════════════════════════════════════════════════════════════════════ */
function renderPage(identity, jwtPresent, req) {
  const name = identity.name || identity.username || '未知'
  // 真实域名：页面 curl 示例要用「当前访问的 host」+ 环境变量里的 Keycloak 域名，
  // 而不是写死 example.com 占位符（否则照着跑会解析失败）。
  const demoHost = req?.headers?.host || 'demo-a.example.com'
  const kcBase = process.env.KC_BASE_URL || 'https://auth.example.com'
  // 门户文档地址（点开直达「身份透传」章节）；demo-a client 的 secret（curl password grant 用）
  const portalBase = process.env.PORTAL_BASE_URL || 'https://ai.ict.cmcc'
  const demoASecret = process.env.DEMO_A_CLIENT_SECRET || '<demo-a 的 client secret>'
  const rows = [
    ['用户名 username', identity.username],
    ['姓名 name', identity.name],
    ['邮箱 email', identity.email],
    ['手机号 phone', identity.phone],
    ['工号 employeeNo', identity.employeeNo],
    ['sub', identity.sub],
  ]
    .filter(([, v]) => v != null)
    .map(([k, v]) => `<tr><th>${k}</th><td>${escapeHtml(v)}</td></tr>`)
    .join('')

  const status = jwtPresent
    ? '<span style="color:#1a7f37">已登录（持有 access token，可透传下一跳）</span>'
    : '<span style="color:#b35900">未取到 access token（pass_access_token 可能未生效）</span>'

  return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>系统 A · 身份透传演示</title>
<style>
  body { font-family: -apple-system, "Segoe UI", "Microsoft YaHei", sans-serif;
         max-width: 640px; margin: 40px auto; padding: 0 20px; color: #1f2328; }
  h1 { font-size: 22px; }
  .card { border: 1px solid #d0d7de; border-radius: 8px; padding: 16px 20px; margin: 16px 0; }
  .card h2 { font-size: 15px; margin: 0 0 12px; color: #57606a; }
  table { border-collapse: collapse; width: 100%; }
  th, td { text-align: left; padding: 6px 8px; border-bottom: 1px solid #eaeef2; font-size: 14px; }
  th { color: #57606a; font-weight: 500; width: 40%; white-space: nowrap; }
  button { background: #1f6feb; color: #fff; border: 0; border-radius: 6px;
           padding: 10px 18px; font-size: 15px; cursor: pointer; margin-right: 8px; }
  button:disabled { background: #9bb8e6; cursor: not-allowed; }
  table.cmp th { width: 22%; }
  table.cmp td { font-size: 13px; }
  code { background: #f6f8fa; padding: 1px 5px; border-radius: 4px; font-size: 13px; }
  pre { background: #f6f8fa; border: 1px solid #d0d7de; border-radius: 6px;
        padding: 12px; font-size: 12px; overflow-x: auto; white-space: pre-wrap; }
  .logout { display: inline-block; margin-left: 12px; color: #cf222e; font-size: 14px; }
  .muted { color: #57606a; font-size: 13px; }
</style>
</head>
<body>
  <h1>系统 A · OIDC 登录页 + 身份透传（A → B → C 三跳）</h1>
  <p class="muted">这是「系统 A」的浏览器入口：你经公司统一认证（OIDC）登录后，点按钮，
     后台持你的身份 token 经网关调用「系统 B」，B 再透传调「系统 C」——每一跳都由网关重新验签注入身份。
     页面演示 <strong>S1（API 直调，jwt-auth，/aiapi）</strong> 与 <strong>S2（浏览器按钮，oidc 会话）</strong> 两种方案。</p>

  <div class="card">
    <h2>① 第一跳 · 我是谁（网关注入 X-User-* 头）</h2>
    <p>${status}</p>
    <table>${rows || '<tr><td class="muted">（未读到身份头）</td></tr>'}</table>
  </div>

  <div class="card">
    <h2>② 链式透传 · A 调 B → B 调 C（两种方案对比）</h2>
    <p class="muted">两个按钮演示「系统 A 调 B，B 再调 C」的两种身份透传方式，后端每跳都持 token 经网关调下一跳、由网关重新验签注入身份。区别在于 token 从哪来、认证插件是谁。</p>
    <table class="cmp">
      <tr><th></th><th>S1 · API 直调</th><th>S2 · 浏览器按钮</th></tr>
      <tr><th>触发路径</th><td><code>/aiapi/call-b</code></td><td><code>/ui/call-b</code></td></tr>
      <tr><th>认证插件</th><td>jwt-auth（无状态验签）</td><td>oidc（有状态 cookie 会话）</td></tr>
      <tr><th>token 来源</th><td>调用方自带 <code>Authorization: Bearer &lt;JWT&gt;</code></td><td>oidc 插件放 <code>X-Forwarded-Access-Token</code>，后端取出</td></tr>
      <tr><th>适合场景</th><td>系统 / 程序间调用</td><td>人在浏览器里点按钮</td></tr>
    </table>
    <button id="s1Btn" onclick="callS1()">S1 · 点击即测（先拿 token → 带 Bearer 直调）</button>
    <button id="s2Btn" onclick="callS2()">S2 · 浏览器按钮（oidc 会话）</button>
    <button id="headersBtn" onclick="callHeaders()">🔍 查看 A/B/C 实际收到的请求头</button>
    <a class="logout" href="/oauth2/sign_out">退出登录</a>

    <div id="s1Panel" style="margin-top:16px;border:1px solid #d0d7de;border-radius:6px;padding:14px 16px;">
      <h3 style="font-size:14px;margin:0 0 10px;color:#1f2328;">S1 · 正确的调用方式（先拿 token → 再带 Bearer 直调）</h3>
      <p class="muted" style="margin:0 0 8px;">S1 是「系统/程序间直调」：调用方先拿到 JWT，再自带 <code>Authorization: Bearer &lt;JWT&gt;</code> 直调 <code>/aiapi/call-b</code>（走 jwt-auth 验签）。
      关键事实：<strong>经过网关后，业务 A 的 request header 里本来就有 token</strong>——<code>X-Forwarded-Access-Token</code>（access token）+ <code>Authorization</code>（ID token）。
      所以点上面的 <strong>S1 按钮</strong> 就能自动完成「先经 <code>/api/token</code> 拿 token → 再带 Bearer 直调」两步，无需手动粘贴。</p>

      <p style="margin:10px 0 4px;font-weight:600;">① 先用 curl 拿 JWT（password grant，demo-a client）</p>
      <pre style="margin:0 0 10px;">curl -s -X POST "${kcBase}/realms/employees/protocol/openid-connect/token" \\
  -H "Content-Type: application/x-www-form-urlencoded" \\
  -d "grant_type=password" \\
  -d "client_id=demo-a" \\
  -d "client_secret=${demoASecret}" \\
  -d "username=&lt;你的工号&gt;" \\
  -d "password=&lt;你的密码&gt;" \\
  -d "scope=openid profile email phone" \\
  | node -e "let s='';process.stdin.on('data',d=&gt;s+=d).on('end',()=&gt;console.log(JSON.parse(s).access_token))"</pre>

      <p style="margin:10px 0 4px;font-weight:600;">② 再带 Bearer 直调（curl）</p>
      <pre style="margin:0 0 10px;">curl -s "https://${demoHost}/aiapi/call-b" \\
  -H "Authorization: Bearer &lt;上一步拿到的 JWT&gt;"</pre>

      <p style="margin:10px 0 4px;font-weight:600;">③ 或在浏览器里用 fetch + Bearer 直调（点 S1 按钮已自动完成，此输入框供手动验证）</p>
      <input id="jwtInput" type="text" placeholder="粘贴 JWT（eyJhbGci... 开头）" style="width:100%;box-sizing:border-box;padding:8px 10px;border:1px solid #d0d7de;border-radius:6px;font-size:13px;margin-bottom:10px;">
      <button id="s1FetchBtn" onclick="callS1WithBearer()">用 Bearer 直调 /aiapi/call-b</button>
      <p class="muted" style="margin:8px 0 0;">实现：<code>fetch('/aiapi/call-b', { headers: { 'Authorization': 'Bearer ' + jwt } })</code> —— 服务端拿到原始 JWT 后透传下一跳，由网关重新验签注入身份。</p>
    </div>

    <pre id="result" style="display:none"></pre>
    <pre id="headersOut" style="display:none"></pre>
    <p class="muted" style="margin-top:16px">📖 <a href="${portalBase}/auth.html#transit" target="_blank" rel="noopener">开发指导：身份透传（第二跳）完整文档</a> —— S1/S2 的架构图、网关配置、代码逐行拆解与踩坑记录。</p>
  </div>

  <script>
  function setResult(btn, out, txt) {
    btn.disabled = false;
    out.style.display = 'block';
    out.textContent = txt;
  }
  async function callS1() {
    const btn = document.getElementById('s1Btn');
    const out = document.getElementById('result');
    btn.disabled = true;
    out.style.display = 'block';
    out.textContent = '① 正在经 /api/token 获取 access token…';
    try {
      // 第一步：经 /api/token（走 oidc 会话，非 /aiapi）拿到 access token
      // —— 这是「经过网关后，A 从 request header 里拿到的 token」的直接体现
      const t = await fetch('/api/token');
      const tj = await t.json();
      if (!tj.access_token) {
        out.textContent = 'HTTP ' + t.status + '\\n\\n' + JSON.stringify(tj, null, 2);
        btn.disabled = false;
        return;
      }
      out.textContent = '① 已从 /api/token 拿到 access token（长度 ' + tj.access_token.length + '）\\n② 正在带 Bearer 直调 /aiapi/call-b…';
      // 第二步：带 Bearer 直调 /aiapi/call-b（走 jwt-auth 验签）
      const r = await fetch('/aiapi/call-b', {
        headers: { 'Authorization': 'Bearer ' + tj.access_token },
      });
      const txt = await r.text();
      out.textContent = '① 经 /api/token 拿到的 access token（脱敏）:\\n    Bearer ' + tj.access_token.slice(0, 20) + '...' + tj.access_token.slice(-6) +
        '\\n\\n② 带 Bearer 直调 /aiapi/call-b 的结果（HTTP ' + r.status + '）:\\n\\n' + txt;
    } catch (e) {
      out.textContent = '请求失败：' + e;
    } finally {
      btn.disabled = false;
    }
  }
  async function callS1WithBearer() {
    const btn = document.getElementById('s1FetchBtn');
    const out = document.getElementById('result');
    const jwt = document.getElementById('jwtInput').value.trim();
    btn.disabled = true;
    out.style.display = 'block';
    out.textContent = '调用中…';
    if (!jwt) {
      setResult(btn, out, '请先在输入框粘贴 JWT。\\n\\n' +
        'JWT 获取方式见上方「① 先用 curl 拿 JWT」——用 demo-a client 做 password grant 签发 employees token。');
      return;
    }
    try {
      // S1 正确用法：fetch 附加 Authorization: Bearer 头直调 /aiapi/call-b
      const r = await fetch('/aiapi/call-b', {
        headers: { 'Authorization': 'Bearer ' + jwt },
      });
      const txt = await r.text();
      setResult(btn, out, 'HTTP ' + r.status + '\\n\\n' + txt);
    } catch (e) {
      setResult(btn, out, '请求失败：' + e);
    }
  }
  async function callS2() {
    const btn = document.getElementById('s2Btn');
    const out = document.getElementById('result');
    btn.disabled = true;
    out.style.display = 'block';
    out.textContent = '调用中…';
    try {
      // S2：走 /ui/call-b，该路径由 oidc 插件兜住，后端从 X-Forwarded-Access-Token 拿 token
      const r = await fetch('/ui/call-b');
      const txt = await r.text();
      setResult(btn, out, 'HTTP ' + r.status + '\\n\\n' + txt);
    } catch (e) {
      setResult(btn, out, '请求失败：' + e);
    }
  }
  async function callHeaders() {
    // 🔍 点击即测：走 /ui/headers（oidc 会话），后端用 access token 依次取 A/B/C 三跳各自收到的请求头
    const btn = document.getElementById('headersBtn');
    const out = document.getElementById('headersOut');
    btn.disabled = true;
    out.style.display = 'block';
    out.textContent = '正在聚合 A/B/C 三跳的请求头…';
    try {
      const r = await fetch('/ui/headers');
      const txt = await r.text();
      out.textContent = 'HTTP ' + r.status + '\\n\\n' + txt;
    } catch (e) {
      out.textContent = '请求失败：' + e;
    } finally {
      btn.disabled = false;
    }
  }
  </script>
</body>
</html>`
}

function escapeHtml(v) {
  return String(v).replace(/[&<>"']/g, (c) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
  }[c]))
}

/* ═══════════════════════════════════════════════════════════════════════
 * 【业务代码】HTTP 服务器主干
 * 就是一个普通 Node 服务：/health 探针 + 主路由调用下游并回显。
 * ═══════════════════════════════════════════════════════════════════════ */
const server = http.createServer((req, res) => {
  const url = new URL(req.url, `http://${req.headers.host}`)

  if (url.pathname === '/health') {
    res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8' })
    res.end(JSON.stringify({ ok: true, service: 'echo-a' }))
    return
  }

  // 浏览器首页：渲染 HTML 登录页（不自动调 demo-b，等用户点按钮）
  if (url.pathname === '/') {
    const identity = collectIdentity(req)
    const jwt = extractJwt(req)
    console.log('[echo-a]', JSON.stringify({ path: '/', identity, hasJwt: !!jwt }))
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' })
    res.end(renderPage(identity, !!jwt, req))
    return
  }

  // S1（API 直调）：/aiapi/call-b 走 jwt-auth（无状态验签），调用方自带 Authorization: Bearer <JWT>
  if (url.pathname === '/aiapi/call-b') {
    const identity = collectIdentity(req)
    const jwt = extractJwt(req)
    console.log('[echo-a]', JSON.stringify({ path: '/aiapi/call-b', identity, hasJwt: !!jwt }))

    if (!jwt) {
      // 无 JWT：正常情况下网关 jwt-auth 已拦 401，到不了这里；只有直接绕过网关才可能出现
      res.writeHead(401, { 'Content-Type': 'application/json; charset=utf-8' })
      res.end(JSON.stringify({
        service: 'echo-a', hop: 1, mode: 'S1-API',
        error: 'Jwt is missing',
        hint: 'S1 是 API 直调方案，需自带 Authorization: Bearer <JWT>（程序/curl）。浏览器点此路径会 401，这是预期的。',
      }, null, 2))
      return
    }

    callEchoB(jwt)
      .then((bResult) => {
        res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8' })
        res.end(renderJson(identity, true, bResult))
      })
      .catch((err) => {
        res.writeHead(502, { 'Content-Type': 'application/json; charset=utf-8' })
        res.end(JSON.stringify({
          service: 'echo-a',
          error: '调用 echo-b 失败',
          detail: String(err && err.message || err),
          hint: '检查 ECHO_B_URL 是否指向网关域名、NODE_EXTRA_CA_CERTS 是否挂载',
        }, null, 2))
      })
    return
  }

  // S2（浏览器按钮）：/ui/call-b 走 oidc 会话，后端从 X-Forwarded-Access-Token 拿 access token 透传
  if (url.pathname === '/ui/call-b') {
    const identity = collectIdentity(req)
    const jwt = extractJwt(req)
    console.log('[echo-a]', JSON.stringify({ path: '/ui/call-b', identity, hasJwt: !!jwt }))

    if (!jwt) {
      // 未取到 access token：说明 oidc 插件没把 token 放进来（pass_access_token 未生效或没登录）
      res.writeHead(401, { 'Content-Type': 'application/json; charset=utf-8' })
      res.end(JSON.stringify({
        service: 'echo-a', hop: 1, mode: 'S2-BROWSER',
        error: '未取到 access token（X-Forwarded-Access-Token 缺失）',
        hint: 'S2 依赖 oidc 插件的 pass_access_token。请先登录（/ 会自动 302 到 Keycloak），再点按钮。',
      }, null, 2))
      return
    }

    callEchoB(jwt)
      .then((bResult) => {
        res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8' })
        res.end(renderJson(identity, true, bResult))
      })
      .catch((err) => {
        res.writeHead(502, { 'Content-Type': 'application/json; charset=utf-8' })
        res.end(JSON.stringify({
          service: 'echo-a',
          error: '调用 echo-b 失败',
          detail: String(err && err.message || err),
          hint: '检查 ECHO_B_URL 是否指向网关域名、NODE_EXTRA_CA_CERTS 是否挂载',
        }, null, 2))
      })
    return
  }

  // 点击即测：/ui/headers 走 oidc 会话，回显 A/B/C 三跳各自实际收到的请求头
  // （浏览器点「查看 A/B/C 实际收到的请求头」→ fetch 这里，后端用 access token 依次调 B、C 的 echo-headers）
  if (url.pathname === '/ui/headers') {
    const identity = collectIdentity(req)
    const jwt = extractJwt(req)
    console.log('[echo-a]', JSON.stringify({ path: '/ui/headers', identity, hasJwt: !!jwt }))

    if (!jwt) {
      res.writeHead(401, { 'Content-Type': 'application/json; charset=utf-8' })
      res.end(JSON.stringify({
        service: 'echo-a', endpoint: '/ui/headers',
        error: '未取到 access token（X-Forwarded-Access-Token 缺失）',
        hint: '请先登录（/ 会自动 302 到 Keycloak），再点按钮。',
      }, null, 2))
      return
    }

    const cUrl = (process.env.ECHO_C_URL || 'https://demo-c.example.com/aiapi/me').replace(/\/aiapi\/me$/, '/aiapi/echo-headers')
    const bUrl = (process.env.ECHO_B_URL || 'https://demo-b.example.com/aiapi/me').replace(/\/aiapi\/me$/, '/aiapi/echo-headers')

    async function fetchHeaders(url) {
      try {
        const r = await fetch(url, { headers: { Authorization: 'Bearer ' + jwt } })
        const txt = await r.text()
        let j; try { j = JSON.parse(txt) } catch { j = txt }
        return { url, status: r.status, data: j }
      } catch (e) {
        return { url, status: 'ERR', error: String(e && e.message || e) }
      }
    }

    Promise.all([fetchHeaders(bUrl), fetchHeaders(cUrl)])
      .then(([bRes, cRes]) => {
        res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8' })
        res.end(JSON.stringify({
          endpoint: '/ui/headers',
          note: 'A/B/C 三跳各自实际收到的请求头（Authorization / X-Forwarded-Access-Token 已脱敏）',
          hop1_echoA: {
            url: 'https://demo-a.example.com（本服务）',
            identity,
            headers: collectHeaders(req),
          },
          hop2_echoB: bRes,
          hop3_echoC: cRes,
        }, null, 2))
      })
      .catch((err) => {
        res.writeHead(502, { 'Content-Type': 'application/json; charset=utf-8' })
        res.end(JSON.stringify({ service: 'echo-a', error: '聚合 B/C header 失败', detail: String(err && err.message || err) }))
      })
    return
  }

  // S1 点击即测·第一步：/api/token 走 oidc 会话（/api 不在 jwt-auth 的 match_list 里，由 oidc 兜住），
  // 后端从自己 header 里取出 access token（oidc 插件 pass_access_token 放 X-Forwarded-Access-Token）返回给前端。
  // 前端拿到 token 后，再带 Bearer 调 /aiapi/call-b（jwt-auth 验签）——完整演示「先拿 token → 再带 Bearer 直调」。
  if (url.pathname === '/api/token') {
    const identity = collectIdentity(req)
    const jwt = extractJwt(req)
    console.log('[echo-a]', JSON.stringify({ path: '/api/token', identity, hasJwt: !!jwt }))
    if (!jwt) {
      res.writeHead(401, { 'Content-Type': 'application/json; charset=utf-8' })
      res.end(JSON.stringify({
        service: 'echo-a', endpoint: '/api/token',
        error: '未取到 access token（X-Forwarded-Access-Token 缺失）',
        hint: '请先登录（/ 会自动 302 到 Keycloak），再点按钮。',
      }, null, 2))
      return
    }
    res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8' })
    res.end(JSON.stringify({
      service: 'echo-a',
      endpoint: '/api/token',
      note: '这是经过网关后，A 从 request header（X-Forwarded-Access-Token）里拿到的 access token。拿到它后，就能带 Bearer 直调 /aiapi/call-b（jwt-auth 验签路径）。',
      // 供前端 S1 按钮「先拿 token 再带 Bearer 直调」使用（token 是当前登录用户自己的，同源返回无越权）
      access_token: jwt,
      identity,
    }, null, 2))
    return
  }

  // API: whoami —— 回显第一跳身份（docs/10 §4.1 契约；s1s2 版补齐，suhuhu 等真实账号可见工号）
  if (url.pathname === '/aiapi/whoami') {
    const identity = collectIdentity(req)
    console.log('[echo-a]', JSON.stringify({ path: '/aiapi/whoami', identity }))
    res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8' })
    res.end(JSON.stringify({
      service: 'echo-a',
      endpoint: '/aiapi/whoami',
      authenticated: !!identity.username,
      user: {
        username: identity.username,
        name: identity.name,
        email: identity.email,
        emp_no: identity.employeeNo,
        sub: identity.sub,
      },
      note: '身份来自网关 jwt-auth X-User-* 注入（或 oidc token claims 兜底），伪造头会被网关覆盖',
    }, null, 2))
    return
  }

  // 完整回显实际收到的请求头（页面「点击即测」展示 A 这一跳收到的头）
  if (url.pathname === '/aiapi/echo-headers') {
    const identity = collectIdentity(req)
    console.log('[echo-a]', JSON.stringify({ path: '/aiapi/echo-headers', identity }))
    res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8' })
    res.end(JSON.stringify({
      service: 'echo-a',
      hop: 1,
      endpoint: '/aiapi/echo-headers',
      identity,
      headers: collectHeaders(req),
      note: 'Authorization / X-Forwarded-Access-Token 已脱敏（仅前缀）；X-User-* 由网关 jwt-auth-demo-a 注入',
    }, null, 2))
    return
  }

  res.writeHead(404, { 'Content-Type': 'application/json; charset=utf-8' })
  res.end(JSON.stringify({ service: 'echo-a', error: 'not found' }))
})

server.listen(PORT, '0.0.0.0', () => {
  console.log(`echo-a 身份透传入口已启动: http://0.0.0.0:${PORT}（下一跳 ${process.env.ECHO_B_URL || 'https://demo-b.example.com/aiapi/me'}）`)
})
