#!/usr/bin/env node
/**
 * ============================================================================
 * echo 身份回显服务 —— 一个「标准的公司内网业务应用」接入示例
 * ============================================================================
 *
 * 这个项目是给【业务开发人员】看的标准范例：一个企业业务应用，要上公司内网
 * 网关（Higress）+ 接公司统一认证（Keycloak OIDC / JWT），代码要怎么组织、
 * 哪些是「业务本来就该写的」，哪些是「为了对接认证/网关额外加的」。
 *
 * ── 认证链路（浏览器 OIDC 场景，最典型）───────────────────────────────────
 *   浏览器 → Higress oidc 插件
 *            （未认证 → 302 跳到 Keycloak 登录 → 回调 → 注入 X-User-* 身份头）
 *         → echo-server（读取 X-User-* 头回显「我是谁」）
 *
 * ── 认证链路（后端 API 场景，机器对机器）──────────────────────────────────
 *   客户端（带 Bearer JWT）→ Higress jwt-auth 插件（JWKS 验签 + claims 透传）
 *         → echo-server（读取 X-User-* 头回显）
 *
 * ── 代码如何划分（这是关键）──────────────────────────────────────────────
 *   【业务代码】  ：任何 Web 应用都有的——HTTP 服务器、路由、渲染、健康检查。
 *   【对接代码】  ：为了接「公司统一认证 / 网关」额外加的——
 *                  (a) 读取 X-User-* 身份头（ASCII 字段：username/email/phone 等）
 *                  (b) 调 UserInfo 拿中文姓名（非 ASCII 字段，干净 UTF-8 不乱码）
 *                  (c) 退出登录链接（真正登出 Keycloak SSO）
 *                  (d) Cache-Control: no-store（保证每次经网关拦截）
 *   每个函数顶部都标注了它是【业务】还是【对接】。
 *
 * ── 身份获取规范（重要，公司统一约定）───────────────────────────────────────
 *   身份信息分两类，走两条通道（见 userinfo.js 顶部注释）：
 *     · ASCII 字段（username/email/phone_number/sub/员工编号）→ 读 X-User-* 头，
 *       零查询、零乱码；
 *     · 中文姓名（name/given_name/family_name）→ 用 access token 调 UserInfo，
 *       拿干净 UTF-8（不再用 unMojibake 反解码 header）。
 *
 * 运行：node echo-server.mjs（PORT 默认 8080）
 * 镜像：见 Dockerfile + build.sh（如何打进镜像上内网网关）
 * 认证配置：见 docs/认证接入/01-运维-配置手册.md
 * ============================================================================
 */
import http from 'node:http'
import { fetchUserInfo, extractAccessToken, claimsToIdentity } from './userinfo.js'

const PORT = Number(process.env.PORT || 8080)

/* ═══════════════════════════════════════════════════════════════════════
 * 【对接代码】(a) 读取网关注入的认证身份头（仅 ASCII 字段）
 * ───────────────────────────────────────────────────────────────────────
 * 网关（oidc / jwt-auth 插件）校验通过后，会把 JWT 里的 ASCII 身份字段以
 * X-User-* 请求头注入并转发给后端。业务后端「不再自己管登录」，
 * 只需要从这里读取「当前是谁」即可。
 *
 * 具体注入哪些头，由网关 wasmplugin 的 claims_to_headers 配置决定
 * （见 docs/认证接入/01-运维-配置手册.md）。当前已注入：
 *   preferred_username→X-User-Username、email→X-User-Email、
 *   phone_number→X-User-Phone、new_emp_no→X-User-Employee-No、
 *   given_name/family_name→X-User-Given-Name/Family-Name、sub→X-User-Sub。
 *
 * ⚠️ 注意：这里【只读 ASCII 字段】。中文姓名（name/given_name/family_name）
 * 走 header 会 latin-1 乱码，统一改由 UserInfo 拿（见下方 collectIdentity）。
 *
 * 员工编号：Keycloak claim 名 new_emp_no（由 LDAP 属性 NewEmpNo 映射，
 * LDAP 属性名不可改）。
 * ═══════════════════════════════════════════════════════════════════════ */
function collectAsciiFromHeaders(req) {
  return {
    username: req.headers['x-user-username'] ?? null,
    email: req.headers['x-user-email'] ?? null,
    phone: req.headers['x-user-phone'] ?? null,
    employeeNo: req.headers['x-user-employee-no'] ?? null,
    sub: req.headers['x-user-sub'] ?? null,
  }
}

/* ═══════════════════════════════════════════════════════════════════════
 * 【对接代码】(b) 汇总身份：ASCII 读头 + 中文走 UserInfo
 * ───────────────────────────────────────────────────────────────────────
 * 这是本示例的核心范式（公司统一约定的「身份透传规范」）：
 *
 *   1. ASCII 字段（username/email/phone/员工编号/sub）→ 直接读网关注入的头，
 *      零查询、零乱码；
 *   2. 中文姓名（name/given_name/family_name）→ 用 access token 调 UserInfo
 *      拿【干净 UTF-8】，不再写 unMojibake 反解码。
 *
 * 兜底逻辑：
 *   · 若网关注入的头缺失（如浏览器 OIDC 链路不注入 X-User-*），则 ASCII 字段
 *     也一并从 UserInfo 结果里补齐；
 *   · 若 UserInfo 调失败（token 无效 / 网络故障），中文姓名降级为 null，
 *     ASCII 字段仍从头里拿到（不影响主流程）。
 *
 * 因为要调 UserInfo，本函数是 async（业务端 await 一下即可）。
 * ═══════════════════════════════════════════════════════════════════════ */
async function collectIdentity(req) {
  // ① ASCII 字段：直接读头（快，零查询）
  const fromHeaders = collectAsciiFromHeaders(req)

  // ② 中文 + 兜底：用 access token 调 UserInfo 拿全量（含干净中文 name）
  const token = extractAccessToken(req)
  const info = claimsToIdentity(await fetchUserInfo(token))

  // ③ 合并：ASCII 优先读头（更省），中文优先 UserInfo（干净）；头缺失时用 UserInfo 兜底
  return {
    username: fromHeaders.username ?? info.username ?? null,
    name: info.name ?? null, // 中文姓名只信任 UserInfo 的干净 UTF-8，不读乱码头
    email: fromHeaders.email ?? info.email ?? null,
    phone: fromHeaders.phone ?? info.phone ?? null,
    employeeNo: fromHeaders.employeeNo ?? info.employeeNo ?? null,
    givenName: info.givenName ?? null,
    familyName: info.familyName ?? null,
    sub: fromHeaders.sub ?? info.sub ?? null,
  }
}

/* ═══════════════════════════════════════════════════════════════════════
 * Harmony of business + integration：把「身份 + consumer」渲染成一个
 * 人类可读的 HTML 身份页（浏览器访问时展示，带退出登录按钮）。
 *
 * 业务上：这是「我的服务」的页面。
 * 对接上：(c) 退出登录链接 —— 见下。
 * ═══════════════════════════════════════════════════════════════════════ */
function renderPage(identity, consumer) {
  const esc = (v) => String(v ?? '').replace(/[&<>"']/g, (c) => (
    { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]
  ))
  const rows = [
    ['用户名 (username)', identity.username],
    ['姓名 (name)', identity.name],
    ['员工编号 (employeeNo)', identity.employeeNo],
    ['邮箱 (email)', identity.email],
    ['手机号 (phone)', identity.phone],
    ['名 (givenName)', identity.givenName],
    ['姓 (familyName)', identity.familyName],
    ['消费者 (x-mse-consumer)', consumer],
    ['开发指导', 'https://portal.example.com/auth.html'],
    ['进阶 · 身份透传(第二跳)', 'https://demo-a.example.com'],
  ]
  const tr = rows.map(([k, v]) =>
    `<tr><th>${esc(k)}</th><td>${esc(v) ? (k.startsWith('开发') || k.startsWith('进阶') ? `<a href="${esc(v)}" target="_blank">${esc(v)}</a>` : esc(v)) : '<span class="na">—</span>'}</td></tr>`
  ).join('')
  const loggedIn = !!(identity.username || identity.phone || identity.name || identity.email)
  return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>echo 身份回显（OIDC 接入示例）</title>
<style>
  :root { --brand:#1667c9; --ok:#1a7f37; --danger:#cf222e; --bg:#f6f8fa; --line:#d0d7de; }
  * { box-sizing:border-box; }
  body { font-family:-apple-system,"Segoe UI",Roboto,"Microsoft YaHei",sans-serif; background:var(--bg); margin:0; color:#1f2328; }
  .card { max-width:640px; margin:48px auto; background:#fff; border:1px solid var(--line); border-radius:12px; overflow:hidden; box-shadow:0 1px 3px rgba(0,0,0,.06); }
  .head { background:linear-gradient(135deg,#1667c9,#1f9bd8); color:#fff; padding:20px 24px; }
  .head h1 { margin:0; font-size:20px; }
  .head p { margin:6px 0 0; opacity:.9; font-size:13px; }
  .body { padding:24px; }
  table { width:100%; border-collapse:collapse; font-size:14px; }
  th, td { text-align:left; padding:10px 12px; border-bottom:1px solid var(--line); }
  th { width:46%; color:#57606a; font-weight:500; background:#f6f8fa; }
  td { font-family:ui-monospace,Consolas,monospace; word-break:break-all; }
  a { color:var(--brand); }
  .na { color:#9aa0a6; }
  .status { display:inline-block; margin-bottom:16px; padding:4px 10px; border-radius:20px; font-size:13px; font-weight:600; }
  .on { background:#dafbe1; color:var(--ok); }
  .off { background:#ffebe9; color:var(--danger); }
  .actions { display:flex; gap:12px; margin-top:20px; flex-wrap:wrap; }
  .btn { display:inline-block; padding:10px 18px; border-radius:8px; border:1px solid transparent; font-size:14px; font-weight:600; cursor:pointer; text-decoration:none; }
  .btn-logout { background:var(--danger); color:#fff; }
  .btn-logout:hover { background:#b91c29; }
  .btn-home { background:#fff; color:var(--brand); border-color:var(--brand); }
  .hint { margin-top:14px; font-size:12px; color:#57606a; }
  .hint code { background:#eff1f3; padding:1px 5px; border-radius:4px; }
</style>
</head>
<body>
  <div class="card">
    <div class="head">
      <h1>🔐 echo 身份回显</h1>
      <p>echo.ai.example.com · Keycloak(employees) OIDC 认证 · 后端 JWT/JWKS 示例</p>
    </div>
    <div class="body">
      <span class="status ${loggedIn ? 'on' : 'off'}">${loggedIn ? '已认证' : '未认证'}</span>
      <table>
        ${tr}
      </table>
      <div class="actions">
        <a class="btn btn-logout" href="/oauth2/sign_out?rd=https%3A%2F%2Fauth.example.com%2Frealms%2Femployees%2Fprotocol%2Fopenid-connect%2Flogout%3Fpost_logout_redirect_uri%3Dhttps%253A%252F%252Fecho.ai.example.com%252F">退出登录</a>
        <a class="btn btn-home" href="/">刷新</a>
        <a class="btn btn-home" href="https://portal.example.com/auth.html" target="_blank">开发指导</a>
        <a class="btn btn-home" href="https://demo-a.example.com" target="_blank">进阶 · 身份透传</a>
      </div>
      <p class="hint">
        点击「退出登录」会清除会话，并跳转到 <code>auth.example.com</code> 注销 Keycloak
        SSO 会话，再回到本页。<br>
        「开发指导」是完整接入文档（含架构图 / 时序图 / 运维配置 / 开发指南）。
      </p>
    </div>
  </div>
</body>
</html>`
}

/* ═══════════════════════════════════════════════════════════════════════
 * 【业务代码】JSON 回显（非浏览器客户端 / API 调用方）
 * 返回当前身份与请求详情，方便脚本 / 联调工具直接看认证结果。
 * ═══════════════════════════════════════════════════════════════════════ */
function renderJson(identity, consumer, req, url, body) {
  const echo = {
    service: 'echo-identity',
    method: req.method,
    path: url.pathname,
    query: url.search,
    identity,
    consumer,
    authorization: req.headers['authorization']
      ? `${req.headers['authorization'].slice(0, 40)}...` : '(无)',
    allHeaders: req.headers,
    body: body ? body.slice(0, 500) : null,
  }
  return JSON.stringify(echo, null, 2)
}

/* ═══════════════════════════════════════════════════════════════════════
 * 【业务代码】HTTP 服务器主干
 * 这就是一个普通 Node HTTP 服务 —— 路由 / 健康检查 / 响应。
 * 唯一的不同：它读取的是「网关注入的身份头」，而不是自己弹登录框。
 * ═══════════════════════════════════════════════════════════════════════ */
const server = http.createServer((req, res) => {
  const url = new URL(req.url, `http://${req.headers.host}`)

  // 健康检查（K8S probe 用）
  if (url.pathname === '/health') {
    res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8' })
    res.end(JSON.stringify({ ok: true, service: 'echo-identity' }))
    return
  }

  let body = ''
  req.on('data', (c) => { body += c })
  req.on('end', async () => {
    const identity = await collectIdentity(req)
    const consumer = req.headers['x-mse-consumer'] ?? null
    console.log('[echo]', JSON.stringify({ path: url.pathname, identity, consumer }))

    // 浏览器请求 → 渲染 HTML 页面（带退出登录按钮 + 开发指导链接）
    const accept = (req.headers['accept'] || '').toLowerCase()
    if (accept.includes('text/html')) {
      /* 【对接代码】(d) Cache-Control: no-store
       * 保证每次访问都经过网关 OIDC 拦截/重定向到登录，而不是被浏览器缓存的
       * 旧页面骗过（否则看不到跳转 auth.example.com）。业务上非必需，但对接
       * 认证时建议加上，避免「看起来登录了其实是缓存」的假象。 */
      res.writeHead(200, {
        'Content-Type': 'text/html; charset=utf-8',
        'Cache-Control': 'no-store, no-cache, must-revalidate, max-age=0',
        'Pragma': 'no-cache',
        'Expires': '0',
      })
      res.end(renderPage(identity, consumer))
      return
    }

    // 其余客户端 → 维持 JSON 回显
    res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8' })
    res.end(renderJson(identity, consumer, req, url, body))
  })
})

server.listen(PORT, '0.0.0.0', () => {
  console.log(`echo 身份回显服务已启动: http://0.0.0.0:${PORT}`)
})
