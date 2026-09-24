#!/usr/bin/env node
/**
 * ============================================================================
 * echo-c.mjs —— 「身份透传」链路的【第三跳：链式末端服务】
 * ============================================================================
 *
 * 这是「A → B → C 链式透传」示例的第三跳。它要回答的问题是：
 *
 *   ★ 当链路不止两跳（客户端 → 网关 → A → 网关 → B → 网关 → C），
 *     身份怎么一路不衰减地传到最末端？
 *     答案和两跳完全一样：**每一跳都「透传原始 JWT 给网关，由网关重新验签」**，
 *     而不是服务之间手动复制身份头。跳数再多，规则不变。
 *
 * ── 为什么 echo-c 的代码和 echo-b / echo-server 几乎一模一样 ───────────────
 *   这正是本模式最优雅的地方：**对末端服务而言，它根本不知道、也不需要知道
 *   请求是「客户端直接来的」还是「上游 B 转发的」**。它只做一件事 ——
 *   读网关注入的 X-User-* 头。身份透传是【网关】的职责，不是每个服务要写的代码。
 *
 * ── 与 echo-b 的唯一区别 ──────────────────────────────────────────────────
 *   echo-c 是链式末端（不再往下调），所以它【没有】透传逻辑，只有：
 *   ① 读网关注入的 X-User-* 身份头（对接代码）
 *   ② /aiapi/echo-headers 端点 —— 把「实际收到的 HTTP 请求头」完整回显，
 *      用于在页面里直观展示「C 这一跳到底收到了什么头」（Authorization / X-User-* / X-Forwarded-Access-Token 等）
 *
 * ── /aiapi 路径约定 ────────────────────────────────────────────────────────
 *   为避免与「传统 API」路径冲突，所有「可能有 AI 参与」的 API 统一规划成
 *   /aiapi 前缀，且 /aiapi 只挂 jwt-auth（验签）。传统 /api 留给普通后端接口。
 *   echo-c 作为链式末端的 API 都在 /aiapi 下。
 *
 * 运行：node echo-c.mjs（PORT 默认 8080）
 * ═══════════════════════════════════════════════════════════════════════ */
import http from 'node:http'
import { fetchUserInfo, extractAccessToken, claimsToIdentity } from './userinfo.js'

const PORT = Number(process.env.PORT || 8080)

/* ═══════════════════════════════════════════════════════════════════════
 * 【对接代码】读网关注入的身份头（ASCII 字段）+ 调 UserInfo 拿中文姓名
 * ───────────────────────────────────────────────────────────────────────
 * 公司统一约定的「身份透传规范」（详见 userinfo.js 顶部注释）：
 *   · ASCII 字段（username/email/phone/员工编号/sub）→ 读 X-User-* 头，零查询；
 *   · 中文姓名（name/given_name/family_name）→ 用 access token 调 UserInfo
 *     拿干净 UTF-8，不再 unMojibake 反解码。
 * ═══════════════════════════════════════════════════════════════════════ */
async function collectIdentity(req) {
  const fromHeaders = {
    username: req.headers['x-user-username'] ?? null,
    email: req.headers['x-user-email'] ?? null,
    phone: req.headers['x-user-phone'] ?? null,
    employeeNo: req.headers['x-user-employee-no'] ?? null,
    sub: req.headers['x-user-sub'] ?? null,
  }
  const info = claimsToIdentity(await fetchUserInfo(extractAccessToken(req)))
  return {
    username: fromHeaders.username ?? info.username ?? null,
    name: info.name ?? null,
    email: fromHeaders.email ?? info.email ?? null,
    phone: fromHeaders.phone ?? info.phone ?? null,
    employeeNo: fromHeaders.employeeNo ?? info.employeeNo ?? null,
    givenName: info.givenName ?? null,
    familyName: info.familyName ?? null,
    sub: fromHeaders.sub ?? info.sub ?? null,
  }
}

/* ═══════════════════════════════════════════════════════════════════════
 * 【业务代码】返回「我知道你是谁」（链式末端，不再往下调）
 * ═══════════════════════════════════════════════════════════════════════ */
function render(identity) {
  const authenticated = !!(identity.username || identity.name || identity.sub)
  const name = identity.name || identity.username || '未知'
  return JSON.stringify({
    service: 'echo-c',
    hop: 3,
    authenticated,
    message: authenticated
      ? `我知道你是谁：${name}（${identity.username}）—— 这是第三跳`
      : '我不知道你是谁（未经过网关身份注入）',
    identity,
    note: '身份由网关 jwt-auth-demo-c 在这一跳重新验签注入（X-User-* 头），非上游转发',
  }, null, 2)
}

/* ═══════════════════════════════════════════════════════════════════════
 * 【对接代码】完整回显「实际收到的 HTTP 请求头」
 * ───────────────────────────────────────────────────────────────────────
 * 这是给页面「点击即测」展示用的：让用户直观看到 demo-c 这一跳到底收到了
 * 哪些头 —— Authorization（若 keep_token）/ X-User-*（网关注入身份）/
 * X-Forwarded-Access-Token（oidc 透传）等。
 *
 * ⚠️ 安全：Authorization / X-Forwarded-Access-Token 里的 token 只回显前缀
 *   （前 20 字符 + "..."），绝不回显完整 token，避免泄露到页面/日志。
 * ═══════════════════════════════════════════════════════════════════════ */
function maskToken(v) {
  if (v == null) return null
  const s = String(v)
  if (s.length <= 24) return s.slice(0, 8) + '...'
  return s.slice(0, 20) + '...' + s.slice(-6)
}

const SENSITIVE_HEADERS = new Set([
  'authorization',
  'x-forwarded-access-token',
])

function collectHeaders(req) {
  const headers = {}
  for (const [k, v] of Object.entries(req.headers)) {
    if (SENSITIVE_HEADERS.has(k)) {
      headers[k] = Array.isArray(v)
        ? v.map(maskToken)
        : maskToken(v)
    } else {
      headers[k] = v
    }
  }
  return headers
}

/* ═══════════════════════════════════════════════════════════════════════
 * 【业务代码】HTTP 服务器主干
 * ═══════════════════════════════════════════════════════════════════════ */
const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, `http://${req.headers.host}`)

  if (url.pathname === '/health') {
    res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8' })
    res.end(JSON.stringify({ ok: true, service: 'echo-c' }))
    return
  }

  // 链式末端身份回显（/aiapi/me 与 / 同义，供上游 B 透传调用）
  if (url.pathname === '/' || url.pathname === '/aiapi/me') {
    const identity = await collectIdentity(req)
    console.log('[echo-c]', JSON.stringify({ path: url.pathname, identity }))
    res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8' })
    res.end(render(identity))
    return
  }

  // 完整回显实际收到的请求头（给页面「点击即测」展示 C 这一跳收到的头）
  if (url.pathname === '/aiapi/echo-headers') {
    const identity = await collectIdentity(req)
    console.log('[echo-c]', JSON.stringify({ path: url.pathname, identity }))
    res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8' })
    res.end(JSON.stringify({
      service: 'echo-c',
      hop: 3,
      endpoint: '/aiapi/echo-headers',
      identity,
      headers: collectHeaders(req),
      note: 'Authorization / X-Forwarded-Access-Token 已脱敏（仅前缀）；X-User-* 由网关 jwt-auth-demo-c 注入',
    }, null, 2))
    return
  }

  res.writeHead(404, { 'Content-Type': 'application/json; charset=utf-8' })
  res.end(JSON.stringify({ service: 'echo-c', error: 'not found' }))
})

server.listen(PORT, '0.0.0.0', () => {
  console.log(`echo-c 身份透传链式末端已启动: http://0.0.0.0:${PORT}`)
})
