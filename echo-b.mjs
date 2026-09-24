#!/usr/bin/env node
/**
 * ============================================================================
 * echo-b.mjs —— 「身份透传」链路的【第二跳：中转服务（B 后台透传调 C）】
 * ============================================================================
 *
 * 这是「A → B → C 链式透传」示例的第二跳（中间跳）。它演示的核心命题是：
 *
 *   ★ 链路不止两跳时（客户端 → 网关 → A → 网关 → B → 网关 → C），
 *     身份怎么一路不衰减地传到末端 C？
 *     答案是：**每一跳都「透传原始 JWT 给网关，由网关重新验签注入身份」**。
 *     echo-b 作为中间跳，既「读网关注入头知道自己是谁」，又「把原始 JWT
 *     透传给网关的 demo-c 域名」，让 C 这一跳也由网关重新验签。
 *
 * ── 链式透传的正确姿势（对比旧 Java demo 的反面教材）──────────────────────
 *   旧 DemoA.java 的第二跳是「手动复制 X-User-* 头 + 走集群内 DNS 直连」，
 *   绕过了网关 → 身份是 A 自己转传的，可伪造。
 *   本文件（及 echo-a）演示的正确做法：只透传【原始 JWT】，身份由网关对
 *   下一跳重新验签，这样身份在任何一跳都可信、不随跳数衰减。
 *
 * ── 与单跳 echo-server 的差别 ──────────────────────────────────────────────
 *   唯一新增的对接代码是「读原始 JWT + 透传调 C」：
 *     (a) 读 Authorization 头拿原始 JWT（依赖网关 keep_token: true）
 *     (b) 透传 JWT 调下一跳（发到网关域名而非集群内）
 *   其余（读 X-User-* 身份头）与单跳 echo-server 完全一致。
 *
 * ── /aiapi 路径约定 ────────────────────────────────────────────────────────
 *   「可能有 AI 参与」的 API 统一 /aiapi 前缀、只挂 jwt-auth（验签）。
 *   echo-b 的 API 都在 /aiapi 下：/aiapi/me、/aiapi/call-c、/aiapi/echo-headers。
 *
 * 运行：node echo-b.mjs（PORT 默认 8080；ECHO_C_URL 指向 demo-c 的网关域名）
 * ═══════════════════════════════════════════════════════════════════════ */
import http from 'node:http'
import { fetchUserInfo, extractAccessToken, claimsToIdentity } from './userinfo.js'

const PORT = Number(process.env.PORT || 8080)

/* ═══════════════════════════════════════════════════════════════════════
 * 【对接代码】(a) 读取「原始 JWT」（供透传到下一跳 demo-c）
 * ───────────────────────────────────────────────────────────────────────
 * 要让第三跳 echo-c 也「由网关重新验签」，echo-b 必须能拿到客户端带来的
 * 原始 JWT。这依赖网关 jwt-auth-demo-b 配置 keep_token: true（中间跳必须
 * 保留 token，否则下一跳无 token 可透传）。
 * 这里取出「下一跳要透传的 JWT」，可能在：
 *   1. Authorization 头（keep_token:true 时网关原样透传原始 JWT）
 *   2. X-Forwarded-Access-Token 头（oidc 链路透传 access token）
 * ═══════════════════════════════════════════════════════════════════════ */
function extractJwt(req) {
  const fwd = req.headers['x-forwarded-access-token']
  if (fwd) return String(fwd).trim()
  const auth = req.headers['authorization'] || ''
  if (auth.startsWith('Bearer ')) return auth.slice(7).trim()
  return null
}

/* ═══════════════════════════════════════════════════════════════════════
 * 【对接代码】(b) 透传原始 JWT 调用下一跳（走网关，而非集群内 DNS）
 * 与 echo-a 的 callEchoB 同构：目标 = 网关的 demo-c 域名，不是集群内 DNS。
 * ═══════════════════════════════════════════════════════════════════════ */
async function callEchoC(jwt) {
  const url = process.env.ECHO_C_URL || 'https://demo-c.example.com/aiapi/me'
  const res = await fetch(url, {
    headers: {
      Authorization: `Bearer ${jwt}`,
    },
  })
  const body = await res.text()
  return { status: res.status, url, body }
}

/* ═══════════════════════════════════════════════════════════════════════
 * 【对接代码】读网关注入的身份头（ASCII）+ 调 UserInfo 拿中文姓名
 * ═══════════════════════════════════════════════════════════════════════
 * 公司统一约定的「身份透传规范」（详见 userinfo.js）：
 *   ASCII 字段读 X-User-* 头（零查询），中文姓名调 UserInfo 拿干净 UTF-8。
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
 * 【对接代码】完整回显「实际收到的 HTTP 请求头」（token 脱敏）
 * 给页面「点击即测」展示 B 这一跳实际收到的头。
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
 * 【业务代码】JSON 回显：本跳身份 + 下一跳 echo-c 的返回
 * ═══════════════════════════════════════════════════════════════════════ */
function renderChain(identity, jwtPresent, cResult) {
  return JSON.stringify({
    service: 'echo-b',
    hop: 2,
    myIdentity: identity,
    jwtForNextHop: jwtPresent ? '透传中（keep_token=true 生效）' : '缺失（第三跳会失败）',
    downstream: cResult
      ? {
          target: cResult.url,
          status: cResult.status,
          echoCResponse: (() => {
            try { return JSON.parse(cResult.body) } catch { return cResult.body }
          })(),
        }
      : null,
  }, null, 2)
}

/* ═══════════════════════════════════════════════════════════════════════
 * 【业务代码】HTTP 服务器主干
 * ═══════════════════════════════════════════════════════════════════════ */
const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, `http://${req.headers.host}`)

  if (url.pathname === '/health') {
    res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8' })
    res.end(JSON.stringify({ ok: true, service: 'echo-b' }))
    return
  }

  // 中间跳身份回显 + 链式透传调 C（/aiapi/me 与 / 同义）
  if (url.pathname === '/' || url.pathname === '/aiapi/me') {
    const identity = await collectIdentity(req)
    const jwt = extractJwt(req)
    console.log('[echo-b]', JSON.stringify({ path: url.pathname, identity, hasJwt: !!jwt }))

    if (!jwt) {
      res.writeHead(401, { 'Content-Type': 'application/json; charset=utf-8' })
      res.end(JSON.stringify({
        service: 'echo-b', hop: 2, mode: 'B-mid',
        error: 'Jwt is missing',
        hint: '中间跳需要原始 JWT 才能透传下一跳，请确认网关 jwt-auth-demo-b 配置了 keep_token: true',
      }, null, 2))
      return
    }

    callEchoC(jwt)
      .then((cResult) => {
        res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8' })
        res.end(renderChain(identity, true, cResult))
      })
      .catch((err) => {
        res.writeHead(502, { 'Content-Type': 'application/json; charset=utf-8' })
        res.end(JSON.stringify({
          service: 'echo-b',
          error: '调用 echo-c 失败',
          detail: String(err && err.message || err),
          hint: '检查 ECHO_C_URL 是否指向网关域名、NODE_EXTRA_CA_CERTS 是否挂载',
        }, null, 2))
      })
    return
  }

  // 显式「透传调 C」端点（页面点击即测用）
  if (url.pathname === '/aiapi/call-c') {
    const identity = await collectIdentity(req)
    const jwt = extractJwt(req)
    console.log('[echo-b]', JSON.stringify({ path: url.pathname, identity, hasJwt: !!jwt }))

    if (!jwt) {
      res.writeHead(401, { 'Content-Type': 'application/json; charset=utf-8' })
      res.end(JSON.stringify({ service: 'echo-b', hop: 2, mode: 'B-call-c', error: 'Jwt is missing' }))
      return
    }

    callEchoC(jwt)
      .then((cResult) => {
        res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8' })
        res.end(renderChain(identity, true, cResult))
      })
      .catch((err) => {
        res.writeHead(502, { 'Content-Type': 'application/json; charset=utf-8' })
        res.end(JSON.stringify({ service: 'echo-b', error: '调用 echo-c 失败', detail: String(err && err.message || err) }))
      })
    return
  }

  // 完整回显实际收到的请求头（页面「点击即测」展示 B 这一跳收到的头）
  // 若带 ?with-c=1，则 B 内部再透传 JWT 调 C 的 /aiapi/echo-headers，把 C 收到的头
  // 一并带回 —— 体现「A → B → C」真链路（C 的头是 B 调出来的，不是 A 直连 C）。
  if (url.pathname === '/aiapi/echo-headers') {
    const identity = await collectIdentity(req)
    const jwt = extractJwt(req)
    console.log('[echo-b]', JSON.stringify({ path: url.pathname, identity, hasJwt: !!jwt, withC: url.searchParams.get('with-c') === '1' }))

    // 不带 with-c=1：只回显 B 自己的头（向后兼容旧行为）
    if (url.searchParams.get('with-c') !== '1') {
      res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8' })
      res.end(JSON.stringify({
        service: 'echo-b',
        hop: 2,
        endpoint: '/aiapi/echo-headers',
        identity,
        headers: collectHeaders(req),
        note: 'Authorization / X-Forwarded-Access-Token 已脱敏（仅前缀）；X-User-* 由网关 jwt-auth-demo-b 注入',
      }, null, 2))
      return
    }

    // 带 with-c=1：B 内部透传 JWT 调 C 的 echo-headers，把 C 的头一并带回
    if (!jwt) {
      res.writeHead(401, { 'Content-Type': 'application/json; charset=utf-8' })
      res.end(JSON.stringify({ service: 'echo-b', hop: 2, mode: 'B-echo-headers-with-c', error: 'Jwt is missing' }))
      return
    }
    const cHeadersUrl = (process.env.ECHO_C_URL || 'https://demo-c.example.com/aiapi/me').replace(/\/aiapi\/me$/, '/aiapi/echo-headers')
    try {
      const cr = await fetch(cHeadersUrl, { headers: { Authorization: 'Bearer ' + jwt } })
      const ctxt = await cr.text()
      let cj; try { cj = JSON.parse(ctxt) } catch { cj = ctxt }
      res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8' })
      res.end(JSON.stringify({
        service: 'echo-b',
        hop: 2,
        endpoint: '/aiapi/echo-headers',
        identity,
        headers: collectHeaders(req),
        note: 'Authorization / X-Forwarded-Access-Token 已脱敏（仅前缀）；X-User-* 由网关 jwt-auth-demo-b 注入',
        downstreamEchoC: {
          url: cHeadersUrl,
          status: cr.status,
          data: cj,
        },
      }, null, 2))
    } catch (e) {
      res.writeHead(502, { 'Content-Type': 'application/json; charset=utf-8' })
      res.end(JSON.stringify({ service: 'echo-b', error: '调用 echo-c 失败', detail: String(e && e.message || e) }))
    }
    return
  }

  res.writeHead(404, { 'Content-Type': 'application/json; charset=utf-8' })
  res.end(JSON.stringify({ service: 'echo-b', error: 'not found' }))
})

server.listen(PORT, '0.0.0.0', () => {
  console.log(`echo-b 身份透传中间跳已启动: http://0.0.0.0:${PORT}（下一跳 ${process.env.ECHO_C_URL || 'https://demo-c.example.com/aiapi/me'}）`)
})
