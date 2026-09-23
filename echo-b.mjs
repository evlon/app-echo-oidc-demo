#!/usr/bin/env node
/**
 * ============================================================================
 * echo-b.mjs —— 「身份透传」链路的【第二跳：被调服务】
 * ============================================================================
 *
 * 这是「身份透传」标准示例的第二跳。它要回答的问题是：
 *
 *   ★ 当上游服务（echo-a）调用我时，「我是谁」由谁来告诉我？
 *     答案是【网关】—— echo-b 不信任上游传来的任何身份字段，只相信
 *     网关在入口处重新验签后注入的 X-User-* 头。
 *
 * ── 为什么 echo-b 的代码几乎和单跳 echo-server 一模一样 ───────────────────
 *   这正是本示例想强调的：**对 echo-b 而言，它根本不知道、也不需要知道
 *   请求是「客户端直接来的」还是「echo-a 转发来的」**。它只需要做一件事
 *   —— 读网关注入的 X-User-* 头。身份透传是【网关】的职责，不是下游服务
 *   要额外写的代码。
 *
 *   所以 echo-b 的对接代码，和 echo-server.mjs 的 collectIdentity 完全一致：
 *   读 X-User-* 头 + 中文乱码修复，仅此而已。
 *
 * ── 代码如何划分 ───────────────────────────────────────────────────────────
 *   【业务代码】  ：HTTP 服务器、/health、返回「我知道你是谁」。
 *   【对接代码】  ：(a) 读网关注入的 X-User-* 身份头
 *                  (b) unMojibake 中文乱码修复
 * ═══════════════════════════════════════════════════════════════════════ */
import http from 'node:http'

const PORT = Number(process.env.PORT || 8080)

/* ═══════════════════════════════════════════════════════════════════════
 * 【对接代码】(b) 中文 header 乱码修复（与 echo-server.mjs 同源）
 * ═══════════════════════════════════════════════════════════════════════ */
function unMojibake(v) {
  if (v == null) return null
  try {
    return Buffer.from(String(v), 'latin1').toString('utf8')
  } catch {
    return v
  }
}

/* ═══════════════════════════════════════════════════════════════════════
 * 【对接代码】(a) 读网关注入的身份头（这是接入认证唯一要写的核心代码）
 * ───────────────────────────────────────────────────────────────────────
 * 网关 jwt-auth-b 对 demo-b 这一跳重新验签后，把 JWT 身份字段注入
 * X-User-* 头。echo-b 只从这里读「当前是谁」，不信任任何上游直接传来的
 * 身份头（因为它可能是被 echo-a 伪造的）。
 * ═══════════════════════════════════════════════════════════════════════ */
function collectIdentity(req) {
  return {
    username: req.headers['x-user-username'] ?? null,
    name: unMojibake(req.headers['x-user-name']),
    email: req.headers['x-user-email'] ?? null,
    phone: req.headers['x-user-phone'] ?? null,
    employeeNo: req.headers['x-user-employee-no'] ?? null,
    givenName: unMojibake(req.headers['x-user-given-name']),
    familyName: unMojibake(req.headers['x-user-family-name']),
    sub: req.headers['x-user-sub'] ?? null,
  }
}

/* ═══════════════════════════════════════════════════════════════════════
 * 【业务代码】返回「我知道你是谁」
 * 这就是本示例要的最终结果：第二跳服务能准确说出「你是谁」。
 * 身份来自网关注入头，echo-b 零登录代码。
 * ═══════════════════════════════════════════════════════════════════════ */
function render(identity) {
  const authenticated = !!(identity.username || identity.name || identity.sub)
  const name = identity.name || identity.username || '未知'
  return JSON.stringify({
    service: 'echo-b',
    hop: 2,
    authenticated,
    message: authenticated
      ? `我知道你是谁：${name}（${identity.username}）`
      : '我不知道你是谁（未经过网关身份注入）',
    identity,
    // 关键提示：echo-b 只认网关注入的头，不认上游手动传的身份
    note: '身份由网关 jwt-auth-b 在这一跳重新验签注入（X-User-* 头），非上游转发',
  }, null, 2)
}

/* ═══════════════════════════════════════════════════════════════════════
 * 【业务代码】HTTP 服务器主干
 * 与 echo-server.mjs 同构：/health 探针 + 主路由读身份回显。
 * ═══════════════════════════════════════════════════════════════════════ */
const server = http.createServer((req, res) => {
  const url = new URL(req.url, `http://${req.headers.host}`)

  if (url.pathname === '/health') {
    res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8' })
    res.end(JSON.stringify({ ok: true, service: 'echo-b' }))
    return
  }

  if (url.pathname === '/' || url.pathname === '/api/me') {
    const identity = collectIdentity(req)
    console.log('[echo-b]', JSON.stringify({ path: url.pathname, identity }))
    res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8' })
    res.end(render(identity))
    return
  }

  res.writeHead(404, { 'Content-Type': 'application/json; charset=utf-8' })
  res.end(JSON.stringify({ service: 'echo-b', error: 'not found' }))
})

server.listen(PORT, '0.0.0.0', () => {
  console.log(`echo-b 身份透传被调服务已启动: http://0.0.0.0:${PORT}`)
})
