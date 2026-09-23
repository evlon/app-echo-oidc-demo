#!/usr/bin/env node
// verify-transit.mjs —— 端到端验证「身份透传」链路（本机运行）
//
// 验证命题：echo-a（第一跳）收到带 JWT 的请求后，透传原始 JWT 调 echo-b（第二跳），
// 第二跳由网关重新验签注入身份，echo-b 返回「我知道你是谁」。
//
// 步骤：
//   1. Keycloak admin token（master realm）
//   2. 给 ssotest 员工重置密码（employees realm）
//   3. password grant 签一个新鲜的 employees token（demo-a client）
//   4. 带 token 调 https://demo-a.example.com/api/call-b → 看第一跳身份 + 第二跳返回
//   5. 无 token → 401；直接调 demo-b → 独立可认证
//
// 运行（本机，需能访问 auth.example.com / demo-a/b.example.com）：
//   node verify-transit.mjs

const KC = 'https://auth.example.com'
const ADMIN_USER = process.env.KC_ADMIN_USER || 'admin'
const ADMIN_PASS = process.env.KC_ADMIN_PASS  // 从环境变量读，不硬编码
const EMP_USER = 'ssotest'
const EMP_NEW_PASS = process.env.KC_EMP_PASS || 'ChangeMe@123'  // 测试账号临时密码
const DEMO_A_SECRET = process.env.DEMO_A_SECRET  // demo-a client secret，从环境变量读

if (!ADMIN_PASS) { console.error('需要 KC_ADMIN_PASS 环境变量'); process.exit(1) }
if (!DEMO_A_SECRET) { console.error('需要 DEMO_A_SECRET 环境变量'); process.exit(1) }

async function kcPost(path, formObj) {
  const body = new URLSearchParams(formObj).toString()
  const r = await fetch(KC + path, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body,
  })
  const t = await r.text()
  let j; try { j = JSON.parse(t) } catch { j = null }
  return { status: r.status, data: j, raw: t }
}

async function kcReq(method, path, { token, jsonBody } = {}) {
  const headers = { Accept: 'application/json' }
  if (token) headers.Authorization = 'Bearer ' + token
  if (jsonBody) headers['Content-Type'] = 'application/json'
  const r = await fetch(KC + path, {
    method, headers, body: jsonBody ? JSON.stringify(jsonBody) : undefined,
  })
  const t = await r.text()
  let j; try { j = JSON.parse(t) } catch { j = null }
  return { status: r.status, data: j, raw: t }
}

async function main() {
  // 1. admin token
  console.log('═══ 1. 拿 Keycloak admin token ═══')
  const admin = await kcPost('/realms/master/protocol/openid-connect/token', {
    grant_type: 'password', client_id: 'admin-cli',
    username: ADMIN_USER, password: ADMIN_PASS,
  })
  if (!admin.data?.access_token) { console.error('❌ admin token 失败', admin.status, admin.raw.slice(0, 200)); process.exit(1) }
  const AT = admin.data.access_token
  console.log('  ✅ admin token OK')

  // 2. 查 ssotest
  console.log('═══ 2. 查 employees realm 的 ssotest ═══')
  const users = await kcReq('GET', '/admin/realms/employees/users?username=' + EMP_USER + '&exact=true', { token: AT })
  const u = users.data?.[0]
  if (!u) { console.error('❌ 找不到 ssotest'); process.exit(1) }
  console.log('  ✅ 用户', u.username, 'id=', u.id)

  // 3. 重置密码
  console.log('═══ 3. 重置 ssotest 密码 ═══')
  const reset = await kcReq('PUT', `/admin/realms/employees/users/${u.id}/reset-password`, {
    token: AT, jsonBody: { type: 'password', value: EMP_NEW_PASS, temporary: false },
  })
  console.log('  重置密码 HTTP', reset.status)

  // 4. 签 employees token
  console.log('═══ 4. password grant 签 employees token（demo-a client）═══')
  const emp = await kcPost('/realms/employees/protocol/openid-connect/token', {
    grant_type: 'password', client_id: 'demo-a',
    client_secret: DEMO_A_SECRET,
    username: EMP_USER, password: EMP_NEW_PASS,
    scope: 'openid profile email phone',
  })
  if (!emp.data?.access_token) { console.error('❌ employees token 失败', emp.status, emp.raw.slice(0, 500)); process.exit(1) }
  const JWT = emp.data.access_token
  console.log('  ✅ employees token OK，长度', JWT.length)

  // 5. 解码 claims
  const payload = JSON.parse(Buffer.from(JWT.split('.')[1].replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString())
  console.log('  claims:', JSON.stringify({ iss: payload.iss, azp: payload.azp, sub: payload.sub, preferred_username: payload.preferred_username, name: payload.name }, null, 2))

  // 6. 调 demo-a（第一跳）→ 内部调 echo-b（第二跳）
  console.log('\n═══ 5. 调 demo-a/api/call-b（第一跳 → 第二跳身份透传）═══')
  const da = await fetch('https://demo-a.example.com/api/call-b', {
    headers: { Authorization: 'Bearer ' + JWT, Accept: 'application/json' },
  })
  const daBody = await da.text()
  console.log('  demo-a HTTP', da.status)
  console.log('  body:')
  console.log(daBody.split('\n').map(l => '    ' + l).join('\n'))

  // 7. 无 token → 401
  console.log('\n═══ 6. 无 token 应 401 ═══')
  const noTok = await fetch('https://demo-a.example.com/api/call-b')
  console.log('  无 token HTTP', noTok.status)

  // 8. 直接调 demo-b（第二跳独立可认证）
  console.log('\n═══ 7. 直接调 demo-b/api/me（第二跳独立认证）═══')
  const db = await fetch('https://demo-b.example.com/api/me', {
    headers: { Authorization: 'Bearer ' + JWT },
  })
  const dbBody = await db.text()
  console.log('  demo-b HTTP', db.status)
  console.log(dbBody.split('\n').map(l => '    ' + l).join('\n'))
}

main().catch(e => { console.error('ERR', e); process.exit(1) })
