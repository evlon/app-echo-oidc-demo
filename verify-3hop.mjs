#!/usr/bin/env node
// verify-3hop.mjs —— 端到端验证「A → B → C 三跳链式透传」+ /aiapi 迁移 + header 回显
// 本机运行（需能访问 auth.example.com / demo-a/b/c.example.com）
// 凭据从环境变量读（不硬编码）：
//   KC_ADMIN_PASS  Keycloak 管理员密码
//   DEMO_A_SECRET  demo-a 这个 OIDC client 的 secret
//   （真实值只存在公司部署环境，勿提交到 GitHub）

const KC = 'https://auth.example.com'
const ADMIN_USER = process.env.KC_ADMIN_USER || 'admin'
const ADMIN_PASS = process.env.KC_ADMIN_PASS
const DEMO_A_SECRET = process.env.DEMO_A_SECRET
const EMP_USER = 'ssotest'
const EMP_NEW_PASS = process.env.KC_EMP_PASS || 'ChangeMe@123'

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
  const admin = await kcPost('/realms/master/protocol/openid-connect/token', {
    grant_type: 'password', client_id: 'admin-cli',
    username: 'admin', password: ADMIN_PASS,
  })
  if (!admin.data?.access_token) { console.error('❌ admin token 失败', admin.status, admin.raw.slice(0, 200)); process.exit(1) }
  const AT = admin.data.access_token
  console.log('✅ admin token OK')

  // 2. 查 ssotest
  const users = await kcReq('GET', '/admin/realms/employees/users?username=' + EMP_USER + '&exact=true', { token: AT })
  const u = users.data?.[0]
  if (!u) { console.error('❌ 找不到 ssotest'); process.exit(1) }

  // 3. 重置密码
  await kcReq('PUT', `/admin/realms/employees/users/${u.id}/reset-password`, {
    token: AT, jsonBody: { type: 'password', value: EMP_NEW_PASS, temporary: false },
  })
  console.log('✅ ssotest 密码已重置')

  // 4. 签 employees token（demo-a client）
  const emp = await kcPost('/realms/employees/protocol/openid-connect/token', {
    grant_type: 'password', client_id: 'demo-a',
    client_secret: DEMO_A_SECRET,
    username: EMP_USER, password: EMP_NEW_PASS,
    scope: 'openid profile email phone',
  })
  if (!emp.data?.access_token) { console.error('❌ employees token 失败', emp.status, emp.raw.slice(0, 500)); process.exit(1) }
  const JWT = emp.data.access_token
  console.log('✅ employees token OK，长度', JWT.length)

  // 5. 三跳验证：demo-a /aiapi/call-b（A → B → C）
  console.log('\n═══ A /aiapi/call-b（三跳链 A→B→C）═══')
  const da = await fetch('https://demo-a.example.com/aiapi/call-b', {
    headers: { Authorization: 'Bearer ' + JWT, Accept: 'application/json' },
  })
  const daBody = await da.text()
  console.log('  HTTP', da.status)
  console.log(daBody.split('\n').map(l => '  ' + l).join('\n'))

  // 6. A 的 echo-headers
  console.log('\n═══ A /aiapi/echo-headers（A 收到的头）═══')
  const ha = await fetch('https://demo-a.example.com/aiapi/echo-headers', {
    headers: { Authorization: 'Bearer ' + JWT },
  })
  console.log('  HTTP', ha.status)
  console.log((await ha.text()).split('\n').map(l => '  ' + l).join('\n'))

  // 7. 直接调 demo-c（第三跳独立认证）
  console.log('\n═══ 直接调 demo-c /aiapi/me（第三跳独立）═══')
  const dc = await fetch('https://demo-c.example.com/aiapi/me', {
    headers: { Authorization: 'Bearer ' + JWT },
  })
  console.log('  HTTP', dc.status)
  console.log((await dc.text()).split('\n').map(l => '  ' + l).join('\n'))

  // 8. 无 token → 401
  console.log('\n═══ 无 token 应 401 ═══')
  const noTok = await fetch('https://demo-a.example.com/aiapi/call-b')
  console.log('  /aiapi/call-b 无 token HTTP', noTok.status)
  const noTokC = await fetch('https://demo-c.example.com/aiapi/me')
  console.log('  demo-c /aiapi/me 无 token HTTP', noTokC.status)
}

main().catch(e => { console.error('ERR', e); process.exit(1) })
