#!/usr/bin/env node
// verify-3hop-real.mjs —— 端到端复测「A→B→C 真第二跳」+ hop3 修复验证
// 真实域名：demo-a/b/c.ai.ict.cmcc，Keycloak auth.ict.cmcc
import { execSync } from 'node:child_process'

const KC = 'https://auth.ict.cmcc'
const ADMIN_USER = 'admin'
const ADMIN_PASS = process.env.KC_ADMIN_PASS || ''        // Keycloak 管理员密码，从环境变量读（不硬编码）
const DEMO_A_SECRET = process.env.DEMO_A_SECRET || ''     // demo-a client secret，从环境变量读（不硬编码）
const EMP_USER = 'ssotest'
const EMP_NEW_PASS = process.env.SSOTEST_PASS || 'ChangeMe@123'  // ssotest 测试账号临时密码（可环境变量覆盖）

async function post(path, formObj) {
  const r = await fetch(KC + path, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams(formObj).toString(),
  })
  const t = await r.text()
  let j; try { j = JSON.parse(t) } catch { j = null }
  return { status: r.status, data: j, raw: t }
}

async function req(method, path, { token, jsonBody } = {}) {
  const headers = { Accept: 'application/json' }
  if (token) headers.Authorization = 'Bearer ' + token
  if (jsonBody) headers['Content-Type'] = 'application/json'
  const r = await fetch(KC + path, { method, headers, body: jsonBody ? JSON.stringify(jsonBody) : undefined })
  const t = await r.text()
  let j; try { j = JSON.parse(t) } catch { j = null }
  return { status: r.status, data: j, raw: t }
}

const results = []
function check(name, ok, detail) {
  results.push({ name, ok, detail })
  console.log((ok ? '✅' : '❌') + ' ' + name + (detail ? ' — ' + detail : ''))
}

async function main() {
  // 1. admin token
  const admin = await post('/realms/master/protocol/openid-connect/token', {
    grant_type: 'password', client_id: 'admin-cli', username: ADMIN_USER, password: ADMIN_PASS,
  })
  if (!admin.data?.access_token) { console.error('❌ admin token 失败', admin.status, admin.raw.slice(0, 200)); process.exit(1) }
  const AT = admin.data.access_token
  check('Keycloak admin token', true, 'OK')

  // 2. 查 ssotest
  const users = await req('GET', '/admin/realms/employees/users?username=' + EMP_USER + '&exact=true', { token: AT })
  const u = users.data?.[0]
  if (!u) { console.error('❌ 找不到 ssotest'); process.exit(1) }

  // 3. 重置密码
  await req('PUT', `/admin/realms/employees/users/${u.id}/reset-password`, {
    token: AT, jsonBody: { type: 'password', value: EMP_NEW_PASS, temporary: false },
  })
  check('ssotest 密码重置', true)

  // 4. 签 employees token（demo-a client）
  const emp = await post('/realms/employees/protocol/openid-connect/token', {
    grant_type: 'password', client_id: 'demo-a', client_secret: DEMO_A_SECRET,
    username: EMP_USER, password: EMP_NEW_PASS, scope: 'openid profile email phone',
  })
  if (!emp.data?.access_token) { console.error('❌ employees token 失败', emp.status, emp.raw.slice(0, 500)); process.exit(1) }
  const JWT = emp.data.access_token
  check('employees JWT 签发', true, '长度 ' + JWT.length)

  // ═══ 核心验证 1：B /aiapi/echo-headers?with-c=1 应返回 downstreamEchoC（B 透传调 C）═══
  console.log('\n═══ B /aiapi/echo-headers?with-c=1（真第二跳 B→C）═══')
  const rb = await fetch('https://demo-b.ai.ict.cmcc/aiapi/echo-headers?with-c=1', {
    headers: { Authorization: 'Bearer ' + JWT },
  })
  const rbText = await rb.text()
  let rbJson; try { rbJson = JSON.parse(rbText) } catch { rbJson = null }
  check('B echo-headers HTTP 200', rb.status === 200, 'HTTP ' + rb.status)
  check('B 返回 downstreamEchoC', !!(rbJson?.downstreamEchoC), rbJson?.downstreamEchoC ? '存在' : '缺失（下游 C 调用失败）')
  if (rbJson?.downstreamEchoC) {
    const cStatus = rbJson.downstreamEchoC.status
    check('C 这一跳 HTTP 200', cStatus === 200, 'HTTP ' + cStatus)
    check('C 返回身份（hop3 不再是 fetch failed）', !!rbJson.downstreamEchoC.data?.identity?.username || !!rbJson.downstreamEchoC.data?.service, 
      rbJson.downstreamEchoC.data?.service + ' / ' + (rbJson.downstreamEchoC.data?.identity?.username || '?'))
  }
  console.log('  B 原始返回（截断）:\n' + rbText.split('\n').slice(0, 60).map(l => '    ' + l).join('\n'))

  // ═══ 核心验证 2：A /ui/headers 走真链路（A→B→C）═══
  // 该端点走 oidc 会话，本机无法直接带 oidc cookie；改测 A /aiapi/echo-headers 确认 A 自身正常
  console.log('\n═══ A /aiapi/echo-headers（A 自身这一跳）═══')
  const ra = await fetch('https://demo-a.ai.ict.cmcc/aiapi/echo-headers', {
    headers: { Authorization: 'Bearer ' + JWT },
  })
  check('A echo-headers HTTP 200', ra.status === 200, 'HTTP ' + ra.status)
  const raText = await ra.text()

  // ═══ 核心验证 3：A /aiapi/call-b 走三跳链（A→B→C，B 透传调 C）═══
  console.log('\n═══ A /aiapi/call-b（三跳链 A→B→C）═══')
  const rc = await fetch('https://demo-a.ai.ict.cmcc/aiapi/call-b', {
    headers: { Authorization: 'Bearer ' + JWT },
  })
  const rcText = await rc.text()
  let rcJson; try { rcJson = JSON.parse(rcText) } catch { rcJson = null }
  check('A call-b HTTP 200', rc.status === 200, 'HTTP ' + rc.status)
  // downstream.echoBResponse.downstream.echoCResponse 应存在（B 透传 C 的结果）
  const cResp = rcJson?.downstream?.echoBResponse?.downstream?.echoCResponse
  check('三跳链 C 端有响应', !!(cResp?.message || cResp?.service), cResp ? (cResp.service + ' hop' + cResp.hop) : '缺失')
  if (cResp?.identity?.username) check('C 端识别到身份', true, cResp.identity.username + ' / ' + cResp.identity.name)

  // ═══ 4：无 token 应 401（回归）═══
  const noTok = await fetch('https://demo-c.ai.ict.cmcc/aiapi/me')
  check('无 token 401（回归）', noTok.status === 401, 'HTTP ' + noTok.status)

  console.log('\n════════ 结果汇总 ════════')
  const fail = results.filter(r => !r.ok)
  console.log('通过 ' + (results.length - fail.length) + '/' + results.length)
  if (fail.length) {
    console.log('失败项：')
    fail.forEach(f => console.log('  ❌ ' + f.name + ' — ' + f.detail))
    process.exit(1)
  } else {
    console.log('🎉 全部通过，hop3（C 请求头）修复已生效')
  }
}

main().catch(e => { console.error('ERR', e); process.exit(1) })
