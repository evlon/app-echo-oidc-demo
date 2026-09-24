/**
 * ============================================================================
 * userinfo.js —— 「身份查询」标准对接模块（业务后端调用 Keycloak UserInfo）
 * ============================================================================
 *
 * 这是给业务开发人员照抄的【标准对接代码】：用 access token 调用公司统一认证
 * （Keycloak）的 UserInfo 端点，拿到「当前用户」的完整身份信息。
 *
 * ── 为什么要有这个模块 ────────────────────────────────────────────────────────
 * 身份信息分两类，各自走不同的通道（这是公司统一约定的「身份透传规范」）：
 *
 *   ├─ ASCII 类（username / email / phone_number / sub / 员工编号…）
 *   │     → 网关 claims_to_headers 注入 X-User-* 头，业务【直接读头】，零查询。
 *   │       这些字段天生 ASCII，不会乱码，读头是最快、最省的姿势。
 *   │
 *   └─ 非 ASCII 类（中文姓名 name / given_name / family_name…）
 *         → 网关把 UTF-8 中文字段写进 header 时，Node 会按 latin-1 解码导致乱码
 *           （「牛昆亮」→「çæäº®」）。与其让每个业务都写 unMojibake 反解码，
 *           不如统一约定：中文这类【会乱码】的字段，业务用 access token 调
 *           UserInfo 拿【干净 UTF-8】。这是 OIDC 标准端点，返回标准 JSON，
 *           中文永远正确，且能拿到 JWT/头里没有的完整 profile。
 *
 * ── 什么时候调、什么时候不调（性能约定）─────────────────────────────────────
 *   大多数业务只需要 username/email/phone 这类 ASCII 字段 → 读头即可，【零查询】。
 *   只有【确实需要中文姓名】时才调一次 UserInfo（一次网络往返，换取中文干净）。
 *   这样既保证了中文正确，又把查询代价降到最低。
 *
 * ── 关键点（照抄清单）────────────────────────────────────────────────────────
 *   1. UserInfo 是 OIDC 标准端点：
 *        GET {issuer}/protocol/openid-connect/userinfo
 *        Authorization: Bearer <access_token>
 *      本公司的 issuer = https://auth.ict.cmcc/realms/employees
 *      （即 UserInfo 地址 = https://auth.ict.cmcc/realms/employees/protocol/openid-connect/userinfo）
 *   2. 返回是标准 UTF-8 JSON：{ sub, preferred_username, name, email, phone_number, ... }
 *      name 里的中文是【干净】的，直接 resp.name 即可，无需任何反解码。
 *   3. access token 从哪来：
 *      - API/Bearer 链路：Authorization 头（网关 keep_token:true 时透传）；
 *      - 浏览器 OIDC 链路：X-Forwarded-Access-Token 头（oidc 插件 pass_access_token 注入）。
 *      两者都拿到后，二选一（优先 X-Forwarded-Access-Token，见 extractAccessToken）。
 *   4. 内网自签证书：调 https://auth.ict.cmcc 需要信任企业根证书，见 deploy yaml
 *      的 NODE_EXTRA_CA_CERTS + company-root-ca 挂载。
 *
 * 用法：
 *   import { fetchUserInfo, extractAccessToken } from './userinfo.js'
 *   const tok = extractAccessToken(req)          // 拿 access token
 *   const info = tok ? await fetchUserInfo(tok) : null  // 调 UserInfo 拿全量
 * ============================================================================
 */

/** Keycloak issuer（公司统一认证基址）。可用环境变量覆盖，便于多环境部署。 */
export const ISSUER = process.env.KEYCLOAK_ISSUER || 'https://auth.ict.cmcc/realms/employees'

/** UserInfo 端点完整地址（OIDC 标准路径，勿改后缀）。 */
export const USERINFO_URL = `${ISSUER}/protocol/openid-connect/userinfo`

/**
 * 【对接代码】从请求里取出「要拿去调 UserInfo 的 access token」。
 *
 * 两种链路，token 位置不同（顺序很重要）：
 *   1. X-Forwarded-Access-Token —— 浏览器 OIDC 链路，oidc 插件 pass_access_token
 *      注入的是 access token（受众正确、含完整 claim），【优先】用它；
 *   2. Authorization: Bearer —— API/Bearer 直调链路，网关 jwt-auth keep_token:true
 *      时透传原始 JWT。浏览器链路里这个头放的是 ID Token（受众是 client，不含
 *      完整 profile），不能用来调 UserInfo，所以只作 API 场景的兜底。
 *
 * @param {import('node:http').IncomingMessage} req
 * @returns {string|null} access token（或 null）
 */
export function extractAccessToken(req) {
  const fwd = req.headers['x-forwarded-access-token']
  if (fwd) return String(fwd).trim()
  const auth = req.headers['authorization'] || ''
  if (auth.startsWith('Bearer ')) return auth.slice(7).trim()
  return null
}

/**
 * 【对接代码】调用 Keycloak UserInfo，拿「当前用户」的完整身份。
 *
 * 返回标准 UTF-8 JSON（claims 原样透传），中文干净无需反解码。
 * 失败（401/网络错误/超时）返回 null，调用方按「读头兜底」处理，绝不 throw。
 *
 * @param {string} accessToken
 * @returns {Promise<object|null>} UserInfo 返回的 claims 对象，失败为 null
 */
export async function fetchUserInfo(accessToken) {
  if (!accessToken) return null
  try {
    const res = await fetch(USERINFO_URL, {
      headers: { Authorization: `Bearer ${accessToken}` },
      // 内网自签证书由 NODE_EXTRA_CA_CERTS 信任；这里不主动关闭校验
    })
    if (!res.ok) return null // 401/403 说明 token 无效，静默降级
    return await res.json()
  } catch {
    return null // 网络失败 / 证书问题，静默降级（读头兜底）
  }
}

/**
 * 【对接代码】把 UserInfo 返回的 claims 归一化成业务侧统一的身份对象。
 *
 * 字段名与网关注入的 X-User-* 头一一对应，业务层拿到后无需区分「值来自头还是来自
 * UserInfo」，直接用同一套字段名（username/name/email/phone/employeeNo/sub…）。
 *
 * @param {object|null} claims UserInfo 返回的 claims
 * @returns {object} 归一化身份对象（缺失字段为 null）
 */
export function claimsToIdentity(claims) {
  return claims ? {
    username: claims.preferred_username ?? null,
    name: claims.name ?? null,
    email: claims.email ?? null,
    phone: claims.phone_number ?? null,
    employeeNo: claims.new_emp_no ?? null,
    givenName: claims.given_name ?? null,
    familyName: claims.family_name ?? null,
    sub: claims.sub ?? null,
  } : {}
}
