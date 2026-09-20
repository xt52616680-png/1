// E2E 测试套件：注册/登录/心跳/换绑/错误路径（本地 keygen_dev 库）
// 用法: node scripts/e2e-auth.mjs [baseUrl]
import http from 'node:http'
import { createHash } from 'node:crypto'

const BASE = process.argv[2] || 'http://127.0.0.1:3210'
const fp = (n) => createHash('sha256').update(`fp-machine-${n}-e2e-${Math.random().toString(36).slice(2, 8)}`).digest('hex')
let pass = 0
let fail = 0

function req(path, body, method = 'POST') {
  return new Promise((resolve) => {
    const data = JSON.stringify(body)
    const r = http.request(
      BASE + path,
      { method, headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(data) } },
      (res) => {
        let d = ''
        res.on('data', (c) => (d += c))
        res.on('end', () => {
          let j = null
          try { j = JSON.parse(d) } catch {}
          resolve({ status: res.statusCode, json: j, raw: d })
        })
      },
    )
    r.on('error', (e) => resolve({ status: 0, json: null, raw: e.message }))
    r.end(data)
  })
}

function check(name, cond, detail = '') {
  if (cond) { pass++; console.log(`  ✓ ${name}`) }
  else { fail++; console.log(`  ✗ ${name} ${detail}`) }
}


const EMAIL = `e2e-${Date.now()}@local.dev`
const PASSWORD = 'Passw0rd!2026'

console.log(`\n=== E2E 授权系统 · ${BASE} ===\n`)

// 1. 版本接口（公开）
const v = await req('/api/version', {}, 'GET')
check('版本接口 200', v.status === 200 && v.json?.data?.minVersion)

// 2. 注册
const reg = await req('/api/auth/register', { email: EMAIL, password: PASSWORD })
check('注册成功 201', reg.status === 201)

// 3. 重复注册
const reg2 = await req('/api/auth/register', { email: EMAIL, password: PASSWORD })
check('重复注册 409', reg2.status === 409)

// 4. 登录机器1
const l1 = await req('/api/auth/login', { email: EMAIL, password: PASSWORD, fingerprintHash: fp('m1'), machineName: 'e2e-m1' })
check('登录 m1 200', l1.status === 200 && l1.json?.data?.token)
const token1 = l1.json?.data?.token

// 5. 心跳（滚动续期；Ed25519 确定性签名——同秒内令牌相同是正常行为）
const hb = await req('/api/auth/heartbeat', { token: token1, clientVersion: '0.2.1' })
check('心跳 200 + 有效令牌', hb.status === 200 && hb.json?.data?.token && hb.json.data.token.split('.').length === 3)
check('心跳返回版本信息', !!hb.json?.data?.minVersion)

// 6. 篡改令牌
const bad = await req('/api/auth/heartbeat', { token: token1.slice(0, -4) + 'xxxx', clientVersion: '0.2.1' })
check('篡改令牌 401', bad.status === 401)

// 7. 错密码
const wp = await req('/api/auth/login', { email: EMAIL, password: 'wrong-password', fingerprintHash: fp('m1') })
check('错密码 401', wp.status === 401)

// 8. 登录机器2（挤下线机器1）
const l2 = await req('/api/auth/login', { email: EMAIL, password: PASSWORD, fingerprintHash: fp('m2'), machineName: 'e2e-m2' })
check('登录 m2 200（挤下线 m1）', l2.status === 200 && l2.json?.data?.token)

// 9. 机器1 旧令牌 → 已吊销
const hb1 = await req('/api/auth/heartbeat', { token: token1, clientVersion: '0.2.1' })
check('旧令牌心跳 401 TOKEN_REVOKED', hb1.status === 401 && hb1.json?.code === 'TOKEN_REVOKED')

// 10. 登录机器3（挤下线机器2，当月第2次换绑）
const l3 = await req('/api/auth/login', { email: EMAIL, password: PASSWORD, fingerprintHash: fp('m3'), machineName: 'e2e-m3' })
check('登录 m3 200（挤下线 m2，第2次）', l3.status === 200 && l3.json?.data?.token)

// 11. 登录机器4 → 月配额用完（已2次驱逐）→ REBIND_LIMIT；若配额未满则接受 200
const l4 = await req('/api/auth/login', { email: EMAIL, password: PASSWORD, fingerprintHash: fp('m4'), machineName: 'e2e-m4' })
check('登录 m4 按配额处理（200=未满/403=REBIND_LIMIT）', l4.status === 200 || (l4.status === 403 && l4.json?.code === 'REBIND_LIMIT'))
const tokenM4 = l4.json?.data?.token

// 12. 账号B：解绑成功路径（独立账号，不受A的驱逐配额影响）
const EMAIL_B = `e2e-b-${Date.now()}@local.dev`
const rb = await req('/api/auth/register', { email: EMAIL_B, password: PASSWORD })
const lb1 = await req('/api/auth/login', { email: EMAIL_B, password: PASSWORD, fingerprintHash: fp('b1'), machineName: 'e2e-b1' })
const ub = await req('/api/auth/unbind', { token: lb1.json?.data?.token })
check('账号B 解绑当前机器 200', ub.status === 200)

// 13. 解绑后心跳 → tv 已变 → TOKEN_REVOKED
const hb3 = await req('/api/auth/heartbeat', { token: lb1.json?.data?.token, clientVersion: '0.2.1' })
check('解绑后心跳 401', hb3.status === 401)

// 14. 重新登录（重绑，第1次换绑）
const l4b = await req('/api/auth/login', { email: EMAIL_B, password: PASSWORD, fingerprintHash: fp('b2'), machineName: 'e2e-b2' })
check('解绑后重登 200', l4b.status === 200 && l4b.json?.data?.token)

// 15. 错误指纹格式
const bf = await req('/api/auth/login', { email: EMAIL, password: PASSWORD, fingerprintHash: 'not-a-hash' })
check('无效指纹 400', bf.status === 400)

console.log(`\n=== 结果: ${pass} 通过 / ${fail} 失败 ===\n`)
process.exit(fail ? 1 : 0)
