// 从部署密钥文件提取 LICENSE_* 到本地开发环境文件（本机专用，gitignore 已覆盖）
import fs from 'node:fs'

const KEY_FILE = 'E:\\Program Files (x86)\\注册机系统\\部署密钥-勿外传.txt'
const OUT_FILE = 'E:\\Program Files (x86)\\注册机系统\\keygen-webapp\\.env.development.local'

const txt = fs.readFileSync(KEY_FILE, 'utf8')
const get = (key) => {
  const re = new RegExp(key + '\\s*[=:]\\s*([A-Za-z0-9+/=_-]+)')
  const m = re.exec(txt)
  return m ? m[1] : ''
}

const priv = get('LICENSE_ED25519_PRIVATE_KEY_B64')
const pub = get('LICENSE_ED25519_PUBLIC_KEY_B64')
const admin = get('LICENSE_ADMIN_KEY')

if (!priv || priv.length < 40) {
  console.error('提取失败: priv 长度 =', priv.length)
  process.exit(1)
}
console.log('priv b64 长度:', priv.length, '→ 解码', Buffer.from(priv, 'base64url').length, 'bytes')
console.log('pub b64 长度:', pub.length)
console.log('admin key 长度:', admin.length)

const env =
  `DATABASE_URL=postgresql://postgres:postgres@127.0.0.1:5432/keygen_dev\n` +
  `LICENSE_ED25519_PRIVATE_KEY_B64=${priv}\n` +
  `LICENSE_ED25519_PUBLIC_KEY_B64=${pub}\n` +
  `LICENSE_ADMIN_KEY=${admin}\n`

fs.writeFileSync(OUT_FILE, env, 'utf8')
console.log('✓', OUT_FILE)
