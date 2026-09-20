import fs from 'node:fs'
import * as ed from '@noble/ed25519'
import { sha512 } from '@noble/hashes/sha2.js'
ed.hashes.sha512 = sha512
ed.hashes.sha512Async = async (msg) => sha512(msg)
const env = fs.readFileSync('E:/Program Files (x86)/注册机系统/keygen-webapp/.env.development.local', 'utf8')
const priv = Buffer.from(env.match(/^LICENSE_ED25519_PRIVATE_KEY_B64=(.*)$/m)[1], 'base64url')
const pub = Buffer.from(env.match(/^LICENSE_ED25519_PUBLIC_KEY_B64=(.*)$/m)[1], 'base64url')
const r1 = JSON.parse(fs.readFileSync('C:/Users/xt775/AppData/Local/Temp/r1.json', 'utf8'))
const parts = r1.data.token.split('.')
const sig = new Uint8Array(Buffer.from(parts[2], 'base64url'))
const data = Buffer.from(parts[0] + '.' + parts[1], 'utf8')
console.log('真实令牌公钥验签:', await ed.verify(sig, new Uint8Array(data), pub))
console.log('令牌 payload:', Buffer.from(parts[1], 'base64url').toString('utf8'))
const b64uJson = (obj) => Buffer.from(JSON.stringify(obj), 'utf8').toString('base64url')
const header = b64uJson({ alg: 'Ed25519', typ: 'PAG-TOKEN', v: 1 })
const payload = b64uJson({ uid: 'debug', fp: 'f'.repeat(32), tv: 1, plan: 'TRIAL', iat: 1, exp: 2 })
const data2 = Buffer.from(header + '.' + payload, 'utf8')
const sig2 = await ed.signAsync(new Uint8Array(data2), priv)
console.log('自签自验:', await ed.verify(sig2, new Uint8Array(data2), pub))
