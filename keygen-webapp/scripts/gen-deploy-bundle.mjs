// 生成服务端 deploy 包模块：从 D:\pentagi 提取配置类部署文件 → src/lib/deploy-bundle.ts
// v1 范围：compose 编排 + 配置（外挂层）。汉化前端 dist 仍在安装器内（后续版本迁入）。
import fs from 'node:fs'
import path from 'node:path'
import { createHash } from 'node:crypto'

const REPO = 'D:\\pentagi'
const OUT = path.join(import.meta.dirname, '..', 'src', 'lib', 'deploy-bundle.ts')

const FILES = [
  'docker-compose.yml',
  'docker-compose.litellm.yml',
  'docker-compose.cn.yml',
  'docker-compose-graphiti.yml',
  'docker-compose.graphiti-llm.yml',
  'example.custom.provider.yml',
  '.env.example',
  'configs/pentagi-brains.provider.yml',
  'configs/graphiti/litellm.yaml',
]

const entries = FILES.map((rel) => {
  const abs = path.join(REPO, rel)
  const content = fs.readFileSync(abs, 'utf8')
  const sha256 = createHash('sha256').update(content, 'utf8').digest('hex')
  return { rel: rel.split('\\').join('/'), sha256, content }
})

const manifest = JSON.stringify(
  { version: 'v0.2.1', generatedAt: new Date().toISOString(), files: entries.map(({ rel, sha256 }) => ({ path: rel, sha256 })) },
  null,
  2,
)

const ts = `/**
 * src/lib/deploy-bundle.ts —— 自动生成（scripts/gen-deploy-bundle.mjs），勿手改。
 * deploy 外挂层文件的内容清单（UTF-8 明文 + sha256）。
 */
export const DEPLOY_VERSION = 'v0.2.1'
export const DEPLOY_MANIFEST_JSON = ${JSON.stringify(manifest)}

export interface DeployFile {
  path: string
  sha256: string
  content: string
}

export const DEPLOY_FILES: DeployFile[] = ${JSON.stringify(entries.map(({ rel, sha256, content }) => ({ path: rel, sha256, content })), null, 2)}
`

fs.writeFileSync(OUT, ts, 'utf8')
console.log(`✓ deploy-bundle.ts: ${entries.length} 个文件, manifest ${manifest.length} bytes`)
