# License Keygen Web App

Next.js 16 注册机 Web 控制台。这是 License SDK 系统的服务端组件，提供激活码生成、状态查看、仪表盘、设置等 Web 界面和 API。

## 目录说明

这个目录包含**完整的 Next.js 项目源码**，可以直接部署到 Vercel / Cloudflare / 自建服务器。

## 快速开始

### 1. 安装依赖

```bash
cd keygen-webapp
bun install        # 或 npm install / pnpm install
```

### 2. 配置环境变量

```bash
cp .env.example .env
# 编辑 .env，填入您的 Ed25519 密钥对
# 用 download/license-sdk-python/generate_keypair.py 生成新密钥
```

### 3. 初始化数据库

```bash
bun run db:push    # 创建 SQLite 数据库（自动生成 db/custom.db）
```

### 4. 启动开发服务器

```bash
bun run dev
# 访问 http://localhost:3000
```

### 5. 生产部署（Vercel 推荐）

```bash
# 安装 Vercel CLI
npm i -g vercel

# 在项目根目录
vercel              # 首次部署
vercel --prod       # 生产部署

# 在 Vercel 控制台配置环境变量：
#   LICENSE_ED25519_PRIVATE_KEY_B64
#   LICENSE_ED25519_PUBLIC_KEY_B64
#   DATABASE_URL (使用 Vercel Postgres 免费层)
```

如果使用 Vercel Postgres，需要修改 `prisma/schema.prisma`：

```prisma
datasource db {
  provider = "postgresql"     // 改为 postgresql
  url      = env("DATABASE_URL")
}
```

## 项目结构

```
keygen-webapp/
├── src/
│   ├── app/
│   │   ├── page.tsx                       # 主控台（4 标签页）
│   │   ├── layout.tsx                     # 根布局
│   │   ├── globals.css                    # 暗色主题样式
│   │   └── api/
│   │       ├── keygen/generate/route.ts   # POST 生成激活码
│   │       ├── activate/route.ts          # POST 软件端激活
│   │       ├── callback/route.ts          # POST 周期性回调
│   │       ├── codes/route.ts             # GET 激活码列表
│   │       ├── codes/[id]/revoke/route.ts # POST 吊销激活码
│   │       ├── activations/route.ts       # GET 激活记录（状态表数据源）
│   │       └── stats/route.ts             # GET 仪表盘统计
│   ├── components/
│   │   ├── keygen/                        # 4 个业务面板
│   │   │   ├── generate-panel.tsx         # 生成激活码
│   │   │   ├── status-panel.tsx           # 状态查看（表格）
│   │   │   ├── dashboard-panel.tsx        # 仪表盘
│   │   │   └── settings-panel.tsx         # 设置（密钥/SDK 说明）
│   │   └── ui/                            # shadcn/ui 组件库（60+ 组件）
│   ├── lib/
│   │   ├── keygen-shared.ts               # 客户端常量/类型（卡类型/默认天数）
│   │   ├── keygen.ts                      # 服务端 Ed25519 签名/验签
│   │   ├── db.ts                          # Prisma 客户端
│   │   └── utils.ts                       # 工具函数
│   └── hooks/
│       ├── use-mobile.ts
│       └── use-toast.ts
├── prisma/
│   └── schema.prisma                      # 数据库 schema（4 张表）
├── public/
│   ├── logo.svg
│   └── robots.txt
├── package.json                           # 依赖与脚本
├── next.config.ts                         # Next.js 配置
├── tsconfig.json                          # TypeScript 配置
├── tailwind.config.ts                     # Tailwind CSS 配置
├── postcss.config.mjs
├── eslint.config.mjs
├── components.json                        # shadcn/ui 配置
├── Caddyfile                              # 反向代理配置（自建时用）
├── bun.lock                               # 依赖锁定文件
└── .env.example                           # 环境变量模板
```

## 卡类型默认天数（强制约束）

编辑 `src/lib/keygen-shared.ts` 的 `CARD_DEFAULT_DURATIONS` 常量即可修改：

```typescript
export const CARD_DEFAULT_DURATIONS: Record<CardType, number> = {
  month: 30,      // 月卡
  season: 30,     // 季卡（如需 90 天，改这里）
  year: 30,       // 年卡（如需 365 天，改这里）
  time: 0,        // 时卡（用户输入，1-3650）
};
```

## 数据库 Schema（4 张表）

| 表名 | 用途 |
|------|------|
| `ActivationCode` | 激活码（含签名、卡类型、有效期） |
| `Machine` | 已激活的机器（含指纹哈希、组件加密） |
| `Activation` | 激活记录（绑定 code + machine） |
| `CallbackLog` | 回调日志（IP、时间、状态） |

详见 `prisma/schema.prisma`。

## API 接口一览

| 方法 | 路径 | 用途 |
|------|------|------|
| POST | `/api/keygen/generate` | 生成新激活码 |
| POST | `/api/activate` | 软件端首次激活 |
| POST | `/api/callback` | 软件端周期性回调（每 6h） |
| GET | `/api/codes` | 查询所有激活码 |
| POST | `/api/codes/[id]/revoke` | 吊销激活码 |
| GET | `/api/activations` | 查询激活记录（状态表数据源） |
| GET | `/api/stats` | 仪表盘统计数据 |

## 客户端 SDK 配合使用

注册机部署后，配合 `download/license-sdk-python/` 里的 Python SDK 使用：

```python
from license_sdk import LicenseVerifier, LicenseConfig

verifier = LicenseVerifier(LicenseConfig(
    public_key_b64="<嵌入公钥>",
    keygen_url="https://your-app.vercel.app",  # 指向部署的注册机
    software_version="1.0.0",
    refuse_in_vm=True,  # 生产环境
))
```

## 部署选项

| 方案 | 成本 | 公网访问 | 推荐场景 |
|------|------|---------|---------|
| **Vercel 免费层** | 0 | ✓ | **生产推荐** |
| Cloudflare Workers | 0 | ✓ | 全球加速 |
| 自建 VPS | $5+/月 | ✓ | 完全控制 |
| 内网服务器 | 1 台机器 | 内网 | 企业内网 |

## 技术栈

- **Framework**: Next.js 16 (App Router)
- **Language**: TypeScript 5
- **Styling**: Tailwind CSS 4 + shadcn/ui (New York style)
- **Database**: Prisma ORM (SQLite 开发 / Postgres 生产)
- **Crypto**: @noble/ed25519 + @noble/hashes
- **Icons**: lucide-react
- **Notifications**: sonner

## 故障排查

### `LICENSE_ED25519_PRIVATE_KEY_B64 not set`
环境变量未配置。复制 `.env.example` 为 `.env` 并填入密钥。

### `Can't resolve '@noble/hashes/sha2'`
模块路径问题。已使用 `@noble/hashes/sha2.js`（带 .js 后缀）修复。

### `prisma/client not found`
首次运行需要生成 Prisma Client：
```bash
bun run db:generate
```

### 部署到 Vercel 后数据库丢失
SQLite 不适合生产环境。改用 Vercel Postgres：
1. 在 Vercel 控制台创建 Postgres 数据库
2. 修改 `prisma/schema.prisma` 的 `provider` 为 `"postgresql"`
3. 设置 `DATABASE_URL` 环境变量为 Vercel Postgres URL
4. 运行 `bun run db:push`

## 相关文档

- 完整技术文档：`download/docs/LICENSE_SDK_GUIDE.pdf` (22 页)
- Markdown 版本：`download/docs/LICENSE_SDK_GUIDE.md`
- Python SDK：`download/license-sdk-python/`
- 项目总说明：`download/README.md`
