/**
 * /api/deploy/download?id=... — 单个部署文件内容（需有效会话令牌）
 * v1 文件随 serverless 包分发（deploy-bundle.ts）；量大后迁 R2/OSS 签名 URL。
 */
import { NextRequest, NextResponse } from 'next/server';
import { verifySessionToken } from '@/lib/auth-token';
import { DEPLOY_FILES } from '@/lib/deploy-bundle';

export const runtime = 'nodejs';

export async function GET(req: NextRequest) {
  const token = (req.headers.get('authorization') || '').replace(/^Bearer\s+/i, '');
  const v = await verifySessionToken(token);
  if (!v.valid || !v.payload) {
    return NextResponse.json({ ok: false, code: 'UNAUTHORIZED', message: '需要登录后才能下载部署文件' }, { status: 401 });
  }

  const id = req.nextUrl.searchParams.get('id') || '';
  const file = DEPLOY_FILES.find((f) => f.path === id);
  if (!file) {
    return NextResponse.json({ ok: false, code: 'NOT_FOUND', message: `部署文件不存在：${id}` }, { status: 404 });
  }

  return NextResponse.json({
    ok: true,
    data: { path: file.path, sha256: file.sha256, content: file.content },
  });
}
