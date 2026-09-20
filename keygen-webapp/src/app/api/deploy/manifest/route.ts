/**
 * /api/deploy/manifest — 部署文件清单（需有效会话令牌）
 * 清单整体由服务器 Ed25519 私钥签名，客户端可用固化公钥验签防中间人。
 */
import { NextRequest, NextResponse } from 'next/server';
import { verifySessionToken, signSessionToken } from '@/lib/auth-token';
import { DEPLOY_MANIFEST_JSON } from '@/lib/deploy-bundle';
import { getPrivateKey } from '@/lib/keygen';
import * as ed from '@noble/ed25519';
import { sha512 } from '@noble/hashes/sha2.js';

(ed as any).hashes.sha512 = sha512;
(ed as any).hashes.sha512Async = async (msg: Uint8Array) => sha512(msg);

export const runtime = 'nodejs';

export async function GET(req: NextRequest) {
  const token = (req.headers.get('authorization') || '').replace(/^Bearer\s+/i, '');
  const v = await verifySessionToken(token);
  if (!v.valid || !v.payload) {
    return NextResponse.json({ ok: false, code: 'UNAUTHORIZED', message: '需要登录后才能获取部署清单' }, { status: 401 });
  }

  const manifest = JSON.parse(DEPLOY_MANIFEST_JSON);
  const manifestBytes = Buffer.from(DEPLOY_MANIFEST_JSON, 'utf8');
  const signature = await ed.signAsync(new Uint8Array(manifestBytes), getPrivateKey());
  const manifestSig = Buffer.from(signature).toString('base64url');

  return NextResponse.json({
    ok: true,
    data: { manifest, manifestSignature: manifestSig },
  });
}
