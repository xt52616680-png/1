/**
 * /api/auth/heartbeat — periodic token renewal + revocation check.
 * Body: { token, clientVersion? }
 * Returns a FRESH token (rolling renewal) + authoritative plan/versions.
 */
import { NextRequest, NextResponse } from 'next/server';
import { db } from '@/lib/db';
import { verifySessionToken, signSessionToken } from '@/lib/auth-token';
import { getClientIp } from '@/lib/request-utils';

export const runtime = 'nodejs';

export const LATEST_VERSION = '0.2.1';
export const MIN_VERSION = '0.2.0';

function versionAtLeast(current: string, minimum: string): boolean {
  const c = current.split('.').map(Number);
  const m = minimum.split('.').map(Number);
  for (let i = 0; i < 3; i++) {
    if ((c[i] || 0) > (m[i] || 0)) return true;
    if ((c[i] || 0) < (m[i] || 0)) return false;
  }
  return true;
}

export async function POST(req: NextRequest) {
  let body: { token?: string; clientVersion?: string };
  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ ok: false, code: 'BAD_REQUEST', message: '请求格式错误' }, { status: 400 });
  }
  const token = (body.token || '').trim();
  if (!token) {
    return NextResponse.json({ ok: false, code: 'NO_TOKEN', message: '缺少令牌' }, { status: 401 });
  }

  const first = await verifySessionToken(token);
  if (!first.valid || !first.payload) {
    console.error('[heartbeat-debug] verify fail reason:', first.reason, '| token前30:', token.slice(0, 30), '| token长度:', token.length);
    const map: Record<string, { code: string; message: string }> = {
      expired: { code: 'TOKEN_EXPIRED', message: '令牌已过期，请重新登录' },
      token_version_mismatch: { code: 'TOKEN_REVOKED', message: '令牌已被更换（设备被挤下线或换绑），请重新登录' },
    };
    const m = map[first.reason ?? ''] ?? { code: 'TOKEN_INVALID', message: '令牌无效' };
    return NextResponse.json({ ok: false, code: m.code, message: m.message }, { status: 401 });
  }
  const claims = first.payload;

  const user = await db.user.findUnique({ where: { id: claims.uid }, include: { machines: true } });
  if (!user) {
    return NextResponse.json({ ok: false, code: 'TOKEN_REVOKED', message: '账号不存在，请重新登录' }, { status: 401 });
  }
  const machine = user.machines.find((m) => m.fingerprintHash.slice(0, 32) === claims.fp);
  if (!machine) {
    return NextResponse.json({ ok: false, code: 'TOKEN_REVOKED', message: '设备绑定已变更，请重新登录' }, { status: 401 });
  }
  if (machine.tokenVersion !== claims.tv) {
    return NextResponse.json(
      { ok: false, code: 'TOKEN_REVOKED', message: '令牌已被更换（设备被挤下线或换绑），请重新登录' },
      { status: 401 },
    );
  }
  if (user.status === 'BANNED') {
    return NextResponse.json({ ok: false, code: 'BANNED', message: '账号已被停用' }, { status: 403 });
  }

  const planExpired = user.planExpiresAt ? user.planExpiresAt.getTime() < Date.now() : false;
  const plan = planExpired ? 'EXPIRED' : user.plan;
  const { token: fresh, payload } = await signSessionToken({
    uid: user.id,
    fp: claims.fp,
    tv: machine.tokenVersion,
    plan,
  });

  await db.machine.update({
    where: { id: machine.id },
    data: { lastSeenAt: new Date(), lastIp: getClientIp(req) },
  });

  const clientVersion = (body.clientVersion || '').trim();
  const upgradeRequired = clientVersion ? !versionAtLeast(clientVersion, MIN_VERSION) : false;

  return NextResponse.json({
    ok: true,
    data: {
      token: fresh,
      expiresAt: payload.exp,
      plan,
      planExpiresAt: user.planExpiresAt,
      minVersion: MIN_VERSION,
      latestVersion: LATEST_VERSION,
      upgradeRequired,
    },
  });
}
