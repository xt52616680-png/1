/**
 * /api/auth/unbind — release a bound machine (self-service, monthly limit).
 * Body: { token, targetMachineId? }  (缺省 = 解绑当前机器)
 */
import { NextRequest, NextResponse } from 'next/server';
import { db } from '@/lib/db';
import { verifySessionToken } from '@/lib/auth-token';
import { audit } from '@/lib/rate-limit';

export const runtime = 'nodejs';

const MONTHLY_UNBIND_LIMIT = 2;

export async function POST(req: NextRequest) {
  let body: { token?: string; targetMachineId?: string };
  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ ok: false, code: 'BAD_REQUEST', message: '请求格式错误' }, { status: 400 });
  }
  const token = (body.token || '').trim();
  const first = await verifySessionToken(token);
  if (!first.valid || !first.payload) {
    return NextResponse.json({ ok: false, code: 'TOKEN_INVALID', message: '令牌无效，请重新登录' }, { status: 401 });
  }
  const claims = first.payload;

  const user = await db.user.findUnique({ where: { id: claims.uid }, include: { machines: true } });
  if (!user) {
    return NextResponse.json({ ok: false, code: 'TOKEN_REVOKED', message: '账号不存在' }, { status: 401 });
  }

  const target = body.targetMachineId
    ? user.machines.find((m) => m.id === body.targetMachineId)
    : user.machines.find((m) => m.fingerprintHash.slice(0, 32) === claims.fp);

  if (!target) {
    return NextResponse.json({ ok: false, code: 'MACHINE_NOT_FOUND', message: '目标设备不存在或不属于该账号' }, { status: 404 });
  }

  // 月度换绑计数：解绑 + 新绑定共享当月 2 次额度
  const monthStart = new Date();
  monthStart.setDate(1);
  monthStart.setHours(0, 0, 0, 0);
  const unbindsThisMonth = await db.auditLog.count({
    where: { userId: user.id, action: { in: ['machine_evicted', 'unbind'] }, createdAt: { gte: monthStart } },
  });
  if (unbindsThisMonth >= MONTHLY_UNBIND_LIMIT) {
    return NextResponse.json(
      { ok: false, code: 'UNBIND_LIMIT', message: `本月解绑次数已用完（${MONTHLY_UNBIND_LIMIT} 次/月）` },
      { status: 403 },
    );
  }

  await db.machine.update({
    where: { id: target.id },
    data: { tokenVersion: { increment: 1 }, userId: null, machineName: target.machineName, rebindCount: { increment: 1 } },
  });
  await audit({ userId: user.id, action: 'unbind', req, meta: { machineId: target.id } });

  return NextResponse.json({
    ok: true,
    message: '设备已解绑',
    data: { machineId: target.id, remainingUnbinds: MONTHLY_UNBIND_LIMIT - unbindsThisMonth - 1 },
  });
}
