/**
 * /api/auth/login — account login, binds machine, issues session token.
 * Body: { email, password, fingerprintHash (sha256 hex), machineName? }
 * Rate limit: 5 consecutive failures / 15 min per account; 10/IP/15min.
 *
 * Machine-slot policy: when a NEW machine joins and slots are full,
 * the OLDEST machine is evicted (tokenVersion+1) — allowed at most
 * 2 evictions per calendar month per user (REBIND_LIMIT otherwise).
 */
import { NextRequest, NextResponse } from 'next/server';
import { db } from '@/lib/db';
import { verifyPassword } from '@/lib/password';
import { audit, checkIpLimit, checkLoginFailures } from '@/lib/rate-limit';
import { signSessionToken } from '@/lib/auth-token';
import { getClientIp } from '@/lib/request-utils';

export const runtime = 'nodejs';

const MONTHLY_REBIND_LIMIT = 2;

function fpPrefix(hash: string): string {
  return hash.slice(0, 32);
}

export async function POST(req: NextRequest) {
  const ipLimit = await checkIpLimit(req, 'login', 10, 15 * 60);
  if (!ipLimit.allowed) {
    await audit({ action: 'rate_limited', req, meta: { api: 'login' } });
    return NextResponse.json({ ok: false, code: 'RATE_LIMITED', message: '尝试过于频繁，请稍后再试' }, { status: 429 });
  }

  let body: { email?: string; password?: string; fingerprintHash?: string; machineName?: string };
  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ ok: false, code: 'BAD_REQUEST', message: '请求格式错误' }, { status: 400 });
  }

  const email = (body.email || '').trim().toLowerCase();
  const password = body.password || '';
  const fingerprintHash = (body.fingerprintHash || "").trim().toLowerCase();
  console.error("[login-debug] 收到指纹:", JSON.stringify(fingerprintHash).slice(0,80));
  const machineName = (body.machineName || '未命名设备').slice(0, 64);

  if (!email || !password || !/^[a-f0-9]{64}$/.test(fingerprintHash)) {
    return NextResponse.json(
      { ok: false, code: 'BAD_REQUEST', message: '缺少账号、密码或有效机器指纹（64 位十六进制）' },
      { status: 400 },
    );
  }

  const failGuard = await checkLoginFailures(email);
  if (!failGuard.allowed) {
    await audit({ action: 'rate_limited', req, meta: { api: 'login', email } });
    return NextResponse.json(
      { ok: false, code: 'TOO_MANY_FAILURES', message: '失败次数过多，账号已临时锁定 15 分钟' },
      { status: 429 },
    );
  }

  const user = await db.user.findUnique({ where: { email }, include: { machines: true } });
  if (!user || !(await verifyPassword(password, user.passwordHash))) {
    await audit({ action: 'login_fail', req, meta: { email, fingerprintHash: fingerprintHash.slice(0, 16) } });
    return NextResponse.json({ ok: false, code: 'INVALID_CREDENTIALS', message: '账号或密码错误' }, { status: 401 });
  }
  if (user.status === 'BANNED') {
    await audit({ userId: user.id, action: 'login_fail', req, meta: { reason: 'banned' } });
    return NextResponse.json({ ok: false, code: 'BANNED', message: '账号已被停用，请联系服务方' }, { status: 403 });
  }
  if (user.planExpiresAt && user.planExpiresAt.getTime() < Date.now()) {
    return NextResponse.json({ ok: false, code: 'PLAN_EXPIRED', message: '订阅已到期，请续费' }, { status: 403 });
  }

  // ── 机器绑定 ──
  const existing = await db.machine.findUnique({ where: { fingerprintHash } });
  const isNewMachine = !existing;
  let machine;

  if (existing && existing.userId && existing.userId !== user.id) {
    // 机器已被其他账号绑定 → 拒绝
    await audit({ userId: user.id, action: 'login_fail', req, meta: { reason: 'machine_owned_by_other' } });
    return NextResponse.json(
      { ok: false, code: 'MACHINE_BOUND', message: '该机器已绑定其他账号' },
      { status: 403 },
    );
  }

  if (!existing) {
    const activeMachines = user.machines.filter((m) => m.userId === user.id);
    if (activeMachines.length >= user.maxMachines) {
      // 满员 → 挤下线最老机器（当月限 2 次）
      const monthStart = new Date();
      monthStart.setDate(1);
      monthStart.setHours(0, 0, 0, 0);
      const evictionsThisMonth = await db.auditLog.count({
        where: { userId: user.id, action: { in: ['machine_evicted', 'unbind'] }, createdAt: { gte: monthStart } },
      });
      if (evictionsThisMonth >= MONTHLY_REBIND_LIMIT) {
        await audit({ userId: user.id, action: 'login_fail', req, meta: { reason: 'rebind_limit', email } });
        return NextResponse.json(
          {
            ok: false,
            code: 'REBIND_LIMIT',
            message: `本月设备换绑次数已用完（${MONTHLY_REBIND_LIMIT} 次/月），如需更换请联系服务方`,
          },
          { status: 403 },
        );
      }
      const oldest = activeMachines
        .slice()
        .sort((a, b) => (a.lastBindAt?.getTime() ?? 0) - (b.lastBindAt?.getTime() ?? 0))[0];
      // 挤下线 = 解绑（userId 置空）+ 作废旧令牌；否则旧机器仍占活跃名额
      await db.machine.update({
        where: { id: oldest.id },
        data: { tokenVersion: { increment: 1 }, userId: null, lastBindAt: new Date() },
      });
      await audit({
        userId: user.id,
        action: 'machine_evicted',
        req,
        meta: { evictedMachineId: oldest.id, newFingerprint: fingerprintHash.slice(0, 16) },
      });
    }
    machine = await db.machine.create({
      data: {
        fingerprintHash,
        componentsEnc: JSON.stringify({ machineName }),
        userId: user.id,
        machineName,
        lastBindAt: new Date(),
        rebindCount: 0,
      },
    });
  } else {
    // 已有机器：确保归属正确 + 刷新友好名
    machine = await db.machine.update({
      where: { id: existing.id },
      data: { userId: user.id, machineName, lastBindAt: new Date() },
    });
  }

  // ── 签发会话令牌 ──
  const { token, payload } = await signSessionToken({
    uid: user.id,
    fp: fpPrefix(fingerprintHash),
    tv: machine.tokenVersion,
    plan: user.plan,
  });

  await db.machine.update({ where: { id: machine.id }, data: { lastSeenAt: new Date(), lastIp: getClientIp(req) } });
  await audit({ userId: user.id, action: 'login_ok', req, meta: { machineId: machine.id, isNewMachine } });

  return NextResponse.json({
    ok: true,
    data: {
      token,
      expiresAt: payload.exp,
      plan: user.plan,
      planExpiresAt: user.planExpiresAt,
      machineId: machine.id,
      maxMachines: user.maxMachines,
    },
  });
}
