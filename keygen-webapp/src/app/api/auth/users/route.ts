/**
 * /api/auth/users — 用户管理（管理员接口，x-admin-key 鉴权）
 * GET    列出用户（含机器数）      ?email= 可选过滤
 * POST   创建用户 {email,password,plan,maxMachines,planExpiresAt?}
 * PATCH  更新用户 {userId, plan?, maxMachines?, status?, planExpiresAt?}
 * DELETE 删除用户 ?userId=
 */
import { NextRequest, NextResponse } from 'next/server';
import { db } from '@/lib/db';
import { checkAdmin } from '@/lib/admin';
import { hashPassword, isValidEmail } from '@/lib/password';

export const runtime = 'nodejs';

export async function GET(req: NextRequest) {
  const denied = checkAdmin(req);
  if (denied) return denied;

  const email = req.nextUrl.searchParams.get('email');
  const users = await db.user.findMany({
    where: email ? { email } : undefined,
    include: { machines: { select: { id: true, machineName: true, lastSeenAt: true, lastIp: true, tokenVersion: true, fingerprintHash: true } } },
    orderBy: { createdAt: 'desc' },
  });

  return NextResponse.json({
    ok: true,
    data: users.map((u) => ({
      id: u.id,
      email: u.email,
      plan: u.plan,
      planExpiresAt: u.planExpiresAt,
      maxMachines: u.maxMachines,
      status: u.status,
      createdAt: u.createdAt,
      machines: u.machines.map((m) => ({
        id: m.id,
        name: m.machineName,
        lastSeenAt: m.lastSeenAt,
        lastIp: m.lastIp,
        fingerprint: m.fingerprintHash.slice(0, 16), // 设备机器码（前 16 位展示）
      })),
    })),
  });
}

export async function POST(req: NextRequest) {
  const denied = checkAdmin(req);
  if (denied) return denied;

  let body: { email?: string; password?: string; plan?: string; maxMachines?: number; planExpiresAt?: string };
  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ ok: false, code: 'BAD_REQUEST', message: '请求格式错误' }, { status: 400 });
  }

  const email = (body.email || '').trim().toLowerCase();
  const password = body.password || '';
  if (!isValidEmail(email)) {
    return NextResponse.json({ ok: false, code: 'INVALID_EMAIL', message: '邮箱格式无效' }, { status: 400 });
  }
  if (password.length < 8) {
    return NextResponse.json({ ok: false, code: 'WEAK_PASSWORD', message: '密码至少 8 位' }, { status: 400 });
  }
  const existing = await db.user.findUnique({ where: { email } });
  if (existing) {
    return NextResponse.json({ ok: false, code: 'EMAIL_TAKEN', message: '该邮箱已注册' }, { status: 409 });
  }

  const plan = ['TRIAL', 'STANDARD', 'PRO'].includes(body.plan || '') ? body.plan! : 'TRIAL';
  const user = await db.user.create({
    data: {
      email,
      passwordHash: await hashPassword(password),
      plan: plan as 'TRIAL' | 'STANDARD' | 'PRO',
      maxMachines: Math.max(1, Math.min(50, body.maxMachines ?? 1)),
      planExpiresAt: body.planExpiresAt ? new Date(body.planExpiresAt) : null,
    },
  });

  return NextResponse.json({ ok: true, message: '用户已创建', data: { userId: user.id, email: user.email, plan: user.plan } }, { status: 201 });
}

export async function PATCH(req: NextRequest) {
  const denied = checkAdmin(req);
  if (denied) return denied;

  let body: { userId?: string; plan?: string; maxMachines?: number; status?: string; planExpiresAt?: string | null };
  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ ok: false, code: 'BAD_REQUEST', message: '请求格式错误' }, { status: 400 });
  }
  if (!body.userId) {
    return NextResponse.json({ ok: false, code: 'BAD_REQUEST', message: '缺少 userId' }, { status: 400 });
  }

  const data: Record<string, unknown> = {};
  if (body.plan && ['TRIAL', 'STANDARD', 'PRO'].includes(body.plan)) data.plan = body.plan;
  if (typeof body.maxMachines === 'number') data.maxMachines = Math.max(1, Math.min(50, body.maxMachines));
  if (body.status && ['ACTIVE', 'BANNED'].includes(body.status)) data.status = body.status;
  if (body.planExpiresAt !== undefined) data.planExpiresAt = body.planExpiresAt ? new Date(body.planExpiresAt) : null;
  if (Object.keys(data).length === 0) {
    return NextResponse.json({ ok: false, code: 'NOTHING_TO_UPDATE', message: '没有可更新的字段' }, { status: 400 });
  }

  const user = await db.user.update({ where: { id: body.userId }, data });
  return NextResponse.json({ ok: true, message: '已更新', data: { userId: user.id } });
}

export async function DELETE(req: NextRequest) {
  const denied = checkAdmin(req);
  if (denied) return denied;

  const userId = req.nextUrl.searchParams.get('userId');
  if (!userId) {
    return NextResponse.json({ ok: false, code: 'BAD_REQUEST', message: '缺少 userId' }, { status: 400 });
  }
  // 机器解绑（保留 Machine 记录本身，供指纹历史）
  await db.machine.updateMany({ where: { userId }, data: { userId: null, tokenVersion: { increment: 1 } } });
  await db.user.delete({ where: { id: userId } });
  return NextResponse.json({ ok: true, message: '用户已删除，其设备已解绑' });
}
