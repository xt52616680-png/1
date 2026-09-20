/**
 * /api/auth/register — create a user account.
 * Rate limit: 3/IP/hour + global 30/IP/hour.
 */
import { NextRequest, NextResponse } from 'next/server';
import { db } from '@/lib/db';
import { hashPassword, isValidEmail } from '@/lib/password';
import { audit, checkIpLimit } from '@/lib/rate-limit';

export const runtime = 'nodejs';

export async function POST(req: NextRequest) {
  const ipLimit = await checkIpLimit(req, 'register', 10, 3600);
  if (!ipLimit.allowed) {
    await audit({ action: 'rate_limited', req, meta: { api: 'register' } });
    return NextResponse.json(
      { ok: false, code: 'RATE_LIMITED', message: '注册过于频繁，请 1 小时后再试' },
      { status: 429 },
    );
  }

  let body: { email?: string; password?: string };
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
  if (password.length < 8 || password.length > 100) {
    return NextResponse.json({ ok: false, code: 'WEAK_PASSWORD', message: '密码长度须为 8-100 个字符' }, { status: 400 });
  }

  const existing = await db.user.findUnique({ where: { email } });
  if (existing) {
    return NextResponse.json({ ok: false, code: 'EMAIL_TAKEN', message: '该邮箱已注册' }, { status: 409 });
  }

  const user = await db.user.create({
    data: { email, passwordHash: await hashPassword(password), plan: 'TRIAL' },
  });

  await audit({ userId: user.id, action: 'register', req, meta: { email } });
  return NextResponse.json({ ok: true, message: '注册成功', data: { userId: user.id, plan: user.plan } }, { status: 201 });
}
