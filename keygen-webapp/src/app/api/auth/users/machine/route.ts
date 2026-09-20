/**
 * /api/auth/users/machine — 管理员解绑设备（x-admin-key 鉴权）
 * DELETE ?machineId=... → 解除绑定（userId 置空）+ 旧令牌作废（tokenVersion+1）。
 * 客户下次登录该机器时自动重新绑定。
 */
import { NextRequest, NextResponse } from 'next/server';
import { db } from '@/lib/db';
import { checkAdmin } from '@/lib/admin';
import { audit } from '@/lib/rate-limit';

export const runtime = 'nodejs';

export async function DELETE(req: NextRequest) {
  const denied = checkAdmin(req);
  if (denied) return denied;

  const machineId = req.nextUrl.searchParams.get('machineId');
  if (!machineId) {
    return NextResponse.json({ ok: false, code: 'BAD_REQUEST', message: '缺少 machineId' }, { status: 400 });
  }

  const machine = await db.machine.findUnique({ where: { id: machineId } });
  if (!machine) {
    return NextResponse.json({ ok: false, code: 'NOT_FOUND', message: '设备不存在' }, { status: 404 });
  }

  await db.machine.update({
    where: { id: machineId },
    data: { userId: null, tokenVersion: { increment: 1 } },
  });
  await audit({ userId: machine.userId, action: 'admin_unbind', req, meta: { machineId } });

  return NextResponse.json({ ok: true, message: '设备已解绑，客户下次登录时将自动重新绑定' });
}
