/**
 * PATCH /api/activations/[id]
 * Manage a single activated device (admin only).
 *
 * Body: { action: 'pause' | 'resume' | 'revoke' }
 *   pause  -> status 'paused'  (recoverable; software is told "revoked")
 *   resume -> status 'active'  (only from 'paused')
 *   revoke -> status 'revoked' (final; re-activation of this device is rejected)
 *
 * Response: { ok: true, status }
 */

import { NextRequest, NextResponse } from 'next/server';
import { db } from '@/lib/db';
import { checkAdmin } from '@/lib/admin';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

const ACTIONS: Record<string, string> = {
  pause: 'paused',
  resume: 'active',
  revoke: 'revoked',
};

export async function PATCH(
  req: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  const denied = checkAdmin(req);
  if (denied) return denied;

  try {
    const { id } = await params;
    const body = await req.json();
    const action = body?.action;
    const newStatus = ACTIONS[action];
    if (!newStatus) {
      return NextResponse.json(
        { error: "action 必须是 'pause' | 'resume' | 'revoke' 之一" },
        { status: 400 }
      );
    }

    const activation = await db.activation.findUnique({ where: { id } });
    if (!activation) {
      return NextResponse.json({ error: 'activation not found' }, { status: 404 });
    }

    if (action === 'resume' && activation.status !== 'paused') {
      return NextResponse.json(
        { error: `仅「已暂停」的设备可以恢复（当前状态: ${activation.status}）` },
        { status: 400 }
      );
    }

    const updated = await db.activation.update({
      where: { id },
      data: { status: newStatus },
    });

    return NextResponse.json({ ok: true, status: updated.status });
  } catch (e: any) {
    console.error('activation manage error:', e);
    return NextResponse.json(
      { error: e.message || 'internal error' },
      { status: 500 }
    );
  }
}
