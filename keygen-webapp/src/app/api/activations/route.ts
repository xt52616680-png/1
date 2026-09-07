/**
 * GET  /api/activations - list all activations (for status table)
 * POST /api/activations - revoke a specific activation
 *
 * The status table is the main "查看状态" view:
 *   [激活码] [机器码] [登录IP] [激活码类型] [激活时间] [剩余时间]
 */

import { NextRequest, NextResponse } from 'next/server';
import { db } from '@/lib/db';
import { checkAdmin } from '@/lib/admin';
import { remainingDays } from '@/lib/request-utils';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

export async function GET(req: NextRequest) {
  const denied = checkAdmin(req);
  if (denied) return denied;

  try {
    const url = new URL(req.url);
    const status = url.searchParams.get('status'); // active | expired | revoked
    const cardType = url.searchParams.get('cardType');

    const where: any = {};
    if (status) where.status = status;
    if (cardType) where.code = { cardType };

    const activations = await db.activation.findMany({
      where,
      include: {
        code: true,
        machine: true,
      },
      orderBy: { activatedAt: 'desc' },
    });

    const now = Date.now();
    const result = activations.map(a => {
      // Recalculate remaining days (more accurate than cached);
      // ceil so a license with hours left still shows 1 day, not 0.
      const realRemaining = remainingDays(a.expiresAt, new Date(now));
      const realStatus = a.status === 'revoked' ? 'revoked'
                        : now >= a.expiresAt.getTime() ? 'expired' : 'active';
      return {
        id: a.id,
        codeId: a.code.codeId,
        fullCode: a.code.fullCode,
        cardType: a.code.cardType,
        durationDays: a.code.durationDays,
        fingerprintHash: a.machine.fingerprintHash,
        fingerprintShort: a.machine.fingerprintHash.substring(0, 16),
        activatedAt: a.activatedAt.toISOString(),
        expiresAt: a.expiresAt.toISOString(),
        lastCallbackAt: a.lastCallbackAt?.toISOString() || null,
        lastIp: a.lastIp || '-',
        lastUserAgent: a.lastUserAgent || '',
        status: realStatus,
        remainingDays: realRemaining,
        machineFirstSeen: a.machine.firstSeenAt.toISOString(),
        machineLastSeen: a.machine.lastSeenAt.toISOString(),
      };
    });

    return NextResponse.json({ activations: result, total: result.length });
  } catch (e: any) {
    console.error('activations list error:', e);
    return NextResponse.json(
      { error: e.message || 'internal error' },
      { status: 500 }
    );
  }
}
