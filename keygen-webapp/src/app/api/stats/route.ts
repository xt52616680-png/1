/**
 * GET /api/stats
 * Dashboard stats: total codes, active, expired, revoked, total machines,
 * activations today, etc.
 */

import { NextRequest, NextResponse } from 'next/server';
import { db } from '@/lib/db';
import { checkAdmin } from '@/lib/admin';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

export async function GET(req: NextRequest) {
  const denied = checkAdmin(req);
  if (denied) return denied;

  try {
    const [
      totalCodes,
      activeCodes,
      unusedCodes,
      expiredCodes,
      revokedCodes,
      totalMachines,
      totalActivations,
      activeActivations,
      callbacksToday,
    ] = await Promise.all([
      db.activationCode.count(),
      db.activationCode.count({ where: { status: 'active' } }),
      db.activationCode.count({ where: { status: 'unused' } }),
      db.activationCode.count({ where: { status: 'expired' } }),
      db.activationCode.count({ where: { status: 'revoked' } }),
      db.machine.count(),
      db.activation.count(),
      db.activation.count({ where: { status: 'active' } }),
      db.callbackLog.count({
        where: {
          calledAt: {
            gte: new Date(Date.now() - 24 * 3600 * 1000),
          },
        },
      }),
    ]);

    // Breakdown by card type
    const byCardTypeRaw = await db.activationCode.groupBy({
      by: ['cardType'],
      _count: true,
    });
    const byCardType: Record<string, number> = {};
    for (const r of byCardTypeRaw) byCardType[r.cardType] = r._count;

    return NextResponse.json({
      totalCodes,
      activeCodes,
      unusedCodes,
      expiredCodes,
      revokedCodes,
      totalMachines,
      totalActivations,
      activeActivations,
      callbacksToday,
      byCardType,
    });
  } catch (e: any) {
    return NextResponse.json(
      { error: e.message || 'internal error' },
      { status: 500 }
    );
  }
}
