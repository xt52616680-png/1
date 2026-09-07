/**
 * GET /api/codes
 * List all activation codes (with optional filters).
 *
 * Query: ?status=active|unused|expired|revoked
 *        ?cardType=month|season|year|time
 *        ?q=search by codeId/note
 *
 * Response: array of code records with computed activation counts.
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
    const url = new URL(req.url);
    const status = url.searchParams.get('status');
    const cardType = url.searchParams.get('cardType');
    const q = url.searchParams.get('q');

    const where: any = {};
    if (status) where.status = status;
    if (cardType) where.cardType = cardType;
    if (q) {
      where.OR = [
        { codeId: { contains: q } },
        { note: { contains: q } },
      ];
    }

    const codes = await db.activationCode.findMany({
      where,
      include: {
        activations: {
          include: { machine: true },
          orderBy: { lastCallbackAt: 'desc' },
        },
      },
      orderBy: { createdAt: 'desc' },
    });

    const result = codes.map(c => {
      const activeActivations = c.activations.filter(a => a.status === 'active');
      return {
        id: c.id,
        codeId: c.codeId,
        fullCode: c.fullCode,
        cardType: c.cardType,
        durationDays: c.durationDays,
        issuedAt: c.issuedAt.toISOString(),
        expiresAt: c.expiresAt.toISOString(),
        maxMachines: c.maxMachines,
        status: c.status,
        note: c.note,
        createdAt: c.createdAt.toISOString(),
        activatedMachines: c.activations.length,
        activeMachines: activeActivations.length,
        activations: c.activations.map(a => ({
          id: a.id,
          activatedAt: a.activatedAt.toISOString(),
          expiresAt: a.expiresAt.toISOString(),
          lastCallbackAt: a.lastCallbackAt?.toISOString() || null,
          lastIp: a.lastIp,
          status: a.status,
          remainingDays: a.remainingDays,
          machine: {
            fingerprintHash: a.machine.fingerprintHash,
            firstSeenAt: a.machine.firstSeenAt.toISOString(),
            lastSeenAt: a.machine.lastSeenAt.toISOString(),
          },
        })),
      };
    });

    return NextResponse.json({ codes: result, total: result.length });
  } catch (e: any) {
    console.error('codes list error:', e);
    return NextResponse.json(
      { error: e.message || 'internal error' },
      { status: 500 }
    );
  }
}
