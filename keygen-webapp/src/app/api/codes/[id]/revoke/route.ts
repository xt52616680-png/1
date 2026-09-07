/**
 * POST /api/codes/[id]/revoke
 * Revoke an activation code (and all its activations).
 */

import { NextRequest, NextResponse } from 'next/server';
import { db } from '@/lib/db';
import { checkAdmin } from '@/lib/admin';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

export async function POST(
  req: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  const denied = checkAdmin(req);
  if (denied) return denied;

  try {
    const { id } = await params;
    const code = await db.activationCode.findUnique({ where: { id } });
    if (!code) {
      return NextResponse.json({ error: 'code not found' }, { status: 404 });
    }
    await db.activationCode.update({
      where: { id },
      data: { status: 'revoked' },
    });
    await db.activation.updateMany({
      where: { codeId: id },
      data: { status: 'revoked' },
    });
    return NextResponse.json({ ok: true, message: 'revoked' });
  } catch (e: any) {
    return NextResponse.json(
      { error: e.message || 'internal error' },
      { status: 500 }
    );
  }
}
