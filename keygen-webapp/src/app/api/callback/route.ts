/**
 * POST /api/callback
 * Periodic callback from activated software.
 *
 * Body: {
 *   code_id: string,
 *   full_code: string,
 *   fingerprint_hash: string,
 *   components_encrypted: string,
 *   local_ip: string,
 *   software_version: string,
 *   client_nonce: string,
 *   client_time: number,
 *   last_known_remaining: number,
 * }
 *
 * Response: {
 *   status: 'ok' | 'expired' | 'revoked' | 'mismatch',
 *   server_time: number,
 *   remaining_days: number,
 *   next_callback_in: number,
 *   message?: string,
 * }
 */

import { NextRequest, NextResponse } from 'next/server';
import { db } from '@/lib/db';
import { getClientIp, isValidFingerprint, remainingDays } from '@/lib/request-utils';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

export async function POST(req: NextRequest) {
  try {
    const body = await req.json();
    const { code_id, fingerprint_hash } = body;

    if (typeof code_id !== 'string' || !code_id || code_id.length > 32 ||
        !isValidFingerprint(fingerprint_hash)) {
      return NextResponse.json(
        { status: 'mismatch', server_time: Math.floor(Date.now()/1000),
          remaining_days: 0, next_callback_in: 3600,
          message: 'missing or malformed fields' },
        { status: 400 }
      );
    }

    // Find code
    const code = await db.activationCode.findUnique({
      where: { codeId: code_id },
      include: { activations: { include: { machine: true } } },
    });
    if (!code) {
      return NextResponse.json({
        status: 'revoked', server_time: Math.floor(Date.now()/1000),
        remaining_days: 0, next_callback_in: 3600,
        message: 'code unknown',
      });
    }

    // Find matching activation by machine fingerprint
    const activation = code.activations.find(
      a => a.machine.fingerprintHash === fingerprint_hash
    );
    if (!activation) {
      return NextResponse.json({
        status: 'mismatch', server_time: Math.floor(Date.now()/1000),
        remaining_days: 0, next_callback_in: 3600,
        message: 'machine not activated with this code',
      });
    }

    // Check status
    if (code.status === 'revoked') {
      return NextResponse.json({
        status: 'revoked', server_time: Math.floor(Date.now()/1000),
        remaining_days: 0, next_callback_in: 3600,
        message: 'code revoked',
      });
    }

    const now = new Date();
    // Expiry must be decided by timestamp: rounding days down would mark a
    // license with a few hours left as expired.
    const expired = now.getTime() >= activation.expiresAt.getTime();
    const remaining = remainingDays(activation.expiresAt, now);
    let newStatus = 'active';
    if (expired) newStatus = 'expired';

    // Update activation
    await db.activation.update({
      where: { id: activation.id },
      data: {
        lastCallbackAt: now,
        lastIp: getClientIp(req),
        lastUserAgent: (req.headers.get('user-agent') || '').slice(0, 256),
        remainingDays: remaining,
        status: newStatus,
      },
    });

    // Update machine lastSeen
    await db.machine.update({
      where: { id: activation.machineId },
      data: { lastSeenAt: now },
    });

    // Log callback
    const noteVersion = String(body.software_version || '?').slice(0, 64);
    const noteLocalIp = String(body.local_ip || '?').slice(0, 64);
    await db.callbackLog.create({
      data: {
        activationId: activation.id,
        machineId: activation.machineId,
        ip: getClientIp(req),
        userAgent: (req.headers.get('user-agent') || '').slice(0, 256),
        remainingDays: remaining,
        status: newStatus === 'active' ? 'ok' : 'expired',
        notes: `v=${noteVersion}, local_ip=${noteLocalIp}`,
      },
    });

    return NextResponse.json({
      status: newStatus === 'active' ? 'ok' : newStatus,
      server_time: Math.floor(now.getTime() / 1000),
      remaining_days: remaining,
      next_callback_in: 6 * 3600,
      message: 'ok',
    });
  } catch (e: any) {
    console.error('callback error:', e);
    return NextResponse.json(
      { status: 'mismatch', server_time: Math.floor(Date.now()/1000),
        remaining_days: 0, next_callback_in: 3600,
        message: e.message || 'internal error' },
      { status: 500 }
    );
  }
}
