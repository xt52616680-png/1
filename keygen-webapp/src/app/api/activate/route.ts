/**
 * POST /api/activate
 * Called by the software SDK to register a new machine activation.
 *
 * Body: {
 *   code_id: string,
 *   full_code: string,
 *   fingerprint_hash: string,
 *   components_encrypted: string (base64),
 *   software_version: string,
 *   client_time: number (unix seconds),
 * }
 *
 * Response: {
 *   status: 'ok' | 'rejected',
 *   message: string,
 *   activation_id?: string,
 *   expires_at?: number,
 *   remaining_days?: number,
 * }
 */

import { NextRequest, NextResponse } from 'next/server';
import { db } from '@/lib/db';
import { verifyActivationCode } from '@/lib/keygen';
import { getClientIp, isValidFingerprint, remainingDays } from '@/lib/request-utils';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

export async function POST(req: NextRequest) {
  try {
    const body = await req.json();
    const { code_id, full_code, fingerprint_hash, components_encrypted,
            software_version, client_time } = body;

    if (typeof code_id !== 'string' || !code_id || code_id.length > 32 ||
        typeof full_code !== 'string' || !full_code || full_code.length > 512) {
      return NextResponse.json(
        { status: 'rejected', message: 'missing or malformed required fields' },
        { status: 400 }
      );
    }
    if (!isValidFingerprint(fingerprint_hash)) {
      return NextResponse.json(
        { status: 'rejected', message: 'fingerprint_hash must be a sha256 hex digest' },
        { status: 400 }
      );
    }
    if (components_encrypted !== undefined &&
        (typeof components_encrypted !== 'string' || components_encrypted.length > 16384)) {
      return NextResponse.json(
        { status: 'rejected', message: 'components_encrypted too large' },
        { status: 400 }
      );
    }
    if (software_version !== undefined &&
        (typeof software_version !== 'string' || software_version.length > 64)) {
      return NextResponse.json(
        { status: 'rejected', message: 'software_version too long' },
        { status: 400 }
      );
    }

    // Verify code signature
    let verification;
    try {
      verification = await verifyActivationCode(full_code);
    } catch (e: any) {
      return NextResponse.json(
        { status: 'rejected', message: `code parse failed: ${e.message}` },
        { status: 400 }
      );
    }
    if (!verification.valid) {
      return NextResponse.json(
        { status: 'rejected', message: 'signature verification failed' },
        { status: 403 }
      );
    }
    if (verification.payload.codeId !== code_id) {
      return NextResponse.json(
        { status: 'rejected', message: 'code_id mismatch' },
        { status: 400 }
      );
    }

    // Find the code in DB
    const code = await db.activationCode.findUnique({
      where: { codeId: code_id },
      include: { activations: true },
    });
    if (!code) {
      return NextResponse.json(
        { status: 'rejected', message: 'code not issued by this keygen' },
        { status: 404 }
      );
    }
    if (code.status === 'revoked') {
      return NextResponse.json(
        { status: 'rejected', message: 'code has been revoked' },
        { status: 403 }
      );
    }

    // Check expiry (timestamp comparison, not the rounded day count)
    const expiresAt = new Date(verification.payload.expiresAt * 1000);
    const now = new Date();
    if (now.getTime() >= expiresAt.getTime()) {
      await db.activationCode.update({
        where: { id: code.id },
        data: { status: 'expired' },
      });
      return NextResponse.json(
        { status: 'rejected', message: 'code already expired' },
        { status: 403 }
      );
    }

    // Find or create machine
    let machine = await db.machine.findUnique({
      where: { fingerprintHash: fingerprint_hash },
    });
    if (!machine) {
      machine = await db.machine.create({
        data: {
          fingerprintHash: fingerprint_hash,
          componentsEnc: components_encrypted || '',
          lastSeenAt: now,
        },
      });
    } else {
      await db.machine.update({
        where: { id: machine.id },
        data: { lastSeenAt: now },
      });
    }

    // Check if this (code, machine) already activated
    const existing = await db.activation.findUnique({
      where: { codeId_machineId: { codeId: code.id, machineId: machine.id } },
    });
    if (existing) {
      // Re-activation: allow if still valid
      const remaining = remainingDays(existing.expiresAt, now);
      await db.activation.update({
        where: { id: existing.id },
        data: {
          lastCallbackAt: now,
          lastIp: getClientIp(req),
          lastUserAgent: (req.headers.get('user-agent') || '').slice(0, 256),
          remainingDays: remaining,
          status: 'active',
        },
      });
      return NextResponse.json({
        status: 'ok',
        message: 're-activation ok',
        activation_id: existing.id,
        expires_at: Math.floor(existing.expiresAt.getTime() / 1000),
        remaining_days: remaining,
      });
    }

    // Check max machines
    const activeCount = code.activations.filter(a => a.status === 'active').length;
    if (activeCount >= code.maxMachines) {
      return NextResponse.json(
        { status: 'rejected',
          message: `max machines (${code.maxMachines}) reached for this code` },
        { status: 403 }
      );
    }

    // Create activation
    const remaining = remainingDays(expiresAt, now);
    const activation = await db.activation.create({
      data: {
        codeId: code.id,
        machineId: machine.id,
        activatedAt: now,
        expiresAt,
        lastCallbackAt: now,
        lastIp: getClientIp(req),
        lastUserAgent: (req.headers.get('user-agent') || '').slice(0, 256),
        status: 'active',
        remainingDays: remaining,
      },
    });

    // Update code status
    await db.activationCode.update({
      where: { id: code.id },
      data: { status: 'active' },
    });

    // Log the callback too
    await db.callbackLog.create({
      data: {
        activationId: activation.id,
        machineId: machine.id,
        ip: getClientIp(req),
        userAgent: (req.headers.get('user-agent') || '').slice(0, 256),
        remainingDays: remaining,
        status: 'ok',
        notes: 'initial activation',
      },
    });

    return NextResponse.json({
      status: 'ok',
      message: 'activated',
      activation_id: activation.id,
      expires_at: Math.floor(expiresAt.getTime() / 1000),
      remaining_days: remaining,
    });
  } catch (e: any) {
    console.error('activate error:', e);
    return NextResponse.json(
      { status: 'rejected', message: e.message || 'internal error' },
      { status: 500 }
    );
  }
}
