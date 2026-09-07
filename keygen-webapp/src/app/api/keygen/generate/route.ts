/**
 * POST /api/keygen/generate
 * Generate a new activation code.
 *
 * Body: {
 *   cardType: 'month' | 'season' | 'year' | 'time',
 *   customDays?: number,  // only for 'time'
 *   maxMachines?: number, // default 1
 *   note?: string,
 * }
 *
 * Response: {
 *   codeId, fullCode, cardType, durationDays, issuedAt, expiresAt,
 *   maxMachines, note
 * }
 */

import { NextRequest, NextResponse } from 'next/server';
import { db } from '@/lib/db';
import { checkAdmin } from '@/lib/admin';
import {
  generateActivationCode,
  CardType,
  resolveDuration,
  CARD_LABELS,
} from '@/lib/keygen';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

export async function POST(req: NextRequest) {
  const denied = checkAdmin(req);
  if (denied) return denied;

  try {
    const body = await req.json();
    const { cardType, customDays, maxMachines = 1, note } = body;

    // Validate cardType
    if (!['month', 'season', 'year', 'time'].includes(cardType)) {
      return NextResponse.json(
        { error: 'cardType 必须是 month/season/year/time 之一' },
        { status: 400 }
      );
    }

    // Validate optional fields before signing
    if (!Number.isInteger(maxMachines) || maxMachines < 1 || maxMachines > 100) {
      return NextResponse.json(
        { error: 'maxMachines 必须是 1-100 之间的整数' },
        { status: 400 }
      );
    }
    if (note !== undefined && note !== null &&
        (typeof note !== 'string' || note.length > 200)) {
      return NextResponse.json(
        { error: 'note 必须是不超过 200 字符的字符串' },
        { status: 400 }
      );
    }

    // Resolve duration (this enforces constraints)
    let durationDays: number;
    try {
      durationDays = resolveDuration(cardType as CardType, customDays);
    } catch (e: any) {
      return NextResponse.json({ error: e.message }, { status: 400 });
    }

    // Generate signed code
    const { payload, fullCode, signature } = await generateActivationCode(
      cardType as CardType,
      customDays,
      maxMachines,
    );

    // Persist to DB
    const code = await db.activationCode.create({
      data: {
        codeId: payload.codeId,
        fullCode,
        cardType: payload.cardType,
        durationDays: payload.durationDays,
        issuedAt: new Date(payload.issuedAt * 1000),
        expiresAt: new Date(payload.expiresAt * 1000),
        maxMachines: payload.maxMachines,
        signature: Buffer.from(signature).toString('hex'),
        nonce: payload.nonce,
        status: 'unused',
        note: note || null,
      },
    });

    return NextResponse.json({
      id: code.id,
      codeId: payload.codeId,
      fullCode,
      cardType: payload.cardType,
      cardTypeLabel: CARD_LABELS[payload.cardType],
      durationDays: payload.durationDays,
      issuedAt: payload.issuedAt,
      expiresAt: payload.expiresAt,
      maxMachines: payload.maxMachines,
      note: note || null,
    });
  } catch (e: any) {
    console.error('generate error:', e);
    return NextResponse.json(
      { error: e.message || 'internal error' },
      { status: 500 }
    );
  }
}

export async function GET() {
  return NextResponse.json({ error: 'use POST' }, { status: 405 });
}
