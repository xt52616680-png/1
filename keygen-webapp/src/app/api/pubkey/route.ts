/**
 * GET /api/pubkey
 * Returns the Ed25519 PUBLIC key for display in the settings page and for
 * embedding into the Python SDK. Public keys are safe to expose by design -
 * codes can only be CREATED with the private key, which never leaves the
 * server. No admin gate needed here.
 */

import { NextResponse } from 'next/server';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

export async function GET() {
  try {
    const { getPublicKey } = await import('@/lib/keygen');
    const pub = Buffer.from(getPublicKey()).toString('base64url');
    return NextResponse.json({ public_key_b64: pub });
  } catch (e: any) {
    return NextResponse.json(
      { error: e.message || 'public key not configured' },
      { status: 500 }
    );
  }
}
