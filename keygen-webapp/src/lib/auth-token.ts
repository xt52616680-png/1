/**
 * src/lib/auth-token.ts
 * =====================
 * SERVER-ONLY: short-lived Ed25519-signed session tokens for the
 * account-based licensing system (P1).
 *
 * Format: base64url(headerJSON).base64url(payloadJSON).base64url(sig)
 * (JWT-like but signed with our LICENSE_ED25519 key, no JWT dependency)
 */
import * as ed from '@noble/ed25519';
import { sha512 } from '@noble/hashes/sha2.js';
import { getPrivateKey, getPublicKey } from './keygen';

(ed as any).hashes.sha512 = sha512;
(ed as any).hashes.sha512Async = async (msg: Uint8Array) => sha512(msg);

export interface TokenPayload {
  uid: string;
  fp: string; // fingerprint hash (first 32 hex chars)
  tv: number; // machine tokenVersion — bump invalidates outstanding tokens
  plan: string;
  iat: number;
  exp: number; // epoch seconds
}

const b64u = (input: string | Uint8Array): string =>
  Buffer.from(input as Uint8Array).toString('base64url');
const b64uJson = (obj: unknown): string =>
  Buffer.from(JSON.stringify(obj), 'utf8').toString('base64url');

function b64uDecode(s: string): Buffer {
  return Buffer.from(s, 'base64url');
}

function splitToken(token: string): { hStr: string; pStr: string; s: Uint8Array } | null {
  const parts = token.split('.');
  if (parts.length !== 3) return null;
  try {
    const h = b64uDecode(parts[0]);
    const p = b64uDecode(parts[1]);
    const s = new Uint8Array(b64uDecode(parts[2]));
    if (!h.length || !p.length || s.length !== 64) return null;
    // 保留原始字符串段——验签数据必须与签发时逐字节一致
    return { hStr: parts[0], pStr: parts[1], s };
  } catch {
    return null;
  }
}

/** Sign a session token (24h default validity). */
export async function signSessionToken(
  payload: Omit<TokenPayload, 'iat' | 'exp'> & { iat?: number; exp?: number },
  validitySeconds = 24 * 3600,
): Promise<{ token: string; payload: TokenPayload }> {
  const now = Math.floor(Date.now() / 1000);
  const full: TokenPayload = {
    iat: now,
    exp: now + validitySeconds,
    ...payload,
  };
  const header = b64uJson({ alg: 'Ed25519', typ: 'PAG-TOKEN', v: 1 });
  const body = b64uJson(full);
  const data = Buffer.from(`${header}.${body}`, 'utf8');
  const signature = await ed.signAsync(new Uint8Array(data), getPrivateKey());
  return { token: `${header}.${body}.${Buffer.from(signature).toString('base64url')}`, payload: full };
}

/**
 * Verify signature + structure + expiry. Returns the payload on success.
 * `expectedFp`/`expectedTv`: when provided, must match the token claims
 * (prevents replaying a token from another machine or a pre-rebind era).
 */
export async function verifySessionToken(
  token: string,
  opts: { expectedFp?: string; expectedTv?: number } = {},
): Promise<{ valid: boolean; payload?: TokenPayload; reason?: string }> {
  const parts = splitToken(token);
  if (!parts) return { valid: false, reason: 'malformed' };
  const data = Buffer.from(`${parts.hStr}.${parts.pStr}`, 'utf8');
  let ok = false;
  try {
    ok = await ed.verify(parts.s, new Uint8Array(data), getPublicKey());
  } catch {
    ok = false;
  }
  if (!ok) return { valid: false, reason: 'bad_signature' };

  let payload: TokenPayload;
  try {
    payload = JSON.parse(b64uDecode(parts.pStr).toString('utf8')) as TokenPayload;
  } catch {
    return { valid: false, reason: 'bad_payload' };
  }
  const now = Math.floor(Date.now() / 1000);
  if (!payload.uid || !payload.fp || typeof payload.tv !== 'number') {
    return { valid: false, reason: 'missing_claims' };
  }
  if (typeof payload.exp !== 'number' || now >= payload.exp) {
    return { valid: false, reason: 'expired' };
  }
  if (opts.expectedFp && payload.fp !== opts.expectedFp.slice(0, 32)) {
    return { valid: false, reason: 'fingerprint_mismatch' };
  }
  if (typeof opts.expectedTv === 'number' && payload.tv !== opts.expectedTv) {
    return { valid: false, reason: 'token_version_mismatch' };
  }
  return { valid: true, payload };
}

/** Public key base64 for clients to pin (GET /api/auth/pubkey). */
export function getPublicKeyB64(): string {
  return Buffer.from(getPublicKey()).toString('base64');
}
