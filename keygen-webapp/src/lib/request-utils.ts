/**
 * src/lib/request-utils.ts
 * ========================
 * SERVER-ONLY: helpers shared by the client-facing endpoints
 * (/api/activate, /api/callback).
 */

import { NextRequest } from 'next/server';

/**
 * Best-effort client IP extraction.
 * Behind Vercel/CDN proxies the trusted value is the LAST entry of
 * x-forwarded-for (the one appended by our own proxy); earlier entries can
 * be spoofed by the client. Cap the length before storing.
 */
export function getClientIp(req: NextRequest): string {
  const raw =
    req.headers.get('x-real-ip') ||
    lastForwardedFor(req.headers.get('x-forwarded-for')) ||
    req.headers.get('x-client-ip') ||
    'unknown';
  return raw.slice(0, 64);
}

function lastForwardedFor(header: string | null): string | null {
  if (!header) return null;
  const parts = header.split(',').map(s => s.trim()).filter(Boolean);
  return parts.length ? parts[parts.length - 1] : null;
}

/** The Python SDK sends a SHA-256 hex digest as fingerprint_hash. */
export function isValidFingerprint(hash: unknown): hash is string {
  return typeof hash === 'string' && /^[0-9a-f]{64}$/i.test(hash);
}

/** Remaining whole days, rounded UP so a license valid for 12h shows 1, not 0. */
export function remainingDays(expiresAt: Date, now: Date = new Date()): number {
  const ms = expiresAt.getTime() - now.getTime();
  if (ms <= 0) return 0;
  return Math.ceil(ms / 86400000);
}

export function isExpired(expiresAt: Date, now: Date = new Date()): boolean {
  return now.getTime() >= expiresAt.getTime();
}
