/**
 * src/lib/admin.ts
 * ================
 * SERVER-ONLY: management API authentication.
 *
 * All management endpoints (generate / codes / activations / stats / revoke)
 * require the `x-admin-key` header to match the LICENSE_ADMIN_KEY env var.
 * Client-facing endpoints (/api/activate, /api/callback) are NOT gated here —
 * they are protected by Ed25519 signature verification instead.
 */

import 'server-only';
import { timingSafeEqual } from 'crypto';
import { NextRequest, NextResponse } from 'next/server';

export const ADMIN_KEY_HEADER = 'x-admin-key';

export function getAdminKey(): string | null {
  const key = process.env.LICENSE_ADMIN_KEY;
  return key && key.trim().length >= 8 ? key.trim() : null;
}

function safeEqual(a: string, b: string): boolean {
  const ab = Buffer.from(a, 'utf8');
  const bb = Buffer.from(b, 'utf8');
  if (ab.length !== bb.length) return false;
  return timingSafeEqual(ab, bb);
}

/**
 * Returns a 401/503 NextResponse when the request is not authorized,
 * or null when the caller may proceed.
 *
 * - LICENSE_ADMIN_KEY unset/too short  -> 503 (fail closed, server misconfigured)
 * - missing/wrong x-admin-key header   -> 401
 */
export function checkAdmin(req: NextRequest): NextResponse | null {
  const expected = getAdminKey();
  if (!expected) {
    return NextResponse.json(
      {
        error:
          '管理接口已锁定：服务端未配置 LICENSE_ADMIN_KEY（至少 8 个字符）。请在 .env / Vercel 环境变量中设置后重新部署。',
      },
      { status: 503 }
    );
  }
  const provided = req.headers.get(ADMIN_KEY_HEADER) || '';
  if (!provided || !safeEqual(provided, expected)) {
    return NextResponse.json(
      { error: 'unauthorized: missing or invalid x-admin-key' },
      { status: 401 }
    );
  }
  return null;
}
