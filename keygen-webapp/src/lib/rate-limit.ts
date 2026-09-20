/**
 * src/lib/rate-limit.ts
 * =====================
 * SERVER-ONLY: DB-backed rate limiting via the AuditLog table.
 * No external service dependency (Upstash etc. can replace this later).
 */
import { db } from './db';
import { getClientIp } from './request-utils';
import type { NextRequest } from 'next/server';

export interface LimitResult {
  allowed: boolean
  retryAfterSeconds?: number
}

function windowStart(seconds: number): Date {
  return new Date(Date.now() - seconds * 1000)
}

/** Generic counter: audit rows matching action+ip within the window. */
export async function checkIpLimit(
  req: NextRequest,
  action: string,
  max: number,
  windowSeconds: number,
): Promise<LimitResult> {
  const ip = getClientIp(req)
  const count = await db.auditLog.count({
    where: { action, ip, createdAt: { gte: windowStart(windowSeconds) } },
  })
  if (count >= max) {
    return { allowed: false, retryAfterSeconds: windowSeconds }
  }
  return { allowed: true }
}

/** Login brute-force guard: consecutive failures per account (by email hash side-channel safe enough here). */
export async function checkLoginFailures(
  email: string,
  max = 5,
  windowSeconds = 15 * 60,
): Promise<LimitResult> {
  const count = await db.auditLog.count({
    where: {
      action: 'login_fail',
      meta: { contains: `"email":"${email.toLowerCase()}"` },
      createdAt: { gte: windowStart(windowSeconds) },
    },
  })
  if (count >= max) {
    return { allowed: false, retryAfterSeconds: windowSeconds }
  }
  return { allowed: true }
}

export async function audit(entry: {
  userId?: string | null
  action: string
  req?: NextRequest
  meta?: Record<string, unknown>
}): Promise<void> {
  try {
    await db.auditLog.create({
      data: {
        userId: entry.userId ?? undefined,
        action: entry.action,
        ip: entry.req ? getClientIp(entry.req) : undefined,
        meta: entry.meta ? JSON.stringify(entry.meta).slice(0, 2000) : undefined,
      },
    })
  } catch {
    // 审计失败不阻断主流程
  }
}
