/**
 * /api/version — public version check for the auto-updater (P7).
 * The authoritative source for { latestVersion, minVersion }.
 * Edit these two constants to force/offer upgrades; no client release needed.
 */
import { NextResponse } from 'next/server';

export const runtime = 'nodejs';

export const LATEST_VERSION = '0.2.1';
export const MIN_VERSION = '0.2.0'; // bump to force-upgrade all older clients

export async function GET() {
  return NextResponse.json({
    ok: true,
    data: {
      latestVersion: LATEST_VERSION,
      minVersion: MIN_VERSION,
      upgradeRequired: false, // 客户端自行与自身版本比较
      downloadUrl: '/api/update/download',
      notes: '',
      serverTime: Math.floor(Date.now() / 1000),
    },
  });
}
