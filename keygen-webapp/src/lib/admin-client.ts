/**
 * src/lib/admin-client.ts
 * =======================
 * Client-side helper for calling management APIs.
 * The admin key is entered once in the 设置 (Settings) tab and stored in
 * localStorage; every management request attaches it as `x-admin-key`.
 */

const STORAGE_KEY = 'keygen_admin_key';

export function getAdminKey(): string {
  if (typeof window === 'undefined') return '';
  try {
    return window.localStorage.getItem(STORAGE_KEY) || '';
  } catch {
    return '';
  }
}

export function setAdminKey(key: string) {
  if (typeof window === 'undefined') return;
  try {
    if (key) window.localStorage.setItem(STORAGE_KEY, key);
    else window.localStorage.removeItem(STORAGE_KEY);
  } catch {
    // storage unavailable (private mode etc.) - ignore
  }
}

export function adminHeaders(): Record<string, string> {
  const key = getAdminKey();
  return key ? { 'x-admin-key': key } : {};
}
