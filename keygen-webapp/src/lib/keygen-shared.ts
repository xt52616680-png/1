/**
 * src/lib/keygen-shared.ts
 * ========================
 * Constants and types shared between client and server.
 * NO crypto imports here - safe to import from client components.
 */

export type CardType = 'month' | 'season' | 'year' | 'time';

/**
 * Default duration per card type.
 *
 * Per user spec:
 *   month  = 30 days (forced)
 *   season = 30 days (forced) [NOTE: change to 90 if needed]
 *   year   = 30 days (forced) [NOTE: change to 365 if needed]
 *   time   = custom (input field, 1-3650 days)
 */
export const CARD_DEFAULT_DURATIONS: Record<CardType, number> = {
  month: 30,
  season: 30,
  year: 30,
  time: 0,
};

export const CARD_LABELS: Record<CardType, string> = {
  month: '月卡',
  season: '季卡',
  year: '年卡',
  time: '时卡',
};

export const CARD_DESCRIPTIONS: Record<CardType, string> = {
  month: '月卡 · 强制 30 天',
  season: '季卡 · 强制 30 天',
  year: '年卡 · 强制 30 天',
  time: '时卡 · 自定义天数',
};

export interface CodePayload {
  codeId: string;
  cardType: CardType;
  durationDays: number;
  issuedAt: number;
  expiresAt: number;
  maxMachines: number;
  nonce: string;
}

/**
 * Resolve the duration for a card type.
 * Throws if validation fails.
 */
export function resolveDuration(
  cardType: CardType,
  customDays?: number
): number {
  if (cardType === 'time') {
    if (!customDays || !Number.isInteger(customDays)) {
      throw new Error('时卡必须提供有效的天数（整数）');
    }
    if (customDays < 1 || customDays > 3650) {
      throw new Error('时卡天数必须在 1-3650 范围内');
    }
    return customDays;
  }
  return CARD_DEFAULT_DURATIONS[cardType];
}
