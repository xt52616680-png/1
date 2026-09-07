/**
 * src/lib/keygen.ts
 * =================
 * SERVER-ONLY: Ed25519 signing and code generation/verification.
 * Do NOT import from client components - use keygen-shared.ts for constants.
 */

import 'server-only';
import * as ed from '@noble/ed25519';
import { sha512 } from '@noble/hashes/sha2.js';
import { randomBytes } from 'crypto';

// Configure SHA-512 for @noble/ed25519 v3 (required - the lib doesn't bundle a hash impl)
(ed as any).hashes.sha512 = sha512;
(ed as any).hashes.sha512Async = async (msg: Uint8Array) => sha512(msg);
import {
  type CardType,
  type CodePayload,
  CARD_DEFAULT_DURATIONS,
  CARD_LABELS,
  CARD_DESCRIPTIONS,
  resolveDuration as resolveDurationShared,
} from './keygen-shared';

// Re-export shared constants for server consumers
export {
  type CardType,
  type CodePayload,
  CARD_DEFAULT_DURATIONS,
  CARD_LABELS,
  CARD_DESCRIPTIONS,
  resolveDurationShared as resolveDuration,
};

// (SHA-512 configured above)

// ---------------------------------------------------------------------------
// Encoding (must mirror the Python SDK exactly)
// ---------------------------------------------------------------------------

const MAGIC = Buffer.from('LIC1');
const VERSION = 1;

const ALPHABET = '23456789ABCDEFGHJKMNPQRSTUVWXYZ';
const ALPHABET_INDEX: Record<string, number> = {};
for (let i = 0; i < ALPHABET.length; i++) ALPHABET_INDEX[ALPHABET[i]] = i;

function crc16(data: Buffer): number {
  let crc = 0xffff;
  for (const byte of data) {
    crc ^= byte;
    for (let i = 0; i < 8; i++) {
      if (crc & 1) crc = (crc >> 1) ^ 0xa001;
      else crc >>= 1;
    }
  }
  return crc & 0xffff;
}

function base29Encode(data: Buffer): string {
  let num = BigInt(0);
  for (const b of data) num = (num << 8n) | BigInt(b);
  if (num === 0n) return ALPHABET[0];
  const chars: string[] = [];
  while (num > 0n) {
    const rem = num % 29n;
    chars.push(ALPHABET[Number(rem)]);
    num = num / 29n;
  }
  return chars.reverse().join('');
}

function base29Decode(s: string): Buffer {
  let num = BigInt(0);
  for (const c of s) {
    if (!(c in ALPHABET_INDEX)) throw new Error(`invalid character: ${c}`);
    num = num * 29n + BigInt(ALPHABET_INDEX[c]);
  }
  if (num === 0n) return Buffer.from([0]);
  const bytes: number[] = [];
  while (num > 0n) {
    bytes.push(Number(num & 0xffn));
    num = num >> 8n;
  }
  return Buffer.from(bytes.reverse());
}

// ---------------------------------------------------------------------------
// Payload (fixed-width binary form, signed by Ed25519)
// Layout: MAGIC(4) | VERSION(4) | CODE_ID(8) | CARD_TYPE(8) |
//         DURATION(4) | ISSUED(8) | EXPIRES(8) | MAX_MACHINES(4) | NONCE(16)
// Total: 64 bytes
// ---------------------------------------------------------------------------

function bufUInt32LE(v: number): Buffer {
  const b = Buffer.alloc(4); b.writeUInt32LE(v, 0); return b;
}
function bufInt32LE(v: number): Buffer {
  const b = Buffer.alloc(4); b.writeInt32LE(v, 0); return b;
}
function bufInt64LE(v: number): Buffer {
  const b = Buffer.alloc(8); b.writeBigUInt64LE(BigInt(v), 0); return b;
}
function padString(s: string, len: number): Buffer {
  const b = Buffer.alloc(len, 0);
  Buffer.from(s, 'ascii').copy(b);
  return b;
}

function payloadToBytes(p: CodePayload): Buffer {
  return Buffer.concat([
    MAGIC,                                  // 4
    bufUInt32LE(VERSION),                   // 4
    padString(p.codeId, 8),                 // 8
    padString(p.cardType, 8),               // 8
    bufInt32LE(p.durationDays),             // 4
    bufInt64LE(p.issuedAt),                 // 8
    bufInt64LE(p.expiresAt),                // 8
    bufInt32LE(p.maxMachines),              // 4
    Buffer.from(p.nonce, 'hex'),            // 16
  ]);                                       // total: 64
}

function parsePayloadBytes(buf: Buffer): CodePayload {
  if (buf.length < 64) throw new Error('payload too short');
  if (!buf.subarray(0, 4).equals(MAGIC)) throw new Error('magic mismatch');
  const version = buf.readUInt32LE(4);
  if (version !== VERSION) throw new Error(`unsupported version ${version}`);
  const codeId = buf.subarray(8, 16).toString('ascii').replace(/\0+$/, '');
  const cardType = buf.subarray(16, 24).toString('ascii').replace(/\0+$/, '') as CardType;
  const durationDays = buf.readInt32LE(24);
  const issuedAt = Number(buf.readBigUInt64LE(28));
  const expiresAt = Number(buf.readBigUInt64LE(36));
  const maxMachines = buf.readInt32LE(44);
  const nonce = buf.subarray(48, 64).toString('hex');
  return { codeId, cardType, durationDays, issuedAt, expiresAt, maxMachines, nonce };
}

// ---------------------------------------------------------------------------
// Code ID generator
// ---------------------------------------------------------------------------

export function generateCodeId(): string {
  const bytes = randomBytes(8);
  let id = '';
  for (let i = 0; i < 8; i++) {
    id += ALPHABET[bytes[i] % ALPHABET.length];
  }
  return id;
}

// ---------------------------------------------------------------------------
// Key management
// ---------------------------------------------------------------------------

function b64decode(s: string): Uint8Array {
  return new Uint8Array(Buffer.from(s, 'base64url'));
}

export function getPrivateKey(): Uint8Array {
  const b64 = process.env.LICENSE_ED25519_PRIVATE_KEY_B64;
  if (!b64) throw new Error('LICENSE_ED25519_PRIVATE_KEY_B64 not set');
  return b64decode(b64);
}

export function getPublicKey(): Uint8Array {
  const b64 = process.env.LICENSE_ED25519_PUBLIC_KEY_B64;
  if (!b64) throw new Error('LICENSE_ED25519_PUBLIC_KEY_B64 not set');
  return b64decode(b64);
}

// ---------------------------------------------------------------------------
// Generate activation code
// ---------------------------------------------------------------------------

export async function generateActivationCode(
  cardType: CardType,
  customDays?: number,
  maxMachines: number = 1,
): Promise<{ payload: CodePayload; fullCode: string; signature: Buffer }> {
  const durationDays = resolveDurationShared(cardType, customDays);
  const now = Math.floor(Date.now() / 1000);
  const payload: CodePayload = {
    codeId: generateCodeId(),
    cardType,
    durationDays,
    issuedAt: now,
    expiresAt: now + durationDays * 86400,
    maxMachines,
    nonce: randomBytes(16).toString('hex'),
  };

  const payloadBytes = payloadToBytes(payload);
  const privateKey = getPrivateKey();
  const signature = await ed.signAsync(payloadBytes, privateKey);

  const blob = Buffer.concat([payloadBytes, Buffer.from(signature)]);
  const crc = crc16(blob);
  const crcBuf = Buffer.alloc(2);
  crcBuf.writeUInt16LE(crc, 0);
  const blobWithCrc = Buffer.concat([blob, crcBuf]);

  let encoded = base29Encode(blobWithCrc);
  while (encoded.length % 4 !== 0) encoded = ALPHABET[0] + encoded;
  const grouped = encoded.match(/.{1,4}/g)!.join('-');

  return { payload, fullCode: grouped, signature: Buffer.from(signature) };
}

// ---------------------------------------------------------------------------
// Verify an activation code
// ---------------------------------------------------------------------------

export async function verifyActivationCode(
  fullCode: string
): Promise<{ payload: CodePayload; signature: Uint8Array; valid: boolean }> {
  const clean = fullCode.trim().toUpperCase().replace(/[-\s]/g, '');
  // A valid 130-byte code is ~216 base29 chars; anything wildly longer is
  // garbage (and expensive to BigInt-decode) - reject early.
  if (clean.length > 400) throw new Error('code too long');
  const blobWithCrc = base29Decode(clean);
  if (blobWithCrc.length < 2) throw new Error('code too short');
  const blob = blobWithCrc.subarray(0, -2);
  const crcBuf = blobWithCrc.subarray(-2);
  const crc = crcBuf.readUInt16LE(0);
  if (crc16(blob) !== crc) throw new Error('CRC mismatch - code corrupted');

  if (blob.length < 128) throw new Error('code payload too short (expected >= 128 bytes)');
  const payloadBytes = blob.subarray(0, 64);
  const signature = new Uint8Array(blob.subarray(64, 128));

  const publicKey = getPublicKey();
  let valid = false;
  try {
    valid = await ed.verifyAsync(signature, payloadBytes, publicKey);
  } catch {
    valid = false;
  }

  const payload = parsePayloadBytes(Buffer.from(payloadBytes));
  return { payload, signature, valid };
}


