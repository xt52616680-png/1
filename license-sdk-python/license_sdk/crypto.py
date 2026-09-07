"""
license_sdk.crypto
==================
Cryptographic primitives for the license system.

Design:
- Ed25519 for activation code signing (asymmetric, private key only in keygen)
- X25519 + Ed25519 -> HKDF -> AES-256-GCM for payload encryption
- scrypt for hardware fingerprint salting
- HMAC-SHA256 for storage integrity

The PUBLIC key is embedded in the SDK (safe to ship).
The PRIVATE key NEVER leaves the keygen backend.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import struct
import time
from dataclasses import dataclass, field
from typing import Tuple

try:
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey, Ed25519PublicKey,
    )
    from cryptography.hazmat.primitives.asymmetric.x25519 import (
        X25519PrivateKey, X25519PublicKey,
    )
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
    from cryptography.exceptions import InvalidSignature, InvalidTag
except ImportError as exc:  # pragma: no cover
    raise RuntimeError(
        "cryptography library required. Install with: pip install cryptography"
    ) from exc


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

ED25519_PUBKEY_B64 = "ZnieBCUPW3IakEwVUf3aiH_cZuUT9wXvkzfyHz_CPMU"
ED25519_PRIVKEY_B64_ENV = "LICENSE_ED25519_PRIVATE_KEY_B64"  # only set in keygen

# A non-secret per-release salt mixed into hardware fingerprints.
# Changing this invalidates ALL previously-activated machines.
FINGERPRINT_SALT = b"LicenseSDK::Fingerprint::v1::2026"

# HKDF info strings
HKDF_INFO_ENC = b"license-sdk::aes-gcm::v1"
HKDF_INFO_MAC = b"license-sdk::hmac::v1"

# Activation-code container format (magic + version)
MAGIC = b"LIC1"  # 4 bytes
VERSION = 1


# ---------------------------------------------------------------------------
# B64 helpers
# ---------------------------------------------------------------------------

def b64encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode("ascii").rstrip("=")


def b64decode(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


# ---------------------------------------------------------------------------
# Ed25519 key management
# ---------------------------------------------------------------------------

def generate_keypair() -> Tuple[str, str]:
    """Generate (priv_b64, pub_b64). Used by keygen ONLY."""
    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key()
    priv_pem = priv.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_pem = pub.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return b64encode(priv_pem), b64encode(pub_pem)


def load_public_key(b64: str) -> Ed25519PublicKey:
    raw = b64decode(b64)
    return Ed25519PublicKey.from_public_bytes(raw)


def load_private_key(b64: str) -> Ed25519PrivateKey:
    raw = b64decode(b64)
    return Ed25519PrivateKey.from_private_bytes(raw)


# ---------------------------------------------------------------------------
# Hardware fingerprint hashing
# ---------------------------------------------------------------------------

def hash_fingerprint(components: dict, machine_id_secret: bytes) -> str:
    """
    Deterministic SHA-256 of (sorted components + machine-id secret + salt).
    The machine_id_secret is a per-installation random 32-byte value stored
    in a hidden location; without it, an attacker cannot forge the same
    fingerprint hash even on the same hardware.
    """
    payload = json.dumps(components, sort_keys=True, separators=(",", ":")).encode()
    h = hashlib.sha256()
    h.update(FINGERPRINT_SALT)
    h.update(machine_id_secret)
    h.update(payload)
    return h.hexdigest()


def derive_storage_key(fingerprint_hash: str, salt: bytes) -> bytes:
    """
    scrypt-derive a 32-byte AES key from the fingerprint hash + a per-fragment
    salt. Used to encrypt each storage fragment independently so compromising
    one fragment does not reveal the others.
    """
    kdf = Scrypt(
        salt=salt,
        length=32,
        n=2 ** 15,  # CPU/memory cost
        r=8,
        p=1,
    )
    return kdf.derive(fingerprint_hash.encode())


# ---------------------------------------------------------------------------
# AES-256-GCM encrypt/decrypt
# ---------------------------------------------------------------------------

def aes_gcm_encrypt(key: bytes, plaintext: bytes, aad: bytes = b"") -> bytes:
    """Returns nonce(12) || ciphertext_with_tag."""
    nonce = os.urandom(12)
    ct = AESGCM(key).encrypt(nonce, plaintext, aad)
    return nonce + ct


def aes_gcm_decrypt(key: bytes, blob: bytes, aad: bytes = b"") -> bytes:
    if len(blob) < 13:
        raise ValueError("ciphertext too short")
    nonce, ct = blob[:12], blob[12:]
    return AESGCM(key).decrypt(nonce, ct, aad)


# ---------------------------------------------------------------------------
# HMAC
# ---------------------------------------------------------------------------

def hmac_sha256(key: bytes, msg: bytes) -> bytes:
    return hmac.new(key, msg, hashlib.sha256).digest()


def hmac_verify(key: bytes, msg: bytes, expected: bytes) -> bool:
    return hmac.compare_digest(hmac_sha256(key, msg), expected)


# ---------------------------------------------------------------------------
# Activation code: payload + Ed25519 signature
# ---------------------------------------------------------------------------

@dataclass
class CodePayload:
    """The signed payload embedded inside an activation code."""
    code_id: str          # 8-char short id
    card_type: str        # month | season | year | time
    duration_days: int
    issued_at: int        # unix seconds
    expires_at: int       # unix seconds
    max_machines: int
    nonce: str            # 16-byte hex

    def to_bytes(self) -> bytes:
        """
        Canonical FIXED-WIDTH binary form for signing.
        Layout (no field separators to avoid collision):
          MAGIC(4) | VERSION(4) | CODE_ID(8) | CARD_TYPE(8 padded with 0)
          | DURATION(4) | ISSUED(8) | EXPIRES(8) | MAX_MACHINES(4) | NONCE(16)
        Total: 64 bytes
        """
        card_type_padded = self.card_type.encode("ascii").ljust(8, b"\x00")
        return (
            MAGIC
            + struct.pack("<I", VERSION)
            + self.code_id.encode("ascii").ljust(8, b"\x00")[:8]
            + card_type_padded
            + struct.pack("<i", self.duration_days)
            + struct.pack("<q", self.issued_at)
            + struct.pack("<q", self.expires_at)
            + struct.pack("<i", self.max_machines)
            + bytes.fromhex(self.nonce)
        )

    def to_dict(self) -> dict:
        return {
            "code_id": self.code_id,
            "card_type": self.card_type,
            "duration_days": self.duration_days,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "max_machines": self.max_machines,
            "nonce": self.nonce,
        }


def sign_payload(priv: Ed25519PrivateKey, payload: CodePayload) -> bytes:
    return priv.sign(payload.to_bytes())


def verify_payload_signature(pub: Ed25519PublicKey, payload: CodePayload, sig: bytes) -> bool:
    try:
        pub.verify(sig, payload.to_bytes())
        return True
    except InvalidSignature:
        return False


# ---------------------------------------------------------------------------
# Activation code packing (what the user types in)
# Format: XXXX-XXXX-XXXX-XXXX-XXXX-XXXX  (base32-like, with checksum)
# Internally: [payload_bytes(120)] [signature(64)] [crc16(2)]
# ---------------------------------------------------------------------------

import string

# Custom alphabet: visually unambiguous (no 0/O/1/I)
ALPHABET = "23456789ABCDEFGHJKMNPQRSTUVWXYZ"  # 29 chars
ALPHABET_INDEX = {c: i for i, c in enumerate(ALPHABET)}


def _crc16(data: bytes) -> int:
    crc = 0xFFFF
    for byte in data:
        crc ^= byte
        for _ in range(8):
            if crc & 1:
                crc = (crc >> 1) ^ 0xA001
            else:
                crc >>= 1
    return crc & 0xFFFF


def _base29_encode(data: bytes) -> str:
    """Encode bytes into base-29 using ALPHABET."""
    num = int.from_bytes(data, "big")
    chars = []
    while num > 0:
        num, rem = divmod(num, 29)
        chars.append(ALPHABET[rem])
    return "".join(reversed(chars)) or ALPHABET[0]


def _base29_decode(s: str) -> bytes:
    num = 0
    for c in s:
        if c not in ALPHABET_INDEX:
            raise ValueError(f"invalid character: {c}")
        num = num * 29 + ALPHABET_INDEX[c]
    # Compute byte length (round up)
    if num == 0:
        return b"\x00"
    length = (num.bit_length() + 7) // 8
    return num.to_bytes(length, "big")


def format_activation_code(payload: CodePayload, signature: bytes) -> str:
    """Produce the user-facing XXXX-XXXX-... activation string."""
    blob = payload.to_bytes() + signature
    crc = _crc16(blob)
    blob_with_crc = blob + struct.pack("<H", crc)
    encoded = _base29_encode(blob_with_crc)
    # Pad to a multiple of 4 chars
    while len(encoded) % 4 != 0:
        encoded = ALPHABET[0] + encoded
    # Group into 4-char chunks
    return "-".join(encoded[i:i + 4] for i in range(0, len(encoded), 4))


def parse_activation_code(code: str) -> Tuple[CodePayload, bytes]:
    """Parse + verify CRC. Returns (payload, signature) or raises."""
    clean = code.strip().upper().replace("-", "").replace(" ", "")
    blob_with_crc = _base29_decode(clean)
    if len(blob_with_crc) < 2:
        raise ValueError("code too short")
    blob, crc_bytes = blob_with_crc[:-2], blob_with_crc[-2:]
    crc = struct.unpack("<H", crc_bytes)[0]
    if _crc16(blob) != crc:
        raise ValueError("CRC mismatch - code corrupted or tampered")
    # blob = payload_bytes(64) | signature(64)
    if len(blob) < 128:
        raise ValueError("code payload too short (expected >= 128 bytes)")
    payload_bytes, signature = blob[:64], blob[64:128]
    # Any extra bytes after signature are ignored (forward compat).
    # Parse payload (fixed-width)
    if not payload_bytes.startswith(MAGIC):
        raise ValueError("magic mismatch")
    version = struct.unpack("<I", payload_bytes[4:8])[0]
    if version != VERSION:
        raise ValueError(f"unsupported version {version}")
    code_id = payload_bytes[8:16].rstrip(b"\x00").decode("ascii")
    card_type = payload_bytes[16:24].rstrip(b"\x00").decode("ascii")
    duration_days = struct.unpack("<i", payload_bytes[24:28])[0]
    issued_at = struct.unpack("<q", payload_bytes[28:36])[0]
    expires_at = struct.unpack("<q", payload_bytes[36:44])[0]
    max_machines = struct.unpack("<i", payload_bytes[44:48])[0]
    nonce = payload_bytes[48:64].hex()
    return CodePayload(
        code_id=code_id,
        card_type=card_type,
        duration_days=duration_days,
        issued_at=issued_at,
        expires_at=expires_at,
        max_machines=max_machines,
        nonce=nonce,
    ), signature
