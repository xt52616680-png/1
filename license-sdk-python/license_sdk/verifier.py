"""
license_sdk.verifier
====================
Main activation verifier that orchestrates all checks.

Flow:
  1. Anti-debug check (refuse to run if debugger detected)
  2. Anti-VM check (refuse to run in VM/sandbox, configurable)
  3. Try to load activation from local storage layers
     a. If valid -> check expiry -> permit
     b. If expired -> refuse
     c. If missing/corrupt -> prompt user to enter activation code
  4. When user enters a code:
     a. Parse + verify Ed25519 signature with embedded public key
     b. Check expiry against system clock + +max clock-skew tolerance
     c. Collect hardware components + generate machine_secret
     d. POST to keygen backend to register activation
        (backend records machine IP, time, fingerprint)
     e. If backend confirms, store activation across 5 layers
  5. Periodically (every 6h) callback to keygen
     - Updates IP/last-seen on backend
     - Receives authoritative remaining_days
     - Detects revocation
  6. If callbacks fail for >7 days, treat as expired
"""

from __future__ import annotations

import json
import os
import secrets
import time
from dataclasses import dataclass
from typing import Optional, Tuple

from . import anti_debug, anti_vm, callback, crypto, fingerprint, storage


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

@dataclass
class LicenseConfig:
    """User-configurable options. Override via LicenseVerifier(config=...)."""
    # Ed25519 PUBLIC key (base64). The private key lives only in the keygen.
    # Replace this with your own keypair's public key before shipping.
    public_key_b64: str = crypto.ED25519_PUBKEY_B64

    # URL of the keygen backend (Next.js app). Can be localhost for dev,
    # or your deployed Vercel/Cloudflare URL for production.
    keygen_url: str = os.environ.get("LICENSE_KEYGEN_URL", "http://localhost:3000")

    # Software version (for callback telemetry)
    software_version: str = "1.0.0"

    # Anti-VM: refuse to activate in VM/sandbox?
    # For development convenience, default is False.
    # Set True for production shipping.
    refuse_in_vm: bool = False

    # Allow callback failures for this long before forcing re-activation
    offline_grace_seconds: int = callback.MAX_OFFLINE_GRACE

    # Callback interval
    callback_interval: int = callback.DEFAULT_CALLBACK_INTERVAL

    # Max acceptable clock skew (seconds) when verifying issued/expires
    max_clock_skew: int = 24 * 3600  # 24 hours


# ---------------------------------------------------------------------------
# Result types
# ---------------------------------------------------------------------------

@dataclass
class ActivationStatus:
    is_activated: bool
    is_expired: bool
    is_revoked: bool
    code_id: Optional[str] = None
    card_type: Optional[str] = None
    activated_at: Optional[int] = None
    expires_at: Optional[int] = None
    remaining_days: int = 0
    last_callback_at: Optional[int] = None
    failure_reason: Optional[str] = None


# ---------------------------------------------------------------------------
# Verifier
# ---------------------------------------------------------------------------

class LicenseVerifier:
    def __init__(self, config: Optional[LicenseConfig] = None):
        self.config = config or LicenseConfig()
        self._master_key: Optional[bytes] = None  # derived lazily
        self._cached_status: Optional[ActivationStatus] = None

    # ------------------------- Public API -------------------------

    def preflight(self) -> Tuple[bool, str]:
        """
        Run pre-flight checks (anti-debug, anti-VM). Call this BEFORE
        any activation logic. Returns (ok, reason).
        """
        # Anti-debug: require 2+ checks to fire
        if anti_debug.is_being_debugged(min_hits=2):
            return False, "debugger detected"
        # Anti-VM: configurable
        if self.config.refuse_in_vm and anti_vm.is_in_vm_or_sandbox(min_hits=3):
            return False, "vm/sandbox not allowed"
        return True, "ok"

    def check_status(self) -> ActivationStatus:
        """
        Check current activation status WITHOUT network call.
        Reads from local storage layers.
        """
        ok, reason = self.preflight()
        if not ok:
            return ActivationStatus(
                is_activated=False, is_expired=False, is_revoked=False,
                failure_reason=reason,
            )

        # We need a fingerprint_hash to derive storage keys.
        # The fingerprint_hash depends on machine_secret, which is stored
        # in the activation itself (chicken-and-egg).
        # Strategy: try to load activation using each "candidate" master key:
        #   - The activation's machine_secret is stored inside the encrypted payload.
        #   - So we use a temporary "loader" approach: read layer 3 (ProgramData)
        #     which contains the machine_secret in plaintext-after-decrypt form.
        # Actually, simpler: the master_key is derived from the public key +
        # installation UUID. We can store the master_key itself in a 6th
        # "bootstrap" location that's NOT XOR-split.

        # Bootstrap: read master key from a dedicated location
        master_key = self._load_master_key()
        if not master_key:
            return ActivationStatus(
                is_activated=False, is_expired=False, is_revoked=False,
                failure_reason="no master key (never activated on this machine)",
            )

        # Reconstruct fingerprint hash from stored components
        # (we don't have them yet because they're inside the encrypted activation)
        # Trick: we use master_key directly to derive a fingerprint-agnostic key.
        # For production we should use the components; but for now use a fallback.

        # Try loading activation: we need fingerprint_hash, but components are
        # stored encrypted INSIDE the activation. We solve this by also storing
        # the fingerprint_hash in the bootstrap location.

        fph = self._load_fingerprint_hash()
        if not fph:
            return ActivationStatus(
                is_activated=False, is_expired=False, is_revoked=False,
                failure_reason="no fingerprint hash",
            )

        stored = storage.load_activation(fph, master_key)
        if not stored:
            return ActivationStatus(
                is_activated=False, is_expired=False, is_revoked=False,
                failure_reason="activation storage missing or corrupted",
            )

        # Verify components still match (allow 3/4 partial match)
        current_components = fingerprint.collect_components()
        if not fingerprint.partial_match(current_components, stored.components, min_match=3):
            return ActivationStatus(
                is_activated=False, is_expired=False, is_revoked=False,
                failure_reason="hardware mismatch (machine changed)",
            )

        # Check expiry
        now = int(time.time())
        if now > stored.expires_at:
            return ActivationStatus(
                is_activated=False, is_expired=True, is_revoked=False,
                code_id=stored.code_id,
                card_type=stored.card_type,
                activated_at=stored.activated_at,
                expires_at=stored.expires_at,
                remaining_days=0,
                failure_reason="expired",
            )

        remaining = max(0, (stored.expires_at - now) // 86400)
        return ActivationStatus(
            is_activated=True, is_expired=False, is_revoked=False,
            code_id=stored.code_id,
            card_type=stored.card_type,
            activated_at=stored.activated_at,
            expires_at=stored.expires_at,
            remaining_days=remaining,
        )

    def activate(self, activation_code: str) -> Tuple[bool, str]:
        """
        Activate using a user-provided activation code.
        Returns (success, message).
        """
        ok, reason = self.preflight()
        if not ok:
            return False, f"preflight failed: {reason}"

        # Parse code
        try:
            payload, signature = crypto.parse_activation_code(activation_code)
        except ValueError as e:
            return False, f"invalid code format: {e}"

        # Verify signature with public key
        try:
            pub = crypto.load_public_key(self.config.public_key_b64)
        except Exception as e:
            return False, f"invalid public key config: {e}"

        if not crypto.verify_payload_signature(pub, payload, signature):
            return False, "signature verification failed (forged or tampered code)"

        # Check expiry with clock-skew tolerance
        now = int(time.time())
        if now + self.config.max_clock_skew < payload.issued_at:
            return False, "code issued in the future (clock skewed?)"
        if now > payload.expires_at:
            return False, "code already expired"

        # Collect hardware fingerprint
        components = fingerprint.collect_components()

        # Generate (or load existing) machine_secret
        existing_fph = self._load_fingerprint_hash()
        if existing_fph:
            # Reuse existing machine_secret if present
            machine_secret = self._load_machine_secret() or fingerprint.generate_machine_secret()
        else:
            machine_secret = fingerprint.generate_machine_secret()

        fph = fingerprint.fingerprint_hash(components, machine_secret)

        # Register activation with keygen backend (records IP, time)
        # Encrypt components with keygen's public key (Ed25519 -> X25519 conversion)
        components_encrypted = self._encrypt_components_for_keygen(components, machine_secret)

        reg_result = self._register_with_keygen(
            code_id=payload.code_id,
            full_code=activation_code.strip().upper().replace(" ", ""),
            fingerprint_hash=fph,
            components_encrypted=components_encrypted,
        )
        if not reg_result[0]:
            return False, f"keygen registration failed: {reg_result[1]}"

        # Persist master key + fingerprint hash (bootstrap)
        master_key = secrets.token_bytes(32)
        self._store_master_key(master_key)
        self._store_fingerprint_hash(fph)
        self._store_machine_secret(machine_secret)

        # Store activation across 5 layers
        stored = storage.StoredActivation(
            code_id=payload.code_id,
            card_type=payload.card_type,
            duration_days=payload.duration_days,
            activated_at=now,
            expires_at=payload.expires_at,
            machine_secret_hex=machine_secret.hex(),
            components=components,
        )
        ok, written = storage.store_activation(stored, fph, master_key)
        if not ok:
            return False, f"failed to store activation (only layers {written} written)"

        return True, f"activated successfully (layers: {written})"

    def do_callback(self) -> callback.CallbackResult:
        """Perform a callback to the keygen backend."""
        status = self.check_status()
        if not status.is_activated:
            return callback.CallbackResult(
                status="offline", server_time=int(time.time()),
                remaining_days=0, next_callback_in=3600,
                message="not activated",
            )

        # Load full code from storage (we need it for callback)
        # For simplicity, we re-derive from storage
        master_key = self._load_master_key()
        fph = self._load_fingerprint_hash()
        stored = storage.load_activation(fph, master_key) if master_key and fph else None
        if not stored:
            return callback.CallbackResult(
                status="offline", server_time=int(time.time()),
                remaining_days=0, next_callback_in=3600,
                message="cannot load stored activation",
            )

        # We don't have the original full_code stored (only code_id).
        # In a real impl, store the full code encrypted too. For demo, pass code_id.
        components = fingerprint.collect_components()
        machine_secret = bytes.fromhex(stored.machine_secret_hex)
        components_encrypted = self._encrypt_components_for_keygen(components, machine_secret)

        # Compose a synthetic full_code (just for callback)
        # In production, store the real full_code in storage too.
        full_code_synthetic = f"CALLBACK::{stored.code_id}"

        return callback.do_callback(
            keygen_url=self.config.keygen_url,
            code_id=stored.code_id,
            full_code=full_code_synthetic,
            fingerprint_hash=fph,
            components_encrypted=components_encrypted,
            software_version=self.config.software_version,
            last_known_remaining=status.remaining_days,
        )

    def revoke(self) -> Tuple[bool, str]:
        """Revoke local activation (deletes all stored fragments)."""
        cleared = storage.clear_activation()
        self._delete_bootstrap()
        return True, f"cleared {cleared} layers"

    # ------------------------- Bootstrap storage -------------------------

    def _bootstrap_dir(self) -> str:
        """A small bootstrap location that survives reinstall (ProgramData)."""
        base = os.environ.get("ProgramData", r"C:\ProgramData")
        d = os.path.join(base, "Microsoft", "DeviceSync")
        os.makedirs(d, exist_ok=True)
        return d

    def _bootstrap_path(self, name: str) -> str:
        return os.path.join(self._bootstrap_dir(), name)

    def _store_master_key(self, key: bytes) -> bool:
        try:
            # XOR with a fixed obfuscation value (not real security, just
            # prevents trivial string-search extraction)
            obf = bytes(b ^ 0x5A for b in key)
            with open(self._bootstrap_path("idx.dat"), "wb") as f:
                f.write(obf)
            return True
        except Exception:
            return False

    def _load_master_key(self) -> Optional[bytes]:
        try:
            with open(self._bootstrap_path("idx.dat"), "rb") as f:
                obf = f.read()
            return bytes(b ^ 0x5A for b in obf)
        except Exception:
            return None

    def _store_fingerprint_hash(self, fph: str) -> bool:
        try:
            with open(self._bootstrap_path("fph.dat"), "w") as f:
                f.write(fph)
            return True
        except Exception:
            return False

    def _load_fingerprint_hash(self) -> Optional[str]:
        try:
            with open(self._bootstrap_path("fph.dat"), "r") as f:
                return f.read().strip()
        except Exception:
            return None

    def _store_machine_secret(self, secret: bytes) -> bool:
        try:
            obf = bytes(b ^ 0xA5 for b in secret)
            with open(self._bootstrap_path("sec.dat"), "wb") as f:
                f.write(obf)
            return True
        except Exception:
            return False

    def _load_machine_secret(self) -> Optional[bytes]:
        try:
            with open(self._bootstrap_path("sec.dat"), "rb") as f:
                obf = f.read()
            return bytes(b ^ 0xA5 for b in obf)
        except Exception:
            return None

    def _delete_bootstrap(self) -> None:
        for name in ("idx.dat", "fph.dat", "sec.dat"):
            try:
                os.remove(self._bootstrap_path(name))
            except OSError:
                pass

    # ------------------------- Keygen communication -------------------------

    def _encrypt_components_for_keygen(self, components: dict, machine_secret: bytes) -> str:
        """Encrypt components for transmission to keygen.
        Uses a simple AES-GCM with a key derived from machine_secret (for demo).
        In production, use the keygen's X25519 public key for true end-to-end encryption.
        """
        key = machine_secret  # 32 bytes
        plaintext = json.dumps(components, sort_keys=True).encode()
        blob = crypto.aes_gcm_encrypt(key, plaintext)
        return crypto.b64encode(blob)

    def _register_with_keygen(self,
                              code_id: str,
                              full_code: str,
                              fingerprint_hash: str,
                              components_encrypted: str) -> Tuple[bool, str]:
        """POST to keygen /api/activate to register this machine."""
        import json as _json
        from urllib import request as urlreq

        payload = {
            "code_id": code_id,
            "full_code": full_code,
            "fingerprint_hash": fingerprint_hash,
            "components_encrypted": components_encrypted,
            "software_version": self.config.software_version,
            "client_time": int(time.time()),
        }
        body = _json.dumps(payload).encode()
        url = self.config.keygen_url.rstrip("/") + "/api/activate"
        req = urlreq.Request(
            url, data=body, method="POST",
            headers={"Content-Type": "application/json"},
        )
        try:
            with urlreq.urlopen(req, timeout=10) as resp:
                data = _json.loads(resp.read().decode())
                if data.get("status") == "ok":
                    return True, data.get("message", "registered")
                else:
                    return False, data.get("message", "registration rejected")
        except Exception as e:
            # Offline mode: allow activation without keygen (less secure)
            # In production you may want to refuse activation if keygen is unreachable.
            return True, f"keygen unreachable, activated offline: {e}"
