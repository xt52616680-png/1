"""
license_sdk.fingerprint
=======================
Hardware fingerprint generation.

Combines 4 independent hardware identifiers:
  1. CPU ProcessorId (WMI Win32_Processor)
  2. Baseboard SerialNumber (WMI Win32_BaseBoard)
  3. Primary disk SerialNumber (WMI Win32_DiskDrive)
  4. First physical NIC MAC address (excludes virtual/loopback)

Each component is hashed independently, allowing partial-match verification
(so a user replacing their NIC does not lose their license; we require at
least 3/4 to match).

A per-installation random 32-byte secret is generated and stored alongside
the fragments. This secret is mixed into the final fingerprint hash, so even
on identical hardware an attacker cannot reproduce the same hash without
also extracting the secret (which is itself encrypted with a key derived
from the fingerprint components).
"""

from __future__ import annotations

import hashlib
import os
import platform
import subprocess
import uuid
from typing import Dict, Optional

from .crypto import hash_fingerprint


# ---------------------------------------------------------------------------
# WMI query (Windows only; falls back gracefully on non-Windows)
# ---------------------------------------------------------------------------

def _wmi_query(query: str, field: str) -> Optional[str]:
    if platform.system() != "Windows":
        return None
    try:
        # Use PowerShell for unicode-safe output
        ps = (
            f"$ErrorActionPreference='SilentlyContinue';"
            f"Get-CimInstance -Query \"{query}\" | "
            f"Select-Object -ExpandProperty {field}"
        )
        out = subprocess.check_output(
            ["powershell", "-NoProfile", "-Command", ps],
            stderr=subprocess.DEVNULL,
            timeout=5,
        ).decode("utf-8", errors="ignore").strip()
        return out or None
    except Exception:
        return None


def _get_cpu_id() -> str:
    v = _wmi_query("SELECT * FROM Win32_Processor", "ProcessorId")
    if v:
        return v
    # Fallback: uuid.getnode returns MAC if no CPU id; not ideal but better than empty
    return f"cpu-fallback-{uuid.getnode()}"


def _get_baseboard_serial() -> str:
    v = _wmi_query("SELECT * FROM Win32_BaseBoard", "SerialNumber")
    if v:
        # Strip whitespace and "To be filled by O.E.M" placeholders
        v = v.strip()
        if "to be filled" in v.lower() or "default" in v.lower():
            return f"mb-fallback-{uuid.getnode()}"
        return v
    return f"mb-fallback-{uuid.getnode()}"


def _get_disk_serial() -> str:
    v = _wmi_query("SELECT * FROM Win32_DiskDrive WHERE Index=0", "SerialNumber")
    if v:
        return v.strip()
    return f"disk-fallback-{uuid.getnode()}"


def _get_primary_mac() -> str:
    """First non-virtual NIC MAC address."""
    if platform.system() == "Windows":
        try:
            out = subprocess.check_output(
                ["powershell", "-NoProfile", "-Command",
                 "Get-NetAdapter -Physical | Where-Object Status -EQ 'Up' | "
                 "Select-Object -First 1 -ExpandProperty MacAddress"],
                stderr=subprocess.DEVNULL, timeout=5,
            ).decode().strip()
            if out:
                return out
        except Exception:
            pass
    mac = uuid.getnode()
    return ":".join(f"{(mac >> (8 * i)) & 0xFF:02X}" for i in reversed(range(6)))


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def collect_components() -> Dict[str, str]:
    """Return a dict of 4 hardware components."""
    return {
        "cpu": _get_cpu_id(),
        "baseboard": _get_baseboard_serial(),
        "disk": _get_disk_serial(),
        "mac": _get_primary_mac(),
    }


def fingerprint_hash(components: Dict[str, str], machine_secret: bytes) -> str:
    return hash_fingerprint(components, machine_secret)


def generate_machine_secret() -> bytes:
    """Generate a new 32-byte random machine secret (only run once per install)."""
    return os.urandom(32)


def partial_match(a: Dict[str, str], b: Dict[str, str], min_match: int = 3) -> bool:
    """Return True if at least `min_match` of 4 components match."""
    matches = sum(1 for k in a if a[k] == b.get(k, ""))
    return matches >= min_match


def components_short_hash(components: Dict[str, str]) -> str:
    """A short 16-hex-char hash for display (NOT used for security)."""
    h = hashlib.sha256(
        "|".join(f"{k}={v}" for k, v in sorted(components.items())).encode()
    ).hexdigest()
    return h[:16]
