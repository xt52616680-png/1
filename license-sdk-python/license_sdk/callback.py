"""
license_sdk.callback
====================
Periodic callback to the keygen backend.

The activated software periodically (default: every 6 hours + jitter)
calls POST {KEYGEN_URL}/api/callback with:
  - activation code
  - machine fingerprint hash
  - hardware components (encrypted with the keygen's public key)
  - software version
  - timestamp + nonce

The keygen responds with:
  - status: ok | expired | revoked | mismatch
  - server_time: unix seconds (for clock-drift compensation)
  - remaining_days: authoritative remaining days
  - next_callback_in: seconds until next required callback

If the callback fails N consecutive times, the SDK enters "offline grace"
mode for up to 7 days, after which it forces re-activation.
"""

from __future__ import annotations

import json
import os
import secrets
import socket
import ssl
import time
from dataclasses import dataclass
from typing import Optional
from urllib import request as urlreq
from urllib.error import HTTPError, URLError

from .crypto import b64encode, b64decode


DEFAULT_CALLBACK_INTERVAL = 6 * 3600  # 6 hours
MAX_OFFLINE_GRACE = 7 * 24 * 3600     # 7 days
CALLBACK_TIMEOUT = 10  # seconds


@dataclass
class CallbackResult:
    status: str  # ok | expired | revoked | mismatch | offline
    server_time: int
    remaining_days: int
    next_callback_in: int
    message: str = ""


def _local_ip() -> str:
    """Get the local IP address used for outbound connections (best-effort)."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def do_callback(keygen_url: str,
                code_id: str,
                full_code: str,
                fingerprint_hash: str,
                components_encrypted: str,
                software_version: str,
                last_known_remaining: int) -> CallbackResult:
    """
    Perform a single callback. Returns CallbackResult.
    On network failure, returns status="offline".
    """
    payload = {
        "code_id": code_id,
        "full_code": full_code,
        "fingerprint_hash": fingerprint_hash,
        "components_encrypted": components_encrypted,
        "local_ip": _local_ip(),
        "software_version": software_version,
        "client_nonce": secrets.token_hex(16),
        "client_time": int(time.time()),
        "last_known_remaining": last_known_remaining,
    }
    body = json.dumps(payload).encode()
    url = keygen_url.rstrip("/") + "/api/callback"
    req = urlreq.Request(
        url, data=body, method="POST",
        headers={
            "Content-Type": "application/json",
            "User-Agent": f"LicenseSDK/1.0 (Python {software_version})",
        },
    )
    try:
        ctx = ssl.create_default_context()
        # For self-signed / dev, allow override via env var
        if os.environ.get("LICENSE_INSECURE_TLS") == "1":
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        with urlreq.urlopen(req, timeout=CALLBACK_TIMEOUT, context=ctx) as resp:
            data = json.loads(resp.read().decode())
            return CallbackResult(
                status=data.get("status", "ok"),
                server_time=data.get("server_time", int(time.time())),
                remaining_days=data.get("remaining_days", 0),
                next_callback_in=data.get("next_callback_in", DEFAULT_CALLBACK_INTERVAL),
                message=data.get("message", ""),
            )
    except (HTTPError, URLError, socket.timeout, ConnectionError, OSError):
        return CallbackResult(
            status="offline",
            server_time=int(time.time()),
            remaining_days=last_known_remaining,
            next_callback_in=3600,  # retry in 1 hour
            message="network unreachable",
        )
    except Exception:
        return CallbackResult(
            status="offline",
            server_time=int(time.time()),
            remaining_days=last_known_remaining,
            next_callback_in=3600,
            message="callback exception",
        )
