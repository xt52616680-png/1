"""
example_app.py
==============
Demo software that integrates the license SDK.

Simulates a typical user flow:
  1. On launch, check activation status
  2. If not activated, prompt for code
  3. If activated, run the "software"
  4. Periodically callback to keygen

Usage:
  python example_app.py

Environment variables:
  LICENSE_KEYGEN_URL  - URL of the keygen backend (default: http://localhost:3000)
  LICENSE_ED25519_PUBKEY_B64 - Ed25519 public key (overrides default)
  LICENSE_REFUSE_IN_VM - "1" to refuse to run in VMs (production)
"""

from __future__ import annotations

import os
import sys
import time
import threading

# Add parent dir to path so we can import license_sdk
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from license_sdk import LicenseVerifier, LicenseConfig


def build_verifier() -> LicenseVerifier:
    pubkey = os.environ.get(
        "LICENSE_ED25519_PUBKEY_B64",
        LicenseConfig().public_key_b64,
    )
    return LicenseVerifier(LicenseConfig(
        public_key_b64=pubkey,
        keygen_url=os.environ.get("LICENSE_KEYGEN_URL", "http://localhost:3000"),
        software_version="1.0.0-demo",
        refuse_in_vm=os.environ.get("LICENSE_REFUSE_IN_VM") == "1",
    ))


def periodic_callback(verifier: LicenseVerifier, stop_event: threading.Event):
    """Background thread: callback every 6 hours."""
    while not stop_event.is_set():
        try:
            result = verifier.do_callback()
            if result.status == "revoked":
                print("\n[!] License revoked by server. Exiting.")
                os._exit(2)
            elif result.status == "expired":
                print("\n[!] License expired.")
                os._exit(3)
            print(f"[i] Callback OK: {result.remaining_days}d remaining, next in {result.next_callback_in}s")
        except Exception as e:
            print(f"[!] Callback error: {e}")
        # Wait 6 hours (or until stopped)
        stop_event.wait(6 * 3600)


def main():
    print("=" * 60)
    print("  Demo Software (Protected by License SDK)")
    print("=" * 60)

    verifier = build_verifier()

    # Step 1: Pre-flight (anti-debug, anti-VM)
    ok, reason = verifier.preflight()
    if not ok:
        print(f"\n[X] Security check failed: {reason}")
        print("    This software cannot run in this environment.")
        sys.exit(10)

    # Step 2: Check activation
    status = verifier.check_status()
    if not status.is_activated:
        print(f"\n[!] Not activated: {status.failure_reason}")
        if status.is_expired:
            print(f"    Previous license expired on "
                  f"{time.ctime(status.expires_at)}")
        print("\nPlease enter your activation code.")
        print("Format: XXXX-XXXX-XXXX-XXXX-XXXX-XXXX")
        for attempt in range(3):
            code = input(f"\n[Attempt {attempt+1}/3] Code: ").strip()
            if not code:
                continue
            ok, msg = verifier.activate(code)
            if ok:
                print(f"\n[OK] {msg}")
                # Re-check status
                status = verifier.check_status()
                break
            else:
                print(f"[X] Activation failed: {msg}")
        else:
            print("\n[X] Too many failed attempts. Exiting.")
            sys.exit(11)

    if not status.is_activated:
        sys.exit(11)

    # Step 3: Show license info
    print(f"\n[OK] License Active")
    print(f"     Code ID:      {status.code_id}")
    print(f"     Card Type:    {status.card_type}")
    print(f"     Activated At: {time.ctime(status.activated_at)}")
    print(f"     Expires At:   {time.ctime(status.expires_at)}")
    print(f"     Remaining:    {status.remaining_days} days")

    # Step 4: Start background callback
    stop_event = threading.Event()
    cb_thread = threading.Thread(
        target=periodic_callback, args=(verifier, stop_event), daemon=True
    )
    cb_thread.start()

    # Step 5: "Run the software"
    print("\n" + "=" * 60)
    print("  Software running. Press Ctrl+C to exit.")
    print("=" * 60)
    try:
        while True:
            time.sleep(1)
            # In a real app, this is where your main loop lives
    except KeyboardInterrupt:
        print("\n[i] Shutting down...")
        stop_event.set()
        sys.exit(0)


if __name__ == "__main__":
    main()
