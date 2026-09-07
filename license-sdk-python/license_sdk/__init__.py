"""
license_sdk
===========
Software activation SDK with strong anti-cracking, anti-debug, anti-VM,
and multi-layer tamper-resistant storage.

Quick start:
    from license_sdk import LicenseVerifier, LicenseConfig

    verifier = LicenseVerifier(LicenseConfig(
        public_key_b64="YOUR_ED25519_PUBLIC_KEY_BASE64",
        keygen_url="http://localhost:3000",  # or your Vercel URL
        software_version="1.0.0",
        refuse_in_vm=False,  # set True for production
    ))

    # 1. Check if already activated
    status = verifier.check_status()
    if status.is_activated:
        print(f"Licensed - {status.remaining_days} days remaining")
    else:
        # 2. Prompt user for activation code
        code = input("Enter activation code: ")
        ok, msg = verifier.activate(code)
        if not ok:
            print(f"Activation failed: {msg}")
            sys.exit(1)

    # 3. Periodically callback (e.g., every 6h)
    result = verifier.do_callback()
    print(f"Callback: {result.status}, remaining: {result.remaining_days}d")
"""

from .verifier import LicenseVerifier, LicenseConfig, ActivationStatus
from .callback import CallbackResult, do_callback
from . import crypto, fingerprint, anti_debug, anti_vm, storage

__version__ = "1.0.0"
__all__ = [
    "LicenseVerifier",
    "LicenseConfig",
    "ActivationStatus",
    "CallbackResult",
    "do_callback",
    "crypto",
    "fingerprint",
    "anti_debug",
    "anti_vm",
    "storage",
]
