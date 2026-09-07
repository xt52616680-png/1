"""
generate_keypair.py
===================
Generate a new Ed25519 keypair for the license system.

Run this ONCE (e.g., on the keygen backend), then:
  - PRIVATE KEY: set as env var LICENSE_ED25519_PRIVATE_KEY_B64 on the keygen
  - PUBLIC KEY:  set as the `public_key_b64` in LicenseConfig (and in the SDK)

NEVER ship the private key with the software.
"""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from license_sdk import crypto


def main():
    priv_b64, pub_b64 = crypto.generate_keypair()
    print("=" * 60)
    print("  Ed25519 Keypair Generated")
    print("=" * 60)
    print()
    print("PRIVATE KEY (KEYGEN ONLY - never ship to clients!):")
    print(f"  LICENSE_ED25519_PRIVATE_KEY_B64={priv_b64}")
    print()
    print("PUBLIC KEY (embed in software SDK):")
    print(f"  public_key_b64=\"{pub_b64}\"")
    print()
    print("=" * 60)
    print("  Next Steps:")
    print("=" * 60)
    print("1. Add the private key to your keygen's .env file:")
    print("   LICENSE_ED25519_PRIVATE_KEY_B64=" + priv_b64)
    print()
    print("2. Update src/lib/keygen.ts PUBLIC_KEY constant in the Next.js app")
    print("   (or add LICENSE_ED25519_PUBLIC_KEY_B64 to .env)")
    print()
    print("3. Update LicenseConfig().public_key_b64 in:")
    print("   download/license-sdk-python/license_sdk/crypto.py")
    print("   (or pass via env var LICENSE_ED25519_PUBKEY_B64)")
    print()


if __name__ == "__main__":
    main()
