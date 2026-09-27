#!/usr/bin/env python3
"""Create a git-ignored .env containing random lab-only credentials."""

from __future__ import annotations

import argparse
import secrets
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def token(prefix: str, nbytes: int = 18) -> str:
    return prefix + secrets.token_urlsafe(nbytes).replace("-", "A").replace("_", "B")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=ROOT / ".env")
    parser.add_argument("--force", action="store_true")
    args = parser.parse_args()
    if args.output.exists() and not args.force:
        parser.error(f"{args.output} already exists; use --force to rotate credentials")

    values = {
        "LAB_IKEV2_MPLS_PSK": token("Mpls_"),
        "LAB_IKEV2_INET_PSK": token("Inet_"),
        # IOS 15.2 rejects local enable/user secrets longer than 25 characters.
        "LAB_ENABLE_SECRET": token("Enable_", 12),
        "LAB_ADMIN_SECRET": token("Admin_", 12),
        "LAB_SNMP_AUTH": token("SnmpAuth_"),
        "LAB_SNMP_PRIV": token("SnmpPriv_"),
    }
    text = "\n".join(f"{key}={value}" for key, value in values.items()) + "\n"
    args.output.write_text(text, encoding="utf-8", newline="\n")
    print(f"Created {args.output} with random lab credentials.")
    print("Keep this file private; it is excluded by .gitignore.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
