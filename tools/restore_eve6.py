#!/usr/bin/env python3
"""Restore the compact project migration bundle onto a fresh EVE-NG CE 6 VM."""

from __future__ import annotations

import argparse
import getpass
import hashlib
import os
import shlex
import sys
from pathlib import Path

import paramiko


DEFAULT_ARCHIVE = (
    Path(__file__).resolve().parents[1] / "eve" / "copilot-eve6-migration.tgz"
)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", required=True, help="Fresh EVE v6 management IP")
    parser.add_argument("--username", default="root")
    parser.add_argument("--password", help="Prefer EVE6_ROOT_PASSWORD.")
    parser.add_argument("--archive", type=Path, default=DEFAULT_ARCHIVE)
    args = parser.parse_args()

    if not args.archive.is_file():
        print(f"ERROR: archive not found: {args.archive}", file=sys.stderr)
        return 1

    password = args.password or os.environ.get("EVE6_ROOT_PASSWORD")
    if not password:
        password = getpass.getpass("Fresh EVE root password: ")

    local_hash = sha256(args.archive)
    remote_archive = "/tmp/copilot-eve6-migration.tgz"
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(
            args.host,
            username=args.username,
            password=password,
            timeout=15,
        )
        with client.open_sftp() as sftp:
            sftp.put(str(args.archive), remote_archive)

        remote_q = shlex.quote(remote_archive)
        command = (
            f"test \"$(sha256sum {remote_q} | cut -d' ' -f1)\" = {local_hash} && "
            f"tar -C / -xzf {remote_q} && "
            "/opt/unetlab/wrappers/unl_wrapper -a fixpermissions && "
            f"rm -f {remote_q}"
        )
        _, stdout, stderr = client.exec_command(command, timeout=300)
        rc = stdout.channel.recv_exit_status()
        output = stdout.read().decode("utf-8", errors="replace").strip()
        error = stderr.read().decode("utf-8", errors="replace").strip()
        if output:
            print(output)
        if rc:
            raise RuntimeError(error or f"restore failed with status {rc}")
        print(f"Restored bundle SHA256 {local_hash}")
        print("Labs and project images are installed; EVE permissions repaired.")
        return 0
    except (OSError, RuntimeError, paramiko.SSHException) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    finally:
        client.close()


if __name__ == "__main__":
    raise SystemExit(main())
