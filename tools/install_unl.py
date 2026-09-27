#!/usr/bin/env python3
"""Atomically install a generated .unl file on an EVE-NG host over SSH."""

from __future__ import annotations

import argparse
import getpass
import os
import posixpath
import shlex
import sys
import time
import uuid
import xml.etree.ElementTree as ET
from pathlib import Path

import paramiko


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_LOCAL = ROOT / "eve" / "air-gapped-predictive-copilot.unl"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", required=True)
    parser.add_argument("--username", default="root")
    parser.add_argument("--password", help="Prefer EVE_ROOT_PASSWORD.")
    parser.add_argument("--local", type=Path, default=DEFAULT_LOCAL)
    parser.add_argument(
        "--remote",
        default="/opt/unetlab/labs/RS/Air-Gapped Predictive Copilot.unl",
    )
    args = parser.parse_args()

    ET.parse(args.local)
    password = args.password or os.environ.get("EVE_ROOT_PASSWORD")
    if not password:
        password = getpass.getpass("EVE shell password: ")

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(
            args.host,
            username=args.username,
            password=password,
            timeout=15,
        )
        remote_dir = posixpath.dirname(args.remote)
        temp = f"{args.remote}.tmp-{uuid.uuid4().hex}"
        backup = f"{args.remote}.bak-{time.strftime('%Y%m%d-%H%M%S')}"
        with client.open_sftp() as sftp:
            sftp.put(str(args.local), temp)
        remote_q = shlex.quote(args.remote)
        temp_q = shlex.quote(temp)
        backup_q = shlex.quote(backup)
        dir_q = shlex.quote(remote_dir)
        command = (
            f"test -d {dir_q} && "
            f"(test ! -f {remote_q} || cp -p {remote_q} {backup_q}) && "
            f"mv {temp_q} {remote_q} && "
            f"chown www-data:www-data {remote_q} && chmod 644 {remote_q}"
        )
        _, stdout, stderr = client.exec_command(command, timeout=30)
        rc = stdout.channel.recv_exit_status()
        error = stderr.read().decode("utf-8", errors="replace").strip()
        if rc:
            raise RuntimeError(error or f"remote install failed with status {rc}")
        print(f"Installed {args.remote}")
        print(f"Previous file backed up as {backup}")
        return 0
    except (OSError, RuntimeError, paramiko.SSHException) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    finally:
        client.close()


if __name__ == "__main__":
    raise SystemExit(main())
