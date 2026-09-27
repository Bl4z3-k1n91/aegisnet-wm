"""Small unzip CLI compatibility shim for presentation template tooling."""

from __future__ import annotations

import sys
import zipfile


def main() -> int:
    if len(sys.argv) == 3 and sys.argv[1] == "-Z1":
        with zipfile.ZipFile(sys.argv[2]) as archive:
            sys.stdout.write("\n".join(archive.namelist()) + "\n")
        return 0
    if len(sys.argv) == 4 and sys.argv[1] == "-p":
        with zipfile.ZipFile(sys.argv[2]) as archive:
            sys.stdout.buffer.write(archive.read(sys.argv[3]))
        return 0
    print("usage: unzip -Z1 ZIP | unzip -p ZIP MEMBER", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
