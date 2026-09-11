"""Command-line entry point: `check-no-secrets-in-argv <path> [<path> ...]`.

Designed for pre-commit, which passes the STAGED files it matched. Paths may also be
directories, for a full-tree sweep by hand or from a health check.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__
from .scanner import scan, shell_files

_EPILOG = """\
A secret reaches a subprocess on STDIN, never as an argument: a command line is
world-readable from /proc/<pid>/cmdline for the life of the process.

Waive a line that only LOOKS like a credential with a trailing
`# argv-secret-ok: <reason>` comment. A reason is required.
"""


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="check-no-secrets-in-argv",
        description="Fail if a secret-shaped variable reaches a spawned process's argv.",
        epilog=_EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "paths",
        nargs="*",
        type=Path,
        help="Shell scripts to scan, or directories to walk.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    paths: list[Path] = args.paths

    # No paths at all is not an empty scan, it is a MISSING one. Reporting success here
    # would make a misconfigured hook indistinguishable from a clean tree.
    if not paths:
        parser.print_help(sys.stdout)
        print(
            "\ncheck-no-secrets-in-argv: no paths given -- refusing to report success on a scan that never looked at anything.",
            file=sys.stderr,
        )
        return 2

    # A DIRECTORY that yields no shell scripts is blindness: the caller asked for a sweep
    # and got nothing, which is not the same as a clean sweep. An explicit FILE list is
    # the caller's own enumeration (pre-commit's, normally) and is taken at face value --
    # holding it to "must be non-empty" would fail every commit that touches no shell.
    directories = [p for p in paths if p.is_dir()]
    files = shell_files(paths)
    if directories and not files:
        print(
            f"check-no-secrets-in-argv: found NO shell scripts under {', '.join(str(d) for d in directories)} -- refusing to report success on an empty scan.",
            file=sys.stderr,
        )
        return 2

    findings = scan(files)
    if not findings:
        return 0

    print(
        f"Secrets in argv ({len(findings)} in {len(files)} shell script(s) scanned):\n",
        file=sys.stderr,
    )
    for finding in findings:
        print(finding.message(), file=sys.stderr)
    print(
        "\nNOTE: this scans SHELL only. Python subprocess call sites are the same hazard and are NOT covered.",
        file=sys.stderr,
    )
    return 1


if __name__ == "__main__":
    sys.exit(main())
