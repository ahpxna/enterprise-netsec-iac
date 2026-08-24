#!/usr/bin/env python3
"""Execute a command with variables loaded from a dotenv file without shell evaluation.

This intentionally does not `source` .env: password hashes such as `$6$...` and
other metacharacters must be passed byte-for-byte rather than interpreted by a
shell. Only simple KEY=VALUE assignments are accepted.
"""

from __future__ import annotations

import argparse
import os
import pathlib
import re
import sys

KEY = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def parse_dotenv(path: pathlib.Path) -> dict[str, str]:
    values: dict[str, str] = {}
    for lineno, raw in enumerate(path.read_text().splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        key, sep, value = line.partition("=")
        key = key.strip()
        if not sep or not KEY.fullmatch(key):
            raise ValueError(f"{path}:{lineno}: invalid dotenv assignment")
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
            value = value[1:-1]
        values[key] = value
    return values


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--env-file", default=".env", type=pathlib.Path)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    if args.command and args.command[0] == "--":
        args.command = args.command[1:]
    if not args.command:
        parser.error("a command is required after options")
    if not args.env_file.is_file():
        parser.error(f"environment file not found: {args.env_file}")
    try:
        values = parse_dotenv(args.env_file)
    except ValueError as exc:
        parser.error(str(exc))
    # Path-valued variables are expanded here rather than by a shell. This
    # preserves the no-eval property while allowing portable ~/.ssh paths.
    for key, value in list(values.items()):
        if key.endswith("_FILE") and value.startswith("~"):
            values[key] = str(pathlib.Path(value).expanduser())
    environment = os.environ.copy()
    environment.update(values)
    os.execvpe(args.command[0], args.command, environment)
    return 127


if __name__ == "__main__":
    raise SystemExit(main())
