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
        values[key] = _clean_value(value)
    return values


def _clean_value(value: str) -> str:
    """Unquote a value and drop a trailing ``  # comment`` exactly as Docker Compose does.

    A ``#`` only starts a comment when whitespace precedes it, so passwords and crypt(3)
    hashes containing ``#``/``$`` without leading whitespace are preserved.
    """

    if re.match(r"\s+#", value):            # `KEY=   # only a comment` is an empty value
        return ""
    value = value.strip()
    if value[:1] in {"'", '"'}:
        closing = value.find(value[0], 1)
        if closing != -1:
            return value[1:closing]
        return value
    comment = re.search(r"\s#", value)
    return value[: comment.start()].rstrip() if comment else value


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--env-file", default=".env", type=pathlib.Path)
    parser.add_argument("--print-var", metavar="KEY", help="print one parsed dotenv value without shell evaluation")
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    if args.command and args.command[0] == "--":
        args.command = args.command[1:]
    if args.print_var and args.command:
        parser.error("--print-var cannot be combined with a command")
    if not args.print_var and not args.command:
        parser.error("a command is required after options")
    if not args.env_file.is_file():
        parser.error(f"environment file not found: {args.env_file}")
    try:
        values = parse_dotenv(args.env_file)
    except ValueError as exc:
        parser.error(str(exc))
    if args.print_var:
        if args.print_var not in values:
            parser.error(f"dotenv variable not found: {args.print_var}")
        print(values[args.print_var])
        return 0
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
