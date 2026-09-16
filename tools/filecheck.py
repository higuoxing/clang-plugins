#!/usr/bin/env python3
"""Minimal FileCheck replacement when LLVM FileCheck is not installed."""

from __future__ import annotations

import argparse
import re
import sys


def subst_line_numbers(text: str, lineno: int) -> str:
    def repl(match: re.Match[str]) -> str:
        sign = match.group(1)
        number = match.group(2)
        if sign is None:
            return str(lineno)
        offset = int(number)
        if sign == "-":
            return str(lineno - offset)
        return str(lineno + offset)

    return re.sub(r"\[\[@LINE(?:([+-])(\d+))?\]\]", repl, text)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("check_file")
    parser.add_argument("--check-prefix", default="CHECK")
    args = parser.parse_args()

    output = sys.stdin.read()
    prefix_re = re.compile(r"^//\s*" + re.escape(args.check_prefix) + r":\s*(.*)$")
    checks: list[tuple[int, str]] = []
    with open(args.check_file, encoding="utf-8") as handle:
        for lineno, line in enumerate(handle, 1):
            match = prefix_re.match(line.rstrip("\n"))
            if not match:
                continue
            checks.append((lineno, subst_line_numbers(match.group(1), lineno)))

    cursor = 0
    for lineno, text in checks:
        found = output.find(text, cursor)
        if found < 0:
            sys.stderr.write(
                f"{args.check_file}:{lineno}: error: {args.check_prefix}: "
                f"expected string not found in input\n  {text}\n"
            )
            sys.exit(1)
        cursor = found + len(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
