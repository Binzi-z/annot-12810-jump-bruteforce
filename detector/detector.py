"""Baseline detector: flags every failed password and every request.

This is what the SOC running now. It has no correlation: one attacker IP still
produces dozens of rows and the analyst cannot tell which ones mattered.
"""

from __future__ import annotations

import json
import re
import sys

FAIL = re.compile(r"Failed password for (?P<user>\S+) from (?P<ip>[\d.]+)")
WEB = re.compile(r'nginx: (?P<ip>[\d.]+) - - "(?P<path>\S+)')


def scan(path: str) -> list[dict]:
    findings: list[dict] = []
    with open(path, encoding="utf-8") as fh:
        for no, line in enumerate(fh, start=1):
            m = FAIL.search(line)
            if m:
                findings.append({"rule": "failed_password", "line": no, "ip": m.group("ip"),
                                 "user": m.group("user"), "severity": "low"})
                continue
            m = WEB.search(line)
            if m:
                findings.append({"rule": "web_request", "line": no, "ip": m.group("ip"),
                                 "path": m.group("path"), "severity": "info"})
    return findings


def main() -> int:
    if len(sys.argv) < 3:
        print("usage: detector.py <log> <out.json>")
        return 2
    findings = scan(sys.argv[1])
    with open(sys.argv[2], "w", encoding="utf-8") as fh:
        json.dump({"findings": findings}, fh, ensure_ascii=False, indent=2)
    print(f"{len(findings)} findings -> {sys.argv[2]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
