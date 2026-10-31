#!/usr/bin/env python3
"""M0: build the authoritative route table from the exact upstream source tree
(commit verified by vcs.revision inside the binary).

Group prefixes are resolved from `rg.Group("...")` calls; each registration's
method/path/handler/middleware chain is read literally, including handler
expressions like `recordCreate(true, nil)`.

Usage:
    python3 tools/extract_routes_from_source.py \
        --src .upstream/apis --prefix /api --out spec/routes-full.tsv
"""

from __future__ import annotations

import argparse
import glob
import os
import re

GROUP_RE = re.compile(r'(\w+)\s*:=\s*(\w+)\.Group\("([^"]*)"\)')
BIND_RE = re.compile(r"^func (bind\w+)\(app core\.App, rg \*router\.Router")
ROUTE_RE = re.compile(
    r'^\s*(\w+)\.(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\("([^"]*)"\s*,\s*(.+)$'
)


def split_calls(text: str) -> tuple[str, list[str]]:
    """Split `handler.Bind(a).Unbind(b)` into handler + call list."""
    idx = [i for i in (text.find(".Bind("), text.find(".Unbind(")) if i >= 0]
    cut = min(idx) if idx else len(text)
    handler = text[:cut].strip().rstrip(",")
    if handler.endswith(")") and handler.count("(") < handler.count(")"):
        handler = handler.rstrip(")")
    calls: list[str] = []
    for m in re.finditer(r"\.(Bind|Unbind)\((.*)\)", text):
        calls.append(f"{m.group(1)}({m.group(2).strip()})")
    return handler, calls


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--src", default=".upstream/apis")
    ap.add_argument("--prefix", default="/api")
    ap.add_argument("--out", default="spec/routes-full.tsv")
    args = ap.parse_args()

    rows: list[tuple[str, str, str, str, str, str]] = []

    for path in sorted(glob.glob(os.path.join(args.src, "*.go"))):
        if path.endswith("_test.go"):
            continue
        fn = os.path.basename(path)
        current_bind = ""
        groups: dict[str, str] = {}
        group_mw: dict[str, list[str]] = {}

        for line in open(path).read().splitlines():
            s = line.strip()

            m = BIND_RE.match(s)
            if m:
                current_bind = m.group(1)
                groups = {"rg": args.prefix}
                group_mw = {}
                continue

            m = GROUP_RE.search(s)
            if m:
                name, parent, prefix = m.group(1), m.group(2), m.group(3)
                base = groups.get(parent, args.prefix)
                groups[name] = (base + prefix) or "/"
                group_mw[name] = re.findall(r"\.(Bind|Unbind)\(([^)]*)\)", s) and [
                    f"{a}({b.strip()})" for a, b in re.findall(r"\.(Bind|Unbind)\(([^)]*)\)", s)
                ] or []
                continue

            m = ROUTE_RE.match(s)
            if not m:
                continue
            grp, method, sub, rest = m.groups()
            if grp not in groups:
                continue
            route = re.sub(r"/+", "/", groups[grp] + sub) or "/"
            handler, calls = split_calls(rest)
            mw = ",".join(group_mw.get(grp, []) + calls)
            rows.append((method, route, handler, mw, current_bind, fn))

    rows.sort(key=lambda r: (r[1], r[0]))
    with open(args.out, "w") as f:
        f.write("method\troute\thandler\tmiddleware\tbind_fn\tfile\n")
        for r in rows:
            f.write("\t".join(r) + "\n")
    print(f"{len(rows)} routes -> {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
