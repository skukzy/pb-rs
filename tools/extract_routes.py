#!/usr/bin/env python3
"""M0: recover the HTTP route surface from the binary + admin UI, then verify
every candidate against a running PocketBase oracle.

Sources
  1. admin UI bundles (JS string literals are exact, not merged like Go rodata)
  2. the Go binary itself (heuristic runs starting at /api/)

Verification
  Each candidate is probed against the oracle. A live route answers with
  anything other than 404 (401/403/405 all prove the path is registered).

Usage:
    python3 tools/extract_routes.py \
        --binary ~/lab/pb/pocketbase --ui ui --base http://127.0.0.1:18090 \
        --out spec/routes.tsv
"""

from __future__ import annotations

import argparse
import glob
import os
import re
import urllib.error
import urllib.request

UI_API = re.compile(r'["\'`](/api/[A-Za-z0-9_{}$./:-]+)["\'`]')
UI_API_TMPL = re.compile(r'`(/api/[A-Za-z0-9_{}$./:-]+)`')
BIN_API = re.compile(rb"/api/[A-Za-z0-9_{}/.-]{1,80}")

# Characters that end a route run inside the packed Go rodata string blob.
BIN_TERMINATORS = set('"\'`<>()[]{} ,;:\\*?=|!')

PARAM_MAP = {
    "{collection}": "users",
    "{id}": "nonexistentid123",
    "{recordId}": "nonexistentid123",
    "{filename}": "x.txt",
    "{name}": "x",
    "{path...}": "x",
    "{provider}": "google",
    "$": "x",
}


def normalize(raw: str) -> str:
    for k, v in PARAM_MAP.items():
        raw = raw.replace(k, v)
    return raw.rstrip(".,;:")


def probe(base: str, path: str) -> tuple[int, str]:
    req = urllib.request.Request(base + path, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, r.headers.get("content-type", "")
    except urllib.error.HTTPError as e:
        return e.code, e.headers.get("content-type", "") if e.headers else ""
    except Exception:  # noqa: BLE001
        return 0, ""


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--binary", required=True)
    ap.add_argument("--ui", required=True)
    ap.add_argument("--base", default="http://127.0.0.1:18090")
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    candidates: dict[str, set[str]] = {}

    def add(route: str, src: str) -> None:
        route = normalize(route)
        if len(route) < 5 or route == "/api/":
            return
        candidates.setdefault(route, set()).add(src)

    for f in glob.glob(os.path.join(args.ui, "**", "*.js"), recursive=True):
        try:
            text = open(f, encoding="utf-8", errors="ignore").read()
        except OSError:
            continue
        for m in UI_API.finditer(text):
            add(m.group(1), "ui")
        for m in UI_API_TMPL.finditer(text):
            add(m.group(1), "ui")

    blob = open(args.binary, "rb").read()
    for m in BIN_API.finditer(blob):
        run = m.group(0).decode("ascii", "ignore")
        cut = len(run)
        for i, ch in enumerate(run):
            if ch in BIN_TERMINATORS:
                cut = i
                break
        run = run[:cut]
        # Trailing fragments from neighbouring literals.
        run = re.sub(r"(text|json|html|javascript|event-stream|octet-stream).*$", "", run)
        add(run, "binary")

    rows = []
    for route in sorted(candidates):
        status, ctype = probe(args.base, route)
        exists = status not in (0, 404)
        rows.append((route, status, "yes" if exists else "no", ctype.split(";")[0], ",".join(sorted(candidates[route]))))

    with open(args.out, "w") as f:
        f.write("route\tstatus_anon\texists\tcontent_type\tsource\n")
        for r in rows:
            f.write("\t".join(str(x) for x in r) + "\n")

    live = sum(1 for r in rows if r[2] == "yes")
    print(f"{len(rows)} candidates, {live} verified live -> {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
