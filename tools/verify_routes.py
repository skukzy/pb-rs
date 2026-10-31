#!/usr/bin/env python3
"""M0: verify the extracted route table against a running PocketBase oracle.

A route is considered registered when the oracle answers with anything other
than 404/501 for the declared method (401/403/400/422 all prove registration).

Usage:
    python3 tools/verify_routes.py --routes spec/routes-full.tsv \
        --base http://127.0.0.1:18090 --out spec/routes-verified.tsv
"""

from __future__ import annotations

import argparse
import urllib.error
import urllib.request

PARAMS = {
    "{collection}": "users",
    "{id}": "nonexistentid123",
    "{recordId}": "nonexistentid123",
    "{filename}": "x.txt",
    "{key}": "x.zip",
}


def probe(base: str, method: str, path: str) -> tuple[int, str]:
    req = urllib.request.Request(base + path, method=method, data=b"" if method in ("POST", "PUT", "PATCH") else None)
    req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, r.headers.get("content-type", "").split(";")[0]
    except urllib.error.HTTPError as e:
        return e.code, (e.headers.get("content-type", "").split(";")[0] if e.headers else "")
    except Exception:  # noqa: BLE001
        return 0, ""


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--routes", default="spec/routes-full.tsv")
    ap.add_argument("--base", default="http://127.0.0.1:18090")
    ap.add_argument("--out", default="spec/routes-verified.tsv")
    args = ap.parse_args()

    lines = open(args.routes).read().splitlines()
    out = ["method\troute\tprobe_path\tstatus\texists\thandler"]
    ok = bad = 0
    for line in lines[1:]:
        method, route, handler = line.split("\t")[:3]
        path = route
        for k, v in PARAMS.items():
            path = path.replace(k, v)
        status, ctype = probe(args.base, method, path)
        exists = status not in (0, 404, 501)
        ok += exists
        bad += not exists
        out.append(f"{method}\t{route}\t{path}\t{status}\t{'yes' if exists else 'NO'}\t{handler}")

    open(args.out, "w").write("\n".join(out) + "\n")
    print(f"verified {ok} live, {bad} not observed -> {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
