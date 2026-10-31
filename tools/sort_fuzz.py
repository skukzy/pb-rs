#!/usr/bin/env python3
"""Differential sort/pagination fuzzer for the records list endpoint.

Run `tools/filter_fuzz.py` first (or let this script seed the same data), then:

    tools/sort_fuzz.py --oracle-base http://127.0.0.1:18122 \
                       --port-base   http://127.0.0.1:18123

The corpus covers ordinary fields, relation traversal, `@rowid`/`@random`,
empty entries, `+`/`-` prefixes, the 8-expression limit, the 255-byte field
limit and invalid identifiers.
"""

from __future__ import annotations

import argparse
import json
import random
import sys

from filter_fuzz import MAIN, normalize, request_json, setup


def corpus(seed: int) -> list[str]:
    rng = random.Random(seed)
    fields = ["title", "alias", "count", "score", "active", "tags", "when",
              "id", "created", "updated", "rel.name", "rel.rank"]
    out = [
        "title", "-title", "+title", " title ", "- title",
        "title,count", "title,-count", "-count,title",
        "rel.name", "-rel.name", "rel.rank,title", "rel.name,title",
        "id", "-id", "created", "-created", "updated", "-updated",
        "tags", "active", "when", "-when", "score,active,title",
        "@rowid", "-@rowid", "+@rowid",
        # ParseSortFromString keeps empty entries; these must all be errors.
        "title,", ",title", "title,,count", ",", " , ",
        # Invalid names and relation paths.
        "nope", "-nope", "title.nope", "rel.nope", "meta", "rel",
        # Limits.
        ",".join(["title"] * 8),
        ",".join(["title"] * 9),
        ",".join(fields[:8]),
        ",".join(fields[:9]),
        "a" * 255,
        "a" * 256,
        "-" + "a" * 256,
        # Whitespace-only: ParseSortFromString yields one empty field.
        " ",
    ]

    # Random valid chains, with occasional invalid pieces.
    for _ in range(120):
        count = rng.randrange(1, 10)
        parts = []
        for _ in range(count):
            field = rng.choice(fields + ["nope", "rel.nope", "meta"])
            prefix = rng.choice(["", "", "-", "+", " ", " - "])
            parts.append(prefix + field)
        out.append(",".join(parts))
    return out


def compare(base_o: str, base_p: str, token_o: str, token_p: str,
            sort: str, *, random_order: bool) -> bool:
    query = {"sort": sort, "perPage": "100", "skipTotal": "1"}
    so, cto, do = request_json(base_o, "GET", f"/api/collections/{MAIN}/records",
                               token=token_o, query=query)
    sp, ctp, dp = request_json(base_p, "GET", f"/api/collections/{MAIN}/records",
                               token=token_p, query=query)
    ok = True
    if so != sp:
        ok = False
        print(f"MISMATCH status sort={sort!r}: oracle={so} port={sp}")
    if cto != ctp:
        ok = False
        print(f"MISMATCH content-type sort={sort!r}: {cto!r} != {ctp!r}")

    if so == 200 and sp == 200:
        no, np = normalize(do), normalize(dp)
        oi, pi = no.get("items", []), np.get("items", [])
        if random_order:
            oi = sorted(oi, key=lambda v: json.dumps(v, sort_keys=True))
            pi = sorted(pi, key=lambda v: json.dumps(v, sort_keys=True))
        if oi != pi:
            ok = False
            print(f"MISMATCH items sort={sort!r}")
            print("  oracle:", [x.get("title") for x in oi])
            print("  port:  ", [x.get("title") for x in pi])
        for key in ("page", "perPage", "totalItems", "totalPages"):
            if no.get(key) != np.get(key):
                ok = False
                print(f"MISMATCH {key} sort={sort!r}: "
                      f"{no.get(key)!r} != {np.get(key)!r}")
    else:
        mo = do.get("message") if isinstance(do, dict) else do
        mp = dp.get("message") if isinstance(dp, dict) else dp
        if mo != mp:
            ok = False
            print(f"MISMATCH message sort={sort!r}: {mo!r} != {mp!r}")
    return ok


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--oracle-base", default="http://127.0.0.1:18122")
    ap.add_argument("--port-base", default="http://127.0.0.1:18123")
    ap.add_argument("--seed", type=int, default=20261029)
    args = ap.parse_args()

    token_o = setup(args.oracle_base)
    token_p = setup(args.port_base)
    sorts = corpus(args.seed)
    print(f"comparing {len(sorts)} sort expressions ...")

    failures = 0
    for sort in sorts:
        # Record ids are random per install, and a relation column stores the
        # target record id, so their relative order is not comparable across
        # the two databases.  Compare the returned sets for those keys.
        unstable = {"@random", "id", "rel"}
        random_order = any(part.strip().lstrip("+-") in unstable
                           for part in sort.split(","))
        if not compare(args.oracle_base, args.port_base, token_o, token_p,
                       sort, random_order=random_order):
            failures += 1
    if failures:
        print(f"FAIL: {failures}/{len(sorts)} sort expressions differ")
        return 1
    print(f"PASS: {len(sorts)} sort expressions match")
    return 0


if __name__ == "__main__":
    sys.exit(main())
