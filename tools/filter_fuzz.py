#!/usr/bin/env python3
"""Differential filter fuzzer: oracle PocketBase vs the Rust port.

Both servers must already be running with the same superuser credentials.  The
script creates an isolated pair of collections (and removes them first if they
exist), seeds the same records in both installs, then sends a deterministic
corpus of valid and mutated filter expressions to
`GET /api/collections/<name>/records` and compares:

* status code,
* error message (for 4xx/5xx),
* returned item set (ids/timestamps normalized).

Usage:
    tools/filter_fuzz.py --oracle-base http://127.0.0.1:18122 \
                         --port-base   http://127.0.0.1:18123 \
                         [--count 400] [--seed 20261029]

Exit status: 0 when every case matches, 1 otherwise.
"""

from __future__ import annotations

import argparse
import json
import random
import re
import sys
import urllib.error
import urllib.parse
import urllib.request

EMAIL = "admin@example.com"
PASSWORD = "pass12345678"
MAIN = "m7fuzz"
TARGET = "m7fuzz_target"

ID_RE = re.compile(r"\b[a-z0-9]{15}\b")
TS_RE = re.compile(r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?")


def request(base: str, method: str, path: str, *, token: str | None = None,
            body: dict | list | None = None, query: dict[str, str] | None = None):
    url = base.rstrip("/") + path
    if query:
        url += "?" + urllib.parse.urlencode(query)
    data = None
    headers = {}
    if body is not None:
        data = json.dumps(body).encode()
        headers["content-type"] = "application/json"
    if token:
        headers["authorization"] = "Bearer " + token
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req) as resp:
            raw = resp.read()
            ctype = resp.headers.get("content-type", "").split(";")[0].strip()
            return resp.status, ctype, raw
    except urllib.error.HTTPError as err:
        raw = err.read()
        ctype = err.headers.get("content-type", "").split(";")[0].strip()
        return err.code, ctype, raw


def request_json(base: str, method: str, path: str, **kwargs):
    status, ctype, raw = request(base, method, path, **kwargs)
    try:
        return status, ctype, json.loads(raw)
    except json.JSONDecodeError:
        return status, ctype, raw.decode(errors="replace")


def normalize(value):
    if isinstance(value, dict):
        return {k: normalize(v) for k, v in value.items()}
    if isinstance(value, list):
        return [normalize(v) for v in value]
    if isinstance(value, str):
        return TS_RE.sub("<ts>", ID_RE.sub("<id>", value))
    return value


def login(base: str) -> str:
    status, _, data = request_json(
        base, "POST", "/api/collections/_superusers/auth-with-password",
        body={"identity": EMAIL, "password": PASSWORD})
    if status != 200:
        raise SystemExit(f"login failed on {base}: {status} {data}")
    return data["token"]


def delete_collection(base: str, token: str, name: str):
    status, _, _ = request(base, "DELETE", f"/api/collections/{name}", token=token)
    # 404 is fine (not created yet); anything else unexpected is surfaced.
    if status not in (204, 404):
        raise SystemExit(f"could not delete {name} on {base}: {status}")


def create_collection(base: str, token: str, body: dict):
    status, _, data = request_json(base, "POST", "/api/collections",
                                   token=token, body=body)
    if status not in (200, 201):
        raise SystemExit(f"create collection failed on {base}: {status} {data}")
    return data


def setup(base: str) -> str:
    token = login(base)
    delete_collection(base, token, MAIN)
    delete_collection(base, token, TARGET)

    target = create_collection(base, token, {
        "name": TARGET,
        "type": "base",
        "fields": [
            {"name": "name", "type": "text"},
            {"name": "rank", "type": "number"},
        ],
    })

    create_collection(base, token, {
        "name": MAIN,
        "type": "base",
        # Open rules let the guest corpus exercise the missing
        # `@request.auth.*` operand path.
        "listRule": "",
        "viewRule": "",
        "fields": [
            {"name": "title", "type": "text"},
            {"name": "alias", "type": "text"},
            {"name": "count", "type": "number"},
            {"name": "score", "type": "number"},
            {"name": "active", "type": "bool"},
            {"name": "tags", "type": "select", "maxSelect": 3,
             "values": ["red", "green", "blue"]},
            {"name": "when", "type": "date"},
            {"name": "meta", "type": "json"},
            {"name": "rel", "type": "relation",
             "collectionId": target["id"], "maxSelect": 1},
        ],
    })

    target_ids = []
    for name, rank in (("target1", 1), ("target2", 2), ("target3", 3)):
        status, _, data = request_json(
            base, "POST", f"/api/collections/{TARGET}/records",
            token=token, body={"name": name, "rank": rank})
        if status not in (200, 201):
            raise SystemExit(f"seed target failed on {base}: {status} {data}")
        target_ids.append(data["id"])

    rows = [
        ("Alpha", "one", 0, 0.5, True, ["red"], "2024-01-15 10:00:00.000Z",
         {"k": "v", "n": 1}, 0),
        ("beta", "two", 1, 1.5, False, ["green", "blue"],
         "2024-06-01 12:30:00.000Z", {"k": "x", "n": 2}, 1),
        ("Gamma", "three", 2, 2.25, True, [], "2023-12-31 23:59:59.000Z",
         {"k": "v", "n": 3}, 2),
        ("delta", "four", 5, 3.5, False, ["red", "blue"],
         "2025-02-28 08:15:00.000Z", {}, 0),
        ("Hello World", "hello", 10, 4.0, True, ["red", "green"],
         "2024-01-01 00:00:00.000Z", {"nested": {"a": 1}}, 1),
        ("O'Reilly", "quote", -1, 5.5, False, ["blue"],
         "2022-07-04 18:00:00.000Z", {"k": "v"}, None),
        ("a_b", "under", 3, 6.0, True, ["green"],
         "2024-11-11 11:11:11.000Z", {"arr": [1, 2]}, 2),
        ("100%", "percent", 4, 7.5, False, ["red", "green", "blue"],
         "2021-03-03 03:03:03.000Z", {"k": ""}, 0),
    ]
    for title, alias, count, score, active, tags, when, meta, rel in rows:
        body = {
            "title": title, "alias": alias, "count": count, "score": score,
            "active": active, "tags": tags, "when": when, "meta": meta,
        }
        if rel is not None:
            body["rel"] = target_ids[rel]
        status, _, data = request_json(
            base, "POST", f"/api/collections/{MAIN}/records",
            token=token, body=body)
        if status not in (200, 201):
            raise SystemExit(f"seed record failed on {base}: {status} {data}")
    return token


# ---------------------------------------------------------------------------
# corpus generation


TEXT_VALUES = ["'Alpha'", "'beta'", "'hello'", "'Hello World'", "'O\\'Reilly'",
               "'a_b'", "'100%'", "'%'", "'_'", "'zeta'", "''", '"Alpha"',
               '"O\'Reilly"', "'ALPHA'", "'alpha'", "null"]
NUM_VALUES = ["-1", "0", "1", "2", "5", "10", "2.25", "0.5", "100", "-2.5",
              "1e2", "null", "true", "false"]
BOOL_VALUES = ["true", "false", "null", "1", "0", "'true'"]
TEXT_FIELDS = ["title", "alias"]
NUM_FIELDS = ["count", "score"]
BOOL_FIELDS = ["active"]
SELECT_FIELDS = ["tags"]
DATE_FIELDS = ["when"]

SIGNS = ["=", "!=", ">", ">=", "<", "<=", "~", "!~",
         "?=", "?!=", "?>", "?>=", "?<", "?<=", "?~", "?!~"]

MACROS = ["@now", "@todayStart", "@todayEnd", "@monthStart", "@monthEnd",
          "@yearStart", "@yearEnd", "@second", "@minute", "@hour"]
DATE_LITERALS = ["'2024-01-01 00:00:00.000Z'",
                 "'2024-06-01 12:30:00.000Z'",
                 "'2020-01-01 00:00:00.000Z'"]
TEXT_LITERALS = ["'Alpha'", "'beta'", "'Gamma'", "'hello'", "'%'"]
NUM_LITERALS = ["0", "1", "2", "5", "10", "2.25", "0.5"]


def atom(rng: random.Random) -> str:
    kind = rng.randrange(8)
    if kind == 0:
        return rng.choice(TEXT_FIELDS + NUM_FIELDS + BOOL_FIELDS + SELECT_FIELDS
                          + DATE_FIELDS + ["rel.name", "rel.rank", "id"])
    if kind == 1:
        return rng.choice(TEXT_VALUES)
    if kind == 2:
        return rng.choice(NUM_VALUES)
    if kind == 3:
        return rng.choice(BOOL_VALUES)
    if kind == 4:
        return rng.choice(MACROS)
    if kind == 5:
        return rng.choice(DATE_LITERALS)
    if kind == 6:
        return rng.choice(TEXT_LITERALS)
    return rng.choice(NUM_LITERALS)


def simple(rng: random.Random) -> str:
    kind = rng.randrange(10)
    if kind < 3:
        return f"{rng.choice(TEXT_FIELDS)} {rng.choice(SIGNS)} {rng.choice(TEXT_VALUES)}"
    if kind < 5:
        return f"{rng.choice(NUM_FIELDS)} {rng.choice(SIGNS)} {rng.choice(NUM_VALUES)}"
    if kind < 6:
        return f"{rng.choice(BOOL_FIELDS)} {rng.choice(SIGNS)} {rng.choice(BOOL_VALUES)}"
    if kind < 8:
        return f"{rng.choice(SELECT_FIELDS)} {rng.choice(SIGNS)} {rng.choice(['\'red\'', '\'green\'', '\'blue\'', '\'red\', \'blue\'', 'null'])}"
    if kind < 9:
        return f"{rng.choice(['title', 'alias'])}:{rng.choice(['lower', 'length', 'upper'])} {rng.choice(['=', '>', '<'])} {rng.choice(NUM_VALUES + TEXT_VALUES)}"
    return f"{rng.choice(DATE_FIELDS)} {rng.choice(['=', '>', '<', '>=', '<='])} {rng.choice(DATE_LITERALS + MACROS)}"


def expression(rng: random.Random) -> str:
    depth = rng.randrange(1, 4)
    parts = []
    for _ in range(depth):
        piece = simple(rng)
        if rng.random() < 0.25:
            piece = f"({simple(rng)} {rng.choice(['&&', '||'])} {simple(rng)})"
        if rng.random() < 0.15:
            piece = f"!({piece})"
        if rng.random() < 0.1:
            piece = f"{piece} && {simple(rng)}"
        parts.append(piece)
    expr = parts[0]
    for piece in parts[1:]:
        expr += f" {rng.choice(['&&', '||'])} {piece}"
    return expr


def mutate(rng: random.Random, base: str) -> str:
    ops = ["drop", "dup", "swap", "insert", "truncate", "bracket", "quote",
           "sign", "join", "comment"]
    op = rng.choice(ops)
    if op == "drop" and base:
        i = rng.randrange(len(base))
        return base[:i] + base[i + 1:]
    if op == "dup" and base:
        i = rng.randrange(len(base))
        return base[:i] + base[i] + base[i:]
    if op == "swap" and len(base) > 1:
        i = rng.randrange(len(base) - 1)
        return base[:i] + base[i + 1] + base[i] + base[i + 2:]
    if op == "insert":
        i = rng.randrange(len(base) + 1)
        return base[:i] + rng.choice(["'", '"', "(", ")", "!", "&", "|", "=",
                                      "?", "~", "\\", "\0", " ", ","]) + base[i:]
    if op == "truncate" and base:
        return base[:rng.randrange(len(base))]
    if op == "bracket":
        return "(" * rng.randrange(1, 3) + base + ")" * rng.randrange(0, 3)
    if op == "quote":
        return base + rng.choice(["'", '"', "\\'", "''"])
    if op == "sign":
        return base.replace(rng.choice(SIGNS), rng.choice(["===", "><", "!",
                                                           "??", "~~", "="]),
                            rng.randrange(1, 2))
    if op == "join":
        return base + rng.choice([" &&", " ||", " &", " |", " &&&", " |||"])
    return base + rng.choice([" /* x */", " /*", "// x", " -- x"])


def corpus(seed: int, count: int) -> list[str]:
    rng = random.Random(seed)
    out: list[str] = []
    seen = set()

    def add(value: str):
        if value not in seen:
            seen.add(value)
            out.append(value)

    # Hand-written edge cases first: nulls, empty text, escaping, macros,
    # relation traversal, functions, precedence and comments.
    fixed = [
        "title = 'Alpha'",
        "title != 'Alpha'",
        "title ~ 'a'",
        "title !~ 'a'",
        "title ?= 'Alpha'",
        "tags ?= 'red'",
        "tags ?!= 'red'",
        "tags ?~ 're'",
        "tags ?!~ 're'",
        "count ?= 5",
        "count ?!= 5",
        "title = 'O\\'Reilly'",
        'title = "O\'Reilly"',
        "title = ''",
        "title != ''",
        "title = null",
        "count = null",
        "active = true",
        "active = false",
        "active = null",
        "when >= @now",
        "when < @todayStart",
        "when >= @monthStart && when < @monthEnd",
        "when >= '2024-01-01 00:00:00.000Z'",
        "rel.name = 'target1'",
        "rel.rank > 1",
        "rel.name ~ 'target'",
        "rel.name ?= 'target1'",
        "title:lower = 'alpha'",
        "title:length = 5",
        "title:length > 3",
        "count:lower = 1",
        "strftime('%Y', when) = '2024'",
        "strftime('%Y-%m', when) >= '2024-01'",
        "strftime('%Y', when, 'unixepoch') = '2024'",
        "title = 'Alpha' && (count = 0 || active = true)",
        "title = 'Alpha' || count = 1 && active = false",
        "(title = 'Alpha' || title = 'beta') && active = true",
        "!(title = 'Alpha')",
        "! (title = 'Alpha')",
        "@collection.m7fuzz_target.name = 'target1'",
        "@collection.m7fuzz_target.rank >= 2",
        "@collection.m7fuzz_target.name ?= 'target2'",
        "id = 'aaaaaaaaaaaaaaa'",
        "id != ''",
        "1 = 1",
        "1 = 2",
        "true",
        "false",
        "title",
        "title =",
        "= 'Alpha'",
        "title === 'Alpha'",
        "title >< 1",
        "title = 'unterminated",
        "title = \"unterminated",
        "(title = 'Alpha'",
        "title = 'Alpha')",
        "title = 'Alpha' &&&& count = 1",
        "title = 1 /* x */",
        "title = .5",
        "title = -",
        "title = 'Alpha' &&",
        "lower(title) = 'alpha'",
        "geoDistance(1,2,3,4) < 100",
        "geoDistance(1,2,3) < 100",
        # NULL / empty operand normalization (`resolveEqualExpr`): the `null`
        # identifier, the empty string literal and empty relation joins all
        # take the same fallback branches.
        "title = null",
        "title != null",
        "title = ''",
        "title != ''",
        "null = title",
        "null != title",
        "null = null",
        "null != null",
        "'' = null",
        "null = ''",
        "'x' = null",
        "null = 'x'",
        "rel = null",
        "rel != null",
        "rel = ''",
        "rel != ''",
        "rel.name = null",
        "rel.name != null",
        "rel.name = ''",
        "rel.name != ''",
        "rel.members ?= null",
        "tags = null",
        "tags != null",
        "meta = null",
        "meta != null",
        "active = null",
        "count = null",
        "@request.auth.id = title",
        "@request.auth.id = null",
        "@request.auth.id != null",
        "",
        "   ",
    ]
    for item in fixed:
        add(item)

    attempts = 0
    while len(out) < count and attempts < count * 20:
        attempts += 1
        if rng.random() < 0.65:
            candidate = expression(rng)
        else:
            candidate = mutate(rng, expression(rng))
        if len(candidate) > 3400:
            continue
        add(candidate)

    # Limits and length boundaries are checked separately by limits_corpus().
    return out


def limits_corpus() -> list[str]:
    # Oracle: filter > 3500 chars -> 400; > 200 expressions -> 400.
    return [
        "title = '" + "a" * 3487 + "'",          # 3499 chars
        "title = '" + "a" * 3488 + "'",          # 3500 chars
        "title = '" + "a" * 3489 + "'",          # 3501 chars
        " && ".join(["1 = 1"] * 199),
        " && ".join(["1 = 1"] * 200),
        " && ".join(["1 = 1"] * 201),
        " || ".join(["(1 = 1)"] * 201),
    ]


def check_case(oracle: str, port: str, token_o: str, token_p: str,
               filt: str, *, label: str) -> bool:
    query = {"filter": filt, "sort": "title", "perPage": "100", "skipTotal": "1"}
    so, cto, do = request_json(oracle, "GET", f"/api/collections/{MAIN}/records",
                               token=token_o, query=query)
    sp, ctp, dp = request_json(port, "GET", f"/api/collections/{MAIN}/records",
                               token=token_p, query=query)

    ok = True
    if so != sp:
        ok = False
        print(f"MISMATCH status [{label}] {filt!r}: oracle={so} port={sp}")
    if cto != ctp:
        ok = False
        print(f"MISMATCH content-type [{label}] {filt!r}: {cto!r} != {ctp!r}")

    if so == 200 and sp == 200:
        no, np = normalize(do), normalize(dp)
        # Compare the semantic items; totalItems is -1 with skipTotal.
        if no.get("items") != np.get("items"):
            ok = False
            print(f"MISMATCH items [{label}] {filt!r}")
            print("  oracle:", json.dumps(no.get("items"), sort_keys=True)[:1200])
            print("  port:  ", json.dumps(np.get("items"), sort_keys=True)[:1200])
        for key in ("page", "perPage", "totalItems", "totalPages"):
            if no.get(key) != np.get(key):
                ok = False
                print(f"MISMATCH {key} [{label}] {filt!r}: "
                      f"{no.get(key)!r} != {np.get(key)!r}")
    else:
        mo = do.get("message") if isinstance(do, dict) else do
        mp = dp.get("message") if isinstance(dp, dict) else dp
        if mo != mp:
            ok = False
            print(f"MISMATCH message [{label}] {filt!r}: {mo!r} != {mp!r}")
    return ok


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--oracle-base", default="http://127.0.0.1:18122")
    ap.add_argument("--port-base", default="http://127.0.0.1:18123")
    ap.add_argument("--count", type=int, default=400)
    ap.add_argument("--seed", type=int, default=20261029)
    ap.add_argument("--verbose", action="store_true")
    args = ap.parse_args()

    print("seeding oracle ...")
    token_o = setup(args.oracle_base)
    print("seeding port ...")
    token_p = setup(args.port_base)

    filters = corpus(args.seed, args.count) + limits_corpus()
    print(f"comparing {len(filters)} filter expressions ...")

    failures = 0
    for i, filt in enumerate(filters, 1):
        if not check_case(args.oracle_base, args.port_base, token_o, token_p,
                          filt, label=f"case {i}"):
            failures += 1
        if args.verbose and i % 50 == 0:
            print(f"  {i}/{len(filters)}")

    # Missing-auth operand behavior: with no token, `@request.auth.id`
    # resolves to the `NULL` identifier and must compare like an empty value.
    guest_filters = [
        "title = @request.auth.id",
        "title != @request.auth.id",
        "rel = @request.auth.id",
        "rel != @request.auth.id",
        "rel.name = @request.auth.id",
        "rel.name != @request.auth.id",
        "rel.name ~ @request.auth.id",
        "@request.auth.id = null",
        "@request.auth.id != null",
        "@request.auth.id = ''",
        "@request.auth.id != ''",
        "@request.auth.name = null",
        "(@request.auth.id = null) && active = true",
    ]
    for i, filt in enumerate(guest_filters, 1):
        if not check_case(args.oracle_base, args.port_base, None, None,
                          filt, label=f"guest {i}"):
            failures += 1

    total = len(filters) + len(guest_filters)
    if failures:
        print(f"FAIL: {failures}/{total} cases differ")
        return 1
    print(f"PASS: {total} filter expressions match")
    return 0


if __name__ == "__main__":
    sys.exit(main())
