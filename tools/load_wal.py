#!/usr/bin/env python3
"""Concurrent load + WAL test: oracle PocketBase vs the Rust port.

Each worker mirrors the same deterministic sequence of mixed operations
against both installs:

* list with filter/sort/pagination (both with and without `skipTotal`),
* create,
* update by id,
* delete by id,
* `PRAGMA wal_checkpoint(TRUNCATE)` through `POST /api/sql`.

Workers own the records they create, so the mirrored sequences are
independent and their status codes must match.  Record ids differ between
installs; the final comparison is a multiset of the record payloads.

At the end the script also checks `PRAGMA journal_mode` (must be `wal`) and
`PRAGMA integrity_check` (must be `ok`) on both installs.

Usage:
    tools/load_wal.py --oracle-base http://127.0.0.1:18122 \
                      --port-base   http://127.0.0.1:18123 \
                      [--workers 8] [--ops 30] [--seed 20261029]

Exit status: 0 when all checks pass, 1 otherwise.
"""

from __future__ import annotations

import argparse
import json
import random
import sqlite3
import statistics
import sys
import threading
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor

from filter_fuzz import EMAIL, PASSWORD

LOAD = "m7load"


def wal_writer(db_path: str, label: str, stop: threading.Event,
               errors: list[str]):
    """Second connection to the same database, forcing real WAL contention."""
    try:
        conn = sqlite3.connect(db_path, timeout=10.0)
        conn.execute("PRAGMA busy_timeout=10000")
        conn.execute(
            "CREATE TABLE IF NOT EXISTS wal_probe "
            "(id INTEGER PRIMARY KEY AUTOINCREMENT, v TEXT)")
        conn.commit()
    except Exception as err:
        errors.append(f"{label} wal writer setup: {err}")
        return
    step = 0
    try:
        while not stop.is_set():
            try:
                conn.execute("BEGIN IMMEDIATE")
                conn.execute("INSERT INTO wal_probe (v) VALUES (?)",
                             (f"{label}-{step}",))
                conn.execute(
                    "DELETE FROM wal_probe WHERE id <= "
                    "(SELECT MAX(id) - 100 FROM wal_probe)")
                conn.commit()
                if step % 10 == 0:
                    conn.execute("PRAGMA wal_checkpoint(PASSIVE)").fetchall()
            except Exception as err:
                errors.append(f"{label} wal writer: {err}")
                try:
                    conn.rollback()
                except Exception:
                    pass
            step += 1
            time.sleep(0.005)
    finally:
        conn.close()


def request(base: str, method: str, path: str, *, token: str | None = None,
            body=None, query=None, timeout: float = 30.0):
    """Like filter_fuzz.request, but reports transport errors as status 0."""
    import urllib.parse

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
    started = time.monotonic()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read()
            return resp.status, raw, time.monotonic() - started, None
    except urllib.error.HTTPError as err:
        return err.code, err.read(), time.monotonic() - started, None
    except Exception as err:  # transport/timeout
        return 0, b"", time.monotonic() - started, str(err)


def request_json(base: str, method: str, path: str, **kwargs):
    status, raw, elapsed, transport = request(base, method, path, **kwargs)
    try:
        data = json.loads(raw) if raw else None
    except json.JSONDecodeError:
        data = raw.decode(errors="replace")
    return status, data, elapsed, transport


def login(base: str) -> str:
    status, data, _, transport = request_json(
        base, "POST", "/api/collections/_superusers/auth-with-password",
        body={"identity": EMAIL, "password": PASSWORD})
    if status != 200 or not isinstance(data, dict) or "token" not in data:
        raise SystemExit(f"login failed on {base}: {status} {transport or data}")
    return data["token"]


def delete_collection(base: str, token: str, name: str):
    status, _, _, transport = request_json(
        base, "DELETE", f"/api/collections/{name}", token=token)
    if status not in (204, 404):
        raise SystemExit(f"could not delete {name} on {base}: {status} {transport}")


def create_collection(base: str, token: str):
    status, data, _, transport = request_json(
        base, "POST", "/api/collections", token=token,
        body={
            "name": LOAD,
            "type": "base",
            "fields": [
                {"name": "name", "type": "text"},
                {"name": "n", "type": "number"},
                {"name": "flag", "type": "bool"},
                {"name": "payload", "type": "text"},
            ],
        })
    if status not in (200, 201):
        raise SystemExit(f"create {LOAD} failed on {base}: {status} {transport or data}")


def seed(base: str, token: str, count: int) -> list[str]:
    ids = []
    for i in range(count):
        status, data, _, transport = request_json(
            base, "POST", f"/api/collections/{LOAD}/records", token=token,
            body={"name": f"seed-{i:02d}", "n": 1000 + i, "flag": i % 2 == 0,
                  "payload": "seed"})
        if status not in (200, 201):
            raise SystemExit(f"seed failed on {base}: {status} {transport or data}")
        ids.append(data["id"])
    return ids


def setup(base: str, seeds: int) -> tuple[str, list[str]]:
    token = login(base)
    delete_collection(base, token, LOAD)
    create_collection(base, token)
    return token, seed(base, token, seeds)


def pragma(base: str, token: str, query: str):
    return request_json(base, "POST", "/api/sql", token=token, body={"query": query})


def run_worker(worker: int, ops: int, seed_value: int,
               oracle: str, port: str, token_o: str, token_p: str,
               ids_o: list[str], ids_p: list[str],
               errors: list[str], latencies: dict[str, list[float]]):
    rng = random.Random(seed_value + worker)
    alive_o = [ids_o[worker % len(ids_o)]]
    alive_p = [ids_p[worker % len(ids_p)]]
    local_errors = []

    def record(side: str, status: int, data, transport, label: str, expect: set[int]):
        if transport:
            local_errors.append(f"[w{worker}] {label} {side}: transport {transport}")
        elif status not in expect:
            local_errors.append(
                f"[w{worker}] {label} {side}: status {status} "
                f"(expected {sorted(expect)}) {str(data)[:300]}")

    for step in range(ops):
        choice = rng.choices(
            ["list", "list-total", "create", "update", "delete", "checkpoint"],
            weights=[3, 2, 3, 3, 2, 1],
        )[0]

        if choice in ("list", "list-total"):
            filt = f"n >= {rng.randrange(0, 1200)}"
            query = {"filter": filt, "sort": "-n,name", "perPage": "50"}
            if choice == "list-total":
                query.update({"page": str(rng.randrange(1, 3)), "skipTotal": "0",
                              "perPage": "5"})
            else:
                query["skipTotal"] = "1"
            label = f"{choice} filter={filt!r} {query}"
            so, do, to, tro = request_json(
                oracle, "GET", f"/api/collections/{LOAD}/records",
                token=token_o, query=query)
            sp, dp, tp, trp = request_json(
                port, "GET", f"/api/collections/{LOAD}/records",
                token=token_p, query=query)
            latencies["oracle"].append(to)
            latencies["port"].append(tp)
            record("oracle", so, do, tro, label, {200})
            record("port", sp, dp, trp, label, {200})

        elif choice == "create":
            body = {
                "name": f"w{worker}-{step}",
                "n": rng.randrange(0, 2000),
                "flag": rng.random() < 0.5,
                "payload": "x" * rng.randrange(0, 200),
            }
            so, do, to, tro = request_json(
                oracle, "POST", f"/api/collections/{LOAD}/records",
                token=token_o, body=body)
            sp, dp, tp, trp = request_json(
                port, "POST", f"/api/collections/{LOAD}/records",
                token=token_p, body=body)
            latencies["oracle"].append(to)
            latencies["port"].append(tp)
            record("oracle", so, do, tro, "create", {200, 201})
            record("port", sp, dp, trp, "create", {200, 201})
            if so in (200, 201) and isinstance(do, dict):
                alive_o.append(do["id"])
            if sp in (200, 201) and isinstance(dp, dict):
                alive_p.append(dp["id"])

        elif choice == "update":
            if not alive_o or len(alive_o) != len(alive_p):
                continue
            idx = rng.randrange(len(alive_o))
            body = {"n": rng.randrange(0, 2000)}
            so, do, to, tro = request_json(
                oracle, "PATCH", f"/api/collections/{LOAD}/records/{alive_o[idx]}",
                token=token_o, body=body)
            sp, dp, tp, trp = request_json(
                port, "PATCH", f"/api/collections/{LOAD}/records/{alive_p[idx]}",
                token=token_p, body=body)
            latencies["oracle"].append(to)
            latencies["port"].append(tp)
            record("oracle", so, do, tro, "update", {200})
            record("port", sp, dp, trp, "update", {200})

        elif choice == "delete":
            if not alive_o or len(alive_o) != len(alive_p):
                continue
            idx = rng.randrange(len(alive_o))
            target_o = alive_o.pop(idx)
            target_p = alive_p.pop(idx)
            so, do, to, tro = request_json(
                oracle, "DELETE", f"/api/collections/{LOAD}/records/{target_o}",
                token=token_o)
            sp, dp, tp, trp = request_json(
                port, "DELETE", f"/api/collections/{LOAD}/records/{target_p}",
                token=token_p)
            latencies["oracle"].append(to)
            latencies["port"].append(tp)
            record("oracle", so, do, tro, "delete", {204})
            record("port", sp, dp, trp, "delete", {204})

        else:
            so, do, to, tro = pragma(oracle, token_o,
                                     "PRAGMA wal_checkpoint(TRUNCATE)")
            sp, dp, tp, trp = pragma(port, token_p,
                                     "PRAGMA wal_checkpoint(TRUNCATE)")
            latencies["oracle"].append(to)
            latencies["port"].append(tp)
            record("oracle", so, do, tro, "checkpoint", {200})
            record("port", sp, dp, trp, "checkpoint", {200})

    errors.extend(local_errors)


def fetch_all(base: str, token: str) -> list[dict]:
    items = []
    page = 1
    while True:
        status, data, _, transport = request_json(
            base, "GET", f"/api/collections/{LOAD}/records", token=token,
            query={"page": str(page), "perPage": "200", "sort": "name"})
        if status != 200:
            raise SystemExit(f"final list failed on {base}: {status} {transport or data}")
        items.extend(data["items"])
        if page >= data["totalPages"]:
            return items
        page += 1


def canonical(items: list[dict]) -> list[tuple]:
    out = []
    for item in items:
        out.append(tuple(sorted(
            (k, json.dumps(v, sort_keys=True))
            for k, v in item.items()
            if k not in ("id", "collectionId", "collectionName", "created", "updated")
        )))
    out.sort()
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--oracle-base", default="http://127.0.0.1:18122")
    ap.add_argument("--port-base", default="http://127.0.0.1:18123")
    ap.add_argument("--workers", type=int, default=8)
    ap.add_argument("--ops", type=int, default=30)
    ap.add_argument("--seeds", type=int, default=24)
    ap.add_argument("--seed", type=int, default=20261029)
    ap.add_argument("--oracle-dir",
                    help="oracle pb_data directory for the external WAL writer")
    ap.add_argument("--port-dir",
                    help="port pb_data directory for the external WAL writer")
    args = ap.parse_args()

    print("setting up oracle ...")
    token_o, ids_o = setup(args.oracle_base, args.seeds)
    print("setting up port ...")
    token_p, ids_p = setup(args.port_base, args.seeds)

    for label, base, token in (("oracle", args.oracle_base, token_o),
                               ("port", args.port_base, token_p)):
        status, data, _, transport = pragma(base, token, "PRAGMA journal_mode")
        mode = data["rows"][0][0] if status == 200 and data["rows"] else None
        if mode != "wal":
            print(f"FAIL: {label} journal_mode is {mode!r} ({status} {transport or data})")
            return 1

    errors: list[str] = []
    latencies = {"oracle": [], "port": []}
    stop_writers = threading.Event()
    writers: list[threading.Thread] = []
    if args.oracle_dir and args.port_dir:
        for label, directory in (("oracle", args.oracle_dir),
                                 ("port", args.port_dir)):
            thread = threading.Thread(
                target=wal_writer,
                args=(f"{directory.rstrip('/')}/data.db", label,
                      stop_writers, errors),
                daemon=True,
            )
            thread.start()
            writers.append(thread)
        print("external WAL writers running (second sqlite connection each)")
    else:
        print("external WAL writers skipped (pass --oracle-dir/--port-dir)")

    print(f"running {args.workers} workers x {args.ops} mirrored operations ...")
    started = time.monotonic()
    try:
        with ThreadPoolExecutor(max_workers=args.workers) as pool:
            futures = [
                pool.submit(run_worker, w, args.ops, args.seed,
                            args.oracle_base, args.port_base, token_o, token_p,
                            ids_o, ids_p, errors, latencies)
                for w in range(args.workers)
            ]
            for future in futures:
                future.result()
    finally:
        stop_writers.set()
        for thread in writers:
            thread.join(timeout=15)
    elapsed = time.monotonic() - started

    if errors:
        for line in errors[:40]:
            print("ERROR", line)
        if len(errors) > 40:
            print(f"... {len(errors) - 40} more errors")
        print(f"FAIL: {len(errors)} operation errors")
        return 1

    final_o = canonical(fetch_all(args.oracle_base, token_o))
    final_p = canonical(fetch_all(args.port_base, token_p))
    if final_o != final_p:
        only_o = [row for row in final_o if row not in set(final_p)]
        only_p = [row for row in final_p if row not in set(final_o)]
        print("FAIL: final record sets differ")
        print("  only oracle:", json.dumps(only_o[:5], default=str)[:1200])
        print("  only port:  ", json.dumps(only_p[:5], default=str)[:1200])
        return 1

    for label, base, token in (("oracle", args.oracle_base, token_o),
                               ("port", args.port_base, token_p)):
        status, data, _, transport = pragma(base, token, "PRAGMA integrity_check")
        check = data["rows"][0][0] if status == 200 and data["rows"] else None
        if check != "ok":
            print(f"FAIL: {label} integrity_check = {check!r} "
                  f"({status} {transport or data})")
            return 1

    def summary(side: str) -> str:
        values = sorted(latencies[side])
        if not values:
            return "n/a"
        p95 = values[min(len(values) - 1, int(len(values) * 0.95))]
        return (f"p50={statistics.median(values) * 1000:.1f}ms "
                f"p95={p95 * 1000:.1f}ms max={values[-1] * 1000:.1f}ms")

    ops_total = len(latencies["oracle"]) + len(latencies["port"])
    print(f"PASS: {args.workers} workers, {ops_total} requests, "
          f"{len(final_o)} final records, wal + integrity ok, "
          f"{elapsed:.1f}s")
    print(f"  oracle latency: {summary('oracle')}")
    print(f"  port latency:   {summary('port')}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
