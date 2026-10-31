#!/usr/bin/env python3
"""Compare two PocketBase data directories produced by the oracle and the port.

Used by ``tools/gate_m1.sh``. Exit status is the number of failed checks.
"""

import json
import os
import re
import sqlite3
import sys

SECRET = re.compile(r'"(secret)":"[A-Za-z0-9]{50}"')

failures = 0


def report(name, ok, detail=""):
    global failures
    if ok:
        print(f"  \033[32mPASS\033[0m {name}")
    else:
        failures += 1
        print(f"  \033[31mFAIL\033[0m {name}")
        if detail:
            for line in detail.splitlines():
                print(f"        {line}")
    return ok


def schema(path):
    db = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    try:
        return db.execute(
            "select type, name, sql from sqlite_master "
            "where name not like 'sqlite_stat%' order by type, name"
        ).fetchall()
    finally:
        db.close()


def migrate_files(path):
    db = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    try:
        return sorted(r[0] for r in db.execute("select file from _migrations"))
    finally:
        db.close()


def settings_value(path):
    db = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    try:
        row = db.execute("select value from _params where id = 'settings'").fetchone()
        return row[0] if row else None
    finally:
        db.close()


def collections(path):
    db = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    db.row_factory = sqlite3.Row
    try:
        rows = db.execute(
            "select id, system, type, name, fields, indexes, listRule, viewRule,"
            " createRule, updateRule, deleteRule, options from _collections order by id"
        ).fetchall()
        return {r["id"]: dict(r) for r in rows}
    finally:
        db.close()


def compare(go_dir, rs_dir):
    go_db = os.path.join(go_dir, "data.db")
    rs_db = os.path.join(rs_dir, "data.db")

    # 1. main schema
    go_schema, rs_schema = schema(go_db), schema(rs_db)
    if go_schema == rs_schema:
        report("data.db schema identical (sqlite_stat* excluded)", True)
    else:
        go_names = {(t, n) for t, n, _ in go_schema}
        rs_names = {(t, n) for t, n, _ in rs_schema}
        only_go, only_rs = go_names - rs_names, rs_names - go_names
        if only_go or only_rs:
            detail = f"only in oracle: {sorted(only_go)}\nonly in port: {sorted(only_rs)}"
        else:
            changed = [n for (_, n, g), (_, _, r) in zip(go_schema, rs_schema) if g != r]
            detail = "differing definitions: " + ", ".join(changed)
        report("data.db schema identical (sqlite_stat* excluded)", False, detail)

    # 2. migrations
    go_mig, rs_mig = migrate_files(go_db), migrate_files(rs_db)
    report(
        f"_migrations file set identical ({len(go_mig)} entries)",
        go_mig == rs_mig,
        f"only in oracle: {sorted(set(go_mig) - set(rs_mig))}\n"
        f"only in port: {sorted(set(rs_mig) - set(go_mig))}",
    )

    # 3. settings (byte comparison: key order and formatting are part of the contract)
    go_set, rs_set = settings_value(go_db), settings_value(rs_db)
    if go_set == rs_set:
        report("_params.settings byte-identical", True)
    else:
        detail = "value differs"
        try:
            g, r = json.loads(go_set or "{}"), json.loads(rs_set or "{}")
        except ValueError:
            pass
        else:
            keys = [k for k in set(g) | set(r) if g.get(k) != r.get(k)]
            detail = (
                "differing keys: " + ", ".join(sorted(keys))
                if keys
                else "semantically equal but serialized differently"
            )
        report("_params.settings byte-identical", False, detail)

    # 4. collections
    go_cols, rs_cols = collections(go_db), collections(rs_db)
    missing = sorted(set(go_cols) - set(rs_cols))
    extra = sorted(set(rs_cols) - set(go_cols))
    if missing or extra:
        report(
            "system collections present with identical ids",
            False,
            f"missing: {missing}\nextra: {extra}",
        )
    else:
        report(f"system collections present with identical ids ({len(go_cols)})", True)
        problems = []
        for cid, grow in go_cols.items():
            rrow = rs_cols[cid]
            for key in grow:
                gv, rv = grow[key], rrow[key]
                if key == "options":
                    gv = SECRET.sub(r'"\1":"<secret>"', gv or "")
                    rv = SECRET.sub(r'"\1":"<secret>"', rv or "")
                if gv != rv:
                    if key in ("fields", "indexes", "options"):
                        problems.append(f"{grow['name']}.{key} differs")
                    else:
                        problems.append(f"{grow['name']}.{key}: {gv!r} != {rv!r}")
        report(
            "_collections rows identical modulo token secrets",
            not problems,
            "\n".join(problems),
        )

        reused = [
            rrow["name"]
            for cid, rrow in rs_cols.items()
            if rrow["options"]
            and '"secret":"' in rrow["options"]
            and rrow["options"] == go_cols[cid]["options"]
        ]
        report("token secrets are regenerated per install", not reused, ", ".join(reused))

    # 5. installer superuser (the oracle creates one on every fresh install)
    def superusers(path):
        db = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
        db.row_factory = sqlite3.Row
        try:
            return [dict(r) for r in db.execute("select * from _superusers")]
        finally:
            db.close()

    go_su, rs_su = superusers(go_db), superusers(rs_db)
    if len(go_su) != 1 or len(rs_su) != 1:
        report(
            "installer superuser created",
            False,
            f"oracle rows: {len(go_su)}, port rows: {len(rs_su)}",
        )
    else:
        g, r = go_su[0], rs_su[0]
        stable = ("email", "emailVisibility", "verified")
        differing = [k for k in stable if g[k] != r[k]]
        report(
            "installer superuser matches (email/verified/visibility)",
            not differing,
            ", ".join(f"{k}: {g[k]!r} != {r[k]!r}" for k in differing),
        )
        report(
            "installer id/tokenKey/password have oracle-shaped values",
            bool(re.fullmatch(r"[a-z0-9]{15}", r["id"] or ""))
            and bool(re.fullmatch(r"[A-Za-z0-9]{50}", r["tokenKey"] or ""))
            and (r["password"] or "").startswith("$2a$10$"),
            f"id={r['id']!r} tokenKey(len)={len(r['tokenKey'] or '')} password={r['password']!r}",
        )
        report(
            "installer secrets are per-install (not copied)",
            r["id"] != g["id"]
            and r["tokenKey"] != g["tokenKey"]
            and r["password"] != g["password"],
        )

    # 6. storage classes (SQLite affinity lets TEXT and BLOB look identical)
    def storage_classes(path):
        db = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
        try:
            return {
                "_params.value": db.execute(
                    "select typeof(value) from _params where id = 'settings'"
                ).fetchone()[0],
                "_collections.fields": db.execute(
                    "select typeof(fields) from _collections limit 1"
                ).fetchone()[0],
                "_collections.indexes": db.execute(
                    "select typeof(indexes) from _collections limit 1"
                ).fetchone()[0],
                "_collections.options": db.execute(
                    "select typeof(options) from _collections limit 1"
                ).fetchone()[0],
            }
        finally:
            db.close()

    go_types, rs_types = storage_classes(go_db), storage_classes(rs_db)
    differing = [k for k in go_types if go_types[k] != rs_types[k]]
    report(
        "JSON columns use the same SQLite storage classes",
        not differing,
        "\n".join(f"{k}: {go_types[k]} != {rs_types[k]}" for k in differing),
    )

    # 7. auxiliary schema
    report(
        "auxiliary.db schema identical",
        schema(os.path.join(go_dir, "auxiliary.db"))
        == schema(os.path.join(rs_dir, "auxiliary.db")),
    )

    # 8. generated typings
    for label, d in (("oracle", go_dir), ("port", rs_dir)):
        report(f"{label} wrote types.d.ts", os.path.exists(os.path.join(d, "types.d.ts")))


def compare_dropin(
    before_dir, after_dir, actor="port", db_names=("data.db", "auxiliary.db")
):
    """`actor` (the binary under test) must not change an install created by the other."""

    def tables(path):
        db = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
        try:
            return [
                r[0]
                for r in db.execute(
                    "select name from sqlite_master where type = 'table' "
                    "and name not like 'sqlite_%' order by name"
                )
            ]
        finally:
            db.close()

    for db_name in db_names:
        before = os.path.join(before_dir, db_name)
        after = os.path.join(after_dir, db_name)

        report(
            f"{db_name} schema untouched by the {actor}",
            schema(before) == schema(after),
        )

        for table in tables(before):
            def dump(path, table=table):
                db = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
                try:
                    return db.execute(f'select * from "{table}"').fetchall()
                finally:
                    db.close()

            b, a = dump(before), dump(after)
            if b != a:
                report(f"{db_name}:{table} rows untouched by the {actor}", False)
            else:
                report(f"{db_name}:{table} rows untouched by the {actor} ({len(b)})", True)


if __name__ == "__main__":
    if len(sys.argv) == 4 and sys.argv[1] == "--dropin":
        compare_dropin(sys.argv[2], sys.argv[3])
    elif len(sys.argv) == 4 and sys.argv[1] == "--dropin-data":
        # The oracle appends a request log row to auxiliary.db, so the reverse
        # direction only asserts that data.db is untouched.
        compare_dropin(sys.argv[2], sys.argv[3], actor="oracle", db_names=("data.db",))
    elif len(sys.argv) == 3:
        compare(sys.argv[1], sys.argv[2])
    else:
        print(
            f"usage: {sys.argv[0]} GO_DIR RUST_DIR\n"
            f"       {sys.argv[0]} --dropin BEFORE_DIR AFTER_DIR\n"
            f"       {sys.argv[0]} --dropin-data BEFORE_DIR AFTER_DIR",
            file=sys.stderr,
        )
        sys.exit(2)
    sys.exit(min(failures, 125))
