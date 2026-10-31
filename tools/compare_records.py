#!/usr/bin/env python3
"""Compare user-table rows of two PocketBase data.db files.

Used by the M3 gate: the harness compares HTTP responses, but a handler can
return the right JSON while writing a different row. All user tables are
dumped and compared after minimal, explicit normalization:

  * 15-char record ids (`[a-z0-9]{15}`)
  * `YYYY-MM-DD HH:MM:SS.mmmZ` timestamps

Rows are sorted after normalization, so insertion order is not significant.
"""

import json
import re
import sqlite3
import sys

ID = re.compile(r"^[a-z0-9]{15}$")
ID_ANYWHERE = re.compile(r"\b[a-z0-9]{15}\b")
TIMESTAMP = re.compile(r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3}Z")
BCRYPT = re.compile(r"\$2[abxy]\$\d{2}\$[./A-Za-z0-9]+")
SECRET = re.compile(r"\b[A-Za-z0-9]{50}\b")


def normalize(value):
    if isinstance(value, bytes):
        value = value.decode("utf-8", "replace")
    if value is None:
        return None
    if isinstance(value, (int, float)):
        return value
    out = str(value)
    out = TIMESTAMP.sub("<ts>", out)
    out = BCRYPT.sub("<bcrypt>", out)
    out = SECRET.sub("<secret>", out)
    out = ID_ANYWHERE.sub("<id>", out)
    return out


def user_tables(conn):
    rows = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' "
        "AND name NOT LIKE '\\_%' ESCAPE '\\' AND name NOT LIKE 'sqlite_%' ORDER BY name"
    ).fetchall()
    return [r[0] for r in rows]


def dump(path):
    conn = sqlite3.connect(path)
    out = {}
    for table in user_tables(conn):
        cols = [r[1] for r in conn.execute(f'PRAGMA table_info("{table}")')]
        rows = []
        for row in conn.execute(f'SELECT * FROM "{table}"'):
            rows.append({c: normalize(v) for c, v in zip(cols, row)})
        rows.sort(key=lambda r: json.dumps(r, sort_keys=True))
        out[table] = rows
    return out


def main():
    if len(sys.argv) != 3:
        print("usage: compare_records.py <go.db> <rust.db>", file=sys.stderr)
        return 2

    go = dump(sys.argv[1])
    rust = dump(sys.argv[2])

    if go.keys() != rust.keys():
        print(f"table set differs: {sorted(go)} != {sorted(rust)}")
        return 1

    failed = False
    for table in go:
        if go[table] != rust[table]:
            failed = True
            print(f"table {table!r} differs")
            for i, (a, b) in enumerate(zip(go[table], rust[table])):
                if a != b:
                    print(f"  row {i}:")
                    print(f"    go:   {json.dumps(a, sort_keys=True)}")
                    print(f"    rust: {json.dumps(b, sort_keys=True)}")
            if len(go[table]) != len(rust[table]):
                print(f"  row count: go={len(go[table])} rust={len(rust[table])}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
