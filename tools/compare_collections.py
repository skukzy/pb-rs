#!/usr/bin/env python3
"""Compare the collection state of two PocketBase data.db files.

Used by the M2 gate: the API responses are compared by the `harness`, but the
rows and the generated schema must match too (a create that returns the right
JSON but writes a different row is still a compatibility bug).

Normalization is deliberately minimal and explicit:
  * 50-char alphanumeric tokens (collection token secrets, provider secrets)
  * `YYYY-MM-DD HH:MM:SS.mmmZ` timestamps
  * `_clone_XXXX` field ids (view collections, not produced yet)

Everything else — including the key order inside `options` — must match
byte for byte.
"""

import json
import re
import sqlite3
import sys

TIMESTAMP = re.compile(r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3}Z")
SECRET = re.compile(r"\b[A-Za-z0-9]{50}\b")
CLONE = re.compile(r"_clone_[A-Za-z0-9]+")

TOKEN_KEYS = (
    "authToken",
    "passwordResetToken",
    "emailChangeToken",
    "verificationToken",
    "fileToken",
)


def normalize(value):
    if value is None:
        return None
    out = str(value)
    out = TIMESTAMP.sub("<ts>", out)
    out = SECRET.sub("<secret>", out)
    out = CLONE.sub("_clone_<id>", out)
    return out


def normalize_options(raw):
    if not raw:
        return raw
    data = json.loads(raw)
    for key in TOKEN_KEYS:
        config = data.get(key)
        if isinstance(config, dict) and config.get("secret"):
            config["secret"] = "<secret>"
    for provider in data.get("oauth2", {}).get("providers", []):
        if provider.get("clientSecret"):
            provider["clientSecret"] = "<secret>"
    return json.dumps(data)


def load(path):
    conn = sqlite3.connect(path)
    rows = {}
    for row in conn.execute(
        "select id, system, type, name, fields, indexes, listRule, viewRule,"
        " createRule, updateRule, deleteRule, options, created, updated"
        " from _collections order by name"
    ):
        (id_, system, kind, name, fields, indexes, *rest) = row
        rules = rest[:5]
        options, created, updated = rest[5], rest[6], rest[7]
        rows[name] = {
            "id": id_,
            "system": system,
            "type": kind,
            "fields": fields,
            "indexes": indexes,
            "rules": rules,
            "options": options,
            "created": created,
            "updated": updated,
        }
    schema = {
        name: (kind, table, normalize(sql))
        for kind, name, table, sql in conn.execute(
            "select type, name, tbl_name, sql from sqlite_master"
            " where name not like 'sqlite_%' order by name"
        )
    }
    return rows, schema


def main(go_path, rust_path):
    go_rows, go_schema = load(go_path)
    rs_rows, rs_schema = load(rust_path)
    failures = []

    if sorted(go_rows) != sorted(rs_rows):
        failures.append(
            "collection names differ: go=%s rust=%s"
            % (sorted(go_rows), sorted(rs_rows))
        )

    for name in sorted(set(go_rows) & set(rs_rows)):
        for key, go_value in go_rows[name].items():
            rs_value = rs_rows[name][key]
            if key == "options":
                go_value, rs_value = normalize_options(go_value), normalize_options(rs_value)
            else:
                go_value, rs_value = normalize(go_value), normalize(rs_value)
            if go_value != rs_value:
                failures.append(
                    "%s.%s differs:\n  go:   %s\n  rust: %s"
                    % (name, key, go_value, rs_value)
                )

    if sorted(go_schema) != sorted(rs_schema):
        failures.append(
            "schema objects differ: go=%s rust=%s"
            % (sorted(go_schema), sorted(rs_schema))
        )
    for name in sorted(set(go_schema) & set(rs_schema)):
        if go_schema[name] != rs_schema[name]:
            failures.append(
                "schema %s differs:\n  go:   %s\n  rust: %s"
                % (name, go_schema[name], rs_schema[name])
            )

    if failures:
        for failure in failures:
            print(failure)
        return 1

    print(
        "%d collections and %d schema objects match"
        % (len(go_rows), len(go_schema))
    )
    return 0


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("usage: compare_collections.py <go-data.db> <rust-data.db>", file=sys.stderr)
        sys.exit(2)
    sys.exit(main(sys.argv[1], sys.argv[2]))
