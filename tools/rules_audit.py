#!/usr/bin/env python3
"""Differential API-rule audit: oracle PocketBase vs the Rust port.

Covers more than the basic owner checks in `harness/scenarios/m3d-rules.json`:

* list/view/create/update/delete rules evaluated for guests, owners, relation
  members and unrelated users;
* relation traversal in rules (`team.members ?= @request.auth.id`);
* `@collection` macros in rules;
* `@request.auth.<field>` access;
* date macros (`@todayStart` / `@todayEnd`);
* superuser bypass;
* invalid rule validation.

Both servers should be freshly started with the same superuser credentials.

Usage:
    tools/rules_audit.py --oracle-base http://127.0.0.1:18122 \
                         --port-base   http://127.0.0.1:18123
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timedelta, timezone

from filter_fuzz import normalize, request_json

EMAIL = "admin@example.com"
PASSWORD = "pass12345678"
USERS = "m7users"
TEAMS = "m7teams"
DOCS = "m7docs"
OPEN = "m7open"
EVENTS = "m7events"
AUTHNAME = "m7authname"


def call(base: str, method: str, path: str, token=None, body=None, query=None):
    return request_json(base, method, path, token=token, body=body, query=query)


def ensure_ok(label: str, base: str, result):
    status, _, data = result
    if status not in (200, 201, 204):
        raise SystemExit(f"setup {label} failed on {base}: {status} {data}")
    return data


def delete_collection(base: str, token: str, name: str):
    status, _, _ = call(base, "DELETE", f"/api/collections/{name}", token=token)
    if status not in (204, 404):
        raise SystemExit(f"could not delete {name} on {base}: {status}")


def setup(base: str) -> dict:
    _, _, data = call(base, "POST", "/api/collections/_superusers/auth-with-password",
                      body={"identity": EMAIL, "password": PASSWORD})
    if "token" not in data:
        raise SystemExit(f"superuser login failed on {base}: {data}")
    token = data["token"]

    for name in (DOCS, OPEN, EVENTS, AUTHNAME, TEAMS, USERS):
        delete_collection(base, token, name)

    users = ensure_ok("create users collection", base, call(
        base, "POST", "/api/collections", token=token,
        body={"name": USERS, "type": "auth",
              "fields": [{"name": "name", "type": "text"},
                         {"name": "role", "type": "text"}]}))
    teams = ensure_ok("create teams collection", base, call(
        base, "POST", "/api/collections", token=token,
        body={"name": TEAMS, "type": "base",
              "fields": [{"name": "name", "type": "text"},
                         {"name": "members", "type": "relation",
                          "collectionId": users["id"], "maxSelect": 20}]}))

    docs = ensure_ok("create docs collection", base, call(
        base, "POST", "/api/collections", token=token,
        body={
            "name": DOCS, "type": "base",
            "fields": [
                {"name": "title", "type": "text"},
                {"name": "owner", "type": "relation",
                 "collectionId": users["id"], "maxSelect": 1},
                {"name": "team", "type": "relation",
                 "collectionId": teams["id"], "maxSelect": 1},
                {"name": "published", "type": "bool"},
            ],
            "listRule": "published = true || owner = @request.auth.id || team.members ?= @request.auth.id",
            "viewRule": "published = true || owner = @request.auth.id || team.members ?= @request.auth.id",
            "createRule": "@request.auth.id != '' && owner = @request.auth.id",
            "updateRule": "owner = @request.auth.id || team.members ?= @request.auth.id",
            "deleteRule": "owner = @request.auth.id",
        }))

    ensure_ok("create open collection", base, call(
        base, "POST", "/api/collections", token=token,
        body={"name": OPEN, "type": "base",
              "fields": [{"name": "title", "type": "text"}],
              "listRule": "@collection.m7teams.members ?= @request.auth.id"}))

    ensure_ok("create events collection", base, call(
        base, "POST", "/api/collections", token=token,
        body={"name": EVENTS, "type": "base",
              "fields": [{"name": "name", "type": "text"},
                         {"name": "when", "type": "date"}],
              "listRule": "when >= @todayStart && when < @todayEnd"}))

    ensure_ok("create authname collection", base, call(
        base, "POST", "/api/collections", token=token,
        body={"name": AUTHNAME, "type": "base",
              "fields": [{"name": "title", "type": "text"}],
              "listRule": "@request.auth.name = 'Alice'"}))

    ids = {}
    for name, email in (("alice", "alice@example.com"),
                        ("bob", "bob@example.com"),
                        ("carol", "carol@example.com")):
        record = ensure_ok(f"create {name}", base, call(
            base, "POST", f"/api/collections/{USERS}/records", token=token,
            body={"email": email, "password": "pass12345678",
                  "passwordConfirm": "pass12345678", "name": name.title(),
                  "role": "member"}))
        ids[name] = record["id"]
        login = ensure_ok(f"login {name}", base, call(
            base, "POST", f"/api/collections/{USERS}/auth-with-password",
            body={"identity": email, "password": "pass12345678"}))
        ids[name + "_token"] = login["token"]

    team = ensure_ok("create team", base, call(
        base, "POST", f"/api/collections/{TEAMS}/records", token=token,
        body={"name": "core",
              "members": [ids["alice"], ids["bob"]]}))
    ids["team"] = team["id"]

    docs_rows = [
        ("alice-private", ids["alice"], team["id"], False),
        ("bob-public", ids["bob"], team["id"], True),
        ("carol-private", ids["carol"], None, False),
    ]
    for title, owner, team_id, published in docs_rows:
        body = {"title": title, "owner": owner, "published": published}
        if team_id:
            body["team"] = team_id
        record = ensure_ok(f"create doc {title}", base, call(
            base, "POST", f"/api/collections/{DOCS}/records", token=token,
            body=body))
        ids["doc_" + title] = record["id"]

    ensure_ok("create open records", base, call(
        base, "POST", f"/api/collections/{OPEN}/records", token=token,
        body={"title": "open-one"}))
    ensure_ok("create open records", base, call(
        base, "POST", f"/api/collections/{OPEN}/records", token=token,
        body={"title": "open-two"}))

    now = datetime.now(timezone.utc)
    today = now.strftime("%Y-%m-%d 12:00:00.000Z")
    tomorrow = (now + timedelta(days=1)).strftime("%Y-%m-%d 12:00:00.000Z")
    ensure_ok("create event today", base, call(
        base, "POST", f"/api/collections/{EVENTS}/records", token=token,
        body={"name": "today", "when": today}))
    ensure_ok("create event tomorrow", base, call(
        base, "POST", f"/api/collections/{EVENTS}/records", token=token,
        body={"name": "tomorrow", "when": tomorrow}))

    ensure_ok("create authname record", base, call(
        base, "POST", f"/api/collections/{AUTHNAME}/records", token=token,
        body={"title": "auth-field"}))

    ids["token"] = token
    return ids


def compare_case(name: str, base_o: str, base_p: str, o: dict, p: dict,
                 method: str, path: str, *, token: str | None = None,
                 body=None, query=None) -> bool:
    """Send the same request to both installs and compare the normalized result.

    `token` is the variable name in the per-install setup map (e.g. `alice_token`)
    so each request uses the token minted by its own server.
    """
    otoken = o.get(token) if token else None
    ptoken = p.get(token) if token else None
    so, cto, do = call(base_o, method, path, token=otoken, body=body, query=query)
    sp, ctp, dp = call(base_p, method, path, token=ptoken, body=body, query=query)
    ok = True
    if so != sp:
        ok = False
        print(f"MISMATCH status [{name}]: oracle={so} port={sp}")
    if cto != ctp:
        ok = False
        print(f"MISMATCH content-type [{name}]: {cto!r} != {ctp!r}")
    no, np = normalize(do), normalize(dp)
    if no != np:
        ok = False
        print(f"MISMATCH body [{name}]:")
        print("  oracle:", json.dumps(no, sort_keys=True)[:1600])
        print("  port:  ", json.dumps(np, sort_keys=True)[:1600])
    return ok


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--oracle-base", default="http://127.0.0.1:18122")
    ap.add_argument("--port-base", default="http://127.0.0.1:18123")
    args = ap.parse_args()

    print("seeding oracle ...")
    o = setup(args.oracle_base)
    print("seeding port ...")
    p = setup(args.port_base)

    cases = [
        # (name, method, path, token variable, body, query)
        ("guest-list-docs", "GET", f"/api/collections/{DOCS}/records", None,
         None, {"sort": "title", "perPage": "100"}),
        ("alice-list-docs", "GET", f"/api/collections/{DOCS}/records",
         "alice_token", None, {"sort": "title", "perPage": "100"}),
        ("bob-list-docs", "GET", f"/api/collections/{DOCS}/records",
         "bob_token", None, {"sort": "title", "perPage": "100"}),
        ("carol-list-docs", "GET", f"/api/collections/{DOCS}/records",
         "carol_token", None, {"sort": "title", "perPage": "100"}),
        ("superuser-list-docs", "GET", f"/api/collections/{DOCS}/records",
         "token", None, {"sort": "title", "perPage": "100"}),
        ("guest-view-private", "GET",
         f"/api/collections/{DOCS}/records/{{{{doc_carol-private}}}}", None,
         None, None),
        ("alice-view-carol-private", "GET",
         f"/api/collections/{DOCS}/records/{{{{doc_carol-private}}}}",
         "alice_token", None, None),
        ("bob-view-alice-private", "GET",
         f"/api/collections/{DOCS}/records/{{{{doc_alice-private}}}}",
         "bob_token", None, None),
        ("carol-view-alice-private", "GET",
         f"/api/collections/{DOCS}/records/{{{{doc_alice-private}}}}",
         "carol_token", None, None),
        ("superuser-view-carol-private", "GET",
         f"/api/collections/{DOCS}/records/{{{{doc_carol-private}}}}",
         "token", None, None),
        ("guest-create-doc", "POST", f"/api/collections/{DOCS}/records", None,
         {"title": "guest", "owner": "{{alice}}"}, None),
        ("alice-create-own-doc", "POST", f"/api/collections/{DOCS}/records",
         "alice_token", {"title": "alice-new", "owner": "{{alice}}"}, None),
        ("alice-create-bob-doc", "POST", f"/api/collections/{DOCS}/records",
         "alice_token", {"title": "alice-for-bob", "owner": "{{bob}}"}, None),
        ("bob-update-team-doc", "PATCH",
         f"/api/collections/{DOCS}/records/{{{{doc_alice-private}}}}",
         "bob_token", {"title": "edited-by-bob"}, None),
        ("carol-update-team-doc", "PATCH",
         f"/api/collections/{DOCS}/records/{{{{doc_alice-private}}}}",
         "carol_token", {"title": "edited-by-carol"}, None),
        ("bob-delete-team-doc", "DELETE",
         f"/api/collections/{DOCS}/records/{{{{doc_alice-private}}}}",
         "bob_token", None, None),
        ("alice-delete-own-doc", "DELETE",
         f"/api/collections/{DOCS}/records/{{{{doc_alice-private}}}}",
         "alice_token", None, None),
        ("guest-list-open", "GET", f"/api/collections/{OPEN}/records", None,
         None, {"sort": "title", "perPage": "100"}),
        ("alice-list-open", "GET", f"/api/collections/{OPEN}/records",
         "alice_token", None, {"sort": "title", "perPage": "100"}),
        ("carol-list-open", "GET", f"/api/collections/{OPEN}/records",
         "carol_token", None, {"sort": "title", "perPage": "100"}),
        ("guest-list-events", "GET", f"/api/collections/{EVENTS}/records",
         None, None, {"sort": "name", "perPage": "100"}),
        ("superuser-list-events", "GET", f"/api/collections/{EVENTS}/records",
         "token", None, {"sort": "name", "perPage": "100"}),
        ("guest-list-authname", "GET",
         f"/api/collections/{AUTHNAME}/records", None, None,
         {"sort": "title", "perPage": "100"}),
        ("alice-list-authname", "GET",
         f"/api/collections/{AUTHNAME}/records", "alice_token", None,
         {"sort": "title", "perPage": "100"}),
        ("bob-list-authname", "GET", f"/api/collections/{AUTHNAME}/records",
         "bob_token", None, {"sort": "title", "perPage": "100"}),
        ("invalid-rule", "PATCH", f"/api/collections/{DOCS}", "token",
         {"listRule": "owner = "}, None),
    ]

    failures = 0
    for name, method, path, token_var, body, query in cases:
        # Expand `{{var}}` using each install's own ids, then run both sides.
        obody = json.loads(json.dumps(body).replace("{{alice}}", o["alice"])
                           .replace("{{bob}}", o["bob"])) if body else None
        pbody = json.loads(json.dumps(body).replace("{{alice}}", p["alice"])
                           .replace("{{bob}}", p["bob"])) if body else None
        opath = path.replace("{{doc_alice-private}}", o["doc_alice-private"]) \
                    .replace("{{doc_carol-private}}", o["doc_carol-private"])
        ppath = path.replace("{{doc_alice-private}}", p["doc_alice-private"]) \
                    .replace("{{doc_carol-private}}", p["doc_carol-private"])
        # The compare helper accepts one path, so inline the per-install path
        # substitution here instead of adding a special case.
        otoken = o.get(token_var) if token_var else None
        ptoken = p.get(token_var) if token_var else None
        so, cto, do = call(args.oracle_base, method, opath, token=otoken,
                           body=obody, query=query)
        sp, ctp, dp = call(args.port_base, method, ppath, token=ptoken,
                           body=pbody, query=query)
        ok = True
        if so != sp:
            ok = False
            print(f"MISMATCH status [{name}]: oracle={so} port={sp}")
        if cto != ctp:
            ok = False
            print(f"MISMATCH content-type [{name}]: {cto!r} != {ctp!r}")
        no, np = normalize(do), normalize(dp)
        if no != np:
            ok = False
            print(f"MISMATCH body [{name}]:")
            print("  oracle:", json.dumps(no, sort_keys=True)[:1600])
            print("  port:  ", json.dumps(np, sort_keys=True)[:1600])
        if not ok:
            failures += 1

    if failures:
        print(f"FAIL: {failures}/{len(cases)} rule cases differ")
        return 1
    print(f"PASS: {len(cases)} rule cases match")
    return 0


if __name__ == "__main__":
    sys.exit(main())
