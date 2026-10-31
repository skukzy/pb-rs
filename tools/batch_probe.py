#!/usr/bin/env python3
"""Manual batch parity probe: run against the oracle and the port."""
import json, sys, time, urllib.request, urllib.error

BASE = sys.argv[1]

def req(method, path, body=None, token=None):
    data = json.dumps(body).encode() if body is not None else None
    r = urllib.request.Request(BASE + path, data=data, method=method)
    r.add_header("Content-Type", "application/json")
    if token:
        r.add_header("Authorization", token)
    try:
        with urllib.request.urlopen(r, timeout=10) as resp:
            raw = resp.read()
            return resp.status, json.loads(raw) if raw else None
    except urllib.error.HTTPError as e:
        raw = e.read()
        try:
            return e.code, json.loads(raw) if raw else None
        except Exception:
            return e.code, raw.decode(errors="replace")

for _ in range(60):
    try:
        urllib.request.urlopen(BASE + "/api/health", timeout=1)
        break
    except Exception:
        time.sleep(0.25)

s, auth = req("POST", "/api/collections/_superusers/auth-with-password",
              {"identity": "admin@example.com", "password": "pass12345678"})
assert s == 200, (s, auth)
token = auth["token"]

s, _ = req("PATCH", "/api/settings", {"batch": {"enabled": True, "maxRequests": 50, "timeout": 3}}, token)
print("settings", s)

name = "batchprobe"
s, coll = req("POST", "/api/collections", {
    "name": name, "type": "base", "listRule": "", "viewRule": "",
    "createRule": "", "updateRule": "", "deleteRule": "",
    "fields": [{"name": "title", "type": "text", "required": True}],
}, token)
print("collection", s)

out = {}
# success batch: create, create, update via PUT
s, body = req("POST", "/api/batch", {"requests": [
    {"method": "POST", "url": f"/api/collections/{name}/records", "body": {"title": "batch1"}},
    {"method": "POST", "url": f"/api/collections/{name}/records", "body": {"title": "batch2"}},
    {"method": "PUT", "url": f"/api/collections/{name}/records", "body": {"title": "batch3"}},
]}, token)
out["success"] = [s, body]
ids = [r["body"]["id"] for r in body] if s == 200 else []

# failure batch: two creates then invalid, must roll back
s, body = req("POST", "/api/batch", {"requests": [
    {"method": "POST", "url": f"/api/collections/{name}/records", "body": {"title": "rollback1"}},
    {"method": "POST", "url": f"/api/collections/{name}/records", "body": {"title": "rollback2"}},
    {"method": "POST", "url": f"/api/collections/{name}/records", "body": {"title": ""}},
]}, token)
out["failure"] = [s, body]

s, body = req("GET", f"/api/collections/{name}/records?filter=title~'rollback'", token=token)
out["rollback_count"] = [s, body and body.get("totalItems")]

# unknown action
s, body = req("POST", "/api/batch", {"requests": [
    {"method": "GET", "url": "/api/health"},
]}, token)
out["unknown"] = [s, body]

# per-request validation
s, body = req("POST", "/api/batch", {"requests": [
    {},
    {"method": "GET", "url": "/valid"},
    {"method": "invalid", "url": "/valid"},
    {"method": "POST", "url": "a" * 2001},
]}, token)
out["validation"] = [s, body]

# too many
s, body = req("POST", "/api/batch", {"requests": [
    {"method": "POST", "url": f"/api/collections/{name}/records", "body": {"title": f"x{i}"}} for i in range(51)
]}, token)
out["too_many"] = [s, body]

# delete batch
s, body = req("POST", "/api/batch", {"requests": [
    {"method": "DELETE", "url": f"/api/collections/{name}/records/{ids[0]}"},
]}, token)
out["delete"] = [s, body]

print(json.dumps(out, indent=2, sort_keys=True))
