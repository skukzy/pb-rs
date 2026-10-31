#!/usr/bin/env python3
import json, threading, time, urllib.request, urllib.error, sys

BASE = "http://127.0.0.1:18141"

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
        return e.code, json.loads(raw) if raw else None

for _ in range(40):
    try:
        urllib.request.urlopen(BASE + "/api/health", timeout=1)
        break
    except Exception:
        time.sleep(0.25)
else:
    print("server not up"); sys.exit(1)

status, auth = req("POST", "/api/collections/_superusers/auth-with-password",
                   {"identity": "admin@example.com", "password": "pass12345678"})
print("auth", status)
assert status == 200, auth
token = auth["token"]

name = "rt_probe_%d" % int(time.time())
status, coll = req("POST", "/api/collections", {
    "name": name,
    "type": "base",
    "listRule": "",
    "viewRule": "",
    "createRule": "",
    "updateRule": "",
    "deleteRule": "",
    "fields": [{"name": "title", "type": "text"}],
}, token)
print("create collection", status)
assert status == 200, coll
cid = coll["id"]

events = []
ready = threading.Event()
client_id = {}

def sse():
    r = urllib.request.Request(BASE + "/api/realtime")
    r.add_header("Accept", "text/event-stream")
    with urllib.request.urlopen(r, timeout=20) as resp:
        ev = None
        for raw in resp:
            line = raw.decode().rstrip("\n")
            if line.startswith("event:"):
                ev = line[6:].strip()
            elif line.startswith("data:"):
                data = line[5:].strip()
                events.append((ev, data))
                if ev == "PB_CONNECT":
                    client_id["id"] = json.loads(data)["clientId"]
                    ready.set()

t = threading.Thread(target=sse, daemon=True)
t.start()
ready.wait(5)
print("clientId", client_id.get("id"))

status, _ = req("POST", "/api/realtime", {
    "clientId": client_id["id"],
    "subscriptions": [name + "/*"],
}, token)
print("subscribe", status)

status, rec = req("POST", "/api/collections/%s/records" % name, {"title": "hello"}, token)
print("create record", status, rec and rec.get("id"))
time.sleep(1.0)
status, _ = req("PATCH", "/api/collections/%s/records/%s" % (name, rec["id"]), {"title": "world"}, token)
print("update record", status)
time.sleep(1.0)
status, _ = req("DELETE", "/api/collections/%s/records/%s" % (name, rec["id"]), token=token)
print("delete record", status)
time.sleep(1.0)

print("events:", json.dumps(events, indent=2)[:2000])
