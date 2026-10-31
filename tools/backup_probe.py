#!/usr/bin/env python3
"""Manual backups parity probe."""
import json, sys, time, urllib.request, urllib.error, uuid

BASE = sys.argv[1]

def req(method, path, body=None, token=None, raw=None, content_type="application/json"):
    data = raw if raw is not None else (json.dumps(body).encode() if body is not None else None)
    r = urllib.request.Request(BASE + path, data=data, method=method)
    r.add_header("Content-Type", content_type)
    if token:
        r.add_header("Authorization", token)
    try:
        with urllib.request.urlopen(r, timeout=30) as resp:
            payload = resp.read()
            ctype = resp.headers.get("Content-Type", "")
            if "json" in ctype and payload:
                return resp.status, json.loads(payload)
            return resp.status, {"len": len(payload), "ctype": ctype}
    except urllib.error.HTTPError as e:
        payload = e.read()
        try:
            return e.code, json.loads(payload) if payload else None
        except Exception:
            return e.code, payload.decode(errors="replace")

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

out = {}
out["list_empty"] = req("GET", "/api/backups", token=token)
out["create"] = req("POST", "/api/backups", {"name": "probe-backup.zip"}, token)
out["create_dup"] = req("POST", "/api/backups", {"name": "probe-backup.zip"}, token)
out["create_bad"] = req("POST", "/api/backups", {"name": "Bad Name.zip"}, token)
out["create_long"] = req("POST", "/api/backups", {"name": "a" * 151 + ".zip"}, token)
out["list_one"] = req("GET", "/api/backups", token=token)

s, ft = req("POST", "/api/files/token", token=token)
out["file_token"] = s
out["download"] = req("GET", "/api/backups/probe-backup.zip?token=" + (ft or {}).get("token", ""))
out["download_bad"] = req("GET", "/api/backups/probe-backup.zip?token=nope")
out["delete"] = req("DELETE", "/api/backups/probe-backup.zip", token=token)
out["delete_again"] = req("DELETE", "/api/backups/probe-backup.zip", token=token)
out["list_after"] = req("GET", "/api/backups", token=token)

# unauthorized
out["list_unauth"] = req("GET", "/api/backups")
# upload a zip
boundary = "----probe" + uuid.uuid4().hex
zip_bytes = b"PK\x03\x04" + b"\x00" * 32
body = (f"--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"up.zip\"\r\n"
        "Content-Type: application/zip\r\n\r\n").encode() + zip_bytes + f"\r\n--{boundary}--\r\n".encode()
out["upload"] = req("POST", "/api/backups/upload", raw=body, token=token,
                    content_type=f"multipart/form-data; boundary={boundary}")
out["list_upload"] = req("GET", "/api/backups", token=token)
out["cleanup"] = req("DELETE", "/api/backups/up.zip", token=token)

print(json.dumps(out, indent=2, sort_keys=True))
