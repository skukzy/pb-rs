#!/usr/bin/env python3
"""Manual auth-flows parity probe (MFA/OTP/reset/verification/email-change/oauth2)."""
import json, re, sys, time, urllib.request, urllib.error

BASE = sys.argv[1]
SU_EMAIL = "admin@example.com"
SU_PASS = "pass12345678"

def req(method, path, body=None, token=None):
    data = json.dumps(body).encode() if body is not None else None
    r = urllib.request.Request(BASE + path, data=data, method=method)
    r.add_header("Content-Type", "application/json")
    if token:
        r.add_header("Authorization", token)
    try:
        with urllib.request.urlopen(r, timeout=15) as resp:
            raw = resp.read()
            return resp.status, (json.loads(raw) if raw else None)
    except urllib.error.HTTPError as e:
        raw = e.read()
        try:
            return e.code, (json.loads(raw) if raw else None)
        except Exception:
            return e.code, raw.decode(errors="replace")

for _ in range(60):
    try:
        urllib.request.urlopen(BASE + "/api/health", timeout=1)
        break
    except Exception:
        time.sleep(0.25)

s, auth = req("POST", "/api/collections/_superusers/auth-with-password",
              {"identity": SU_EMAIL, "password": SU_PASS})
assert s == 200, (s, auth)
su = auth["token"]

name = "authprobe"
s, coll = req("POST", "/api/collections", {
    "name": name, "type": "auth", "listRule": "", "viewRule": "",
    "createRule": "", "updateRule": "", "deleteRule": "",
    "fields": [{"name": "name", "type": "text"}],
    "passwordAuth": {"enabled": True},
    "otp": {"enabled": True, "duration": 180, "length": 8},
    "mfa": {"enabled": True, "duration": 1800, "rule": ""},
}, su)
out = {}
out["collection"] = s
if s != 200:
    out["collection_body"] = coll
    print(json.dumps(out, indent=2))
    sys.exit(0)

email = "mfa@example.com"
s, user = req("POST", f"/api/collections/{name}/records", {
    "email": email, "password": "pass12345678", "passwordConfirm": "pass12345678",
    "name": "MFA User", "verified": True,
}, su)
out["create_user"] = s

s, first = req("POST", f"/api/collections/{name}/auth-with-password",
               {"identity": email, "password": "pass12345678"})
out["login_mfa_first"] = [s, first]
mfa_id = (first or {}).get("mfaId", "")

out["login_mfa_same_method"] = req("POST", f"/api/collections/{name}/auth-with-password",
                                   {"identity": email, "password": "pass12345678", "mfaId": mfa_id})
out["login_mfa_bogus"] = req("POST", f"/api/collections/{name}/auth-with-password",
                             {"identity": email, "password": "pass12345678", "mfaId": "nope"})
out["login_mfa_query"] = req("POST", f"/api/collections/{name}/auth-with-password?mfaId={mfa_id}",
                             {"identity": email, "password": "pass12345678"})

# disable MFA, log in normally
req("PATCH", f"/api/collections/{name}", {"mfa": {"enabled": False, "duration": 0, "rule": ""}}, su)
s, login = req("POST", f"/api/collections/{name}/auth-with-password",
               {"identity": email, "password": "pass12345678"})
out["login_no_mfa"] = s
token = (login or {}).get("token", "")

out["refresh"] = req("POST", f"/api/collections/{name}/auth-refresh", None, token)
out["refresh_bad"] = req("POST", f"/api/collections/{name}/auth-refresh", None, "bad")

out["otp_request"] = req("POST", f"/api/collections/{name}/request-otp", {"email": email})
out["otp_request_unknown"] = req("POST", f"/api/collections/{name}/request-otp", {"email": "ghost@example.com"})
out["otp_auth_bogus"] = req("POST", f"/api/collections/{name}/auth-with-otp",
                            {"otpId": "nope", "password": "12345678"})

out["reset_request"] = req("POST", f"/api/collections/{name}/request-password-reset", {"email": email})
out["reset_request_unknown"] = req("POST", f"/api/collections/{name}/request-password-reset", {"email": "ghost@example.com"})
out["reset_confirm_bogus"] = req("POST", f"/api/collections/{name}/confirm-password-reset",
                                 {"token": "nope", "password": "newpass12345", "passwordConfirm": "newpass12345"})

out["verify_request"] = req("POST", f"/api/collections/{name}/request-verification", None, token)
out["verify_request_unauth"] = req("POST", f"/api/collections/{name}/request-verification", None)
out["verify_confirm_bogus"] = req("POST", f"/api/collections/{name}/confirm-verification", {"token": "nope"})

out["email_change_request"] = req("POST", f"/api/collections/{name}/request-email-change",
                                  {"newEmail": "changed@example.com"}, token)
out["email_change_unauth"] = req("POST", f"/api/collections/{name}/request-email-change",
                                 {"newEmail": "changed@example.com"})
out["email_change_confirm_bogus"] = req("POST", f"/api/collections/{name}/confirm-email-change",
                                        {"token": "nope", "password": "pass12345678"})

out["oauth2_bad_provider"] = req("POST", f"/api/collections/{name}/auth-with-oauth2",
                                 {"provider": "nope", "code": "x", "codeVerifier": "y",
                                  "redirectUrl": "http://localhost/cb"})

# methods
out["methods"] = req("GET", f"/api/collections/{name}/auth-methods")

text = json.dumps(out, indent=2, sort_keys=True)
text = re.sub(r"\b[a-z0-9]{15}\b", "<id>", text)
text = re.sub(r"\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(\.\d+)?Z", "<ts>", text)
text = re.sub(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+", "<jwt>", text)
print(text)
