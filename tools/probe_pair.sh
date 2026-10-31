#!/usr/bin/env bash
# Run a manual parity probe against fresh oracle/port installs.
#
# Usage: tools/probe_pair.sh <probe.py> <tag> [go_port] [rs_port]
#
# Both servers get isolated pb_data parents (the oracle writes its
# auto-migrations next to the data dir's parent, so a shared parent would leak
# state between runs). The probe output is normalized and diffed.
set -uo pipefail

cd "$(dirname "$0")/.."
ROOT="$PWD"
ORACLE="${ORACLE:-$HOME/lab/pb/pocketbase}"
PORT_BIN="$ROOT/target/debug/pocketbase"
PROBE="$1"
TAG="$2"
GO_PORT="${3:-18161}"
RS_PORT="${4:-18162}"

BASE="/tmp/${TAG}_$(date +%s)"
GO_DIR="$BASE/go"
RS_DIR="$BASE/rs"
mkdir -p "$GO_DIR" "$RS_DIR"

cleanup() {
    pkill -f "serve --http=127.0.0.1:${GO_PORT}" 2>/dev/null
    pkill -f "serve --http=127.0.0.1:${RS_PORT}" 2>/dev/null
}
trap cleanup EXIT

cleanup
sleep 0.3

"$ORACLE" superuser upsert admin@example.com pass12345678 --dir="$GO_DIR" >/dev/null 2>&1
"$PORT_BIN" superuser upsert admin@example.com pass12345678 --dir="$RS_DIR" >/dev/null 2>&1

(nohup "$ORACLE" serve --http="127.0.0.1:${GO_PORT}" --dir="$GO_DIR" >"$BASE/go.log" 2>&1 &)
(nohup "$PORT_BIN" serve --http="127.0.0.1:${RS_PORT}" --dir="$RS_DIR" >"$BASE/rs.log" 2>&1 &)

for _ in $(seq 1 80); do
    curl -sf -m 1 "http://127.0.0.1:${GO_PORT}/api/health" >/dev/null \
        && curl -sf -m 1 "http://127.0.0.1:${RS_PORT}/api/health" >/dev/null \
        && break
    sleep 0.25
done

python3 "$PROBE" "http://127.0.0.1:${GO_PORT}" >"$BASE/go.json" 2>"$BASE/go.err"
python3 "$PROBE" "http://127.0.0.1:${RS_PORT}" >"$BASE/rs.json" 2>"$BASE/rs.err"

python3 - "$BASE" <<'PY'
import re, sys
base = sys.argv[1]

def norm(path):
    text = open(path).read()
    text = re.sub(r'"(execTime|duration|size|len)":\s*-?\d+(?:\.\d+)?', r'"\1":0', text)
    text = re.sub(r"\b[a-z0-9]{15}\b", "<id>", text)
    text = re.sub(r"[a-z0-9]{10}_[a-z0-9]{10}", "<rand>", text)
    text = re.sub(r"\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(\.\d+)?Z", "<ts>", text)
    text = re.sub(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+", "<jwt>", text)
    text = re.sub(r"/tmp/[A-Za-z0-9_./-]+", "<path>", text)
    text = re.sub(r'"created":\s*"[^"]*"', '"created":"<ts>"', text)
    text = re.sub(r'"updated":\s*"[^"]*"', '"updated":"<ts>"', text)
    text = re.sub(r'"tokenKey":\s*"[^"]*"', '"tokenKey":"<key>"', text)
    text = re.sub(r"\b[A-Za-z0-9]{40}\b", "<clientid>", text)
    text = re.sub(r'"secret":\s*"[^"]*"', '"secret":"<secret>"', text)
    text = re.sub(r"pb_backup_[a-z0-9_]+_\d+\.zip", "pb_backup_<name>.zip", text)
    text = re.sub(r"upload-[a-z0-9]+\.zip", "upload-<rand>.zip", text)
    text = re.sub(r"pbc_\d+", "pbc_<id>", text)
    text = re.sub(r'"mtime":\s*"[^"]*"', '"mtime":"<ts>"', text)
    text = re.sub(r'"modified":\s*"[^"]*"', '"modified":"<ts>"', text)
    return text

go = norm(f"{base}/go.json")
rs = norm(f"{base}/rs.json")
if go == rs:
    print("PROBE MATCH")
else:
    import difflib
    print("PROBE DIFF")
    for line in list(difflib.unified_diff(go.splitlines(), rs.splitlines(), "go", "rs", lineterm=""))[:120]:
        print(line)
PY

echo "BASE=$BASE"
