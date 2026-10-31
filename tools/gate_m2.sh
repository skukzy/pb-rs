#!/usr/bin/env bash
# M2 gate: superuser auth + settings/collections read/write parity.
#
# Phases:
#   1. Response parity   — the same scenarios replayed against the oracle and the
#      port must produce identical responses (harness diff, 0 mismatches), the
#      settings written by `PATCH /api/settings` must be byte-identical, and the
#      `_collections` rows + generated schema must match.
#   2. Cross-implementation auth — a token minted by the oracle must be accepted
#      by the port and vice versa, on the same database.
#   3. Admin UI login    — the real embedded admin UI, driven in headless Chrome,
#      must log in and store the session. Set UI_CHECK=0 to skip this phase.
#
# Usage: tools/gate_m2.sh
set -uo pipefail

cd "$(dirname "$0")/.."
ROOT="$PWD"
ORACLE="${ORACLE:-$HOME/lab/pb/pocketbase}"
PORT_BIN="$ROOT/target/debug/pocketbase"
# Each install lives under its own parent directory: PocketBase resolves the
# default JS migrations dir as `<dataDir>/../pb_migrations`, so a shared parent
# would let one install's auto-generated migrations leak into another.
GO_DIR="$ROOT/.oracle/gate_m2/go/pb_data"
RS_DIR="$ROOT/.oracle/gate_m2/rust/pb_data"
SHARED_ROOT="$ROOT/.oracle/gate_m2/shared"
SHARED="$SHARED_ROOT/pb_data"
GO_PORT="${GO_PORT:-18120}"
RS_PORT="${RS_PORT:-18121}"
EMAIL="admin@example.com"
PASSWORD="pass12345678"
SCENARIOS="harness/scenarios/m2-auth.json harness/scenarios/m2b-settings.json harness/scenarios/m2c-collections-write.json harness/scenarios/m2d-collection-update.json harness/scenarios/m2e-import.json"

status=0

wait_health() {
    for _ in $(seq 1 80); do
        if curl -sf -m 1 "http://127.0.0.1:$1/api/health" >/dev/null 2>&1; then
            return 0
        fi
        sleep 0.25
    done
    return 1
}

stop() {
    pkill -TERM -f "serve --http=127.0.0.1:$1" >/dev/null 2>&1
    sleep 0.6
}

start() { # start <binary> <port> <dir> <log>
    nohup "$1" serve --http="127.0.0.1:$2" --dir="$3" >"$4" 2>&1 &
    disown
}

login() { # login <port> -> prints the token
    curl -s -m 5 -X POST \
        -H 'content-type: application/json' \
        -d "{\"identity\":\"$EMAIL\",\"password\":\"$PASSWORD\"}" \
        "http://127.0.0.1:$1/api/collections/_superusers/auth-with-password" |
        python3 -c 'import json,sys; print(json.load(sys.stdin).get("token",""))'
}

probe() { # probe <port> <token> -> prints the HTTP status of /api/settings
    curl -s -m 5 -o /dev/null -w '%{http_code}' \
        -H "authorization: $2" "http://127.0.0.1:$1/api/settings"
}

check() { # check <label> <actual> <expected>
    if [ "$2" = "$3" ]; then
        printf '  \033[32mPASS\033[0m %s\n' "$1"
    else
        printf '  \033[31mFAIL\033[0m %s (%s != %s)\n' "$1" "$2" "$3"
        status=1
    fi
}

printf '\n\033[1mM2 gate: auth and read endpoints\033[0m\n'
printf '  building... '
if ! cargo build -q 2>&1; then
    printf '\033[31mFAILED\033[0m\n'
    exit 1
fi
printf 'ok\n'

# ---------------------------------------------------------------- phase 1
printf '\n\033[1m1. response parity\033[0m\n'

rm -rf "$ROOT/.oracle/gate_m2" .oracle/golden-m2-go .oracle/golden-m2-rust

printf '  seeding a superuser in both installs... '
"$ORACLE" superuser upsert "$EMAIL" "$PASSWORD" --dir="$GO_DIR" >/dev/null 2>&1
"$PORT_BIN" superuser upsert "$EMAIL" "$PASSWORD" --dir="$RS_DIR" >/dev/null 2>&1
printf 'ok\n'

start "$ORACLE" "$GO_PORT" "$GO_DIR" "$ROOT/.oracle/gate_m2_go.log"
wait_health "$GO_PORT" || { echo "oracle did not start"; exit 1; }
for scenario in $SCENARIOS; do
    "$ROOT/target/debug/harness" record --base "http://127.0.0.1:$GO_PORT" \
        --scenario "$scenario" --out .oracle/golden-m2-go >/dev/null
done
stop "$GO_PORT"

start "$PORT_BIN" "$RS_PORT" "$RS_DIR" "$ROOT/.oracle/gate_m2_rust.log"
wait_health "$RS_PORT" || { echo "port did not start"; exit 1; }
for scenario in $SCENARIOS; do
    "$ROOT/target/debug/harness" record --base "http://127.0.0.1:$RS_PORT" \
        --scenario "$scenario" --out .oracle/golden-m2-rust >/dev/null
done
stop "$RS_PORT"

if "$ROOT/target/debug/harness" diff --a .oracle/golden-m2-go --b .oracle/golden-m2-rust; then
    check "scenario responses identical" ok ok
else
    check "scenario responses identical" differs identical
fi

# The `m2b-settings` scenario leaves both installs with the same settings; the
# stored row must match byte for byte (the harness only compares HTTP).
SETTINGS_GO="$(sqlite3 "$GO_DIR/data.db" "SELECT hex(value) FROM _params WHERE id='settings'")"
SETTINGS_RS="$(sqlite3 "$RS_DIR/data.db" "SELECT hex(value) FROM _params WHERE id='settings'")"
if [ -n "$SETTINGS_GO" ] && [ "$SETTINGS_GO" = "$SETTINGS_RS" ]; then
    check "_params.settings written by PATCH is byte-identical" ok ok
else
    check "_params.settings written by PATCH is byte-identical" differs identical
fi

# The `m2c-collections-write` scenario creates/deletes/truncates collections, so
# both `_collections` rows and the generated `sqlite_master` schema must match.
if tools/compare_collections.py "$GO_DIR/data.db" "$RS_DIR/data.db"; then
    check "_collections rows and schema identical" ok ok
else
    check "_collections rows and schema identical" differs identical
fi

# ---------------------------------------------------------------- phase 2
printf '\n\033[1m2. cross-implementation token acceptance\033[0m\n'

rm -rf "$SHARED_ROOT"
mkdir -p "$SHARED_ROOT"
cp -R "$GO_DIR" "$SHARED"

start "$ORACLE" "$GO_PORT" "$SHARED" "$ROOT/.oracle/gate_m2_x1.log"
wait_health "$GO_PORT" || { echo "oracle did not start"; exit 1; }
ORACLE_TOKEN="$(login "$GO_PORT")"
stop "$GO_PORT"
if [ -n "$ORACLE_TOKEN" ]; then
    check "oracle minted a token" yes yes
else
    check "oracle minted a token" no yes
fi

start "$PORT_BIN" "$RS_PORT" "$SHARED" "$ROOT/.oracle/gate_m2_x2.log"
wait_health "$RS_PORT" || { echo "port did not start"; exit 1; }
check "port accepts an oracle-minted token" "$(probe "$RS_PORT" "$ORACLE_TOKEN")" 200
PORT_TOKEN="$(login "$RS_PORT")"
stop "$RS_PORT"
if [ -n "$PORT_TOKEN" ]; then
    check "port minted a token" yes yes
else
    check "port minted a token" no yes
fi

start "$ORACLE" "$GO_PORT" "$SHARED" "$ROOT/.oracle/gate_m2_x3.log"
wait_health "$GO_PORT" || { echo "oracle did not start"; exit 1; }
check "oracle accepts a port-minted token" "$(probe "$GO_PORT" "$PORT_TOKEN")" 200
stop "$GO_PORT"

# ---------------------------------------------------------------- phase 3
printf '\n\033[1m3. admin UI login (headless Chrome)\033[0m\n'

if [ "${UI_CHECK:-1}" = "0" ]; then
    printf '  skipped (UI_CHECK=0)\n'
else
    CHROME="${CHROME:-/Applications/Google Chrome.app/Contents/MacOS/Google Chrome}"
    CDP_PORT="${CDP_PORT:-9333}"

    if [ ! -x "$CHROME" ]; then
        check "headless Chrome available" missing present
    else
        PROFILE="$(mktemp -d "${TMPDIR:-/tmp}/pb-ui-XXXXXX")"
        pkill -f "remote-debugging-port=$CDP_PORT" >/dev/null 2>&1
        sleep 0.5

        "$CHROME" --headless=new --disable-gpu --no-first-run \
            --no-default-browser-check --remote-debugging-port="$CDP_PORT" \
            --user-data-dir="$PROFILE" about:blank \
            >"$ROOT/.oracle/gate_m2_chrome.log" 2>&1 &
        CHROME_PID=$!

        start "$PORT_BIN" "$RS_PORT" "$RS_DIR" "$ROOT/.oracle/gate_m2_ui.log"
        if wait_health "$RS_PORT"; then
            if CDP_HTTP="http://127.0.0.1:$CDP_PORT" \
                node "$ROOT/tools/ui_login_check.mjs" \
                "http://127.0.0.1:$RS_PORT" "$EMAIL" "$PASSWORD"; then
                check "the real admin UI logs in" ok ok
            else
                check "the real admin UI logs in" failed ok
            fi
        else
            check "port started for the UI check" no yes
        fi

        stop "$RS_PORT"
        kill "$CHROME_PID" >/dev/null 2>&1
        wait "$CHROME_PID" 2>/dev/null
        rm -rf "$PROFILE"
    fi
fi

printf '\n'
if [ "$status" -eq 0 ]; then
    printf '\033[32mM2 GATE PASSED\033[0m\n\n'
else
    printf '\033[31mM2 GATE FAILED\033[0m\n\n'
fi
exit "$status"
