#!/usr/bin/env bash
# M3 gate: records CRUD, filters, expand, fields and collection rules.
#
# Phases:
#   1. Response parity — the same scenarios replayed against the oracle and the
#      port must produce identical responses (0 mismatches), and the rows of
#      every user table must match after id/timestamp normalization.
#   2. Drop-in — the port must open the oracle-created pb_data and serve the
#      same read-only responses (login, list/filter/sort/expand/fields, rules).
#
# Usage: tools/gate_m3.sh
set -uo pipefail

cd "$(dirname "$0")/.."
ROOT="$PWD"
ORACLE="${ORACLE:-$HOME/lab/pb/pocketbase}"
PORT_BIN="$ROOT/target/debug/pocketbase"
GO_DIR="$ROOT/.oracle/gate_m3/go/pb_data"
RS_DIR="$ROOT/.oracle/gate_m3/rust/pb_data"
GO_PORT="${GO_PORT:-18122}"
RS_PORT="${RS_PORT:-18123}"
EMAIL="admin@example.com"
PASSWORD="pass12345678"
SCENARIOS="harness/scenarios/m3-records-basic.json harness/scenarios/m3b-filter-basic.json harness/scenarios/m3c-expand-fields.json harness/scenarios/m3d-rules.json harness/scenarios/m3e-readonly.json harness/scenarios/m3f-collection-macro.json harness/scenarios/m3g-fields.json harness/scenarios/m3h-auth-visibility.json harness/scenarios/m3i-views.json harness/scenarios/m3j-filter-errors.json harness/scenarios/m4-auth.json harness/scenarios/m5-logs.json harness/scenarios/m5-rate-limits.json harness/scenarios/m5-batch.json harness/scenarios/m5-crons.json harness/scenarios/m5-backups.json harness/scenarios/m5-cron-scheduler.json harness/scenarios/m5-restore.json harness/scenarios/m5-error-details.json harness/scenarios/m5-record-delete.json harness/scenarios/m4b-impersonate.json harness/scenarios/m5-sql.json harness/scenarios/m5-settings-tools.json harness/scenarios/m5-oauth2-redirect.json harness/scenarios/m5b-restore-renamed-users.json"

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

check() { # check <label> <actual> <expected>
    if [ "$2" = "$3" ]; then
        printf '  \033[32mPASS\033[0m %s\n' "$1"
    else
        printf '  \033[31mFAIL\033[0m %s (%s != %s)\n' "$1" "$2" "$3"
        status=1
    fi
}

printf '\n\033[1mM3 gate: records, filters, expand, fields, rules\033[0m\n'
printf '  building... '
if ! cargo build -q 2>&1; then
    printf '\033[31mFAILED\033[0m\n'
    exit 1
fi
printf 'ok\n'

# ---------------------------------------------------------------- phase 1
printf '\n\033[1m1. response parity\033[0m\n'

rm -rf "$ROOT/.oracle/gate_m3" .oracle/golden-m3-go .oracle/golden-m3-rust

printf '  seeding a superuser in both installs... '
"$ORACLE" superuser upsert "$EMAIL" "$PASSWORD" --dir="$GO_DIR" >/dev/null 2>&1
"$PORT_BIN" superuser upsert "$EMAIL" "$PASSWORD" --dir="$RS_DIR" >/dev/null 2>&1
printf 'ok\n'

start "$ORACLE" "$GO_PORT" "$GO_DIR" "$ROOT/.oracle/gate_m3_go.log"
wait_health "$GO_PORT" || { echo "oracle did not start"; exit 1; }
for scenario in $SCENARIOS; do
    "$ROOT/target/debug/harness" record --base "http://127.0.0.1:$GO_PORT" \
        --scenario "$scenario" --out .oracle/golden-m3-go >/dev/null
done
stop "$GO_PORT"

start "$PORT_BIN" "$RS_PORT" "$RS_DIR" "$ROOT/.oracle/gate_m3_rust.log"
wait_health "$RS_PORT" || { echo "port did not start"; exit 1; }
for scenario in $SCENARIOS; do
    "$ROOT/target/debug/harness" record --base "http://127.0.0.1:$RS_PORT" \
        --scenario "$scenario" --out .oracle/golden-m3-rust >/dev/null
done
stop "$RS_PORT"

if "$ROOT/target/debug/harness" diff --a .oracle/golden-m3-go --b .oracle/golden-m3-rust; then
    check "scenario responses identical" ok ok
else
    check "scenario responses identical" differs identical
fi

if tools/compare_collections.py "$GO_DIR/data.db" "$RS_DIR/data.db"; then
    check "_collections rows and schema identical" ok ok
else
    check "_collections rows and schema identical" differs identical
fi

if tools/compare_records.py "$GO_DIR/data.db" "$RS_DIR/data.db"; then
    check "user table rows identical" ok ok
else
    check "user table rows identical" differs identical
fi

# ---------------------------------------------------------------- phase 2
printf '\n\033[1m2. drop-in: port opens the oracle-created pb_data\033[0m\n'

rm -rf .oracle/golden-m3-dropin-go .oracle/golden-m3-dropin-rust

start "$ORACLE" "$GO_PORT" "$GO_DIR" "$ROOT/.oracle/gate_m3_dropin_go.log"
wait_health "$GO_PORT" || { echo "oracle did not start"; exit 1; }
"$ROOT/target/debug/harness" record --base "http://127.0.0.1:$GO_PORT" \
    --scenario harness/scenarios/m3e-readonly.json --out .oracle/golden-m3-dropin-go >/dev/null
stop "$GO_PORT"

start "$PORT_BIN" "$RS_PORT" "$GO_DIR" "$ROOT/.oracle/gate_m3_dropin_rust.log"
wait_health "$RS_PORT" || { echo "port did not start on the oracle db"; exit 1; }
"$ROOT/target/debug/harness" record --base "http://127.0.0.1:$RS_PORT" \
    --scenario harness/scenarios/m3e-readonly.json --out .oracle/golden-m3-dropin-rust >/dev/null
stop "$RS_PORT"

if "$ROOT/target/debug/harness" diff --a .oracle/golden-m3-dropin-go --b .oracle/golden-m3-dropin-rust; then
    check "port serves the oracle-created pb_data identically" ok ok
else
    check "port serves the oracle-created pb_data identically" differs identical
fi

printf '\n'
if [ "$status" -eq 0 ]; then
    printf '\033[32mM3 GATE PASSED\033[0m\n\n'
else
    printf '\033[31mM3 GATE FAILED\033[0m\n\n'
fi
exit "$status"
