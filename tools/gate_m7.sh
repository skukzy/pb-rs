#!/usr/bin/env bash
# M7 gate: hardening — differential filter/sort fuzz, rule audit, concurrent
# load + WAL integrity, then the full M3 gate and the Rust unit tests.
#
# Phases:
#   1. filter fuzz   — 420 differential filter expressions
#   2. sort fuzz     — 165 differential sort expressions
#   3. rules audit   — 26 rule-engine visibility cases
#   4. load/WAL      — 8 workers x 40 mirrored ops plus a second SQLite
#                      connection per install, then journal_mode/integrity_check
#   5. M3 gate       — the full scenario/at-rest/drop-in gate
#   6. cargo test    — unit tests
#
# Usage: tools/gate_m7.sh
set -uo pipefail

cd "$(dirname "$0")/.."
ROOT="$PWD"
ORACLE="${ORACLE:-$HOME/lab/pb/pocketbase}"
PORT_BIN="$ROOT/target/debug/pocketbase"
GO_DIR="$ROOT/.oracle/gate_m7/go/pb_data"
RS_DIR="$ROOT/.oracle/gate_m7/rust/pb_data"
GO_PORT="${GO_PORT:-18130}"
RS_PORT="${RS_PORT:-18131}"
EMAIL="admin@example.com"
PASSWORD="pass12345678"

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

cleanup() {
    stop "$GO_PORT"
    stop "$RS_PORT"
}
trap cleanup EXIT

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

run_tool() { # run_tool <label> <command...>
    local label="$1"
    shift
    printf '  %s ... ' "$label"
    if "$@" >"$ROOT/.oracle/gate_m7/last.log" 2>&1; then
        printf '\033[32mPASS\033[0m\n'
        tail -1 "$ROOT/.oracle/gate_m7/last.log" | sed 's/^/    /'
    else
        printf '\033[31mFAIL\033[0m\n'
        tail -30 "$ROOT/.oracle/gate_m7/last.log" | sed 's/^/    /'
        status=1
    fi
}

printf '\n\033[1mM7 gate: filter/sort fuzz, rules, load/WAL\033[0m\n'
printf '  building... '
if ! cargo build -q 2>&1; then
    printf '\033[31mFAILED\033[0m\n'
    exit 1
fi
printf 'ok\n'

rm -rf "$ROOT/.oracle/gate_m7"
mkdir -p "$GO_DIR" "$RS_DIR"

printf '  seeding superusers... '
"$ORACLE" superuser upsert "$EMAIL" "$PASSWORD" --dir="$GO_DIR" >/dev/null 2>&1
"$PORT_BIN" superuser upsert "$EMAIL" "$PASSWORD" --dir="$RS_DIR" >/dev/null 2>&1
printf 'ok\n'

start "$ORACLE" "$GO_PORT" "$GO_DIR" "$ROOT/.oracle/gate_m7/go.log"
wait_health "$GO_PORT" || { echo "oracle did not start"; exit 1; }
start "$PORT_BIN" "$RS_PORT" "$RS_DIR" "$ROOT/.oracle/gate_m7/rust.log"
wait_health "$RS_PORT" || { echo "port did not start"; exit 1; }
printf '  oracle on %s, port on %s\n' "$GO_PORT" "$RS_PORT"

run_tool "filter fuzz (420 expressions)" \
    python3 tools/filter_fuzz.py \
    --oracle-base "http://127.0.0.1:$GO_PORT" \
    --port-base "http://127.0.0.1:$RS_PORT" --count 400
run_tool "sort fuzz (165 expressions)" \
    python3 tools/sort_fuzz.py \
    --oracle-base "http://127.0.0.1:$GO_PORT" \
    --port-base "http://127.0.0.1:$RS_PORT"
run_tool "rules audit (26 cases)" \
    python3 tools/rules_audit.py \
    --oracle-base "http://127.0.0.1:$GO_PORT" \
    --port-base "http://127.0.0.1:$RS_PORT"
run_tool "load + WAL (8 workers x 40 ops)" \
    python3 tools/load_wal.py \
    --oracle-base "http://127.0.0.1:$GO_PORT" \
    --port-base "http://127.0.0.1:$RS_PORT" \
    --oracle-dir "$GO_DIR" --port-dir "$RS_DIR" \
    --workers 8 --ops 40

stop "$GO_PORT"
stop "$RS_PORT"
trap - EXIT

printf '\n\033[1mM3 gate\033[0m\n'
if tools/gate_m3.sh; then
    check "M3 gate" ok ok
else
    check "M3 gate" failed ok
fi

printf '\n\033[1mRust tests\033[0m\n'
if cargo test -q >"$ROOT/.oracle/gate_m7/cargo-test.log" 2>&1; then
    check "cargo test" ok ok
    grep -E '^test result' "$ROOT/.oracle/gate_m7/cargo-test.log" | sed 's/^/    /'
else
    check "cargo test" failed ok
    tail -40 "$ROOT/.oracle/gate_m7/cargo-test.log" | sed 's/^/    /'
fi

printf '\n'
if [ "$status" -eq 0 ]; then
    printf '\033[32mM7 GATE PASSED\033[0m\n\n'
else
    printf '\033[31mM7 GATE FAILED\033[0m\n\n'
fi
exit "$status"
