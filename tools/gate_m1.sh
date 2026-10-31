#!/usr/bin/env bash
# M1 gate: "the Rust binary is a drop-in replacement for the Go binary at rest".
#
# Verifies, against a freshly created install:
#   1. data.db .schema identical modulo SQLite's planner artifacts (sqlite_stat*)
#   2. _migrations file set identical (order-insensitive)
#   3. _params.settings byte-identical
#   4. _collections rows identical modulo the per-install token secrets
#   5. token secrets regenerated (never copied from the template)
#   6. auxiliary.db schema identical
#   7. both installs wrote types.d.ts
#
# Usage: tools/gate_m1.sh
# Requires: the oracle binary at $ORACLE (default ~/lab/pb/pocketbase).
set -uo pipefail

cd "$(dirname "$0")/.."
ROOT="$PWD"
ORACLE="${ORACLE:-$HOME/lab/pb/pocketbase}"
GO_DIR="$ROOT/.oracle/gate_go"
RS_DIR="$ROOT/.oracle/gate_rust"
GO_PORT="${GO_PORT:-18110}"
RS_PORT="${RS_PORT:-18111}"

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
    sleep 0.5
}

printf '\n\033[1mM1 gate: at-rest compatibility\033[0m\n'

printf '  building... '
if ! cargo build -q 2>&1; then
    printf '\033[31mFAILED\033[0m\n'
    exit 1
fi
printf 'ok\n'

rm -rf "$GO_DIR" "$RS_DIR"

printf '  oracle  ... '
if ! "$ORACLE" serve --http="127.0.0.1:$GO_PORT" --dir="$GO_DIR" \
    >"$ROOT/.oracle/gate_go.log" 2>&1 & then
    :
fi
if wait_health "$GO_PORT"; then printf 'ok\n'; else
    printf '\033[31mFAILED\033[0m (see .oracle/gate_go.log)\n'
    exit 1
fi
stop "$GO_PORT"

printf '  port    ... '
"$ROOT/target/debug/pocketbase" serve --http="127.0.0.1:$RS_PORT" --dir="$RS_DIR" \
    >"$ROOT/.oracle/gate_rust.log" 2>&1 &
if wait_health "$RS_PORT"; then printf 'ok\n'; else
    printf '\033[31mFAILED\033[0m (see .oracle/gate_rust.log)\n'
    exit 1
fi
stop "$RS_PORT"

printf '\n'
python3 "$ROOT/tools/gate_m1_compare.py" "$GO_DIR" "$RS_DIR"
status=$?

printf '\n\033[1mM1 gate: drop-in direction\033[0m\n'

DROP_DIR="$ROOT/.oracle/gate_dropin"
BEFORE_DIR="$ROOT/.oracle/gate_dropin_before"
rm -rf "$DROP_DIR" "$BEFORE_DIR"
cp -R "$GO_DIR" "$DROP_DIR"
cp -R "$GO_DIR" "$BEFORE_DIR"

printf '  port opens an oracle-created install ... '
"$ROOT/target/debug/pocketbase" serve --http="127.0.0.1:$RS_PORT" --dir="$DROP_DIR" \
    >"$ROOT/.oracle/gate_dropin.log" 2>&1 &
if wait_health "$RS_PORT"; then printf 'ok\n'; else
    printf '\033[31mFAILED\033[0m (see .oracle/gate_dropin.log)\n'
    status=1
fi
stop "$RS_PORT"

printf '\n'
python3 "$ROOT/tools/gate_m1_compare.py" --dropin "$BEFORE_DIR" "$DROP_DIR" || status=1

printf '\n\033[1mM1 gate: reverse drop-in (oracle opens a port-created install)\033[0m\n'

REV_DIR="$ROOT/.oracle/gate_reverse"
REV_BEFORE="$ROOT/.oracle/gate_reverse_before"
rm -rf "$REV_DIR" "$REV_BEFORE"
cp -R "$RS_DIR" "$REV_DIR"
cp -R "$RS_DIR" "$REV_BEFORE"

printf '  oracle opens a port-created install ... '
"$ORACLE" serve --http="127.0.0.1:$GO_PORT" --dir="$REV_DIR" \
    >"$ROOT/.oracle/gate_reverse.log" 2>&1 &
if wait_health "$GO_PORT"; then printf 'ok\n'; else
    printf '\033[31mFAILED\033[0m (see .oracle/gate_reverse.log)\n'
    status=1
fi
stop "$GO_PORT"

printf '\n'
python3 "$ROOT/tools/gate_m1_compare.py" --dropin-data "$REV_BEFORE" "$REV_DIR" || status=1

printf '\n'
if [ "$status" -eq 0 ]; then
    printf '\033[32mM1 GATE PASSED\033[0m\n\n'
else
    printf '\033[31mM1 GATE FAILED\033[0m\n\n'
fi
exit "$status"
