#!/usr/bin/env bash
# M6a gate: JSVM hooks subset (record request/after hooks, tags, errors, $os).
#
# Phases:
#   1. Hook parity — identical pb_hooks are installed for the oracle and the
#      port. Responses, hook-written traces, collection rows and record rows
#      must all match after id/timestamp normalization.
#   2. Drop-in — the port opens the oracle-created pb_data with the oracle's
#      hooks dir (via --hooksDir) and serves the same read-only responses.
#
# The gate always disables hooks watching and auto-migrations so that a trace
# write cannot restart the oracle and generated JS migrations cannot recreate
# test collections.
#
# Usage: tools/gate_m6.sh
set -uo pipefail

cd "$(dirname "$0")/.."
ROOT="$PWD"
ORACLE="${ORACLE:-$HOME/lab/pb/pocketbase}"
PORT_BIN="$ROOT/target/debug/pocketbase"
GATE_DIR="$ROOT/.oracle/gate_m6"
GO_DIR="$GATE_DIR/go/pb_data"
RS_DIR="$GATE_DIR/rust/pb_data"
GO_HOOKS="$GATE_DIR/go/pb_hooks"
RS_HOOKS="$GATE_DIR/rust/pb_hooks"
GO_PORT="${GO_PORT:-18124}"
RS_PORT="${RS_PORT:-18125}"
EMAIL="admin@example.com"
PASSWORD="pass12345678"
SCENARIO="harness/scenarios/m6a-hooks.json"
READONLY_SCENARIO="harness/scenarios/m6a-hooks-readonly.json"

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

start() { # start <binary> <port> <dir> <log> [extra args...]
    local bin="$1" port="$2" dir="$3" log="$4"
    shift 4
    nohup "$bin" serve --http="127.0.0.1:$port" --dir="$dir" \
        --hooksWatch=false --automigrate=false "$@" >"$log" 2>&1 &
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

trace_norm() { # trace_norm <file>: normalize record ids so traces are comparable
    sed -E 's/[a-z0-9]{15}/<id>/g' "$1" 2>/dev/null | tr -d '\r'
}

write_hooks() { # write_hooks <dir>
    mkdir -p "$1"
    cat >"$1/probe.pb.js" <<'EOF'
onRecordCreateRequest((e) => {
  const title = e.record.getString("title");
  if (title === "reject") {
    throw new BadRequestError("title is invalid");
  }
  if (title === "reject-data") {
    throw new BadRequestError("title has data", { title: "bad" });
  }
  if (title === "plain-error") {
    throw new Error("boom");
  }
  if (title === "mutate") {
    e.record.set("title", "mutated");
  }
  e.next();
}, "hooktest");

// Must never run for hooktest: proves tag filtering.
onRecordCreateRequest((e) => {
  e.record.set("title", "wrong-tag-ran");
}, "othertag");

onRecordCreateRequest((e) => {
  e.record.set("note", "hooktest-tag-ran");
  e.next();
}, "hooktest");

onRecordUpdateRequest((e) => {
  if (e.record.getString("title") === "ok") {
    e.record.set("note", "update-hook-ran");
  }
  e.next();
}, "hooktest");

onRecordAfterCreateSuccess((e) => {
  $os.writeFile(__hooks + "/trace-create.log", "created:" + e.record.id + ":" + e.record.getString("title") + "\n", 0o644);
  e.next();
}, "hooktest");

onRecordAfterUpdateSuccess((e) => {
  $os.writeFile(__hooks + "/trace-update.log", "updated:" + e.record.id + ":" + e.record.getString("note") + "\n", 0o644);
  e.next();
}, "hooktest");

onRecordAfterDeleteSuccess((e) => {
  $os.writeFile(__hooks + "/trace-delete.log", "deleted:" + e.record.id + ":" + e.record.getString("title") + "\n", 0o644);
  e.next();
}, "hooktest");

onRecordAfterCreateError((e) => {
  $os.writeFile(__hooks + "/trace-error.log", "error-hook-ran\n", 0o644);
  e.next();
}, "reqtest");

onRecordsListRequest((e) => {
  if (e.requestInfo().query.filter === "title='listreject'") {
    throw new ForbiddenError("list denied");
  }
  e.next();
}, "hooktest");

onRecordViewRequest((e) => {
  if (e.record.getString("title") === "viewreject") {
    throw new NotFoundError("view denied");
  }
  e.next();
}, "hooktest");

onRecordDeleteRequest((e) => {
  if (e.record.getString("title") === "keep") {
    throw new BadRequestError("cannot delete keep");
  }
  e.next();
}, "hooktest");
EOF
}

printf '\n\033[1mM6a gate: JSVM hooks subset\033[0m\n'
printf '  building... '
if ! cargo build -q 2>&1; then
    printf '\033[31mFAILED\033[0m\n'
    exit 1
fi
printf 'ok\n'

# ---------------------------------------------------------------- phase 1
printf '\n\033[1m1. hook parity\033[0m\n'

stop "$GO_PORT"
stop "$RS_PORT"
rm -rf "$GATE_DIR" .oracle/golden-m6-go .oracle/golden-m6-rust
mkdir -p "$GO_DIR" "$RS_DIR"
write_hooks "$GO_HOOKS"
write_hooks "$RS_HOOKS"

printf '  seeding a superuser in both installs... '
"$ORACLE" superuser upsert "$EMAIL" "$PASSWORD" --dir="$GO_DIR" >/dev/null 2>&1
"$PORT_BIN" superuser upsert "$EMAIL" "$PASSWORD" --dir="$RS_DIR" >/dev/null 2>&1
printf 'ok\n'

start "$ORACLE" "$GO_PORT" "$GO_DIR" "$GATE_DIR/go.log"
wait_health "$GO_PORT" || { echo "oracle did not start"; exit 1; }
"$ROOT/target/debug/harness" record --base "http://127.0.0.1:$GO_PORT" \
    --scenario "$SCENARIO" --out .oracle/golden-m6-go >/dev/null
stop "$GO_PORT"

start "$PORT_BIN" "$RS_PORT" "$RS_DIR" "$GATE_DIR/rust.log"
wait_health "$RS_PORT" || { echo "port did not start"; exit 1; }
"$ROOT/target/debug/harness" record --base "http://127.0.0.1:$RS_PORT" \
    --scenario "$SCENARIO" --out .oracle/golden-m6-rust >/dev/null
stop "$RS_PORT"

if "$ROOT/target/debug/harness" diff --a .oracle/golden-m6-go --b .oracle/golden-m6-rust; then
    check "hook responses identical" ok ok
else
    check "hook responses identical" differs identical
fi

if tools/compare_collections.py "$GO_DIR/data.db" "$RS_DIR/data.db"; then
    check "_collections rows and schema identical" ok ok
else
    check "_collections rows and schema identical" differs identical
fi

if tools/compare_records.py "$GO_DIR/data.db" "$RS_DIR/data.db"; then
    check "record rows identical" ok ok
else
    check "record rows identical" differs identical
fi

check "create trace matches" \
    "$(trace_norm "$GO_HOOKS/trace-create.log")" \
    "$(trace_norm "$RS_HOOKS/trace-create.log")"
check "create trace content" \
    "$(trace_norm "$GO_HOOKS/trace-create.log")" \
    "created:<id>:listreject"
check "update trace matches" \
    "$(trace_norm "$GO_HOOKS/trace-update.log")" \
    "$(trace_norm "$RS_HOOKS/trace-update.log")"
check "update trace content" \
    "$(trace_norm "$GO_HOOKS/trace-update.log")" \
    "updated:<id>:update-hook-ran"
check "delete trace matches" \
    "$(trace_norm "$GO_HOOKS/trace-delete.log")" \
    "$(trace_norm "$RS_HOOKS/trace-delete.log")"
check "delete trace content" \
    "$(trace_norm "$GO_HOOKS/trace-delete.log")" \
    "deleted:<id>:ok"
check "error trace matches" \
    "$(trace_norm "$GO_HOOKS/trace-error.log")" \
    "$(trace_norm "$RS_HOOKS/trace-error.log")"
check "error trace content" \
    "$(trace_norm "$GO_HOOKS/trace-error.log")" \
    "error-hook-ran"

# ---------------------------------------------------------------- phase 2
printf '\n\033[1m2. drop-in: port opens the oracle pb_data with oracle hooks\033[0m\n'

rm -rf .oracle/golden-m6-ro-go .oracle/golden-m6-ro-rust

start "$ORACLE" "$GO_PORT" "$GO_DIR" "$GATE_DIR/dropin_go.log"
wait_health "$GO_PORT" || { echo "oracle did not restart"; exit 1; }
"$ROOT/target/debug/harness" record --base "http://127.0.0.1:$GO_PORT" \
    --scenario "$READONLY_SCENARIO" --out .oracle/golden-m6-ro-go >/dev/null
stop "$GO_PORT"

start "$PORT_BIN" "$RS_PORT" "$GO_DIR" "$GATE_DIR/dropin_rust.log" \
    --hooksDir="$GO_HOOKS"
wait_health "$RS_PORT" || { echo "port did not start on the oracle db"; exit 1; }
"$ROOT/target/debug/harness" record --base "http://127.0.0.1:$RS_PORT" \
    --scenario "$READONLY_SCENARIO" --out .oracle/golden-m6-ro-rust >/dev/null
stop "$RS_PORT"

if "$ROOT/target/debug/harness" diff --a .oracle/golden-m6-ro-go --b .oracle/golden-m6-ro-rust; then
    check "port serves oracle pb_data with oracle hooks identically" ok ok
else
    check "port serves oracle pb_data with oracle hooks identically" differs identical
fi

printf '\n'
if [ "$status" -eq 0 ]; then
    printf '\033[32mM6a GATE PASSED\033[0m\n\n'
else
    printf '\033[31mM6a GATE FAILED\033[0m\n\n'
fi
exit "$status"
