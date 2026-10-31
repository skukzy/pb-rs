# Compatibility contract

"Compatible" is defined narrowly and testably. Anything not listed here is not a
compatibility promise.

## Layers

| Layer | Requirement | Verified by |
|---|---|---|
| L1 CLI | `serve`, `superuser {create,update,upsert,delete,otp,ips}`, `migrate`, `version` accept the same flags and produce the same exit codes | scenario: CLI matrix |
| L2 On-disk | `pb_data/data.db` schema identical; `_migrations` rows identical; `_params.settings` byte-identical (incl. BLOB storage class); `_collections` identical modulo per-install secrets; installer superuser created on a fresh install | `tools/gate_m1.sh` |
| L3 HTTP | 54 routes, same methods, same status codes, same JSON envelope `{code,message,data}` | harness `basic` + per-domain scenarios; `tools/gate_m2.sh` for auth/settings/collections reads and collection create/delete/truncate |
| L4 Auth | bcrypt hashes verify; JWT `HS256` with per-collection `authToken.secret`, claims `{collectionId,id,type,refreshable,exp}`; refresh, OTP, MFA, OAuth2, file tokens | cross-token test in `tools/gate_m2.sh`: a token minted by the oracle validates in the port and vice versa |
| L5 Query | filter/sort/expand/fields syntax and semantics, including NULL and relation traversal, the filter limits (3500 bytes, 200 expressions) and sort limits (8 fields, 255 bytes/field) | `tools/filter_fuzz.py` (420 expressions), `tools/sort_fuzz.py` (165 expressions), `tools/rules_audit.py` (26 rule cases), all run by `tools/gate_m7.sh` |
| L6 Realtime | `text/event-stream` framing, `PB_CONNECT` event, subscription payloads | SSE scenario |
| L7 Static/UI | `/_/` serves the mirrored `ui/` tree with identical content types and SPA fallback | byte comparison of `ui/` |
| L8 JSVM | documented hook surface (M6a): load `pb_hooks/*.pb.js`/`*.pb.ts`, 11 record request/after hooks, tags, `console`, error constructors, `$os`/`$security`/`$filepath` subset, `$app.logger`/`$app.dataDir`, `__hooks`, `sleep`, `toString`; request-hook mutations before submit, after-success mutations to response | `tools/gate_m6.sh` (20 responses, 4 traces, rows, drop-in) |

## Rules

1. **Normalization is explicit.** The harness replaces volatile values (record ids,
   timestamps, JWTs, secrets) with placeholders before comparing. A new
   normalization rule must be reviewed, because it can hide a real difference.
   The at-rest gate normalizes exactly four things: the 50-char `[A-Za-z0-9]`
   token secrets inside `_collections.options`, the OAuth2 provider
   `clientSecret` values (also inside `options`), `_collections.created/updated`
   timestamps, and `_clone_XXXX` field ids (view collections, not produced yet).
   The installer superuser's `id`/`password`/`tokenKey` are checked for shape
   instead of equality.

   The HTTP harness normalizes: JWTs, 50-char secrets, 15-char record ids,
   timestamps, and the 10-char random suffix that
   `GET /api/collections/meta/scaffolds` regenerates on every request
   (`collectionScaffolds` calls `security.RandomStringWithAlphabet(10, ...)` and
   embeds it in the default index names). The rule only matches index names
   followed by `` ON `` `` — i.e. the scaffold's empty table name — so real
   collection index names are still compared exactly.
2. **JSON key order is not a contract.** Comparisons are semantic (parsed JSON).
3. **Error text is a contract.** The admin UI and SDKs surface `message` strings;
   they are compared verbatim.
4. **Response headers**: `content-type` is compared; the rest are recorded but not
   enforced in v1.
5. **Unknowns are recorded, not guessed.** When the oracle cannot be made to reveal
   behaviour (e.g. a code path requiring an external SMTP server), the gap is listed
   in `docs/UNKNOWNS.md` rather than filled with an assumption.
6. **Request binding follows `encoding/json/v2`.** A JSON `null` **zeroes** the
   target (it is not the v1 no-op), so `{"authToken":null}` wipes the whole token
   config and fails validation, while a partial object (`{"duration":120}`)
   merges onto the existing struct. Slices/maps zero to `[]`/`{}`. This is
   covered by `m2c-collections-write` (`create-auth-options-null`).

## Query semantics (M7)

* **Filter limits:** a raw filter longer than 3500 bytes is rejected, and more
  than 200 expressions is rejected, with the oracle's messages.
* **Sort limits:** more than 8 sort fields is rejected, as is a single field
  longer than 255 bytes.
* **NULL / empty operands:** `null`, `''`, and a missing `@request.auth.*`
  resolve to the `NULL` identifier (no bound parameter). On either side of
  `=`/`!=` they take the oracle's `resolveEqualExpr` fallback branches:
  `("" = x OR x IS NULL)` for equality, `("" IS NOT x AND x IS NOT NULL)` for
  inequality. This is what makes `team.members ?= @request.auth.id` match
  records whose relation target is empty.
* **LIKE casting:** `~`/`!~` cast every bound operand to text before wrapping it
  in `%...%`, so numeric/boolean literals match the oracle.
* **Math functions:** SQLite math functions are registered at connection open
  (see D15); `geoDistance` binding is expanded to the six references the oracle
  emits.

## Deliberate divergences

Each entry states what differs, why, and which gate proves the difference is
harmless. Everything not listed here is expected to match the oracle exactly.

### D1 — Historical migrations are not replayed

A fresh install is created directly at the v0.40 schema shape; the intermediate
v0.22 → v0.23 transformations (`1717233556..1717233559`) are not executed. The
eight `_migrations` rows are still recorded, so the oracle sees a fully migrated
database and never re-runs them.

*Why:* replaying history would add a large amount of code whose only output is the
final schema, which is already reproduced verbatim from the oracle.
*Proven harmless by:* gate phase 1 (schema + `_migrations` identical) and phase 3
(the oracle opens a port-created install without re-running anything).

### D2 — `sqlite_stat1`/`sqlite_stat4` are not pre-created

The oracle's `PRAGMA optimize` materializes the planner stat tables at slightly
different moments, so their presence and row order are not stable even between two
oracle runs. The gate excludes `sqlite_stat*` from schema comparison.

*Why:* these tables are SQLite planner artifacts, not application data.
*Proven harmless by:* gate phase 1 (filtered schema diff is empty in both
directions); a port-opened oracle database keeps its stat tables untouched.

### D3 — `_defensive=1` is not set

The oracle's DSN passes `_defensive=1` (mattn/go-sqlite3). The bundled SQLite in
`rusqlite` does not expose `sqlite3_db_config(SQLITE_DBCONFIG_DEFENSIVE)`, so the
port sets every other pragma (`busy_timeout`, `journal_mode`, `journal_size_limit`,
`synchronous`, `foreign_keys`, `temp_store`, `cache_size`) but not this one.

*Why:* no available API in the chosen SQLite binding.
*Impact:* the flag only blocks writes to shadow tables and `PRAGMA writable_schema`.
Application-level behaviour is unaffected; a client cannot reach these knobs
through the REST API.

### D4 — Request logging (resolved)

Request logging is implemented: the `activity::activity_logger` middleware writes
one `_logs` row per HTTP request to `auxiliary.db`, including 429s.

*Status:* resolved in M5. The gate now compares `auxiliary.db` rows in both
directions.

### D5 — Installer superuser password is random and unknown

Both binaries create `__pbinstaller@example.com` with a random password and
`tokenKey`, so those three values can never match across installs. The gate checks
their *shape* (`id` = 15 lowercase alnum, `tokenKey` = 50 alnum, `password` =
`$2a$10$` bcrypt) and asserts they are not copied from the oracle.

*Why:* the values are per-install secrets by design.
*Proven harmless by:* gate phase 1 (installer row check) — the row exists exactly
when the oracle would create it, so the installer flow is triggered identically.

### D6 — Collections-list `filter` (resolved)

`GET /api/collections?filter=...` is implemented: the search filter language is
parsed and evaluated against the whitelisted collection fields.

*Status:* resolved in M3.

### D7 — JS migrations and hooks (partially resolved in M6a)

JS migrations (`pb_migrations/*.js`) are still ignored — the port has no goja
runtime, so a database whose schema was produced by JS migrations must already
contain the resulting collections. Hooks, however, are now supported for the
documented subset (M6a): `pb_hooks/*.pb.js` / `*.pb.ts` are loaded by the
rquickjs worker and the 11 record request/after hooks fire with tag filtering.

*Why:* goja is out of scope for v1; rquickjs covers the documented hook surface.
*Impact:* an install migrated only through JS files will look empty to the port.
*Status:* partial (M6a). Full JS-migration execution remains deferred (M6b).

### D16 — `e.next()` is a no-op in the port

The oracle's hook chain stops when a handler returns without calling `e.next()`
and can roll back the surrounding transaction / return an empty 200. The port
always continues the chain unless a hook throws.

*Why:* transactional rollback across the hook boundary is not implemented.
*Impact:* hooks that intentionally short-circuit the chain (e.g. the oracle's
empty-200 pattern) will not reproduce; port always submits and returns the record.
*Status:* documented divergence (M6a).

### D17 — `e.error` shape in after-error hooks

Oracle `e.error` is a Go error object: `String(e.error)` yields the raw message
(e.g. `req: cannot be blank.`) while `.message`/`.data` are `undefined`. The
port passes `{ message, data }`, so JS reading `e.error.message`/`e.error.data`
sees values where the oracle sees `undefined`.

*Why:* the port normalizes the error into a JS object.
*Impact:* hooks relying on `String(e.error)` still work; hooks reading
`.message`/`.data` differ.
*Status:* documented divergence (M6a).

### D18 — List-hook record mutations and hooks watcher

Oracle `onRecordsListRequest` mutations to `e.records` are not applied by the
port (port returns only `event.record`). Oracle `--hooksWatch` defaults to true
and restarts on hooks-dir changes; the port accepts the flag but has no watcher.

*Why:* list-response reshaping and filesystem watching are out of M6a scope.
*Impact:* list hooks can reject but cannot rewrite the result set; hook edits
require a server restart on the port.
*Status:* documented divergence (M6a).

### D8 — JSON request bodies are matched case-sensitively

The oracle decodes JSON with `json.MatchCaseInsensitiveNames(true)`, so
`{"META":{"APPNAME":"X"}}` updates `meta.appName`. The port's `serde`
deserializers match keys exactly, so such a body is silently ignored (unknown
keys are always ignored by both sides).

*Why:* serde has no wildcard case-insensitive field matching; emulating it needs
a normalisation pass over every bound body against a canonical key skeleton.
*Impact:* only hand-written clients that rely on non-canonical casing. The admin
UI always sends the exact camelCase keys.
*Status:* recorded; may be ported later with the shared request-binding layer.

### D9 — View collections and rule parsing (resolved)

Resolved in M3:

* `POST /api/collections` with `type: "view"` derives fields from the query via
  `CreateViewFields` and validates.
* `POST /api/collections/meta/dry-run-view` is mounted.
* Collection and auth rules are parsed and rejected with
  `validation_invalid_rule` when invalid.

### D10 — Truncate skips record hooks (resolved)

Resolved in M3: `truncate` now deletes records one by one through
`delete_record_in_savepoint`, running record hooks (cascade deletes and the
superuser guard).

*Status:* resolved.

### D11 — Only JSON request bodies are bound

`BindBody` in the oracle supports `application/json`, form
(`application/x-www-form-urlencoded`, `multipart/form-data`) and XML
(`text/xml`, `application/xml`). The port's `pb-api::body::bind_json` implements
the JSON path only:

* form bodies are treated as an empty body (no fields are bound, so the request
  behaves like one without a body);
* XML and other content types fail with the same "invalid formatting" error the
  oracle returns for an unsupported type.

*Why:* the admin UI and both official SDKs always send JSON; the form/XML
binders (`UnmarshalRequestData` with its `form` tags, Go's `encoding/xml`) are a
large surface with no observed client.
*Impact:* `curl -d 'name=x'` style requests (and HTML form posts) behave
differently. Documented rather than hidden: `create-form-body` was recorded
against the oracle and removed from the scenario because the port cannot bind it.
*Status:* may be ported later with the shared request-binding layer.

### D12 — Collection import/export (partially resolved)

`PATCH /api/collections/{collection}` is implemented. `POST /api/collections/import`
and `POST /api/collections/meta/dry-run-view` are implemented. What remains:

* `GET /api/collections/{id}/export` (bulk export of a collection definition).

*Why:* convenience endpoint used by the admin UI export button.
*Status:* mostly resolved; export pending.

### D13 — Raw SQLite errors are only translated on the surfaced paths

Index creation and record-table DDL failures are formatted exactly like the
oracle's `modernc.org/sqlite` driver (`SQL logic error: no such column: nope
(1)`), and index failures are returned as a per-index validation tree. Errors
from the remaining statements (e.g. a constraint violation on the `_collections`
insert) keep `rusqlite`'s text.

*Why:* only the index path is reachable from a normal API request; the others are
500-class failures that a client cannot trigger deliberately.
*Status:* partially resolved (index, collection DDL, truncate, and protected-file
paths now translate rusqlite errors); remaining statements still use rusqlite
text.

### D14 — Serialized database access and synchronous request logging

The port holds every API database operation behind one
`Arc<Mutex<Connection>>`, and the activity logger calls `load_auth` again and
writes the `_logs` row synchronously before the response is completed. The oracle
uses a pooled connection and writes activity rows from a fire-and-forget
goroutine.

*Why:* a single connection keeps SQLite transaction semantics and `pb_data`
compatibility simple; the pool/async writer is a performance optimization, not a
correctness requirement.
*Impact (debug build, same machine): authenticated list requests p50 ≈ 9 ms vs
the oracle's ≈ 0.5 ms; under the M7 load test (8 workers × 40 mirrored ops)
p50 ≈ 58 ms vs ≈ 0.9 ms. Status codes, final record sets, WAL mode, and
`integrity_check` all match. Release builds narrow the gap but do not remove the
serialization.
*Proven harmless by:* `tools/load_wal.py` (606 requests, zero 5xx/transport
errors, identical final state) and the full `tools/gate_m7.sh`.
*Status:* documented divergence; candidate for a connection pool in v2.

### D15 — SQL math functions are registered by the port

The oracle's `mattn/go-sqlite3` build includes SQLite's math functions;
`rusqlite`'s bundled build does not compile them in by default. The port enables
rusqlite's `functions` feature and registers `acos`, `acosh`, `asin`, `asinh`,
`atan`, `atan2`, `atanh`, `ceil`, `ceiling`, `cos`, `cosh`, `degrees`, `exp`,
`floor`, `ln`, `log`, `log10`, `log2`, `mod`, `pi`, `pow`, `power`, `radians`,
`sin`, `sinh`, `sqrt`, `tan`, `tanh`, and `trunc` at connection open, matching the
oracle's set.

*Why:* `geoDistance(...)` expands to `acos(...)`/`cos(...)`/`sin(...)`/
`radians(...)` in the generated SQL; without them the oracle query succeeds and
the port returned "no such function".
*Proven harmless by:* the filter fuzz corpus includes `geoDistance` calls and
direct math-function filters.
