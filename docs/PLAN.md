# Plan

Milestones are gated: a milestone is done only when its gate passes against the
oracle. No milestone is skipped, and no gate is "mostly passing".

## M0 — Spec extraction + harness foundation  ✅ done

Deliverables:
- `spec/routes-full.tsv` — 54 API routes with handler + middleware, extracted from the
  source tree at the binary's `vcs.revision`.
- `spec/routes-verified.tsv` — the same table probed live (50/54 answer; the 4 remaining
  404 at the resource level and are recorded as such, not as missing routes).
- `spec/schema.sql` — exact DDL of a fresh `data.db`.
- `spec/system/` — settings seed, system collections (fields/indexes/rules/options incl.
  all auth token secrets + durations), migration chain, field types, validation keys,
  JSVM typings.
- `ui/` — the embedded admin UI mirrored 1:1 (94/94 files verified present).
- `harness/` — `record` + `diff` with explicit normalization.

**Gate (passed):** the harness records the oracle and self-diffs with 0 mismatches
(9 responses), proving the recorder and normalizer are deterministic.

## M1 — Bootstrap, schema, migration parity  ✅ done

Scope: CLI skeleton (`serve`, `version`), config/flag parsing identical to cobra's,
SQLite open with the same pragmas, `_migrations` chain replay, `_params` seeding,
`_collections` seeding for `_superusers` + `users`, installer superuser bootstrap.

Deliverables:
- `crates/pb-core` — `db` (pragma set from `core/db_connect.go`), `migrations`
  (8-entry chain), `seed` (settings + 6 system collections), `superusers`
  (`__pbinstaller@example.com`), `ids` (id/secret generation).
- `crates/pb-api` — `/api/health`, JSON 404 envelope, `/_/` static serving.
- `crates/pb-cli` — cobra-compatible flags, `serve`, `--version`.
- `tools/gate_m1.sh` + `tools/gate_m1_compare.py` — the automated gate.

**Gate (passed):** `tools/gate_m1.sh`, 24 checks in three phases:

1. *Fresh install*: `data.db` schema identical modulo `sqlite_stat*`; `_migrations`
   set identical (8); `_params.settings` **byte-identical**; `_collections` rows
   identical modulo the per-install token secrets; secrets regenerated (50 chars);
   installer superuser row matches (`email`/`verified`/`emailVisibility`, bcrypt
   `$2a$10$` hash); JSON columns share SQLite storage classes (BLOB vs TEXT);
   `auxiliary.db` schema identical; both write `types.d.ts`.
2. *Drop-in*: the port opens an oracle-created install and changes no schema and no
   row in either database.
3. *Reverse drop-in*: the **oracle** opens a port-created install, starts, answers
   `/api/health`, and does not re-run migrations or touch `data.db`.

## M2 — Collections, settings, superuser login

Split in two: **M2a** is done and gated; **M2b** is next.

### M2a — superuser auth + read endpoints  ✅ done

Scope: superuser auth (`auth-with-password`, `auth-refresh`, `auth-methods`),
`GET /api/settings`, `GET /api/collections`, `GET /api/collections/{id|name}`,
`GET /api/collections/meta/scaffolds`, `GET /api/collections/meta/oauth2-providers`,
list pagination/sorting (`page`, `perPage`, `skipTotal`, `sort`), `superuser`
CLI, `/_/` static serving of the mirrored UI.

**Gate (passed):** `tools/gate_m2.sh`, three phases:

1. *Response parity* — 19 recorded requests replayed against both binaries,
   compared semantically: 0 mismatches. Covers bad/unknown identity, missing
   body fields, unknown collection, login, refresh, anonymous/bad-token/valid
   settings reads, collections list (default, paged, `skipTotal`), collection
   view (id/name/missing), auth-methods and both `meta` payloads.
2. *Cross-implementation auth* — a token minted by the oracle is accepted by the
   port and a port-minted token is accepted by the oracle, on the same database.
3. *Admin UI login* — the real embedded admin UI, driven in headless Chrome,
   loads the login form, authenticates, stores the session, and lands on
   `#/collections`. Record-list 404s are explicitly listed as M3 scope.

### M2b — settings writes  ✅ done

Scope: `PATCH /api/settings` with oracle-identical recursive merge and
validation. Gate: `tools/gate_m2.sh` phase 1 (settings row byte-identical).

### M2c — collection create/delete/truncate  ✅ done

Scope: `POST /api/collections`, `DELETE /api/collections/{c}`,
`DELETE /api/collections/{c}/truncate`, field builder validation, auth option
binding, per-index error trees, SQLite error translation. Gate:
`tools/gate_m2.sh` (m2c scenario, 81 requests, DB rows + schema identical).

### M2d — collection update  ✅ done

Scope: `PATCH /api/collections/{c}` — table rename, column add/drop/rename,
single↔multiple normalization, index sync, auth option merge, system-field and
rule guards. Gate: `tools/gate_m2.sh` (m2d scenario, 27 requests, DB rows +
schema identical).

### M2e — collections import  ✅ done (partial)

Scope: `PUT /api/collections/import` (upsert by id/name, deleteMissing). Gate:
`m2e-import` (5 requests, DB rows + schema identical).

Remaining in M2e: collections list `filter`, `dry-run-view`, `CreateViewFields`
(identifier parser, `_clone_` ids) — pending M3 (they share the filter/SQL
introspection subsystem).

### M3 — Records CRUD, filter/sort/expand, rules  ✅ done

Scope: record list/view/create/update/delete, `filter`/`sort`/`expand`/`fields`,
collection rules (`@request.auth`, `@collection.*`), rate limits, plus the
collection-level `filter` and `dry-run-view` deferred from M2e.

## M4 — Auth, files, tokens  ✅ done (core auth, files, tokens, impersonate, OAuth2 redirect broker):

Scope: password, OTP, OAuth2, MFA, email change/verification/password reset,
`_externalAuths`, `_authOrigins`, file tokens, thumbnails incl.
`PB_THUMBS_MAX_SOURCE_PIXELS`.

**Gate:** cross-implementation token acceptance in both directions; bcrypt
verification of hashes produced by the oracle.

## M5 — Realtime, batch, backups, logs, crons  ✅ done

**Gate:** an official SDK client connects over SSE and receives identical events;
batch transaction semantics match under partial failure.

## M6a — JSVM hook subset  ✅ done

**Engine:** rquickjs 0.14 (QuickJS, bundled C build) in workspace crate
`crates/pb-js`. One persistent worker thread, mpsc command channel, serialized
calls. Installed from `pb-cli serve` via `OnceLock<Arc<pb_js::HookEngine>>`
in `pb-api`; handlers no-op when no engine is installed.

**Scope (documented hook surface, not full goja parity):**
- Load `pb_hooks/*.pb.js` / `*.pb.ts` (sorted by filename).
- 11 record hooks: create/view/update/delete request + after-success + after-error
  (request + after-success for list).
- Tags filter handlers (`CanTriggerOn` → `e.Next()` for non-matching tags).
- `console`, JS error constructors, `$os`/`$security`/`$filepath` subset,
  `$app.logger`/`$app.dataDir`, `__hooks`, `sleep`, `toString`.
- `$os.writeFile` honors optional third `perm`; default is Go's `0`
  (creates mode `000`).
- Request-hook record mutations apply before submit; after-success mutations
  apply to the response only.
- Plain JS errors map to generic 400; explicit `ApiError` keeps status/message/data;
  after-success plain errors map to operation-specific 400.

**Gate:** `tools/gate_m6.sh` — 20 hook responses, 0 mismatches; 8 collections /
21 schema objects; record rows and all four traces (create/update/delete/error)
match; drop-in 7 responses, 0 mismatches.

**Known divergences (see `docs/COMPATIBILITY.md`):**
- Port treats `e.next()` as a no-op: the chain always runs to completion unless a
  hook throws. Oracle stops the chain and can roll back the transaction / return
  an empty 200.
- Oracle `$app` is re-bound per handler to `e.app`; port's `$app` is fixed at
  load (no per-handler rebinding), which does not matter for the supported subset
  (`logger`, `dataDir`).
- Oracle `e.error` in after-error hooks is a Go error object: `String(e.error)`
  gives the raw message, while `.message`/`.data` are `undefined`. Port passes
  `{message, data}`.
- Oracle `onRecordsListRequest` mutations to `e.records` are not applied by the
  port; port returns only `event.record`.
- Oracle `--hooksWatch` defaults true and restarts on hooks-dir changes; port
  accepts the flag but has no watcher. Gates always pass `--hooksWatch=false`.
- Hook dirs are absolutized like `jsvm.go`; `$app.dataDir()` returns the CLI
  `--dir` value unchanged (oracle `config.DataDir`).

## M6b — deferred

Full goja parity, hook watcher, `e.next()` transaction rollback, list-record
mutations, per-handler `$app` rebinding. Not required for v1.

## M7 — Hardening  ✅ done

Fuzz the filter parser, load test, audit the rules engine, document every remaining
unknown in `docs/UNKNOWNS.md`.

Deliverables:
- `tools/filter_fuzz.py` — deterministic differential filter corpus: 407 generated
  and hand-written expressions plus 13 guest (`@request.auth.id` = NULL) cases.
  Covers NULL/empty operands, relation-path traversal, `@collection`, LIKE
  escaping, date/number functions, malformed syntax, the 3500-byte filter limit
  and the 200-expression limit.
- `tools/sort_fuzz.py` — 165 sort expressions: ordinary fields, relation
  traversal, `@rowid`/`@random`, empty entries, `+`/`-` prefixes, the
  8-expression and 255-byte limits, invalid identifiers.
- `tools/rules_audit.py` — 26 rule cases across guests, owners, team members,
  unrelated users, relation traversal (`team.members ?= @request.auth.id`),
  `@collection` macros, `@request.auth.<field>`, date macros, superuser bypass
  and invalid-rule validation.
- `tools/load_wal.py` — 8 workers × N mirrored list/create/update/delete
  operations against both binaries, a second SQLite connection per install doing
  write transactions and `wal_checkpoint`, plus `journal_mode` and
  `integrity_check` verification.
- `tools/gate_m7.sh` — wraps all four tools and the full `tools/gate_m3.sh`.

Fixes found by the M7 tools:
- `geoDistance(...)` failed on the bundled SQLite (no math functions) and bound
  its four arguments once instead of the six references in the expression.
- Whitespace-only filters returned 200 instead of the oracle's 400.
- The filter-length (3500 bytes), expression-count (200), sort-count (8) and
  sort-field-length (255) limits were missing.
- `LIKE`/`~` operands were not cast to strings before `%...%` wrapping, changing
  matches for numeric/boolean operands.
- A missing `@request.auth.*` resolved to a bound NULL parameter instead of the
  `NULL` identifier; combined with the synthetic left joins used for relation
  traversal, this made `team.members ?= @request.auth.id` reject records whose
  relation target was empty.
- `null`/`''` operands on either side of `=`/`!=` now follow the oracle's
  `resolveEqualExpr` fallback branches, including parameter duplication for
  positional placeholders.
- Restoring a backup whose default `users` collection had been renamed failed
  with `UNIQUE constraint failed: _collections.id`: the seed step matched system
  collections by `name` only and re-inserted `users` with the retained
  `_pb_users_auth_` id. Seeding now treats the id as the identity (and still
  skips an existing name), and `harness/scenarios/m5b-restore-renamed-users.json`
  covers rename → backup → restore end-to-end.

**Gate (passed):** `tools/gate_m7.sh` — filter fuzz 420/420, sort fuzz 165/165,
rules audit 26/26, load/WAL test (606 requests, 0 errors, identical final state,
`wal` + `integrity_check=ok`), full `gate_m3.sh`, and `cargo test`.
