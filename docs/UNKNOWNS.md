# Unknowns

Behaviour the oracle could not be made to reveal in the current environment, or that
is out of scope for v1. These are gaps in evidence, not assumptions.

| # | Unknown | Why it is open | How to close it |
|---|---|---|---|
| 1 | SMTP delivery, templates, retry behaviour | no mail server; `smtp.enabled=false` in the seed | run a local sink (MailHog) and record |
| 2 | S3 storage backend semantics | requires an S3-compatible endpoint | run MinIO, record |
| 3 | OAuth2 provider flows end-to-end | requires real provider credentials | mock the token endpoint and record |
| 4 | Realtime SSE framing over long sessions | the current harness reads whole bodies; SSE never terminates | add a streaming recorder (M5) |
| 5 | `update` command behaviour | it would fetch and replace the executable | sandbox + local HTTP server replay |
| 6 | Thumbnail generation byte output | depends on Go's image encoders; exact bytes may differ by codec | compare dimensions/format only, or accept divergence |
| 7 | JSVM hook semantics | goja is out of scope for v1; rquickjs covers the documented subset (M6a) | M6b (full goja parity deferred) |
| 8 | Crash/fault-injection durability (kill -9 mid-write, disk-full, torn WAL) | the M7 load test covers steady-state concurrency only; no crash harness yet | run the load test with an external killer/`SIGKILL` loop and compare recovery (`integrity_check`, `-wal`/`-shm` state) |
| 9 | Rate-limiter timing boundaries | wall-clock dependent | injectable clock in the port, record with the oracle |

## Known-bounded negative results

- The 4 routes in `spec/routes-verified.tsv` marked `exists=NO` are **not** missing
  routes: they return 404 because the probed record id does not exist
  (`/records/{id}`, `/files/{collection}/{recordId}/{filename}`). This is a bounded
  observation, not proof about other record ids.
- M7 filter coverage is bounded at **420 expressions** (`tools/filter_fuzz.py`):
  407 generated/hand-written cases plus 13 guest-auth cases. It exercises NULL and
  empty operands, relation traversal, `@collection`, LIKE escaping, date/number
  functions, malformed syntax, and the 3500-byte/200-expression limits. It is a
  sample, not an exhaustive proof over the grammar.
- M7 sort coverage is bounded at **165 expressions** (`tools/sort_fuzz.py`), which
  includes relation paths, `@rowid`/`@random`, prefixes, and the 8-field/255-byte
  limits.
- M7 rule coverage is bounded at **26 cases** (`tools/rules_audit.py`); it covers
  guest/owner/team/stranger visibility, relation traversal, `@collection` macros,
  and superuser bypass, but not every rule grammar production.
- M7 load/WAL coverage is bounded at 8 workers × 40 mirrored operations plus one
  external writer per install (`tools/load_wal.py`). It shows matching status
  codes and final record sets, `journal_mode=wal`, and `integrity_check=ok`; it
  does not prove fairness or throughput parity. The port serializes all API
  database access through one `Arc<Mutex<Connection>>` and writes request logs
  synchronously, so concurrent latency is much higher than the oracle's (see
  COMPATIBILITY.md D14). This is a performance divergence, not a correctness gap.
