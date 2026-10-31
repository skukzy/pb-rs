# spec/

Machine-readable facts recovered from the oracle binary
(`d313ba59…d54f`, v0.40.6, commit `9d281cca…`). Regenerate with the scripts in
`tools/`; do not hand-edit.

| File | Contents | Producer |
|---|---|---|
| `routes-full.tsv` | 54 API routes: method, path, handler, middleware chain, bind function, source file | `tools/extract_routes_from_source.py` |
| `routes-verified.tsv` | same routes probed live against the oracle; `exists=NO` means resource-level 404, not a missing route | `tools/verify_routes.py` |
| `schema.sql` | exact DDL of a freshly bootstrapped `data.db` | `sqlite3 .schema` |
| `system/settings.json` | the `_params.settings` seed row (smtp, s3, backups, rate limits, batch, logs, meta) | oracle `data.db` |
| `system/collections.json` | system collections with fields, indexes, rules and options — includes every auth token secret and duration | oracle `data.db` |
| `system/migrations.txt` | the `_migrations` chain a port must replay identically | oracle `data.db` |
| `system/field-types.tsv` | the 14 collection field types | upstream `core/field_*.go` |
| `system/validation-keys.txt` | 104 `validation_*` error keys | upstream `core`, `apis`, `forms` |
| `system/jsvm-types.d.ts` | generated JSVM typings (hook API surface, M6 reference) | oracle `pb_data/types.d.ts` |
| `raw/ui-manifest.txt` | 94 embedded UI paths recovered from the binary's rodata | `tools/extract_ui_manifest.py` |

## Notes

- Route paths use the router's `{param}` / `{path...}` syntax, not OpenAPI braces.
- `ui/` is the mirror of these 94 files fetched from the running oracle; every
  manifest entry is verified present.
- Token secrets in `system/collections.json` are the **defaults generated for a fresh
  install**, not secrets of any deployed instance.
