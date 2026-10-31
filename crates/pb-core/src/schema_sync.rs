//! Record-table synchronization: `core/collection_record_table_sync.go`.
//!
//! Creating a collection creates its records table (columns sorted
//! alphabetically, `dbx.CreateTable` behaviour) and its indexes; deleting one
//! drops the table; truncating deletes every row. Views own no table.
//!
//! The index parser mirrors `tools/dbutils/index.go` closely enough to
//! validate, normalize and rebuild `CREATE INDEX` expressions, because the
//! stored `indexes` array holds the rebuilt form (backticked identifiers, the
//! collection's own table name).

use anyhow::{Context, Result};
use rusqlite::Connection;
use serde_json::Value;

use crate::collections::Collection;
use crate::fields;

/// A parsed `CREATE INDEX` expression (`dbutils.Index`).
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Index {
    pub schema_name: String,
    pub index_name: String,
    pub table_name: String,
    pub where_expr: String,
    pub columns: Vec<IndexColumn>,
    pub unique: bool,
    pub optional: bool,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct IndexColumn {
    pub name: String,
    pub collate: String,
    pub sort: String,
}

impl Index {
    /// `Index.IsValid`.
    pub fn is_valid(&self) -> bool {
        !self.index_name.is_empty() && !self.table_name.is_empty() && !self.columns.is_empty()
    }

    /// `Index.Build`.
    pub fn build(&self) -> String {
        if !self.is_valid() {
            return String::new();
        }
        let mut out = String::from("CREATE ");
        if self.unique {
            out.push_str("UNIQUE ");
        }
        out.push_str("INDEX ");
        if self.optional {
            out.push_str("IF NOT EXISTS ");
        }
        if !self.schema_name.is_empty() {
            out.push('`');
            out.push_str(&self.schema_name);
            out.push_str("`.");
        }
        out.push('`');
        out.push_str(&self.index_name);
        out.push_str("` ON `");
        out.push_str(&self.table_name);
        out.push_str("` (");
        if self.columns.len() > 1 {
            out.push_str("\n  ");
        }
        let mut has_col = false;
        for col in &self.columns {
            let trimmed = col.name.trim();
            if trimmed.is_empty() {
                continue;
            }
            if has_col {
                out.push_str(",\n  ");
            }
            if col.name.contains('(') || col.name.contains(' ') {
                out.push_str(trimmed);
            } else {
                out.push('`');
                out.push_str(trimmed);
                out.push('`');
            }
            if !col.collate.is_empty() {
                out.push_str(" COLLATE ");
                out.push_str(&col.collate);
            }
            if !col.sort.is_empty() {
                out.push(' ');
                out.push_str(&col.sort.to_uppercase());
            }
            has_col = true;
        }
        if has_col && self.columns.len() > 1 {
            out.push('\n');
        }
        out.push(')');
        if !self.where_expr.is_empty() {
            out.push_str(" WHERE ");
            out.push_str(&self.where_expr);
        }
        out
    }
}

/// Split on a separator, ignoring separators inside quotes, brackets and
/// parentheses (`tools/tokenizer` behaviour).
fn split_outside(input: &str, separator: char) -> Vec<String> {
    let mut parts = Vec::new();
    let mut current = String::new();
    let mut depth = 0i32;
    let mut quote: Option<char> = None;
    for ch in input.chars() {
        if let Some(q) = quote {
            current.push(ch);
            if ch == q {
                quote = None;
            }
            continue;
        }
        match ch {
            '`' | '"' | '\'' | '[' => {
                quote = Some(if ch == '[' { ']' } else { ch });
                current.push(ch);
            }
            '(' => {
                depth += 1;
                current.push(ch);
            }
            ')' => {
                depth -= 1;
                current.push(ch);
            }
            c if c == separator && depth == 0 => {
                parts.push(std::mem::take(&mut current));
            }
            c => current.push(c),
        }
    }
    parts.push(current);
    parts
}

const TRIM_CHARS: &[char] = &['`', '"', '\'', '[', ']', '\r', '\n', '\t', '\x0c', '\x0b', ' '];

fn trim_ident(value: &str) -> String {
    value.trim_matches(TRIM_CHARS).to_string()
}

/// `dbutils.ParseIndex`.
pub fn parse_index(expr: &str) -> Index {
    // (?i)\s*create\s+(unique\s+)?\s*index\s*(if\s+not\s+exists\s+)?(\S*)\s+on\s+(\S*)\s*\(([\s\S]*?)\)(?:\s+where\s+([\s\S]*?))?\s*$
    let lower = expr.to_lowercase();
    let Some(create_at) = lower.find("create") else {
        return Index::default();
    };
    let rest = &expr[create_at + "create".len()..];
    let rest_lower = &lower[create_at + "create".len()..];

    let mut cursor = 0usize;
    let skip_ws = |cursor: &mut usize, s: &str| {
        while *cursor < s.len() && s.as_bytes()[*cursor].is_ascii_whitespace() {
            *cursor += 1;
        }
    };

    skip_ws(&mut cursor, rest);
    let unique = rest_lower[cursor..].starts_with("unique");
    if unique {
        cursor += "unique".len();
    }
    skip_ws(&mut cursor, rest);
    if !rest_lower[cursor..].starts_with("index") {
        return Index::default();
    }
    cursor += "index".len();
    skip_ws(&mut cursor, rest);
    let optional = rest_lower[cursor..].starts_with("if not exists");
    if optional {
        cursor += "if not exists".len();
    }
    skip_ws(&mut cursor, rest);

    // Name token runs until whitespace.
    let name_start = cursor;
    while cursor < rest.len() && !rest.as_bytes()[cursor].is_ascii_whitespace() {
        cursor += 1;
    }
    let name_token = &rest[name_start..cursor];
    skip_ws(&mut cursor, rest);
    if !rest_lower[cursor..].starts_with("on") {
        return Index::default();
    }
    cursor += "on".len();
    skip_ws(&mut cursor, rest);

    let table_start = cursor;
    while cursor < rest.len() && !rest.as_bytes()[cursor].is_ascii_whitespace() {
        cursor += 1;
    }
    let table_token = &rest[table_start..cursor];
    skip_ws(&mut cursor, rest);
    if !rest[cursor..].starts_with('(') {
        return Index::default();
    }
    let columns_start = cursor + 1;
    // Find the matching close paren. The Go regex is non-greedy but anchored
    // at `$`, so it backtracks until the remainder parses; scanning for the
    // balanced `)` at depth 0 is equivalent and also handles expression
    // columns such as `LOWER(name)`.
    let Some(close) = matching_paren(&rest[columns_start..]) else {
        return Index::default();
    };
    let columns_raw = &rest[columns_start..columns_start + close];
    let after = &rest[columns_start + close + 1..];
    let after_lower = after.to_lowercase();
    let trimmed_after = after.trim_start();
    let where_expr = if trimmed_after.to_lowercase().starts_with("where") {
        trimmed_after["where".len()..].trim().to_string()
    } else if after_lower.trim().is_empty() {
        String::new()
    } else {
        // trailing junk -> invalid expression
        return Index::default();
    };

    let name_parts = split_outside(name_token, '.');
    let (schema_name, index_name) = match name_parts.len() {
        1 => (String::new(), trim_ident(&name_parts[0])),
        2 => (trim_ident(&name_parts[0]), trim_ident(&name_parts[1])),
        _ => (String::new(), String::new()),
    };

    let mut columns = Vec::new();
    let raw_columns = split_outside(columns_raw, ',');
    for raw in &raw_columns {
        if let Some(col) = parse_index_column(raw) {
            columns.push(col);
        }
    }
    if raw_columns.len() != columns.len() {
        columns.clear();
    }

    Index {
        schema_name,
        index_name,
        table_name: trim_ident(table_token),
        where_expr,
        columns,
        unique,
        optional,
    }
}

/// Offset of the `)` that closes an already-opened paren, ignoring quoted
/// parens.
fn matching_paren(input: &str) -> Option<usize> {
    let mut depth = 0i32;
    let mut quote: Option<char> = None;
    for (i, ch) in input.char_indices() {
        if let Some(q) = quote {
            if ch == q {
                quote = None;
            }
            continue;
        }
        match ch {
            '`' | '"' | '\'' | '[' => quote = Some(if ch == '[' { ']' } else { ch }),
            '(' => depth += 1,
            ')' => {
                if depth == 0 {
                    return Some(i);
                }
                depth -= 1;
            }
            _ => {}
        }
    }
    None
}

/// `indexColumnRegex`: `^([\s\S]+?)(?:\s+collate\s+([\w]+))?(?:\s+(asc|desc))?\s*$`
fn parse_index_column(raw: &str) -> Option<IndexColumn> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    let mut name = trimmed;
    let mut collate = String::new();
    let mut sort = String::new();

    let lower = trimmed.to_lowercase();
    // Optional trailing ASC/DESC.
    for keyword in ["asc", "desc"] {
        let suffix = format!(" {keyword}");
        if lower.ends_with(&suffix) {
            sort = keyword.to_uppercase();
            name = trimmed[..trimmed.len() - suffix.len()].trim_end();
            break;
        }
    }
    let lower = name.to_lowercase();
    if let Some(at) = lower.rfind(" collate ") {
        let after = &name[at + " collate ".len()..];
        if !after.is_empty() && after.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
            collate = after.to_string();
            name = name[..at].trim_end();
        }
    }
    let name = trim_ident(name);
    if name.is_empty() {
        return None;
    }
    Some(IndexColumn {
        name,
        collate,
        sort,
    })
}

/// `dbutils.FindSingleColumnUniqueIndex`.
pub fn find_single_column_unique_index(indexes: &[String], column: &str) -> Option<Index> {
    indexes.iter().map(|idx| parse_index(idx)).find(|idx| {
        idx.unique
            && idx.columns.len() == 1
            && idx.columns[0].name.eq_ignore_ascii_case(column)
    })
}

fn quote_ident(value: &str) -> String {
    format!("`{}`", value.replace('`', "``"))
}

/// `CreateTable`: one `name TYPE` column per field, sorted alphabetically.
pub fn create_table_sql(collection: &Collection) -> String {
    let mut columns: Vec<(String, &'static str)> = collection
        .field_list()
        .items()
        .iter()
        .map(|field| {
            (
                fields::field_name(field).to_string(),
                fields::column_type(field),
            )
        })
        .collect();
    columns.sort_by(|a, b| a.0.cmp(&b.0));

    let body = columns
        .iter()
        .map(|(name, ty)| format!("{} {ty}", quote_ident(name)))
        .collect::<Vec<_>>()
        .join(", ");

    format!(
        "CREATE TABLE {} ({body})",
        quote_ident(&collection.name)
    )
}

/// Create the records table and its indexes for a new collection.
pub fn create(conn: &Connection, collection: &Collection) -> Result<()> {
    if collection.is_view() {
        return Ok(());
    }
    conn.execute_batch(&create_table_sql(collection))
        .with_context(|| format!("create records table for {}", collection.name))?;
    create_indexes(conn, collection)
}

/// `createCollectionIndexes`: normalize each expression to the collection's
/// table name, then execute it.
pub fn create_indexes(conn: &Connection, collection: &Collection) -> Result<()> {
    if collection.is_view() {
        return Ok(());
    }
    let indexes = collection.index_list();
    for (i, raw) in indexes.iter().enumerate() {
        let mut parsed = parse_index(raw);
        parsed.table_name = collection.name.clone();
        if !parsed.is_valid() {
            anyhow::bail!("invalid index expression at {i}: {raw}");
        }
        conn.execute_batch(&parsed.build())
            .with_context(|| format!("create index {raw}"))?;
    }
    Ok(())
}

/// The oracle's `createCollectionIndexes` error tree: per-index failures with
/// the message the API returns (`Failed to create index <name> - <err>.`).
pub fn create_indexes_errors(conn: &Connection, collection: &Collection) -> Vec<(usize, String)> {
    if collection.is_view() {
        return Vec::new();
    }
    let mut errors = Vec::new();
    for (i, raw) in collection.index_list().iter().enumerate() {
        let mut parsed = parse_index(raw);
        parsed.table_name = collection.name.clone();
        if !parsed.is_valid() {
            errors.push((
                i,
                "Invalid CREATE INDEX expression.".to_string(),
            ));
            continue;
        }
        if let Err(err) = conn.execute_batch(&parsed.build()) {
            errors.push((
                i,
                format!(
                    "Failed to create index {} - {}.",
                    parsed.index_name,
                    go_sqlite_error(&err)
                ),
            ));
        }
    }
    errors
}

/// Format a SQLite error the way the oracle's driver does
/// (`modernc.org/sqlite`: `"<sqlite3_errstr>: <errmsg> (<code>)"`).
///
/// Only the primary codes reachable from the collection write paths are
/// mapped; anything else falls back to the driver's generic string.
pub fn go_sqlite_error(err: &rusqlite::Error) -> String {
    let (rc, message) = match err {
        rusqlite::Error::SqliteFailure(code, message) => {
            (code.extended_code, message.clone().unwrap_or_default())
        }
        // `prepare` failures keep the raw SQL and offset; the driver's message
        // is just the SQLite error text.
        rusqlite::Error::SqlInputError { error, msg, .. } => {
            (error.extended_code, msg.clone())
        }
        _ => return err.to_string(),
    };
    let primary = rc & 0xff;
    let errstr = match primary {
        1 => "SQL logic error",
        2 => "unknown error",
        3 => "access permission denied",
        5 => "database is locked",
        6 => "database table is locked",
        8 => "attempt to write a readonly database",
        10 => "disk I/O error",
        11 => "database disk image is malformed",
        13 => "database or disk is full",
        14 => "unable to open database file",
        17 => "database schema has changed",
        18 => "string or blob too big",
        19 => "constraint failed",
        20 => "datatype mismatch",
        21 => "bad parameter or other API misuse",
        _ => "unknown error",
    };
    if message.is_empty() || message == errstr {
        format!("{errstr} ({rc})")
    } else {
        format!("{errstr}: {message} ({rc})")
    }
}

/// `app.HasTable`.
pub fn has_table(conn: &Connection, name: &str) -> bool {
    conn.query_row(
        "SELECT (1) FROM sqlite_master WHERE type='table' AND name=?1",
        [name],
        |_| Ok(()),
    )
    .is_ok()
}

/// `SyncRecordTableSchema` failure: either a raw driver error or a set of
/// per-index validation errors that the API surfaces as a tree.
#[derive(Debug)]
pub enum SyncError {
    Raw(String),
    Indexes(Vec<(usize, String)>),
}

/// `SyncRecordTableSchema` for both create and update. `old` is `None` on
/// create.
pub fn sync_table(
    conn: &Connection,
    new: &Collection,
    old: Option<&Collection>,
) -> Result<(), SyncError> {
    if new.is_view() {
        return Ok(());
    }

    let create = match old {
        Some(old) if has_table(conn, &old.name) => false,
        _ => true,
    };

    if create {
        conn.execute_batch(&create_table_sql(new))
            .map_err(|e| SyncError::Raw(go_sqlite_error(&e)))?;
        return create_indexes_checked(conn, new);
    }

    let old = old.unwrap();
    let old_fields = old.field_list();
    let new_fields = new.field_list();

    let need_rename = !old.name.eq_ignore_ascii_case(&new.name);
    let need_indexes = need_rename
        || serde_json::to_string(&old.fields).unwrap_or_default()
            != serde_json::to_string(&new.fields).unwrap_or_default()
        || serde_json::to_string(&old.indexes).unwrap_or_default()
            != serde_json::to_string(&new.indexes).unwrap_or_default();

    if need_indexes {
        drop_indexes(conn, old).map_err(|e| SyncError::Raw(e.to_string()))?;
    }

    if need_rename {
        conn.execute_batch(&format!(
            "ALTER TABLE {} RENAME TO {}",
            quote_ident(&old.name),
            quote_ident(&new.name)
        ))
        .map_err(|e| SyncError::Raw(go_sqlite_error(&e)))?;
    }

    // dropped columns
    for old_field in old_fields.items() {
        let old_id = crate::fields::field_id(old_field);
        if new_fields.get_by_id(old_id).is_some() {
            continue;
        }
        conn.execute_batch(&format!(
            "ALTER TABLE {} DROP COLUMN {}",
            quote_ident(&new.name),
            quote_ident(crate::fields::field_name(old_field))
        ))
        .map_err(|e| {
            SyncError::Raw(format!(
                "failed to drop column {} - {}",
                crate::fields::field_name(old_field),
                go_sqlite_error(&e)
            ))
        })?;
    }

    // added or renamed columns (via a temporary name to avoid collisions)
    let mut to_rename: Vec<(String, String)> = Vec::new();
    for field in new_fields.items() {
        let old_field = old_fields.get_by_id(crate::fields::field_id(field));
        match old_field {
            None => {
                let temp = format!("{}{}", crate::fields::field_name(field), ids_random(5));
                to_rename.push((temp.clone(), crate::fields::field_name(field).to_string()));
                conn.execute_batch(&format!(
                    "ALTER TABLE {} ADD COLUMN {} {}",
                    quote_ident(&new.name),
                    quote_ident(&temp),
                    crate::fields::column_type(field)
                ))
                .map_err(|e| {
                    SyncError::Raw(format!(
                        "failed to add column {} - {}",
                        crate::fields::field_name(field),
                        go_sqlite_error(&e)
                    ))
                })?;
            }
            Some(old_field) if crate::fields::field_name(old_field)
                != crate::fields::field_name(field) =>
            {
                let temp = format!("{}{}", crate::fields::field_name(field), ids_random(5));
                to_rename.push((temp.clone(), crate::fields::field_name(field).to_string()));
                conn.execute_batch(&format!(
                    "ALTER TABLE {} RENAME COLUMN {} TO {}",
                    quote_ident(&new.name),
                    quote_ident(crate::fields::field_name(old_field)),
                    quote_ident(&temp)
                ))
                .map_err(|e| SyncError::Raw(go_sqlite_error(&e)))?;
            }
            _ => {}
        }
    }
    for (temp, actual) in &to_rename {
        conn.execute_batch(&format!(
            "ALTER TABLE {} RENAME COLUMN {} TO {}",
            quote_ident(&new.name),
            quote_ident(temp),
            quote_ident(actual)
        ))
        .map_err(|e| SyncError::Raw(go_sqlite_error(&e)))?;
    }

    // single <-> multiple conversion
    normalize_single_vs_multiple(conn, new, old)?;

    if need_indexes {
        return create_indexes_checked(conn, new);
    }

    Ok(())
}

fn create_indexes_checked(
    conn: &Connection,
    collection: &Collection,
) -> Result<(), SyncError> {
    let errors = create_indexes_errors(conn, collection);
    if errors.is_empty() {
        Ok(())
    } else {
        Err(SyncError::Indexes(errors))
    }
}

fn ids_random(n: usize) -> String {
    use rand::Rng;
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let mut rng = rand::thread_rng();
    (0..n)
        .map(|_| ALPHABET[rng.gen_range(0..ALPHABET.len())] as char)
        .collect()
}

fn normalize_single_vs_multiple(
    conn: &Connection,
    new: &Collection,
    old: &Collection,
) -> Result<(), SyncError> {
    let new_fields = new.field_list();
    let old_fields = old.field_list();

    for field in new_fields.items() {
        let is_new_multiple = crate::fields::is_multiple(field);
        let is_old_multiple = old_fields
            .get_by_id(crate::fields::field_id(field))
            .map(crate::fields::is_multiple)
            .unwrap_or(false);

        if is_old_multiple == is_new_multiple {
            continue;
        }

        // drop all views, restore them afterwards
        let views: Vec<(String, String)> = conn
            .prepare("SELECT name, sql FROM sqlite_master WHERE type='view' AND sql IS NOT NULL")
            .map_err(|e| SyncError::Raw(e.to_string()))?
            .query_map([], |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)))
            .map_err(|e| SyncError::Raw(e.to_string()))?
            .filter_map(Result::ok)
            .collect();

        for (name, _) in &views {
            conn.execute_batch(&format!("DROP VIEW IF EXISTS {}", quote_ident(name)))
                .map_err(|e| SyncError::Raw(e.to_string()))?;
        }

        let table = quote_ident(&new.name);
        let original = quote_ident(crate::fields::field_name(field));
        let old_temp = quote_ident(&format!("_{}{}", crate::fields::field_name(field), ids_random(5)));

        conn.execute_batch(&format!(
            "ALTER TABLE {} RENAME COLUMN {} TO {}",
            table, original, old_temp
        ))
        .map_err(|e| SyncError::Raw(go_sqlite_error(&e)))?;

        conn.execute_batch(&format!(
            "ALTER TABLE {} ADD COLUMN {} {}",
            table, original, crate::fields::column_type(field)
        ))
        .map_err(|e| SyncError::Raw(go_sqlite_error(&e)))?;

        let old_temp_name = old_temp.trim_matches('`');
        let sql = if !is_old_multiple && is_new_multiple {
            format!(
                "UPDATE {table} SET {original} = (
                    CASE
                        WHEN COALESCE({old}, '') = ''
                        THEN '[]'
                        ELSE (
                            CASE
                                WHEN json_valid({old}) AND json_type({old}) == 'array'
                                THEN {old}
                                ELSE json_array({old})
                            END
                        )
                    END
                )",
                table = table,
                original = original,
                old = quote_ident(old_temp_name)
            )
        } else {
            format!(
                "UPDATE {table} SET {original} = (
                    CASE
                        WHEN COALESCE({old}, '[]') = '[]'
                        THEN ''
                        ELSE (
                            CASE
                                WHEN json_valid({old}) AND json_type({old}) == 'array'
                                THEN COALESCE(json_extract({old}, '$[#-1]'), '')
                                ELSE {old}
                            END
                        )
                    END
                )",
                table = table,
                original = original,
                old = quote_ident(old_temp_name)
            )
        };
        conn.execute_batch(&sql)
            .map_err(|e| SyncError::Raw(go_sqlite_error(&e)))?;

        conn.execute_batch(&format!(
            "ALTER TABLE {} DROP COLUMN {}",
            table, old_temp
        ))
        .map_err(|e| SyncError::Raw(go_sqlite_error(&e)))?;

        for (_, sql) in &views {
            conn.execute_batch(sql)
                .map_err(|e| SyncError::Raw(e.to_string()))?;
        }
    }

    Ok(())
}

/// `dropCollectionIndexes`.
pub fn drop_indexes(conn: &Connection, collection: &Collection) -> Result<()> {
    for raw in collection.index_list() {
        let parsed = parse_index(&raw);
        if parsed.index_name.is_empty() {
            anyhow::bail!("failed to drop index - missing index name: {raw}");
        }
        conn.execute_batch(&format!(
            "DROP INDEX IF EXISTS {}",
            quote_ident(&parsed.index_name)
        ))?;
    }
    Ok(())
}

/// `app.DeleteTable`.
pub fn drop_table(conn: &Connection, collection: &Collection) -> Result<()> {
    conn.execute_batch(&format!("DROP TABLE IF EXISTS {}", quote_ident(&collection.name)))
        .with_context(|| format!("drop records table for {}", collection.name))?;
    Ok(())
}

/// `app.TruncateCollection`: delete every record, keeping the table.
pub fn truncate(conn: &Connection, collection: &Collection) -> Result<()> {
    conn.execute_batch(&format!("DELETE FROM {}", quote_ident(&collection.name)))
        .with_context(|| format!("truncate {}", collection.name))?;
    Ok(())
}

/// Normalize an index list for storage: rebuild every expression with the
/// collection's own table name.
pub fn normalize_indexes(name: &str, raw_indexes: &[Value]) -> Vec<String> {
    raw_indexes
        .iter()
        .filter_map(Value::as_str)
        .map(|raw| {
            let mut parsed = parse_index(raw);
            // `onCollectionSave`: only rebuild when the table name differs.
            if parsed.table_name == name {
                return raw.to_string();
            }
            parsed.table_name = name.to_string();
            let normalized = parsed.build();
            if normalized.is_empty() {
                // leave invalid expressions to the model validator
                raw.to_string()
            } else {
                normalized
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_and_rebuilds_the_oracle_index_syntax() {
        let parsed = parse_index("CREATE UNIQUE INDEX idx_x ON whatever (x)");
        assert_eq!(parsed.index_name, "idx_x");
        assert_eq!(parsed.table_name, "whatever");
        assert!(parsed.unique);
        assert_eq!(parsed.columns.len(), 1);
        assert_eq!(parsed.columns[0].name, "x");

        let mut parsed = parsed;
        parsed.table_name = "posts".into();
        assert_eq!(
            parsed.build(),
            "CREATE UNIQUE INDEX `idx_x` ON `posts` (`x`)"
        );
    }

    #[test]
    fn parses_partial_and_multi_column_indexes() {
        let parsed = parse_index(
            "CREATE UNIQUE INDEX `idx_email_pbc_1` ON `users` (`email`) WHERE `email` != ''",
        );
        assert_eq!(parsed.where_expr, "`email` != ''");
        assert_eq!(parsed.build(), "CREATE UNIQUE INDEX `idx_email_pbc_1` ON `users` (`email`) WHERE `email` != ''");

        let parsed = parse_index("CREATE INDEX `idx` ON `_mfas` (collectionRef,recordRef)");
        assert_eq!(parsed.columns.len(), 2);
        assert_eq!(
            parsed.build(),
            "CREATE INDEX `idx` ON `_mfas` (\n  `collectionRef`,\n  `recordRef`\n)"
        );
    }

    #[test]
    fn parses_expressions_and_sort_directions() {
        let parsed = parse_index("CREATE INDEX idx ON t (LOWER(name) DESC, other COLLATE NOCASE ASC)");
        assert_eq!(parsed.columns[0].name, "LOWER(name)");
        assert_eq!(parsed.columns[0].sort, "DESC");
        assert_eq!(parsed.columns[1].collate, "NOCASE");
        assert_eq!(parsed.columns[1].sort, "ASC");
        assert_eq!(
            parsed.build(),
            "CREATE INDEX `idx` ON `t` (\n  LOWER(name) DESC,\n  `other` COLLATE NOCASE ASC\n)"
        );
    }

    #[test]
    fn rejects_invalid_expressions() {
        assert!(!parse_index("CREATE BOGUS INDEX").is_valid());
        assert!(!parse_index("CREATE INDEX idx").is_valid());
        assert!(!parse_index("").is_valid());
        assert!(!parse_index("CREATE INDEX idx ON t ()").is_valid());
    }

    #[test]
    fn finds_single_column_unique_indexes() {
        let indexes = vec![
            "CREATE INDEX `idx_a` ON `t` (`a`)".to_string(),
            "CREATE UNIQUE INDEX `idx_b` ON `t` (`b`) WHERE `b` != ''".to_string(),
        ];
        assert!(find_single_column_unique_index(&indexes, "b").is_some());
        assert!(find_single_column_unique_index(&indexes, "a").is_none());
    }
}
