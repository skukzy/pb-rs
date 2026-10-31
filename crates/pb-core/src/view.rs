//! View collections: query parsing, generated fields and dry-run.
//!
//! Port of `core/view.go` and the identifier parser from
//! `core/collection_query.go` (`normalizeViewQueryId`). The SQL text produced
//! here intentionally stays close to the oracle's, including the temp view
//! names, because the dry-run sample and the collection fields are observable
//! through the API.

use std::collections::HashMap;

use rusqlite::Connection;
use serde_json::{json, Map, Value};

use crate::collections::Collection;
use crate::fields::{self, FieldsList};
use crate::ids;
use crate::record_upsert::{prepare_value, FieldValue};
use crate::schema_sync;

/// `security.RandomString` alphabet used for temp names.
fn random_name(length: usize) -> String {
    ids::random_string_with_alphabet(length, ids::RANDOM_ALPHABET)
}

/// Quote a trusted SQL identifier the way `dbx.QuoteSimpleColumnName` does.
fn quote_ident(name: &str) -> String {
    format!("\"{}\"", name.replace('"', "\"\""))
}

/// `strings.Trim(strings.TrimSpace(s), ";")`.
fn trim_query(query: &str) -> String {
    query.trim().trim_matches(';').to_string()
}

// ---------------------------------------------------------------------------
// Tokenizer (`tools/tokenizer`)
// ---------------------------------------------------------------------------

struct Tokenizer {
    chars: Vec<char>,
    pos: usize,
    separators: Vec<char>,
    keep_separator: bool,
    trim_cutset: String,
}

impl Tokenizer {
    fn new(input: &str, separators: &[char]) -> Self {
        let mut tokenizer = Self {
            chars: input.chars().collect(),
            pos: 0,
            separators: separators.to_vec(),
            keep_separator: false,
            trim_cutset: String::new(),
        };
        tokenizer.rebuild_trim_cutset();
        tokenizer
    }

    fn keep_separator(mut self, state: bool) -> Self {
        self.keep_separator = state;
        self
    }

    fn rebuild_trim_cutset(&mut self) {
        // `whitespaceChars` from the Go tokenizer.
        let whitespace = ['\t', '\n', '\u{0b}', '\u{0c}', '\r', ' ', '\u{85}', '\u{a0}'];
        self.trim_cutset = whitespace
            .iter()
            .filter(|ch| !self.separators.contains(ch))
            .collect();
    }

    fn read(&mut self) -> Option<char> {
        let ch = self.chars.get(self.pos).copied();
        if ch.is_some() {
            self.pos += 1;
        }
        ch
    }

    fn read_token(&mut self) -> Result<String, String> {
        let mut buf = String::new();
        let mut parenthesis = 0i32;
        let mut quote_ch: Option<char> = None;
        let mut prev_ch = '\0';

        while let Some(ch) = self.read() {
            if prev_ch != '\\' {
                if ch == '(' && quote_ch.is_none() {
                    parenthesis += 1;
                } else if ch == ')' && parenthesis > 0 && quote_ch.is_none() {
                    parenthesis -= 1;
                } else if matches!(ch, '\'' | '"' | '`') {
                    if quote_ch == Some(ch) {
                        quote_ch = None;
                    } else if quote_ch.is_none() {
                        quote_ch = Some(ch);
                    }
                }
            }

            if self.separators.contains(&ch) && parenthesis == 0 && quote_ch.is_none() {
                if self.keep_separator {
                    buf.push(ch);
                }
                break;
            }

            prev_ch = ch;
            buf.push(ch);
        }

        if parenthesis > 0 || quote_ch.is_some() {
            return Err(format!(
                "unbalanced parenthesis or quoted expression: {}",
                go_quote(&buf)
            ));
        }

        Ok(buf
            .trim_matches(|ch| self.trim_cutset.contains(ch))
            .to_string())
    }

    fn scan(&mut self) -> Result<Option<String>, String> {
        loop {
            let Some(ch) = self.chars.get(self.pos).copied() else {
                return Ok(None);
            };
            if ch == '\0' {
                return Ok(None);
            }

            let token = self.read_token()?;
            if !token.is_empty() {
                return Ok(Some(token));
            }
        }
    }

    fn scan_all(mut self) -> Result<Vec<String>, String> {
        let mut tokens = Vec::new();
        while let Some(token) = self.scan()? {
            tokens.push(token);
        }
        Ok(tokens)
    }
}

/// Go's `%q` for a string (used in tokenizer/field error messages).
pub fn go_quote(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    out.push('"');
    for ch in value.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{07}' => out.push_str("\\a"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            '\u{0b}' => out.push_str("\\v"),
            ch if (ch as u32) < 0x20 => out.push_str(&format!("\\x{:02x}", ch as u32)),
            ch => out.push(ch),
        }
    }
    out.push('"');
    out
}

// ---------------------------------------------------------------------------
// Identifier parser
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct Identifier {
    original: String,
    alias: String,
}

#[derive(Debug, Default)]
struct Identifiers {
    columns: Vec<Identifier>,
    tables: Vec<Identifier>,
}

fn parse_identifiers(select_query: &str) -> Result<Identifiers, String> {
    let mut str = trim_query(select_query);

    let comments = regex::Regex::new(r"(?m)(/\*[\s\S]*?\*/)|(--.+$)").expect("valid regex");
    str = comments.replace_all(&str, " ").into_owned();

    let join = regex::Regex::new(
        r"(?im)[ \t\n\f\r]+(full[ \t\n\f\r]+outer[ \t\n\f\r]+join|left[ \t\n\f\r]+outer[ \t\n\f\r]+join|right[ \t\n\f\r]+outer[ \t\n\f\r]+join|full[ \t\n\f\r]+join|cross[ \t\n\f\r]+join|inner[ \t\n\f\r]+join|outer[ \t\n\f\r]+join|left[ \t\n\f\r]+join|right[ \t\n\f\r]+join|join)[ \t\n\f\r]+?",
    )
    .expect("valid regex");
    str = join.replace_all(&str, " __pb_join__ ").into_owned();

    let discard = regex::Regex::new(
        r"(?im)[ \t\n\f\r]+(where|group[ \t\n\f\r]+by|having|order|limit|with)[ \t\n\f\r]+?",
    )
    .expect("valid regex");
    str = discard.replace_all(&str, " __pb_discard__ ").into_owned();

    let mut tk = Tokenizer::new(&str, &[',', ' ', '\n', '\t']).keep_separator(true);

    let mut skip = false;
    let mut part_type = String::new();
    let mut select_parts = String::new();
    let mut from_parts = String::new();
    let mut join_parts = String::new();

    while let Some(token) = tk.scan()? {
        let trimmed = token.trim().to_lowercase();

        match trimmed.as_str() {
            "select" => {
                skip = false;
                part_type = "select".into();
            }
            "distinct" => continue,
            "from" => {
                skip = false;
                part_type = "from".into();
            }
            "__pb_join__" => {
                skip = false;
                if part_type == "join" {
                    join_parts.push(',');
                }
                part_type = "join".into();
            }
            "__pb_discard__" => skip = true,
            _ => {
                let is_join = part_type == "join";
                if is_join && trimmed == "on" {
                    skip = true;
                }
                if !skip {
                    let target = match part_type.as_str() {
                        "select" => Some(&mut select_parts),
                        "from" => Some(&mut from_parts),
                        "join" => Some(&mut join_parts),
                        _ => None,
                    };
                    if let Some(target) = target {
                        target.push(' ');
                        target.push_str(&token);
                    }
                }
            }
        }
    }

    let columns = extract_identifiers(&select_parts)?;
    let mut tables = extract_identifiers(&from_parts)?;
    tables.extend(extract_identifiers(&join_parts)?);

    Ok(Identifiers { columns, tables })
}

fn extract_identifiers(raw_expression: &str) -> Result<Vec<Identifier>, String> {
    let raw_tokens = Tokenizer::new(raw_expression, &[',']).scan_all()?;
    let mut result = Vec::with_capacity(raw_tokens.len());
    for raw_identifier in raw_tokens {
        let parts = Tokenizer::new(&raw_identifier, &[' ', '\n', '\t']).scan_all()?;
        result.push(identifier_from_parts(&parts)?);
    }
    Ok(result)
}

fn identifier_from_parts(parts: &[String]) -> Result<Identifier, String> {
    let (original, alias) = match parts.len() {
        3 => {
            if !parts[1].eq_ignore_ascii_case("as") {
                return Err(format!(
                    "invalid identifier part - expected \"as\", got {}",
                    parts[1]
                ));
            }
            (parts[0].clone(), parts[2].clone())
        }
        2 => (parts[0].clone(), parts[1].clone()),
        1 => {
            let sub_parts: Vec<&str> = parts[0].split('.').collect();
            (
                parts[0].clone(),
                sub_parts.last().copied().unwrap_or("").to_string(),
            )
        }
        _ => {
            return Err(format!(
                "invalid identifier parts [{}]",
                parts.join(" ")
            ))
        }
    };

    Ok(Identifier {
        original: trim_raw_identifier(&original, ""),
        alias: trim_raw_identifier(&alias, "'"),
    })
}

fn trim_raw_identifier(raw: &str, extra_trim_chars: &str) -> String {
    let mut trim_chars = String::from("`\"[];");
    trim_chars.push_str(extra_trim_chars);
    raw.split('.')
        .map(|part| part.trim_matches(|ch| trim_chars.contains(ch)))
        .collect::<Vec<_>>()
        .join(".")
}

// ---------------------------------------------------------------------------
// Query to fields
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct QueryField {
    field: Value,
}

fn default_view_field(name: &str) -> Value {
    if name == fields::FIELD_NAME_ID {
        default_view_id_field()
    } else {
        fields::from_request(&json!({
            "type": "json",
            "name": name,
            "maxSize": 1,
        }))
        .expect("static field")
    }
}

fn default_view_id_field() -> Value {
    fields::from_request(&json!({
        "type": "text",
        "name": fields::FIELD_NAME_ID,
        "system": true,
        "required": true,
        "primaryKey": true,
        "pattern": "^[a-z0-9]+$",
    }))
    .expect("static field")
}

fn find_collections_by_identifiers(
    conn: &Connection,
    tables: &[Identifier],
) -> Result<HashMap<String, Collection>, String> {
    let mut names: Vec<&str> = Vec::new();
    for table in tables {
        if table.alias.contains('(') {
            continue;
        }
        names.push(&table.original);
    }
    if names.is_empty() {
        return Ok(HashMap::new());
    }

    let collections = Collection::load_all(conn).map_err(|e| e.to_string())?;
    let mut result = HashMap::new();
    for table in tables {
        for collection in &collections {
            if collection.name == table.original {
                result.insert(table.alias.clone(), collection.clone());
            }
        }
    }
    Ok(result)
}

fn parse_query_to_fields(
    conn: &Connection,
    select_query: &str,
) -> Result<HashMap<String, QueryField>, String> {
    let parsed = parse_identifiers(select_query)?;
    let collections = find_collections_by_identifiers(conn, &parsed.tables)?;

    let mut result = HashMap::with_capacity(parsed.columns.len());
    let main_table = parsed.tables.first().cloned();

    let cast_regex = regex::Regex::new(r"(?is)^cast\s*\(.*\s+as\s+(\w+)\s*\)$").expect("valid regex");

    for col in &parsed.columns {
        if col.alias == "*" {
            return Err("wildcard columns (*) are not supported - manually type the collection field names you want the view query to have".into());
        }

        let col_lower = col.original.to_lowercase();

        if col.alias == fields::FIELD_NAME_ID {
            result.insert(
                col.alias.clone(),
                QueryField {
                    field: default_view_id_field(),
                },
            );
            continue;
        }

        if col_lower.starts_with("count(") {
            result.insert(
                col.alias.clone(),
                QueryField {
                    field: fields::from_request(&json!({
                        "type": "number",
                        "name": col.alias,
                        "onlyInt": true,
                    }))
                    .expect("static field"),
                },
            );
            continue;
        }
        if col_lower.starts_with("total(") {
            result.insert(
                col.alias.clone(),
                QueryField {
                    field: fields::from_request(&json!({
                        "type": "number",
                        "name": col.alias,
                    }))
                    .expect("static field"),
                },
            );
            continue;
        }

        if let Some(captures) = cast_regex.captures(&col_lower) {
            let target = captures.get(1).map(|m| m.as_str()).unwrap_or("");
            let field = match target {
                "real" | "decimal" | "numeric" => Some(fields::from_request(&json!({
                    "type": "number",
                    "name": col.alias,
                }))),
                "int" | "integer" => Some(fields::from_request(&json!({
                    "type": "number",
                    "name": col.alias,
                    "onlyInt": true,
                }))),
                "text" => Some(fields::from_request(&json!({
                    "type": "text",
                    "name": col.alias,
                }))),
                "boolean" | "bool" => Some(fields::from_request(&json!({
                    "type": "bool",
                    "name": col.alias,
                }))),
                _ => None,
            };
            if let Some(field) = field {
                result.insert(
                    col.alias.clone(),
                    QueryField {
                        field: field.expect("static field"),
                    },
                );
                continue;
            }
        }

        let parts: Vec<&str> = col.original.split('.').collect();
        let (field_name, collection) = if parts.len() == 2 {
            (
                parts[1].to_string(),
                collections.get(parts[0]).cloned(),
            )
        } else {
            (
                parts[0].to_string(),
                main_table
                    .as_ref()
                    .and_then(|table| collections.get(&table.alias))
                    .cloned(),
            )
        };

        let Some(collection) = collection else {
            result.insert(
                col.alias.clone(),
                QueryField {
                    field: default_view_field(&col.alias),
                },
            );
            continue;
        };

        let list = collection.field_list();
        let found = list
            .items()
            .iter()
            .find(|f| fields::field_name(f).eq_ignore_ascii_case(&field_name))
            .cloned();

        let Some(found) = found else {
            result.insert(
                col.alias.clone(),
                QueryField {
                    field: default_view_field(&col.alias),
                },
            );
            continue;
        };

        if field_name.eq_ignore_ascii_case(fields::FIELD_NAME_ID) {
            result.insert(
                col.alias.clone(),
                QueryField {
                    field: fields::from_request(&json!({
                        "type": "relation",
                        "name": col.alias,
                        "collectionId": collection.id,
                        "maxSelect": 1,
                    }))
                    .expect("static field"),
                },
            );
            continue;
        }

        let mut clone = found;
        if let Some(obj) = clone.as_object_mut() {
            obj.insert(
                "id".into(),
                Value::String(format!("_clone_{}", random_name(4))),
            );
            obj.insert("name".into(), Value::String(col.alias.clone()));
        }
        result.insert(
            col.alias.clone(),
            QueryField { field: clone },
        );
    }

    Ok(result)
}

// ---------------------------------------------------------------------------
// SQL view helpers
// ---------------------------------------------------------------------------

/// `BaseApp.TableInfo` (`PRAGMA_TABLE_INFO`), including the empty-result error.
pub fn table_info(conn: &Connection, table_name: &str) -> Result<Vec<(String, String)>, String> {
    let mut stmt = conn
        .prepare("SELECT name, type FROM PRAGMA_TABLE_INFO(?1)")
        .map_err(|e| schema_sync::go_sqlite_error(&e))?;
    let rows = stmt
        .query_map([table_name], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })
        .map_err(|e| schema_sync::go_sqlite_error(&e))?;

    let mut info = Vec::new();
    for row in rows {
        info.push(row.map_err(|e| schema_sync::go_sqlite_error(&e))?);
    }
    if info.is_empty() {
        return Err(format!(
            "empty table info probably due to invalid or missing table {table_name}"
        ));
    }
    Ok(info)
}

/// `BaseApp.DeleteView`.
pub fn delete_view(conn: &Connection, view_name: &str) -> Result<(), String> {
    conn.execute_batch(&format!("DROP VIEW IF EXISTS {}", quote_ident(view_name)))
        .map_err(|e| schema_sync::go_sqlite_error(&e))
}

/// `normalizeViewSelectQuery`.
pub fn normalize_view_select_query(query: &str) -> Result<String, String> {
    let query = trim_query(query);
    let parts = Tokenizer::new(&query, &[';']).scan_all().unwrap_or_default();
    if parts.len() > 1 {
        return Err("multiple statements are not supported".into());
    }
    Ok(query)
}

/// `BaseApp.SaveView`.
pub fn save_view(conn: &Connection, view_name: &str, query: &str) -> Result<(), String> {
    delete_view(conn, view_name)?;

    let query = normalize_view_select_query(query)?;
    let sql = format!(
        "CREATE VIEW {} AS SELECT * FROM ({})",
        quote_ident(view_name),
        query
    );
    conn.execute_batch(&sql)
        .map_err(|e| schema_sync::go_sqlite_error(&e))?;

    if let Err(err) = table_info(conn, view_name) {
        let _ = delete_view(conn, view_name);
        return Err(err);
    }

    Ok(())
}

fn get_query_table_info(
    conn: &Connection,
    select_query: &str,
) -> Result<Vec<(String, String)>, String> {
    let temp_view = format!("_temp_{}", random_name(6));
    save_view(conn, &temp_view, select_query)?;
    let info = table_info(conn, &temp_view);
    let deleted = delete_view(conn, &temp_view);
    match (info, deleted) {
        (Ok(info), Ok(())) => Ok(info),
        (Err(err), _) => Err(err),
        (Ok(_), Err(err)) => Err(err),
    }
}

/// `BaseApp.CreateViewFields`.
pub fn create_view_fields(conn: &Connection, select_query: &str) -> Result<FieldsList, String> {
    let suggested = parse_query_to_fields(conn, select_query)?;
    let info = get_query_table_info(conn, select_query)?;

    let mut result = FieldsList::new();
    let mut has_id = false;

    for (name, _ty) in info {
        if name == fields::FIELD_NAME_ID {
            has_id = true;
        }
        let field = suggested
            .get(&name)
            .map(|query_field| query_field.field.clone())
            .unwrap_or_else(|| default_view_field(&name));
        result.add(field);
    }

    if !has_id {
        return Err(
            "missing required id column (you can use `(ROW_NUMBER() OVER()) as id` if you don't have one)"
                .into(),
        );
    }

    Ok(result)
}

/// `normalizeViewQueryId`.
pub fn normalize_view_query_id(conn: &Connection, query: &str) -> Result<String, String> {
    let query = trim_query(query);
    let info = get_query_table_info(conn, &query)?;

    if info
        .iter()
        .any(|(name, ty)| name.eq_ignore_ascii_case("id") && ty.eq_ignore_ascii_case("TEXT"))
    {
        return Ok(query);
    }

    let parsed = parse_identifiers(&query)?;
    let columns: Vec<String> = parsed
        .columns
        .iter()
        .map(|col| {
            if col.alias == fields::FIELD_NAME_ID {
                format!(
                    "CAST({} as TEXT) {}",
                    quote_ident(&col.alias),
                    quote_ident(&col.alias)
                )
            } else {
                quote_ident(&col.alias)
            }
        })
        .collect();

    Ok(format!("SELECT {} FROM ({})", columns.join(","), query))
}

// ---------------------------------------------------------------------------
// Dry run
// ---------------------------------------------------------------------------

pub struct DryRunResult {
    pub fields: FieldsList,
    pub sample: Vec<Value>,
}

/// `BaseApp.DryRunView`.
pub fn dry_run(conn: &Connection, query: &str, sample_size: usize) -> Result<DryRunResult, String> {
    let query = normalize_view_select_query(query)?;

    let fields = create_view_fields(conn, &query)?;

    let temp_name = format!("temp_view_{}", random_name(5));
    let temp_collection = Collection {
        id: format!("pbc_{}", ids::crc32(&format!("view{temp_name}"))),
        system: false,
        kind: crate::collections::TYPE_VIEW.into(),
        name: temp_name.clone(),
        fields: fields.to_json(),
        indexes: Value::Array(vec![]),
        list_rule: None,
        view_rule: None,
        create_rule: None,
        update_rule: None,
        delete_rule: None,
        options: Value::Object(Map::new()),
        created: String::new(),
        updated: String::new(),
    };

    // validate generated view fields
    let all = Collection::load_all(conn).map_err(|e| e.to_string())?;
    for (i, field) in fields.items().iter().enumerate() {
        let errors = fields::validate_settings(field, &temp_collection, &all);
        if !errors.is_empty() {
            return Err(format!(
                "invalid field {} ({}): {}",
                go_quote(fields::field_name(field)),
                i,
                crate::validation::errors_display(&errors)
            ));
        }
    }
    let query = normalize_view_query_id(conn, &query)
        .map_err(|err| format!("failed to normalize view query id: {err}"))?;

    let sql = format!(
        "SELECT {}.* FROM (SELECT * FROM ({})) as {} LIMIT {}",
        quote_ident(&temp_name),
        query,
        temp_name,
        sample_size
    );
    let mut stmt = conn
        .prepare(&sql)
        .map_err(|e| format!("failed to retrieve query records: {}", schema_sync::go_sqlite_error(&e)))?;
    let column_names: Vec<String> = stmt.column_names().iter().map(|c| c.to_string()).collect();
    let mut rows = stmt
        .query([])
        .map_err(|e| format!("failed to retrieve query records: {}", schema_sync::go_sqlite_error(&e)))?;

    let mut sample = Vec::new();
    let mut seen_ids: Vec<String> = Vec::new();

    while let Some(row) = rows
        .next()
        .map_err(|e| format!("failed to retrieve query records: {}", schema_sync::go_sqlite_error(&e)))?
    {
        if sample.len() >= sample_size {
            break;
        }

        let mut record = Map::new();
        for field in fields.items() {
            let name = fields::field_name(field);
            let raw = column_names
                .iter()
                .position(|column| column == name)
                .and_then(|idx| row.get_ref(idx).ok())
                .and_then(sql_value_to_string);
            let raw_value = raw.as_ref().map(|s| Value::String(s.clone()));
            let value = prepare_value(field, raw_value.as_ref());
            let json = value.to_json(fields::is_multiple(field));

            if name == fields::FIELD_NAME_ID {
                let id = match &value {
                    FieldValue::Text(s) => s.clone(),
                    _ => String::new(),
                };
                if id.is_empty() {
                    return Err("the query could return records with empty or invalid ids".into());
                }
                if seen_ids.contains(&id) {
                    return Err("the query could return records with non-unique ids".into());
                }
                seen_ids.push(id);
            }

            if !fields::field_bool(field, "hidden") {
                record.insert(name.to_string(), json);
            }
        }

        record.insert(
            "collectionId".into(),
            Value::String(temp_collection.id.clone()),
        );
        record.insert(
            "collectionName".into(),
            Value::String(temp_collection.name.clone()),
        );
        sample.push(Value::Object(record));
    }

    Ok(DryRunResult { fields, sample })
}

/// `database/sql.convertAssign` to `*string` (dbx `NullStringMap`).
fn sql_value_to_string(raw: rusqlite::types::ValueRef<'_>) -> Option<String> {
    use rusqlite::types::ValueRef;
    match raw {
        ValueRef::Null => None,
        ValueRef::Integer(i) => Some(i.to_string()),
        ValueRef::Real(f) => Some(crate::go_json::format_float(f)),
        ValueRef::Text(bytes) => Some(String::from_utf8_lossy(bytes).into_owned()),
        ValueRef::Blob(bytes) => Some(String::from_utf8_lossy(bytes).into_owned()),
    }
}
