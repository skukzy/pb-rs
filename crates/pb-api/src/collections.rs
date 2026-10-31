//! Collection endpoints (read-only in M2a).
//!
//! `GET /api/collections`, `GET /api/collections/{collection}` and the two
//! `meta` payloads are superuser only. The serialization lives in
//! `pb_core::collections`; pagination and sorting follow
//! `tools/search/provider.go` so the envelope matches the oracle exactly.

use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use pb_core::collection_write::{self, SaveError};
use pb_core::collections::Collection;
use pb_core::validation;
use pb_core::view;
use serde::Deserialize;
use serde_json::{json, Value};

use crate::auth::{require_superuser, Db};
use crate::error::ApiError;

/// `search.DefaultPerPage`
const DEFAULT_PER_PAGE: i64 = 30;
/// `search.MaxPerPage`
const MAX_PER_PAGE: i64 = 1000;

/// The collections list only resolves these sort fields
/// (`apis/collection.go`: `search.NewSimpleFieldResolver(...)`).
const SORT_FIELDS: &[&str] = &["id", "created", "updated", "name", "system", "type"];

/// Raw query values: they stay strings so that invalid numbers/bools can be
/// reported exactly like `strconv` failures do (400 + generic message).
#[derive(Debug, Default, Deserialize)]
pub struct ListParams {
    pub page: Option<String>,
    #[serde(rename = "perPage")]
    pub per_page: Option<String>,
    #[serde(rename = "skipTotal")]
    pub skip_total: Option<String>,
    pub sort: Option<String>,
    pub filter: Option<String>,
}

/// `NewBadRequestError("", err)`: status 400 with the generic message.
fn search_error() -> ApiError {
    ApiError::new(
        StatusCode::BAD_REQUEST,
        "Something went wrong while processing your request.",
        json!({}),
    )
}

/// A generic search error carrying the oracle's internal error string.
fn search_error_raw(raw: impl Into<String>) -> ApiError {
    search_error().with_raw_data(json!(raw.into()))
}

/// `strconv.Atoi`.
fn parse_int(raw: &str) -> Result<i64, ApiError> {
    crate::records::go_atoi(raw).map_err(search_error_raw)
}

/// `strconv.ParseBool`.
fn parse_bool(raw: &str) -> Result<bool, ApiError> {
    match raw {
        "1" | "t" | "T" | "TRUE" | "true" | "True" => Ok(true),
        "0" | "f" | "F" | "FALSE" | "false" | "False" => Ok(false),
        _ => Err(search_error_raw(crate::records::go_parse_bool_error(raw))),
    }
}

/// A resolved `search.SortField`.
#[derive(Debug, Clone, PartialEq)]
struct SortField {
    name: String,
    descending: bool,
}

/// `search.ParseSortFromString`.
fn parse_sort(raw: &str) -> Vec<SortField> {
    raw.split(',')
        .map(str::trim)
        .map(|field| {
            let (name, descending) = match field.strip_prefix('-') {
                Some(rest) => (rest, true),
                None => (field.strip_prefix('+').unwrap_or(field), false),
            };
            SortField {
                name: name.to_string(),
                descending,
            }
        })
        .collect()
}

/// `SortField.BuildExpr`: only the whitelisted fields, `@rowid` and `@random`
/// resolve; anything else is an error.
fn validate_sort(fields: &[SortField]) -> Result<(), ApiError> {
    for field in fields {
        match field.name.as_str() {
            "@random" | "@rowid" => {}
            name if SORT_FIELDS.contains(&name) => {}
            _ => {
                return Err(search_error_raw(format!(
                    "invalid sort field {}",
                    pb_core::fields::go_quote(&field.name)
                )))
            }
        }
    }
    Ok(())
}

fn compare_field(a: &Collection, b: &Collection, field: &str) -> std::cmp::Ordering {
    match field {
        "id" => a.id.cmp(&b.id),
        "created" => a.created.cmp(&b.created),
        "updated" => a.updated.cmp(&b.updated),
        "name" => a.name.cmp(&b.name),
        "type" => a.kind.cmp(&b.kind),
        "system" => a.system.cmp(&b.system),
        _ => std::cmp::Ordering::Equal,
    }
}

/// Apply the sort chain the way SQLite would: the first field dominates and
/// ties keep the incoming order (`_collections` is read in `rowid` order).
fn apply_sort(items: &mut [Collection], fields: &[SortField]) {
    if fields.is_empty() {
        return;
    }
    if fields.iter().any(|f| f.name == "@random") {
        use rand::seq::SliceRandom;
        items.shuffle(&mut rand::thread_rng());
        // A mixed `@random` chain is not meaningful; the oracle applies RANDOM()
        // as one sort key among others, which for a single sort key is a shuffle.
        return;
    }

    // `@rowid` is the incoming order, so it needs no work.
    let keys: Vec<&SortField> = fields.iter().filter(|f| f.name != "@rowid").collect();
    items.sort_by(|a, b| {
        for key in &keys {
            let ord = compare_field(a, b, &key.name);
            let ord = if key.descending { ord.reverse() } else { ord };
            if ord != std::cmp::Ordering::Equal {
                return ord;
            }
        }
        std::cmp::Ordering::Equal
    });
}

fn json_to_sqlite(value: &Value) -> rusqlite::types::Value {
    match value {
        Value::Null => rusqlite::types::Value::Null,
        Value::Bool(b) => rusqlite::types::Value::Integer(i64::from(*b)),
        Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                rusqlite::types::Value::Integer(i)
            } else {
                rusqlite::types::Value::Real(n.as_f64().unwrap_or_default())
            }
        }
        Value::String(s) => rusqlite::types::Value::Text(s.clone()),
        other => rusqlite::types::Value::Text(other.to_string()),
    }
}

/// `GET /api/collections`
pub async fn list(
    State(db): State<Db>,
    headers: HeaderMap,
    Query(params): Query<ListParams>,
) -> Result<Json<Value>, ApiError> {
    require_superuser(&db, &headers)?;

    // Parse first: the oracle validates the query string before touching the DB.
    let mut page = match &params.page {
        Some(raw) => parse_int(raw)?,
        None => 1,
    };
    let mut per_page = match &params.per_page {
        Some(raw) => parse_int(raw)?,
        None => DEFAULT_PER_PAGE,
    };
    let skip_total = match &params.skip_total {
        Some(raw) => parse_bool(raw)?,
        None => false,
    };
    let sort = params
        .sort
        .as_deref()
        .filter(|raw| !raw.is_empty())
        .map(parse_sort)
        .unwrap_or_default();
    if sort.len() > pb_core::search::DEFAULT_SORT_EXPR_LIMIT {
        return Err(search_error_raw(pb_core::search::ERR_SORT_EXPR_LIMIT));
    }
    if sort
        .iter()
        .any(|field| field.name.len() > pb_core::search::MAX_SORT_FIELD_LENGTH)
    {
        return Err(search_error_raw(pb_core::search::ERR_SORT_FIELD_LENGTH_LIMIT));
    }
    validate_sort(&sort)?;

    // `Provider.Exec` normalization.
    if page <= 0 {
        page = 1;
    }
    if per_page <= 0 {
        per_page = DEFAULT_PER_PAGE;
    } else if per_page > MAX_PER_PAGE {
        per_page = MAX_PER_PAGE;
    }

    let conn = db
        .lock()
        .map_err(|_| ApiError::internal("database lock poisoned"))?;
    let mut collections = Collection::load_all(&conn)
        .map_err(|e| ApiError::internal(format!("failed to load collections: {e}")))?;

    // `filter` is resolved by `search.NewSimpleFieldResolver(...)` against the
    // `_collections` table itself.
    if let Some(filter) = params.filter.as_deref().filter(|f| !f.is_empty()) {
        let allowed: Vec<String> = SORT_FIELDS.iter().map(|f| f.to_string()).collect();
        pb_core::search::check_filter_length(filter)
            .map_err(|err| search_error_raw(err.0))?;
        let expr =
            pb_core::search::parse_limited(filter).map_err(|err| search_error_raw(err.0))?;
        let sf = pb_core::search::build_sql_simple(&expr, &allowed, false)
            .map_err(|err| search_error_raw(err.0))?;
        let sql = format!("SELECT id FROM _collections WHERE {}", sf.sql);
        let sql_params: Vec<rusqlite::types::Value> =
            sf.params.iter().map(json_to_sqlite).collect();
        let mut stmt = conn.prepare(&sql).map_err(|_| search_error())?;
        let ids: std::collections::HashSet<String> = stmt
            .query_map(rusqlite::params_from_iter(sql_params), |r| r.get::<_, String>(0))
            .map_err(|_| search_error())?
            .filter_map(Result::ok)
            .collect();
        collections.retain(|c| ids.contains(&c.id));
    }
    drop(conn);

    apply_sort(&mut collections, &sort);

    let total_items = if skip_total {
        -1
    } else {
        collections.len() as i64
    };
    let total_pages = if skip_total {
        -1
    } else {
        ((total_items + per_page - 1) / per_page).max(0)
    };

    let offset = per_page.saturating_mul(page - 1);
    let items: Vec<Value> = collections
        .iter()
        .skip(usize::try_from(offset).unwrap_or(usize::MAX))
        .take(per_page as usize)
        .map(Collection::to_api_json)
        .collect();

    Ok(Json(json!({
        "items": items,
        "page": page,
        "perPage": per_page,
        "totalItems": total_items,
        "totalPages": total_pages,
    })))
}

/// `GET /api/collections/{collection}` (id or name)
pub async fn view(
    State(db): State<Db>,
    headers: HeaderMap,
    Path(id_or_name): Path<String>,
) -> Result<Json<Value>, ApiError> {
    require_superuser(&db, &headers)?;

    let conn = db
        .lock()
        .map_err(|_| ApiError::internal("database lock poisoned"))?;
    let collection = Collection::find(&conn, &id_or_name)
        .map_err(|e| ApiError::internal(format!("failed to load collection: {e}")))?
        .ok_or_else(|| ApiError::not_found("The requested resource wasn't found.").with_raw_data(serde_json::json!("sql: no rows in result set")))?;

    Ok(Json(collection.to_api_json()))
}

/// Serve an embedded payload byte for byte, as `application/json`.
fn embedded_json(body: String) -> Response {
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/json")],
        body,
    )
        .into_response()
}

/// `GET /api/collections/meta/scaffolds`
pub async fn scaffolds(
    State(db): State<Db>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    require_superuser(&db, &headers)?;
    Ok(embedded_json(pb_core::assets::collection_scaffolds()))
}

/// `GET /api/collections/meta/oauth2-providers`
pub async fn oauth2_providers(
    State(db): State<Db>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    require_superuser(&db, &headers)?;
    Ok(embedded_json(pb_core::assets::OAUTH2_PROVIDERS.to_string()))
}

/// `e.BadRequestError("Failed to load the collection type data due to invalid formatting.", err)`
fn type_load_error() -> ApiError {
    ApiError::bad_request("Failed to load the collection type data due to invalid formatting.")
}

/// `e.BadRequestError("Failed to load the submitted data due to invalid formatting.", err)`
fn submitted_load_error() -> ApiError {
    ApiError::bad_request("Failed to load the submitted data due to invalid formatting.")
}

/// `POST /api/collections/meta/dry-run-view`
pub async fn dry_run_view(
    State(db): State<Db>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, ApiError> {
    require_superuser(&db, &headers)?;

    let payload = match crate::body::bind_json(&headers, &body) {
        Ok(Some(value)) => value,
        Ok(None) => Value::Null,
        Err(()) => {
            return Err(ApiError::bad_request(
                "An error occurred while loading the submitted data.",
            ))
        }
    };

    // `e.BindBody(&dryRunViewForm{})`: a JSON object binds `query` (null and
    // missing values keep the zero value); any other JSON shape fails.
    let query = match payload {
        Value::Null => String::new(),
        Value::Object(map) => match map.get("query") {
            None | Some(Value::Null) => String::new(),
            Some(Value::String(value)) => value.clone(),
            Some(_) => {
                return Err(ApiError::bad_request(
                    "An error occurred while loading the submitted data.",
                ))
            }
        },
        _ => {
            return Err(ApiError::bad_request(
                "An error occurred while loading the submitted data.",
            ))
        }
    };

    let mut errors = validation::Errors::new();
    if query.is_empty() {
        errors.insert("query".into(), validation::required());
    } else if let Some(err) = validation::length(&query, 0, 5000) {
        errors.insert("query".into(), err);
    }
    if !errors.is_empty() {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "An error occurred while validating the submitted data.",
            validation::errors_to_value(&errors),
        )
        .with_raw_data(validation::errors_to_log_value(&errors)));
    }

    let conn = db
        .lock()
        .map_err(|_| ApiError::internal("database lock poisoned"))?;

    match view::dry_run(&conn, &query, 10) {
        Ok(result) => {
            let mut out = serde_json::Map::new();
            out.insert("fields".into(), result.fields.to_json());
            out.insert("sample".into(), Value::Array(result.sample));
            Ok(Json(Value::Object(out)).into_response())
        }
        Err(err) => Err(ApiError::bad_request(format!(
            "Invalid view query. Raw error: \n{err}"
        ))),
    }
}

/// `POST /api/collections`
///
/// `apis/collection.go: collectionCreate`: bind the minimal factory data, build
/// the scaffold, bind the full payload onto it, then save (normalize → validate
/// → sync the record table).
pub async fn create(
    State(db): State<Db>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, ApiError> {
    require_superuser(&db, &headers)?;

    let payload = match crate::body::bind_json(&headers, &body) {
        Ok(Some(value)) => value,
        Ok(None) => Value::Null,
        Err(()) => return Err(type_load_error()),
    };

    let (kind, name) =
        collection_write::factory_extract(&payload).map_err(|_| type_load_error())?;

    let mut draft = collection_write::factory(&kind, &name);
    collection_write::apply_request(&mut draft, &payload).map_err(|_| submitted_load_error())?;

    let mut conn = db
        .lock()
        .map_err(|_| ApiError::internal("database lock poisoned"))?;
    let all = Collection::load_all(&conn)
        .map_err(|e| ApiError::internal(format!("failed to load collections: {e}")))?;

    match collection_write::save(&mut conn, &mut draft, &all) {
        Ok(()) => {
            pb_core::collections::Collection::invalidate_cache();
            Ok(Json(draft.collection.to_api_json()).into_response())
        }
        Err(SaveError::Validation(errors)) => Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "Failed to create collection.",
            validation::errors_to_value(&errors),
        )
        .with_raw_data(validation::errors_to_log_value(&errors))),
        // `e.BadRequestError("Failed to create collection. Raw error: \n"+err.Error(), nil)`
        Err(SaveError::NotFound) => Err(ApiError::not_found("The requested resource wasn't found.")),
        Err(SaveError::Raw(message)) => Err(ApiError::bad_request(format!(
            "Failed to create collection. Raw error: \n{message}"
        ))),
    }
}

/// `PATCH /api/collections/{collection}`
pub async fn update(
    State(db): State<Db>,
    headers: HeaderMap,
    Path(id_or_name): Path<String>,
    body: Bytes,
) -> Result<Response, ApiError> {
    require_superuser(&db, &headers)?;

    let mut conn = db
        .lock()
        .map_err(|_| ApiError::internal("database lock poisoned"))?;
    let original = Collection::find(&conn, &id_or_name)
        .map_err(|e| ApiError::internal(format!("failed to load collection: {e}")))?
        .ok_or_else(|| ApiError::not_found("The requested resource wasn't found.").with_raw_data(serde_json::json!("sql: no rows in result set")))?;

    let payload = match crate::body::bind_json(&headers, &body) {
        Ok(Some(value)) => value,
        Ok(None) => Value::Null,
        Err(()) => return Err(submitted_load_error()),
    };

    let mut draft = collection_write::Draft {
        collection: original.clone(),
        autogenerated_id: original.id.clone(),
    };

    collection_write::apply_request(&mut draft, &payload).map_err(|_| submitted_load_error())?;

    let all = Collection::load_all(&conn)
        .map_err(|e| ApiError::internal(format!("failed to load collections: {e}")))?;
    let original_for_save = original.clone();

    match collection_write::save_update(&mut conn, &mut draft, &original_for_save, &all) {
        Ok(()) => {
            pb_core::collections::Collection::invalidate_cache();
            Ok(Json(draft.collection.to_api_json()).into_response())
        }
        Err(collection_write::SaveError::Validation(errors)) => Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "Failed to update collection.",
            validation::errors_to_value(&errors),
        )
        .with_raw_data(validation::errors_to_log_value(&errors))),
        Err(collection_write::SaveError::NotFound) => {
            Err(ApiError::not_found("The requested resource wasn't found."))
        }
        Err(collection_write::SaveError::Raw(message)) => Err(ApiError::bad_request(format!(
            "Failed to update collection. Raw error: \n{message}"
        ))),
    }
}

#[derive(Deserialize)]
struct ImportForm {
    collections: Option<Vec<Value>>,
    #[serde(rename = "deleteMissing")]
    delete_missing: Option<bool>,
}

/// `PUT /api/collections/import`
pub async fn import(
    State(db): State<Db>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, ApiError> {
    require_superuser(&db, &headers)?;

    let payload = match crate::body::bind_json(&headers, &body) {
        Ok(Some(value)) => value,
        Ok(None) => Value::Null,
        Err(()) => return Err(submitted_load_error()),
    };

    let form: ImportForm = serde_json::from_value(payload).map_err(|_| submitted_load_error())?;
    let collections = form.collections.unwrap_or_default();
    if collections.is_empty() {
        let mut errs = validation::Errors::new();
        errs.insert(
            "collections".into(),
            validation::required(),
        );
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "An error occurred while validating the submitted data.",
            validation::errors_to_value(&errs),
        )
        .with_raw_data(validation::errors_to_log_value(&errs)));
    }
    let delete_missing = form.delete_missing.unwrap_or(false);

    let mut conn = db
        .lock()
        .map_err(|_| ApiError::internal("database lock poisoned"))?;

    match collection_write::import_collections(&mut conn, &collections, delete_missing) {
        Ok(()) => {
            pb_core::collections::Collection::invalidate_cache();
            Ok(StatusCode::NO_CONTENT.into_response())
        }
        Err(collection_write::SaveError::Validation(errors)) => Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "Failed to import collections.",
            validation::errors_to_value(&errors),
        )
        .with_raw_data(validation::errors_to_log_value(&errors))),
        Err(collection_write::SaveError::NotFound) => {
            Err(ApiError::not_found("The requested resource wasn't found."))
        }
        Err(collection_write::SaveError::Raw(message)) => Err(ApiError::bad_request(format!(
            "Failed to import collections. (raw: {message})"
        ))),
    }
}

/// `DELETE /api/collections/{collection}`
pub async fn delete(
    State(db): State<Db>,
    headers: HeaderMap,
    Path(id_or_name): Path<String>,
) -> Result<Response, ApiError> {
    require_superuser(&db, &headers)?;

    let mut conn = db
        .lock()
        .map_err(|_| ApiError::internal("database lock poisoned"))?;
    let collection = Collection::find(&conn, &id_or_name)
        .map_err(|e| ApiError::internal(format!("failed to load collection: {e}")))?
        .ok_or_else(|| ApiError::not_found("The requested resource wasn't found.").with_raw_data(serde_json::json!("sql: no rows in result set")))?;

    let all = Collection::load_all(&conn)
        .map_err(|e| ApiError::internal(format!("failed to load collections: {e}")))?;
    let references = collection_write::find_references(&collection, &all);

    match collection_write::delete(&mut conn, &collection) {
        Ok(()) => {
            pb_core::collections::Collection::invalidate_cache();
            Ok(StatusCode::NO_CONTENT.into_response())
        }
        Err(_) => {
            let mut message = String::from("Failed to delete collection");
            if !references.is_empty() {
                message.push_str(" probably due to existing reference in ");
                message.push_str(&references.join(", "));
            }
            Err(ApiError::bad_request(validation::sentenize(&message)))
        }
    }
}

/// `DELETE /api/collections/{collection}/truncate`
pub async fn truncate(
    State(db): State<Db>,
    headers: HeaderMap,
    Path(id_or_name): Path<String>,
) -> Result<Response, ApiError> {
    require_superuser(&db, &headers)?;

    let mut conn = db
        .lock()
        .map_err(|_| ApiError::internal("database lock poisoned"))?;
    let collection = Collection::find(&conn, &id_or_name)
        .map_err(|e| ApiError::internal(format!("failed to load collection: {e}")))?
        .ok_or_else(|| ApiError::not_found("The requested resource wasn't found.").with_raw_data(serde_json::json!("sql: no rows in result set")))?;

    if collection.is_view() {
        return Err(ApiError::bad_request(
            "View collections cannot be truncated since they don't store their own records.",
        ));
    }

    match collection_write::truncate(&mut conn, &collection) {
        Ok(()) => Ok(StatusCode::NO_CONTENT.into_response()),
        Err(err) => {
            // `e.BadRequestError(message, err)`: the raw data is the underlying
            // error (a plain string, or the hook's ApiError object).
            let raw = match err {
                pb_core::record_delete::DeleteError::Api { message } => json!({
                    "data": {},
                    "message": pb_core::validation::sentenize(&message),
                    "status": 400,
                }),
                pb_core::record_delete::DeleteError::Raw(message) => json!(message),
            };
            Err(ApiError::bad_request(
                "Failed to truncate collection (most likely due to required cascade delete record references).",
            )
            .with_raw_data(raw))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn collection(name: &str, kind: &str, system: bool, created: &str) -> Collection {
        Collection {
            id: format!("id_{name}"),
            system,
            kind: kind.into(),
            name: name.into(),
            fields: Value::Array(vec![]),
            indexes: Value::Array(vec![]),
            list_rule: None,
            view_rule: None,
            create_rule: None,
            update_rule: None,
            delete_rule: None,
            options: Value::Object(Default::default()),
            created: created.into(),
            updated: created.into(),
        }
    }

    #[test]
    fn parses_the_oracle_sort_syntax() {
        let fields = parse_sort("-name,+created,type");
        assert_eq!(
            fields,
            vec![
                SortField { name: "name".into(), descending: true },
                SortField { name: "created".into(), descending: false },
                SortField { name: "type".into(), descending: false },
            ]
        );
    }

    #[test]
    fn rejects_unknown_sort_fields_like_the_oracle() {
        assert!(validate_sort(&parse_sort("nope")).is_err());
        assert!(validate_sort(&parse_sort("NAME")).is_err());
        assert!(validate_sort(&parse_sort("name")).is_ok());
        assert!(validate_sort(&parse_sort("@rowid")).is_ok());
        assert!(validate_sort(&parse_sort("@random")).is_ok());
    }

    #[test]
    fn sorts_by_multiple_keys_with_ties_preserved() {
        let mut items = vec![
            collection("b", "base", false, "2024-01-02"),
            collection("a", "auth", true, "2024-01-01"),
            collection("c", "base", true, "2024-01-03"),
        ];
        apply_sort(&mut items, &parse_sort("type,-name"));
        let names: Vec<_> = items.iter().map(|c| c.name.as_str()).collect();
        assert_eq!(names, vec!["a", "c", "b"]);

        apply_sort(&mut items, &parse_sort("-system"));
        let names: Vec<_> = items.iter().map(|c| c.name.as_str()).collect();
        assert_eq!(names, vec!["a", "c", "b"]);
    }

    #[test]
    fn skip_total_marker_matches_the_oracle() {
        assert_eq!(parse_bool("1").unwrap(), true);
        assert_eq!(parse_bool("0").unwrap(), false);
        assert_eq!(parse_bool("true").unwrap(), true);
        assert!(parse_bool("yes").is_err());
        assert!(parse_int("abc").is_err());
    }
}
