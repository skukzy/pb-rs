//! Record deletion with relation cascades.
//!
//! Mirrors `core/record_model.go`'s `onRecordDeleteExecute` /
//! `cascadeRecordDelete`:
//!
//! 1. delete the row,
//! 2. for every collection whose relation fields point at it, unset the
//!    deleted id from the referencing records,
//! 3. recursively delete referencing records when the field has
//!    `cascadeDelete` and no other references remain,
//! 4. fail when a `required` field would be left empty.
//!
//! The whole operation is wrapped in a savepoint so it nests inside the batch
//! endpoint's `pb_batch` savepoint. The `_superusers` request hook (rejecting
//! the deletion of the last superuser) is checked per record, exactly like the
//! oracle's `onRecordDeleteRequest` handler.

use rusqlite::Connection;
use serde_json::Value;

use crate::collections::Collection;
use crate::fields;
use crate::record_upsert::{FieldValue, RecordModel};
use crate::records::quote_ident;

/// A record removed by [`delete_record`] (top-level or cascaded), used by the
/// API layer to emit the matching realtime `delete` events.
pub struct DeletedRecord {
    pub collection: Collection,
    pub record: RecordModel,
}

/// `app.Delete` failure: either an already-formed API error (the superuser
/// guard hook) or a plain error wrapped by the endpoint.
#[derive(Debug)]
pub enum DeleteError {
    /// `*router.ApiError` raised by a hook; the endpoint returns it as-is.
    Api { message: String },
    /// Plain error; the endpoint wraps it with its own message and raw data.
    Raw(String),
}

/// Delete `record` and apply its relation cascades in one savepoint.
pub fn delete_record(
    conn: &mut Connection,
    collection: &Collection,
    record: &RecordModel,
) -> Result<Vec<DeletedRecord>, DeleteError> {
    let all = Collection::load_all(conn).map_err(|e| DeleteError::Raw(e.to_string()))?;

    conn.execute_batch("SAVEPOINT pb_delete")
        .map_err(|e| DeleteError::Raw(e.to_string()))?;

    let mut deleted = Vec::new();
    match delete_record_tx(conn, &all, collection, record, &mut deleted) {
        Ok(()) => {
            conn.execute_batch("RELEASE pb_delete")
                .map_err(|e| DeleteError::Raw(e.to_string()))?;
            Ok(deleted)
        }
        Err(err) => {
            let _ = conn.execute_batch("ROLLBACK TO pb_delete; RELEASE pb_delete");
            Err(err)
        }
    }
}

/// Delete a record whose row is still present. Shared by the top-level delete
/// and the recursive cascade (the savepoint belongs to the outermost call).
pub fn delete_record_in_savepoint(
    conn: &Connection,
    all: &[Collection],
    collection: &Collection,
    record: &RecordModel,
    deleted: &mut Vec<DeletedRecord>,
) -> Result<(), DeleteError> {
    delete_record_tx(conn, all, collection, record, deleted)
}

fn delete_record_tx(
    conn: &Connection,
    all: &[Collection],
    collection: &Collection,
    record: &RecordModel,
    deleted: &mut Vec<DeletedRecord>,
) -> Result<(), DeleteError> {
    // `onRecordDeleteRequest` superuser guard (priority -99).
    if collection.name == "_superusers" {
        let total: i64 = conn
            .query_row("SELECT count(*) FROM `_superusers`", [], |row| row.get(0))
            .map_err(|e| DeleteError::Raw(e.to_string()))?;
        if total == 1 {
            return Err(DeleteError::Api {
                message: "You can't delete the only existing superuser".into(),
            });
        }
    }

    // `FindCachedCollectionReferences`: (collection, relation fields) pairs,
    // sorted by collection name so the cascade order is deterministic.
    let mut refs: Vec<(&Collection, Vec<Value>)> = Vec::new();
    for other in all {
        // Self-relations are included; `cascade_field` excludes the record
        // itself from the reference query.
        let mut matched: Vec<Value> = Vec::new();
        for field in other.field_list().items() {
            if fields::field_type(field) == "relation"
                && fields::field_str(field, "collectionId") == collection.id
            {
                matched.push(field.clone());
            }
        }
        if !matched.is_empty() {
            refs.push((other, matched));
        }
    }
    refs.sort_by(|a, b| a.0.name.cmp(&b.0.name));

    let sql = format!(
        "DELETE FROM {} WHERE {} = ?1",
        quote_ident(&collection.name),
        quote_ident("id")
    );
    conn.execute(&sql, [record.id()])
        .map_err(|e| DeleteError::Raw(e.to_string()))?;
    deleted.push(DeletedRecord {
        collection: collection.clone(),
        record: record.clone(),
    });

    for (ref_collection, ref_fields) in refs {
        if ref_collection.is_view() {
            continue;
        }
        for field in &ref_fields {
            cascade_field(conn, all, collection, record, ref_collection, field, deleted)?;
        }
    }

    Ok(())
}

/// `cascadeRecordDelete` for one referencing collection/field pair.
fn cascade_field(
    conn: &Connection,
    all: &[Collection],
    main_collection: &Collection,
    main_record: &RecordModel,
    ref_collection: &Collection,
    field: &Value,
    deleted: &mut Vec<DeletedRecord>,
) -> Result<(), DeleteError> {
    let field_name = fields::field_name(field);
    let multiple = fields::is_multiple(field);
    let table = quote_ident(&ref_collection.name);
    let column = quote_ident(field_name);

    let mut base = if multiple {
        format!(
            "SELECT id FROM {table} WHERE EXISTS (SELECT 1 FROM json_each({column}) WHERE value = ?1)"
        )
    } else {
        format!("SELECT id FROM {table} WHERE {column} = ?1")
    };
    // Self-relations must not re-select the record that is being deleted.
    let same_collection = ref_collection.id == main_collection.id;
    if same_collection {
        base.push_str(" AND id <> ?2");
    }

    // The oracle pages through references in batches of 8000 and re-queries
    // after each batch, because deletes/updates shrink the result set.
    loop {
        let ids: Vec<String> = {
            let sql = format!("{base} LIMIT 8000");
            let mut stmt = conn
                .prepare(&sql)
                .map_err(|e| DeleteError::Raw(e.to_string()))?;
            let rows = if same_collection {
                stmt.query(rusqlite::params![main_record.id(), main_record.id()])
            } else {
                stmt.query([main_record.id()])
            }
            .map_err(|e| DeleteError::Raw(e.to_string()))?;
            let mut rows = rows;
            let mut ids = Vec::new();
            while let Some(row) = rows.next().map_err(|e| DeleteError::Raw(e.to_string()))? {
                ids.push(row.get::<_, String>(0).map_err(|e| DeleteError::Raw(e.to_string()))?);
            }
            ids
        };

        if ids.is_empty() {
            break;
        }
        let total = ids.len();

        for id in ids {
            let Some(ref_record) = RecordModel::find_by_id(conn, ref_collection, &id)
                .map_err(|e| DeleteError::Raw(e.to_string()))?
            else {
                // Already deleted by a previous cascade in this savepoint.
                continue;
            };

            let mut items = match ref_record.get_raw(field_name) {
                Some(FieldValue::List(items)) => items,
                _ => Vec::new(),
            };
            for i in (0..items.len()).rev() {
                if items[i] == main_record.id() {
                    items.remove(i);
                    break;
                }
            }

            if fields::field_bool(field, "cascadeDelete") && items.is_empty() {
                delete_record_tx(conn, all, ref_collection, &ref_record, deleted)?;
                continue;
            }

            if fields::field_bool(field, "required") && items.is_empty() {
                return Err(DeleteError::Raw(format!(
                    "the record cannot be deleted because it is part of a required reference in record {} ({} collection)",
                    ref_record.id(),
                    ref_collection.name
                )));
            }

            // `SaveNoValidate`: write only the relation column (user tables
            // have no created/updated columns).
            let value = if multiple {
                rusqlite::types::Value::Text(crate::go_json::marshal(&Value::Array(
                    items.into_iter().map(Value::String).collect(),
                )))
            } else {
                rusqlite::types::Value::Text(items.last().cloned().unwrap_or_default())
            };
            conn.execute(
                &format!("UPDATE {table} SET {column} = ?1 WHERE id = ?2"),
                rusqlite::params![value, ref_record.id()],
            )
            .map_err(|e| DeleteError::Raw(e.to_string()))?;
        }

        if total < 8000 {
            break;
        }
    }

    Ok(())
}
