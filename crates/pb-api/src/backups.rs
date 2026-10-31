//! `/api/backups` endpoints (local filesystem only).
//!
//! Backups live in `<pb_data>/backups`. Creating a backup zips the data
//! directory using `VACUUM INTO` snapshots of `data.db`/`auxiliary.db`, like
//! the oracle, and excludes the backups/temp/notify/autocert directories.

use std::collections::HashMap;
use std::fs;
use std::io::Read;
use std::path::{Path as FsPath, PathBuf};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::body::Bytes;
use axum::extract::{Multipart, Path, Query, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use pb_core::collections::Collection;
use pb_core::records::Record;
use pb_core::tokens;
use pb_core::validation::{self, Errors};
use serde_json::{json, Value};

use crate::auth::{require_superuser, Db};
use crate::error::ApiError;
use crate::records::DATA_DIR;

const BACKUPS_DIR: &str = "backups";

static ACTIVE_BACKUP: OnceLock<Mutex<Option<String>>> = OnceLock::new();

fn active() -> &'static Mutex<Option<String>> {
    ACTIVE_BACKUP.get_or_init(|| Mutex::new(None))
}

fn data_dir() -> PathBuf {
    DATA_DIR
        .get()
        .cloned()
        .unwrap_or_else(|| PathBuf::from("pb_data"))
}

fn backups_dir() -> PathBuf {
    data_dir().join(BACKUPS_DIR)
}

fn invalid_name_error(message: &str) -> ApiError {
    let mut errors = Errors::new();
    errors.insert(
        "name".into(),
        validation::leaf("validation_backup_name_exists", message),
    );
    ApiError::new(
        StatusCode::BAD_REQUEST,
        "An error occurred while validating the submitted data.",
        validation::errors_to_value(&errors),
    )
    .with_raw_data(validation::errors_to_log_value(&errors))
}

fn validation_error(field: &str, node: validation::Node) -> ApiError {
    let mut errors = Errors::new();
    errors.insert(field.into(), node);
    ApiError::new(
        StatusCode::BAD_REQUEST,
        "An error occurred while validating the submitted data.",
        validation::errors_to_value(&errors),
    )
    .with_raw_data(validation::errors_to_log_value(&errors))
}

/// `inflector.Snakecase`.
fn snakecase(input: &str) -> String {
    let mut out = String::new();
    let mut word = String::new();
    let flush = |word: &mut String, out: &mut String| {
        if word.is_empty() {
            return;
        }
        if !out.is_empty() {
            out.push('_');
        }
        let chars: Vec<char> = word.chars().collect();
        for (i, ch) in chars.iter().enumerate() {
            if ch.is_uppercase() && i > 0 && !chars[i - 1].is_uppercase() {
                out.push('_');
            }
            out.push(*ch);
        }
        word.clear();
    };
    for ch in input.chars() {
        if ch.is_alphanumeric() {
            word.push(ch);
        } else {
            flush(&mut word, &mut out);
        }
    }
    flush(&mut word, &mut out);
    out.to_lowercase()
}

/// `filesystem.extractExtension`: last extension, including a secondary one
/// (`test.tar.gz` -> `.tar.gz`).
fn extract_extension(name: &str) -> &str {
    match name.rfind('.') {
        None => "",
        Some(primary) => match name[..primary].rfind('.') {
            Some(secondary) => &name[secondary..],
            None => &name[primary..],
        },
    }
}

/// `filesystem.normalizeName`: the random internal name used in validation
/// messages. The upload itself is stored under the original filename.
fn normalize_upload_name(name: &str, data: &[u8]) -> String {
    const ALPHABET: &str = "abcdefghijklmnopqrstuvwxyz0123456789";

    // cut the name even if it is not multibyte safe, like the oracle.
    let name = if name.len() > 300 {
        &name[name.len() - 300..]
    } else {
        name
    };

    let original_ext = extract_extension(name);
    let clean_ext: String = original_ext
        .chars()
        .filter(|c| c.is_alphanumeric() || matches!(c, '_' | '.' | '*' | '-' | '+' | '=' | '#'))
        .collect();
    let mut clean_ext = format!(".{}", clean_ext.trim_matches('.'));
    if clean_ext == "." {
        // `detectExtension`: only the content types we accept need an
        // extension; the oracle falls back to the detected mime extension.
        clean_ext = if data.starts_with(b"PK\x03\x04") {
            ".zip".to_string()
        } else {
            String::new()
        };
    }
    if clean_ext.len() > 20 {
        clean_ext = format!(".{}", clean_ext[clean_ext.len() - 20..].trim_matches('.'));
    }

    let base = name
        .strip_suffix(original_ext)
        .unwrap_or(name)
        .trim_matches('.');
    let mut clean_name = snakecase(base);
    if clean_name.len() < 3 {
        clean_name.push_str(&pb_core::ids::random_string_with_alphabet(10, ALPHABET));
    } else if clean_name.len() > 100 {
        clean_name.truncate(100);
    }

    format!(
        "{}_{}{}",
        clean_name,
        pb_core::ids::random_string_with_alphabet(10, ALPHABET),
        clean_ext
    )
}

fn now_timestamp(conn: &rusqlite::Connection, format: &str) -> String {
    conn.query_row(
        &format!("SELECT strftime('{format}', 'now')"),
        [],
        |row| row.get(0),
    )
    .unwrap_or_default()
}

fn modified_string(conn: &rusqlite::Connection, modified: SystemTime) -> String {
    let seconds = modified
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0);
    conn.query_row(
        "SELECT strftime('%Y-%m-%d %H:%M:%fZ', ?1, 'unixepoch')",
        [seconds],
        |row| row.get(0),
    )
    .unwrap_or_default()
}

pub async fn list(
    State(db): State<Db>,
    headers: HeaderMap,
) -> Result<Json<Value>, ApiError> {
    require_superuser(&db, &headers)?;
    let conn = db
        .lock()
        .map_err(|_| ApiError::internal("database lock poisoned"))?;

    let dir = backups_dir();
    fs::create_dir_all(&dir).ok();

    let mut entries = Vec::new();
    if let Ok(read) = fs::read_dir(&dir) {
        for entry in read.flatten() {
            let path = entry.path();
            if !path.is_file() {
                continue;
            }
            let key = entry.file_name().to_string_lossy().to_string();
            if key.ends_with(".attrs") {
                continue;
            }
            let meta = match entry.metadata() {
                Ok(meta) => meta,
                Err(_) => continue,
            };
            entries.push(json!({
                "key": key,
                "size": meta.len(),
                "modified": modified_string(&conn, meta.modified().unwrap_or(UNIX_EPOCH)),
            }));
        }
    }
    entries.sort_by(|a, b| {
        a["key"]
            .as_str()
            .unwrap_or("")
            .cmp(b["key"].as_str().unwrap_or(""))
    });
    Ok(Json(Value::Array(entries)))
}

fn create_zip(
    data: &FsPath,
    dest: &FsPath,
    conn: &rusqlite::Connection,
    aux: Option<&rusqlite::Connection>,
) -> Result<(), String> {
    let file = fs::File::create(dest).map_err(|e| e.to_string())?;
    let mut zip = zip::ZipWriter::new(file);
    let options = zip::write::SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated);

    // Snapshot the databases with VACUUM INTO so the archive is consistent.
    let temp_dir = data.join(".pb_temp_to_delete");
    fs::create_dir_all(&temp_dir).map_err(|e| e.to_string())?;
    for db_name in [pb_core::DATA_DB, pb_core::AUX_DB] {
        let source = data.join(db_name);
        if !source.exists() {
            continue;
        }
        let snapshot = temp_dir.join(db_name);
        let _ = fs::remove_file(&snapshot);
        let sql = format!("VACUUM INTO '{}'", snapshot.to_string_lossy().replace('\'', "''"));
        let snapshot_conn = if db_name == pb_core::AUX_DB {
            aux.ok_or_else(|| "auxiliary database is not available".to_string())?
        } else {
            conn
        };
        snapshot_conn.execute_batch(&sql).map_err(|e| e.to_string())?;
        let mut snapshot_file = fs::File::open(&snapshot).map_err(|e| e.to_string())?;
        zip.start_file(db_name, options).map_err(|e| e.to_string())?;
        std::io::copy(&mut snapshot_file, &mut zip).map_err(|e| e.to_string())?;
        let _ = fs::remove_file(&snapshot);
    }

    // Everything else in pb_data, excluding the special directories.
    fn walk(
        root: &FsPath,
        current: &FsPath,
        zip: &mut zip::ZipWriter<fs::File>,
        options: zip::write::SimpleFileOptions,
    ) -> Result<(), String> {
        let read = match fs::read_dir(current) {
            Ok(read) => read,
            Err(_) => return Ok(()),
        };
        for entry in read.flatten() {
            let path = entry.path();
            let name = entry.file_name().to_string_lossy().to_string();
            if current == root
                && matches!(
                    name.as_str(),
                    BACKUPS_DIR
                        | ".pb_temp_to_delete"
                        | ".notify"
                        | ".autocert_cache"
                        | "lost+found"
                        | pb_core::DATA_DB
                        | pb_core::AUX_DB
                )
            {
                continue;
            }
            if current == root && (name.ends_with("-wal") || name.ends_with("-shm")) {
                continue;
            }
            if path.is_dir() {
                walk(root, &path, zip, options)?;
                continue;
            }
            let relative = path
                .strip_prefix(root)
                .map_err(|e| e.to_string())?
                .to_string_lossy()
                .replace('\\', "/");
            let mut file = fs::File::open(&path).map_err(|e| e.to_string())?;
            zip.start_file(relative, options).map_err(|e| e.to_string())?;
            std::io::copy(&mut file, zip).map_err(|e| e.to_string())?;
        }
        Ok(())
    }
    walk(data, data, &mut zip, options)?;

    zip.finish().map_err(|e| e.to_string())?;
    Ok(())
}

pub async fn create(
    State(db): State<Db>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<StatusCode, ApiError> {
    require_superuser(&db, &headers)?;

    let guard = active().lock().map_err(|_| ApiError::internal("lock poisoned"))?;
    if guard.is_some() {
        return Err(ApiError::bad_request(
            "Try again later - another backup/restore process has already been started",
        ));
    }
    drop(guard);

    let form: Value = if body.is_empty() {
        json!({})
    } else {
        serde_json::from_slice(&body).map_err(|_| {
            ApiError::bad_request("An error occurred while loading the submitted data.")
        })?
    };
    let requested = form.get("name").and_then(Value::as_str).unwrap_or("");
    if requested.chars().count() > 150 {
        return Err(validation_error(
            "name",
            validation::leaf_with_params(
                "validation_length_out_of_range",
                "the length must be between {{.min}} and {{.max}}",
                json!({"min": 1, "max": 150}),
            ),
        ));
    }
    if !requested.is_empty() {
        let valid = requested
            .strip_suffix(".zip")
            .map(|stem| {
                !stem.is_empty()
                    && stem
                        .chars()
                        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '-')
            })
            .unwrap_or(false);
        if !valid {
            return Err(validation_error(
                "name",
                validation::leaf("validation_match_invalid", "must be in a valid format"),
            ));
        }
    }

    let data = data_dir();
    let dir = backups_dir();
    fs::create_dir_all(&dir).map_err(|e| ApiError::internal(e.to_string()))?;

    let name = {
        let conn = db
            .lock()
            .map_err(|_| ApiError::internal("database lock poisoned"))?;
        let name = if requested.is_empty() {
            let settings = pb_core::settings::load(&conn)
                .map_err(|e| ApiError::internal(format!("failed to load settings: {e}")))?;
            let app_name = snakecase(&settings.meta.app_name);
            let app_name = if app_name.len() > 50 {
                &app_name[..50]
            } else {
                &app_name
            };
            format!(
                "pb_backup_{}_{}.zip",
                app_name,
                now_timestamp(&conn, "%Y%m%d%H%M%S")
            )
        } else {
            requested.to_string()
        };

        if dir.join(&name).exists() {
            return Err(invalid_name_error(
                "The backup file name is invalid or already exists.",
            ));
        }

        *active().lock().map_err(|_| ApiError::internal("lock poisoned"))? = Some(name.clone());
        let aux_guard = crate::records::AUX_DB
            .get()
            .and_then(|aux| aux.lock().ok());
        let result = create_zip(
            &data,
            &dir.join(&name),
            &conn,
            aux_guard.as_deref(),
        );
        *active().lock().map_err(|_| ApiError::internal("lock poisoned"))? = None;
        result.map_err(|e| ApiError::bad_request(format!("Failed to create backup. {e}")))?;
        name
    };
    let _ = name;
    Ok(StatusCode::NO_CONTENT)
}

pub async fn delete(
    State(db): State<Db>,
    headers: HeaderMap,
    Path(key): Path<String>,
) -> Result<StatusCode, ApiError> {
    require_superuser(&db, &headers)?;

    if active()
        .lock()
        .map(|guard| guard.as_deref() == Some(key.as_str()))
        .unwrap_or(false)
    {
        return Err(ApiError::bad_request(
            "The backup is currently being used and cannot be deleted.",
        ));
    }

    let path = backups_dir().join(&key);
    if key.is_empty() || !path.is_file() {
        return Err(ApiError::bad_request(format!(
            "Invalid or already deleted backup file. Raw error: \n[key: {key}] remove {}: no such file or directory\nresource not found.",
            path.display()
        )));
    }
    fs::remove_file(&path).map_err(|e| {
        ApiError::bad_request(format!(
            "Invalid or already deleted backup file. Raw error: \n[key: {key}] remove {}: {e}",
            path.display()
        ))
    })?;
    Ok(StatusCode::NO_CONTENT)
}

pub async fn upload(
    State(db): State<Db>,
    headers: HeaderMap,
    mut multipart: Multipart,
) -> Result<StatusCode, ApiError> {
    require_superuser(&db, &headers)?;

    let mut file: Option<(String, Bytes)> = None;
    while let Some(field) = multipart
        .next_field()
        .await
        .map_err(|e| ApiError::bad_request(format!("Failed to upload backup. {e}")))?
    {
        if field.name() == Some("file") {
            let name = field.file_name().unwrap_or("").to_string();
            let data = field
                .bytes()
                .await
                .map_err(|e| ApiError::bad_request(format!("Failed to upload backup. {e}")))?;
            file = Some((name, data));
            break;
        }
    }

    let Some((name, data)) = file else {
        return Err(validation_error("file", validation::required()));
    };
    let valid_zip = zip::ZipArchive::new(std::io::Cursor::new(&data)).is_ok();
    if name.is_empty() || !valid_zip {
        let normalized = normalize_upload_name(&name, &data);
        return Err(validation_error(
            "file",
            validation::leaf(
                "validation_invalid_mime_type",
                format!(
                    "\"{}\" mime type must be one of: application/zip.",
                    normalized
                ),
            ),
        ));
    }

    let dir = backups_dir();
    fs::create_dir_all(&dir).map_err(|e| ApiError::internal(e.to_string()))?;
    let path = dir.join(&name);
    if path.exists() {
        return Err(validation_error(
            "file",
            validation::leaf(
                "validation_backup_name_exists",
                "Backup file with the specified name already exists.",
            ),
        ));
    }
    fs::write(&path, &data)
        .map_err(|e| ApiError::bad_request(format!("Failed to upload backup. {e}")))?;
    Ok(StatusCode::NO_CONTENT)
}

pub async fn download(
    State(db): State<Db>,
    Path(key): Path<String>,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Response, ApiError> {
    let token = params.get("token").cloned().unwrap_or_default();
    {
        let conn = db
            .lock()
            .map_err(|_| ApiError::internal("database lock poisoned"))?;
        let record = Record::find_auth_record_by_token(&conn, &token, &[tokens::TYPE_FILE])
            .map_err(|_| ApiError::forbidden("Insufficient permissions to access the resource."))?;
        let Some(record) = record else {
            return Err(ApiError::forbidden(
                "Insufficient permissions to access the resource.",
            ));
        };
        if record.collection.name != pb_core::superusers::COLLECTION_NAME_SUPERUSERS {
            return Err(ApiError::forbidden(
                "Insufficient permissions to access the resource.",
            ));
        }
        let _ = Collection::find(&conn, &record.collection.id);
    }

    let path = backups_dir().join(&key);
    let data = fs::read(&path).map_err(|_| {
        ApiError::not_found("The requested resource wasn't found.")
    })?;
    let response = (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, "application/zip".to_string()),
            (
                header::CONTENT_DISPOSITION,
                format!("attachment; filename=\"{}\"", key.replace('"', "")),
            ),
        ],
        data,
    )
        .into_response();
    Ok(response)
}

pub async fn restore(
    State(db): State<Db>,
    headers: HeaderMap,
    Path(key): Path<String>,
) -> Result<StatusCode, ApiError> {
    require_superuser(&db, &headers)?;

    if active()
        .lock()
        .map(|guard| guard.is_some())
        .unwrap_or(false)
    {
        return Err(ApiError::bad_request(
            "Try again later - another backup/restore process has already been started.",
        ));
    }

    let path = backups_dir().join(&key);
    if !path.is_file() {
        return Err(ApiError::bad_request("Missing or invalid backup file."));
    }

    *active().lock().map_err(|_| ApiError::internal("lock poisoned"))? = Some(key.clone());

    let data = data_dir();
    std::thread::spawn(move || {
        std::thread::sleep(Duration::from_secs(1));
        if let Err(err) = restore_zip(&path, &data) {
            eprintln!("failed to restore backup: {err}");
            *active().lock().unwrap() = None;
            return;
        }
        if let Err(err) = restart_process() {
            eprintln!("failed to restart after restore: {err}");
            *active().lock().unwrap() = None;
        }
    });

    Ok(StatusCode::NO_CONTENT)
}

/// Entries that are never moved during a restore (`BackupEvent.Exclude`).
const RESTORE_EXCLUDE: &[&str] = &[
    BACKUPS_DIR,
    ".pb_temp_to_delete",
    ".autocert_cache",
    "lost+found",
];

fn extract_zip(path: &FsPath, dest: &FsPath) -> Result<(), String> {
    let file = fs::File::open(path).map_err(|e| e.to_string())?;
    let mut archive = zip::ZipArchive::new(file).map_err(|e| e.to_string())?;
    for i in 0..archive.len() {
        let mut entry = archive.by_index(i).map_err(|e| e.to_string())?;
        let Some(name) = entry.enclosed_name() else {
            continue;
        };
        let out = dest.join(name);
        if entry.is_dir() {
            fs::create_dir_all(&out).map_err(|e| e.to_string())?;
            continue;
        }
        if let Some(parent) = out.parent() {
            fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }
        let mut buf = Vec::new();
        entry.read_to_end(&mut buf).map_err(|e| e.to_string())?;
        fs::write(&out, buf).map_err(|e| e.to_string())?;
    }
    Ok(())
}

/// `osutils.MoveDirContent`: move every entry except the excluded names.
fn move_dir_content(src: &FsPath, dst: &FsPath, exclude: &[&str]) -> Result<(), String> {
    fs::create_dir_all(dst).map_err(|e| e.to_string())?;
    let read = fs::read_dir(src).map_err(|e| e.to_string())?;
    for entry in read.flatten() {
        let name = entry.file_name().to_string_lossy().to_string();
        if exclude.contains(&name.as_str()) {
            continue;
        }
        fs::rename(entry.path(), dst.join(&name)).map_err(|e| e.to_string())?;
    }
    Ok(())
}

fn restore_zip(path: &FsPath, data: &FsPath) -> Result<(), String> {
    let temp_root = data.join(".pb_temp_to_delete");
    fs::create_dir_all(&temp_root).map_err(|e| e.to_string())?;

    let suffix = pb_core::ids::default_random_id();
    let extracted = temp_root.join(format!("pb_restore_{suffix}"));
    extract_zip(path, &extracted)?;

    if !extracted.join(pb_core::DATA_DB).is_file() {
        return Err("data.db file is missing or invalid".to_string());
    }

    // Move the current content aside (including the WAL/SHM files) and the
    // restored content into pb_data. The old directory is removed on the next
    // bootstrap, like the oracle.
    let old = temp_root.join(format!("old_pb_data_{suffix}"));
    move_dir_content(data, &old, RESTORE_EXCLUDE)?;
    move_dir_content(&extracted, data, RESTORE_EXCLUDE)?;
    let _ = fs::remove_dir(&extracted);
    Ok(())
}

/// `App.Restart`: replace the current process image with the same binary and
/// arguments. Only returns on failure.
#[cfg(unix)]
fn restart_process() -> Result<(), String> {
    use std::os::unix::process::CommandExt;

    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let args: Vec<std::ffi::OsString> = std::env::args_os().skip(1).collect();
    let error = std::process::Command::new(exe).args(args).exec();
    Err(format!("failed to restart the app process: {error}"))
}

#[cfg(not(unix))]
fn restart_process() -> Result<(), String> {
    Err("restart is not supported on this platform".to_string())
}

/// Runs a backup immediately (used by the `__pbAutoBackup__` cron job).
pub fn create_backup_now(db: &Db, name: &str) -> Result<(), String> {
    let data = data_dir();
    let dir = backups_dir();
    fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    *active().lock().map_err(|_| "lock poisoned".to_string())? = Some(name.to_string());
    let result = (|| {
        let conn = db.lock().map_err(|_| "database lock poisoned".to_string())?;
        let aux_guard = crate::records::AUX_DB
            .get()
            .and_then(|aux| aux.lock().ok());
        create_zip(
            &data,
            &dir.join(name),
            &conn,
            aux_guard.as_deref(),
        )
    })();
    *active().lock().map_err(|_| "lock poisoned".to_string())? = None;
    result
}

/// Deletes the oldest `@auto_pb_backup_*` archives, keeping `max_keep`.
pub fn prune_auto_backups(max_keep: usize) {
    let dir = backups_dir();
    let Ok(read) = fs::read_dir(&dir) else {
        return;
    };
    let mut names: Vec<String> = read
        .flatten()
        .filter_map(|entry| {
            let name = entry.file_name().to_string_lossy().to_string();
            (name.starts_with("@auto_pb_backup_") && name.ends_with(".zip")).then_some(name)
        })
        .collect();
    names.sort();
    while names.len() > max_keep {
        let oldest = names.remove(0);
        let _ = fs::remove_file(dir.join(oldest));
    }
}
