//! `/api/crons` and the cron scheduler (`apis/cron.go`, `tools/cron`).
//!
//! The job registry mirrors the oracle's registration order. The scheduler
//! aligns to the next UTC minute, runs every due job fire-and-forget, then
//! ticks once per minute.

use std::sync::OnceLock;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use pb_core::collections::Collection;
use pb_core::cron::{Moment, Schedule};
use pb_core::settings::{self, Settings};
use serde_json::{json, Value};

use crate::auth::{require_superuser, Db};
use crate::error::ApiError;

struct Job {
    id: &'static str,
    expression: &'static str,
}

/// The jobs registered at bootstrap, in registration order. `__pbAutoBackup__`
/// and `__pbRateLimitersCleanup__` are appended dynamically.
const JOBS: &[Job] = &[
    Job {
        id: "__pbDBOptimize__",
        expression: "0 0 * * *",
    },
    Job {
        id: "__pbMFACleanup__",
        expression: "0 * * * *",
    },
    Job {
        id: "__pbOTPCleanup__",
        expression: "0 * * * *",
    },
    Job {
        id: "__pbLogsCleanup__",
        expression: "0 */6 * * *",
    },
];

fn job_list(conn: &rusqlite::Connection) -> Vec<Value> {
    let mut jobs: Vec<Value> = JOBS
        .iter()
        .map(|job| json!({"id": job.id, "expression": job.expression}))
        .collect();
    if let Ok(settings) = settings::load(conn) {
        if !settings.backups.cron.is_empty() {
            jobs.push(json!({
                "id": "__pbAutoBackup__",
                "expression": settings.backups.cron,
            }));
        }
        // Registered lazily by `initRateLimitersStore` on the first matched
        // rate-limit rule; a settings PATCH removes it again.
        if crate::rate_limit::is_initialized() {
            jobs.push(json!({
                "id": "__pbRateLimitersCleanup__",
                "expression": "2 * * * *",
            }));
        }
    }
    jobs
}

pub async fn list(State(db): State<Db>, headers: HeaderMap) -> Result<Json<Value>, ApiError> {
    require_superuser(&db, &headers)?;
    let conn = db
        .lock()
        .map_err(|_| ApiError::internal("database lock poisoned"))?;
    Ok(Json(Value::Array(job_list(&conn))))
}

fn delete_expired(
    conn: &rusqlite::Connection,
    collection_name: &str,
    options_key: &str,
) -> Result<(), String> {
    let collections = Collection::load_all(conn).map_err(|e| e.to_string())?;
    for collection in collections.iter().filter(|c| c.is_auth()) {
        let duration = collection
            .options
            .get(options_key)
            .and_then(|v| v.get("duration"))
            .and_then(Value::as_i64)
            .unwrap_or(0);
        conn.execute(
            &format!(
                "DELETE FROM {collection_name} WHERE collectionRef = ?1 AND created < strftime('%Y-%m-%d %H:%M:%fZ','now','-{duration} seconds')"
            ),
            [&collection.id],
        )
        .map_err(|e| e.to_string())?;
    }
    Ok(())
}

fn cleanup_logs(conn: &rusqlite::Connection) -> Result<(), String> {
    let Some(aux) = crate::records::AUX_DB.get() else {
        return Ok(());
    };
    let aux = aux.lock().map_err(|_| "aux lock poisoned".to_string())?;
    let max_days = {
        let settings = settings::load(conn).map_err(|e| e.to_string())?;
        settings.logs.max_days
    };
    aux.execute(
        "DELETE FROM _logs WHERE created <= strftime('%Y-%m-%d %H:%M:%fZ','now', ?1)",
        [format!("-{max_days} days")],
    )
    .map_err(|e| e.to_string())?;
    Ok(())
}

/// Run one registered job. Shared by `POST /api/crons/{id}` and the scheduler.
fn run_job(db: &Db, id: &str) -> Result<(), String> {
    match id {
        "__pbDBOptimize__" => {
            let conn = db.lock().map_err(|_| "database lock poisoned".to_string())?;
            let _ = conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE)");
            if let Some(aux) = crate::records::AUX_DB.get() {
                if let Ok(aux) = aux.lock() {
                    let _ = aux.execute_batch("PRAGMA wal_checkpoint(TRUNCATE)");
                }
            }
            let _ = conn.execute_batch("PRAGMA optimize");
            Ok(())
        }
        "__pbMFACleanup__" => {
            let conn = db.lock().map_err(|_| "database lock poisoned".to_string())?;
            delete_expired(&conn, "_mfas", "mfa")
        }
        "__pbOTPCleanup__" => {
            let conn = db.lock().map_err(|_| "database lock poisoned".to_string())?;
            delete_expired(&conn, "_otps", "otp")
        }
        "__pbLogsCleanup__" => {
            let conn = db.lock().map_err(|_| "database lock poisoned".to_string())?;
            cleanup_logs(&conn)
        }
        "__pbRateLimitersCleanup__" => {
            crate::rate_limit::clean();
            Ok(())
        }
        "__pbAutoBackup__" => {
            let result = {
                let conn = db.lock().map_err(|_| "database lock poisoned".to_string())?;
                let settings = settings::load(&conn).map_err(|e| e.to_string())?;
                let timestamp: String = conn
                    .query_row("SELECT strftime('%Y%m%d%H%M%S','now')", [], |r| r.get(0))
                    .map_err(|e| e.to_string())?;
                let app_name = auto_backup_app_name(&settings);
                format!("@auto_pb_backup_{app_name}_{timestamp}.zip")
            };
            let name = result;
            crate::backups::create_backup_now(db, &name)?;

            let max_keep = {
                let conn = db.lock().map_err(|_| "database lock poisoned".to_string())?;
                settings::load(&conn)
                    .map_err(|e| e.to_string())?
                    .backups
                    .cron_max_keep
            };
            if max_keep > 0 {
                crate::backups::prune_auto_backups(max_keep as usize);
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

fn auto_backup_app_name(settings: &Settings) -> String {
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
    for ch in settings.meta.app_name.chars() {
        if ch.is_alphanumeric() {
            word.push(ch);
        } else {
            flush(&mut word, &mut out);
        }
    }
    flush(&mut word, &mut out);
    let out = out.to_lowercase();
    if out.len() > 50 {
        out[..50].to_string()
    } else {
        out
    }
}

pub async fn run(
    State(db): State<Db>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<StatusCode, ApiError> {
    require_superuser(&db, &headers)?;

    let known = {
        let conn = db
            .lock()
            .map_err(|_| ApiError::internal("database lock poisoned"))?;
        job_list(&conn)
            .iter()
            .any(|job| job["id"].as_str() == Some(id.as_str()))
    };
    if !known {
        return Err(ApiError::not_found("Missing or invalid cron job."));
    }

    let db = db.clone();
    std::thread::spawn(move || {
        if let Err(err) = run_job(&db, &id) {
            eprintln!("cron job {id} failed: {err}");
        }
    });

    Ok(StatusCode::NO_CONTENT)
}

/// Jobs due at `moment` given the current settings.
fn due_jobs(conn: &rusqlite::Connection, moment: &Moment) -> Vec<&'static str> {
    let mut due = Vec::new();
    for job in JOBS {
        if let Ok(schedule) = Schedule::new(job.expression) {
            if schedule.is_due(moment) {
                due.push(job.id);
            }
        }
    }

    let Ok(settings) = settings::load(conn) else {
        return due;
    };

    if !settings.backups.cron.is_empty() {
        if let Ok(schedule) = Schedule::new(&settings.backups.cron) {
            if schedule.is_due(moment) {
                due.push("__pbAutoBackup__");
            }
        }
    }

    if crate::rate_limit::is_initialized() {
        if let Ok(schedule) = Schedule::new("2 * * * *") {
            if schedule.is_due(moment) {
                due.push("__pbRateLimitersCleanup__");
            }
        }
    }

    due
}

fn run_due(db: &Db, moment: &Moment) {
    let jobs = match db.lock() {
        Ok(conn) => due_jobs(&conn, moment),
        Err(_) => return,
    };

    for id in jobs {
        let db = db.clone();
        std::thread::spawn(move || {
            if let Err(err) = run_job(&db, id) {
                eprintln!("cron job {id} failed: {err}");
            }
        });
    }
}

/// Start the cron ticker (`Cron.Start`): align to the next UTC minute, then
/// run once per minute. Only one scheduler exists per process.
pub fn start_scheduler(db: Db) {
    static STARTED: OnceLock<()> = OnceLock::new();
    if STARTED.set(()).is_err() {
        return;
    }

    std::thread::spawn(move || loop {
        let now_millis = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as i64)
            .unwrap_or(0);
        let next_millis = (now_millis / 60_000 + 1) * 60_000;
        let delay = Duration::from_millis((next_millis - now_millis).max(0) as u64);
        std::thread::sleep(delay);

        let moment = Moment::from_unix(next_millis / 1000);
        run_due(&db, &moment);
    });
}
