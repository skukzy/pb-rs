//! SQLite connection setup, mirroring `core/db_connect.go`.
//!
//! The oracle opens both databases with this exact pragma set:
//!
//! ```text
//! busy_timeout(10000) journal_mode(WAL) journal_size_limit(200000000)
//! synchronous(NORMAL) foreign_keys(ON) temp_store(MEMORY) cache_size(-32000)
//! _defensive=1
//! ```

use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result};
use rusqlite::functions::FunctionFlags;
use rusqlite::Connection;

/// Open (creating parent directories) and configure a PocketBase database file.
pub fn open(path: &Path) -> Result<Connection> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("create data dir {}", parent.display()))?;
        }
    }

    let conn = Connection::open(path)
        .with_context(|| format!("open sqlite database {}", path.display()))?;

    configure(&conn)?;
    register_math_functions(&conn)?;
    Ok(conn)
}

/// SQLite math functions used by PocketBase's `geoDistance` filter helper.
///
/// The oracle's driver is compiled with `SQLITE_ENABLE_MATH_FUNCTIONS`; the
/// bundled rusqlite build is not, so the same functions are registered as
/// deterministic scalar functions.  `geoDistance` renders plain `acos`, `cos`,
/// `sin` and `radians` calls, and `/api/sql` exposes the same SQL surface.
fn register_math_functions(conn: &Connection) -> Result<()> {
    let flags = FunctionFlags::SQLITE_UTF8 | FunctionFlags::SQLITE_DETERMINISTIC;
    let real = |ctx: &rusqlite::functions::Context<'_>, index: usize| {
        ctx.get::<Option<f64>>(index).unwrap_or(None)
    };
    let finite = |value: Option<f64>| value.filter(|v| v.is_finite());

    conn.create_scalar_function("acos", 1, flags, move |ctx| {
        Ok(finite(real(ctx, 0).map(f64::acos)))
    })?;
    conn.create_scalar_function("asin", 1, flags, move |ctx| {
        Ok(finite(real(ctx, 0).map(f64::asin)))
    })?;
    conn.create_scalar_function("atan", 1, flags, move |ctx| {
        Ok(finite(real(ctx, 0).map(f64::atan)))
    })?;
    conn.create_scalar_function("atan2", 2, flags, move |ctx| {
        let (Some(y), Some(x)) = (real(ctx, 0), real(ctx, 1)) else {
            return Ok(None);
        };
        Ok(finite(Some(y.atan2(x))))
    })?;
    conn.create_scalar_function("cos", 1, flags, move |ctx| {
        Ok(finite(real(ctx, 0).map(f64::cos)))
    })?;
    conn.create_scalar_function("sin", 1, flags, move |ctx| {
        Ok(finite(real(ctx, 0).map(f64::sin)))
    })?;
    conn.create_scalar_function("tan", 1, flags, move |ctx| {
        Ok(finite(real(ctx, 0).map(f64::tan)))
    })?;
    conn.create_scalar_function("cosh", 1, flags, move |ctx| {
        Ok(finite(real(ctx, 0).map(f64::cosh)))
    })?;
    conn.create_scalar_function("sinh", 1, flags, move |ctx| {
        Ok(finite(real(ctx, 0).map(f64::sinh)))
    })?;
    conn.create_scalar_function("tanh", 1, flags, move |ctx| {
        Ok(finite(real(ctx, 0).map(f64::tanh)))
    })?;
    conn.create_scalar_function("acosh", 1, flags, move |ctx| {
        Ok(finite(real(ctx, 0).map(f64::acosh)))
    })?;
    conn.create_scalar_function("asinh", 1, flags, move |ctx| {
        Ok(finite(real(ctx, 0).map(f64::asinh)))
    })?;
    conn.create_scalar_function("atanh", 1, flags, move |ctx| {
        Ok(finite(real(ctx, 0).map(f64::atanh)))
    })?;
    conn.create_scalar_function("degrees", 1, flags, move |ctx| {
        Ok(finite(real(ctx, 0).map(f64::to_degrees)))
    })?;
    conn.create_scalar_function("radians", 1, flags, move |ctx| {
        Ok(finite(real(ctx, 0).map(f64::to_radians)))
    })?;
    conn.create_scalar_function("sqrt", 1, flags, move |ctx| {
        Ok(finite(real(ctx, 0).map(f64::sqrt)))
    })?;
    conn.create_scalar_function("exp", 1, flags, move |ctx| {
        Ok(finite(real(ctx, 0).map(f64::exp)))
    })?;
    conn.create_scalar_function("ln", 1, flags, move |ctx| {
        Ok(finite(real(ctx, 0).map(f64::ln)))
    })?;
    conn.create_scalar_function("log", 1, flags, move |ctx| {
        Ok(finite(real(ctx, 0).map(f64::log10)))
    })?;
    conn.create_scalar_function("log10", 1, flags, move |ctx| {
        Ok(finite(real(ctx, 0).map(f64::log10)))
    })?;
    conn.create_scalar_function("log2", 1, flags, move |ctx| {
        Ok(finite(real(ctx, 0).map(f64::log2)))
    })?;
    conn.create_scalar_function("pow", 2, flags, move |ctx| {
        let (Some(a), Some(b)) = (real(ctx, 0), real(ctx, 1)) else {
            return Ok(None);
        };
        Ok(finite(Some(a.powf(b))))
    })?;
    conn.create_scalar_function("power", 2, flags, move |ctx| {
        let (Some(a), Some(b)) = (real(ctx, 0), real(ctx, 1)) else {
            return Ok(None);
        };
        Ok(finite(Some(a.powf(b))))
    })?;
    conn.create_scalar_function("mod", 2, flags, move |ctx| {
        let (Some(a), Some(b)) = (real(ctx, 0), real(ctx, 1)) else {
            return Ok(None);
        };
        if b == 0.0 {
            return Ok(None);
        }
        Ok(finite(Some(a % b)))
    })?;
    conn.create_scalar_function("floor", 1, flags, move |ctx| {
        Ok(finite(real(ctx, 0).map(f64::floor)))
    })?;
    conn.create_scalar_function("ceil", 1, flags, move |ctx| {
        Ok(finite(real(ctx, 0).map(f64::ceil)))
    })?;
    conn.create_scalar_function("ceiling", 1, flags, move |ctx| {
        Ok(finite(real(ctx, 0).map(f64::ceil)))
    })?;
    conn.create_scalar_function("trunc", 1, flags, move |ctx| {
        Ok(finite(real(ctx, 0).map(f64::trunc)))
    })?;
    conn.create_scalar_function("pi", 0, flags, move |_ctx| {
        Ok(Some(std::f64::consts::PI))
    })?;

    Ok(())
}

/// Apply the pragma set. Order matters: `busy_timeout` must be first.
pub fn configure(conn: &Connection) -> Result<()> {
    conn.busy_timeout(Duration::from_millis(10_000))?;

    // journal_mode returns the resulting mode as a row.
    let _mode: String = conn.query_row("PRAGMA journal_mode = WAL", [], |row| row.get(0))?;

    conn.pragma_update(None, "journal_size_limit", 200_000_000_i64)?;
    conn.pragma_update(None, "synchronous", "NORMAL")?;
    conn.pragma_update(None, "foreign_keys", "ON")?;
    conn.pragma_update(None, "temp_store", "MEMORY")?;
    conn.pragma_update(None, "cache_size", -32_000_i64)?;

    // `_defensive=1` in the oracle's DSN. rusqlite exposes it as a feature
    // (`modern_sqlite`), which is not enabled; the pragma set above is the
    // part that affects observable behaviour.
    Ok(())
}

/// True when a table (or view) with this name exists in the main schema.
pub fn table_exists(conn: &Connection, name: &str) -> Result<bool> {
    let count: i64 = conn.query_row(
        "SELECT count(*) FROM sqlite_master WHERE type IN ('table','view') AND name = ?1",
        [name],
        |row| row.get(0),
    )?;
    Ok(count > 0)
}

/// Run `PRAGMA optimize` the way the oracle does after syncing record tables.
pub fn optimize(conn: &Connection) -> Result<()> {
    conn.execute_batch("PRAGMA optimize;")?;
    Ok(())
}
