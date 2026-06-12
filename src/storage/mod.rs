// =============================================================================
// storage/mod.rs — DuckDB connection management
//
// Opens the embedded DuckDB database used to store parsed log rows. The single
// connection is shared across the syslog listeners and the web server behind a
// mutex (see AppState); per-log-type schemas are created via Registry::init_all.
// =============================================================================

use anyhow::{Context, Result};
use duckdb::Connection;

// ─────────────────────────────────────────────────────────────────────────────
// open(path)
// Opens (creating if needed) the DuckDB database file at `path`.
// ─────────────────────────────────────────────────────────────────────────────
pub fn open(path: &str) -> Result<Connection> {
    let conn = Connection::open(path).with_context(|| format!("opening DuckDB at {path}"))?;
    Ok(conn)
}
