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
// open(path, memory_limit, threads)
// Opens (creating if needed) the DuckDB database at `path` and applies memory /
// thread limits. DuckDB otherwise sizes its buffer pool to ~80% of system RAM
// and keeps it, so an unbounded EasyLog can appear to "leak" hundreds of MB.
// ─────────────────────────────────────────────────────────────────────────────
pub fn open(path: &str, memory_limit: &str, threads: u16) -> Result<Connection> {
    let conn = Connection::open(path).with_context(|| format!("opening DuckDB at {path}"))?;

    let memory_limit = memory_limit.trim();
    if !memory_limit.is_empty() {
        // Strip quotes so the value can't break out of the SET statement.
        let clean = memory_limit.replace(['\'', '"', ';'], "");
        conn.execute_batch(&format!("SET memory_limit='{clean}';"))
            .with_context(|| format!("setting DuckDB memory_limit to {clean}"))?;
    }
    if threads > 0 {
        conn.execute_batch(&format!("SET threads={threads};"))
            .context("setting DuckDB thread count")?;
    }
    Ok(conn)
}
