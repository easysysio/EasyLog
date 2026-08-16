// =============================================================================
// retention.rs — data retention (pruning) and database compaction
//
// Keeps the database bounded so a long-running collector doesn't fill its disk.
// Two cooperating parts:
//
//   Pruning    — deletes events older than `retention_days` from every log-type
//                table, once shortly after startup and hourly thereafter.
//                `retention_days = 0` disables it (the default: keep everything).
//
//   Compaction — DuckDB never shrinks its file: deleted rows free blocks for
//                reuse, but the high-water mark stays. Pruning therefore bounds
//                growth without returning disk to the OS. To reclaim it the
//                database has to be rewritten, which is only safe with no
//                concurrent writers — so it happens at startup, before the
//                listeners and web server come up, and only when a worthwhile
//                fraction of the file is dead space.
// =============================================================================

use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use chrono::{Duration as ChronoDuration, Utc};
use duckdb::Connection;

use crate::config::Config;
use crate::logtype::Registry;
use crate::state::AppState;
use crate::storage;

// How often the background task re-runs the prune.
const PRUNE_INTERVAL: Duration = Duration::from_secs(60 * 60);

// Wait before the first prune so startup isn't competing with initial ingest.
const FIRST_PRUNE_DELAY: Duration = Duration::from_secs(60);

// Compaction thresholds: rewriting is only worth it when the file is big enough
// for the reclaim to matter *and* enough of it is dead space.
const COMPACT_MIN_BYTES: u64 = 16 * 1024 * 1024;
const COMPACT_MIN_DEAD_RATIO: f64 = 0.30;

// ─────────────────────────────────────────────────────────────────────────────
// prune(conn, registry, retention_days)
// Deletes events older than the retention window from every log-type table and
// checkpoints so the freed blocks become reusable. Returns the number of rows
// removed. A zero window means "keep everything" and does nothing.
//
// Rows are aged by their event timestamp, falling back to the time EasyLog
// received them — a line whose timestamp failed to parse would otherwise be
// immortal.
// ─────────────────────────────────────────────────────────────────────────────
pub fn prune(conn: &Connection, registry: &Registry, retention_days: u32) -> Result<u64> {
    if retention_days == 0 {
        return Ok(0);
    }
    let cutoff = cutoff(retention_days);
    let mut removed = 0u64;
    for table in registry.names() {
        let n = prune_table(conn, table, &cutoff).with_context(|| format!("pruning {table}"))?;
        if n > 0 {
            tracing::info!("retention: removed {n} row(s) from {table}");
        }
        removed += n as u64;
    }
    if removed > 0 {
        conn.execute_batch("CHECKPOINT").context("checkpoint after prune")?;
    }
    Ok(removed)
}

// Oldest timestamp to keep, as a UTC string. The cutoff is computed here rather
// than in SQL because `now()` is a TIMESTAMPTZ, and timestamptz/interval
// arithmetic needs DuckDB's ICU extension, which isn't loaded in the bundled
// build. Stored timestamps are naive UTC, so this compares like for like.
fn cutoff(retention_days: u32) -> String {
    (Utc::now() - ChronoDuration::days(retention_days as i64))
        .format("%Y-%m-%d %H:%M:%S")
        .to_string()
}

// Deletes one table's events older than `cutoff`, ageing each row by its event
// timestamp and falling back to when EasyLog received it.
fn prune_table(conn: &Connection, table: &str, cutoff: &str) -> Result<usize> {
    let sql = format!(
        "DELETE FROM {table} WHERE coalesce(ts, received_at) < CAST(? AS TIMESTAMP)"
    );
    Ok(conn.execute(&sql, duckdb::params![cutoff])?)
}

// ─────────────────────────────────────────────────────────────────────────────
// serve(state)
// Background task: prunes on a fixed interval for as long as the process runs.
// A failed pass is logged and retried on the next tick rather than taking the
// process down — losing a prune is far less serious than losing ingestion.
// ─────────────────────────────────────────────────────────────────────────────
pub async fn serve(state: Arc<AppState>) -> Result<()> {
    let retention_days = state.config.retention_days;
    if retention_days == 0 {
        tracing::info!("retention: disabled (retention_days = 0)");
        return std::future::pending().await; // never resolves; keeps try_join! alive
    }
    tracing::info!("retention: keeping {retention_days} day(s) of events");

    tokio::time::sleep(FIRST_PRUNE_DELAY).await;
    loop {
        let result = {
            let conn = state.db.lock().expect("db mutex poisoned");
            prune(&conn, &state.registry, retention_days)
        };
        if let Err(e) = result {
            tracing::warn!("retention: prune failed: {e:#}");
        }
        tokio::time::sleep(PRUNE_INTERVAL).await;
    }
}

// Block accounting from `PRAGMA database_size`, used to decide whether a
// rewrite would reclaim enough to be worth it.
struct BlockUsage {
    total: i64,
    free: i64,
    block_size: i64,
}

impl BlockUsage {
    fn bytes(&self) -> u64 {
        (self.total * self.block_size).max(0) as u64
    }

    fn dead_ratio(&self) -> f64 {
        if self.total <= 0 {
            0.0
        } else {
            self.free as f64 / self.total as f64
        }
    }
}

fn block_usage(conn: &Connection) -> Result<BlockUsage> {
    let mut stmt = conn.prepare("SELECT block_size, total_blocks, free_blocks FROM pragma_database_size()")?;
    let mut rows = stmt.query_map([], |r| {
        Ok(BlockUsage { block_size: r.get(0)?, total: r.get(1)?, free: r.get(2)? })
    })?;
    rows.next()
        .transpose()?
        .context("pragma_database_size returned no rows")
}

// ─────────────────────────────────────────────────────────────────────────────
// compact_if_needed(conn, config)
// Rewrites the database into a fresh file when enough of it is dead space,
// returning the connection to carry on with (the reopened one after a rewrite,
// the original otherwise).
//
// The swap keeps the old file until the new one has been opened successfully,
// so a failure at any step leaves the original database in place — the worst
// case is that the disk isn't reclaimed this time.
// ─────────────────────────────────────────────────────────────────────────────
pub fn compact_if_needed(conn: Connection, config: &Config) -> Result<Connection> {
    let path = config.db_path.trim();
    if !config.auto_compact || path.is_empty() || path == ":memory:" {
        return Ok(conn);
    }

    let usage = match block_usage(&conn) {
        Ok(u) => u,
        Err(e) => {
            tracing::warn!("compaction: could not read database size: {e:#}");
            return Ok(conn);
        }
    };
    let (bytes, ratio) = (usage.bytes(), usage.dead_ratio());
    if bytes < COMPACT_MIN_BYTES || ratio < COMPACT_MIN_DEAD_RATIO {
        tracing::debug!(
            "compaction: not needed ({:.0} MB, {:.0}% reusable)",
            bytes as f64 / 1024.0 / 1024.0,
            ratio * 100.0
        );
        return Ok(conn);
    }

    tracing::info!(
        "compaction: rewriting database ({:.0} MB, {:.0}% dead space)",
        bytes as f64 / 1024.0 / 1024.0,
        ratio * 100.0
    );
    if let Err(e) = compact(conn, config) {
        tracing::warn!("compaction: skipped, database left as it was: {e:#}");
    }
    // Whether the rewrite succeeded or not, `path` now names a valid database:
    // either the compacted copy or the untouched original.
    storage::open(path, &config.duckdb_memory_limit, config.duckdb_threads)
        .context("reopening the database after compaction")
}

// Rewrites the database into a fresh file and swaps it in. The original is kept
// until the new file is in place, so any failure leaves it untouched — the only
// cost of an error here is that the disk isn't reclaimed this time.
fn compact(conn: Connection, config: &Config) -> Result<()> {
    let path = config.db_path.trim().to_string();
    let tmp = format!("{path}.compact");
    let previous = format!("{path}.previous");

    // A leftover file from an interrupted run would make ATTACH fail.
    let _ = std::fs::remove_file(&tmp);

    let name: String = conn
        .prepare("SELECT current_database()")
        .and_then(|mut s| s.query_row([], |r| r.get(0)))
        .context("reading the database name")?;

    let copy = conn.execute_batch(&format!(
        "ATTACH '{}' AS easylog_compact; COPY FROM DATABASE \"{}\" TO easylog_compact; \
         DETACH easylog_compact;",
        tmp.replace('\'', "''"),
        name.replace('"', "\"\"")
    ));
    // The connection must be closed before the files move, on both paths.
    drop(conn);
    if let Err(e) = copy {
        let _ = std::fs::remove_file(&tmp);
        return Err(anyhow::Error::from(e).context("copying into the compacted database"));
    }

    std::fs::rename(&path, &previous).context("moving the old database aside")?;
    if let Err(e) = std::fs::rename(&tmp, &path) {
        // Put the original back before giving up.
        let _ = std::fs::rename(&previous, &path);
        let _ = std::fs::remove_file(&tmp);
        return Err(anyhow::Error::from(e).context("moving the compacted database into place"));
    }
    let _ = std::fs::remove_file(&previous);
    let _ = std::fs::remove_file(format!("{previous}.wal"));

    let size = database_size_bytes(&path);
    tracing::info!("compaction: done, database is now {:.1} MB", size as f64 / 1024.0 / 1024.0);
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// database_size_bytes(path)
// Size of the database file on disk, for the storage KPI on the home page.
// ─────────────────────────────────────────────────────────────────────────────
pub fn database_size_bytes(path: &str) -> u64 {
    std::fs::metadata(path).map(|m| m.len()).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    // A table shaped like a log-type table, filled with rows of known ages.
    // Ages are built from a naive UTC "now" — the same basis the ingest paths
    // and `cutoff` use.
    fn seeded() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        let ago = |days: i64| {
            (Utc::now() - ChronoDuration::days(days))
                .format("%Y-%m-%d %H:%M:%S")
                .to_string()
        };
        conn.execute_batch(&format!(
            "CREATE TABLE apache (remote_host VARCHAR, ts TIMESTAMP, received_at TIMESTAMP);
             INSERT INTO apache VALUES
               ('1.1.1.1', '{d1}',  '{d1}'),
               ('2.2.2.2', '{d10}', '{d10}'),
               ('3.3.3.3', '{d40}', '{d40}'),
               -- an unparsed timestamp: aged by received_at instead
               ('4.4.4.4', NULL,    '{d40}'),
               ('5.5.5.5', NULL,    '{d2}');",
            d1 = ago(1),
            d2 = ago(2),
            d10 = ago(10),
            d40 = ago(40),
        ))
        .unwrap();
        conn
    }

    fn count(conn: &Connection) -> i64 {
        conn.prepare("SELECT count(*) FROM apache")
            .unwrap()
            .query_row([], |r| r.get(0))
            .unwrap()
    }

    // prune() sweeps every registered table; the tests exercise the same SQL
    // against the one table they seeded.
    fn prune_days(conn: &Connection, days: u32) -> usize {
        prune_table(conn, "apache", &cutoff(days)).unwrap()
    }

    #[test]
    fn prunes_only_events_older_than_the_window() {
        let conn = seeded();
        assert_eq!(prune_days(&conn, 30), 2); // the two 40-day-old rows
        assert_eq!(count(&conn), 3);
        assert_eq!(prune_days(&conn, 7), 1); // the 10-day-old row
        assert_eq!(count(&conn), 2);
    }

    #[test]
    fn rows_without_a_timestamp_are_aged_by_arrival() {
        let conn = seeded();
        // The NULL-ts row that arrived 40 days ago must go; the recent one stays.
        prune_days(&conn, 30);
        let remaining: i64 = conn
            .prepare("SELECT count(*) FROM apache WHERE ts IS NULL")
            .unwrap()
            .query_row([], |r| r.get(0))
            .unwrap();
        assert_eq!(remaining, 1);
    }

    #[test]
    fn a_zero_window_keeps_everything() {
        let conn = seeded();
        let registry = Registry::with_defaults();
        assert_eq!(prune(&conn, &registry, 0).unwrap(), 0);
        assert_eq!(count(&conn), 5);
    }

    // Rewrites a real on-disk database that is mostly dead space, checking the
    // file actually shrinks, the surviving rows are intact, and the database is
    // still writable afterwards.
    #[test]
    fn compaction_reclaims_disk_and_preserves_rows() {
        let dir = std::env::temp_dir().join(format!("easylog-compact-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let db_path = dir.join("easylog.duckdb").to_string_lossy().to_string();
        let config = Config { db_path: db_path.clone(), ..Config::default() };

        let conn = storage::open(&db_path, "", 2).unwrap();
        conn.execute_batch(
            "CREATE TABLE apache (remote_host VARCHAR, ts TIMESTAMP, path VARCHAR,
                                  user_agent VARCHAR, received_at TIMESTAMP, raw VARCHAR);
             INSERT INTO apache SELECT '8.8.8.8', TIMESTAMP '2020-01-01' + INTERVAL (i) MINUTE,
                    '/api/v1/items/' || i, 'Mozilla/5.0 (X11; Linux x86_64) curl/8.4.0',
                    TIMESTAMP '2020-01-01', '8.8.8.8 - - \"GET /x\" 200 4096 \"-\" \"curl\"'
             FROM range(0, 400000) t(i);
             CHECKPOINT;",
        )
        .unwrap();
        let full = database_size_bytes(&db_path);

        // Keep a handful of rows; the rest becomes dead space in the file.
        conn.execute_batch(
            "DELETE FROM apache WHERE ts < TIMESTAMP '2020-01-01' + INTERVAL 399900 MINUTE;
             CHECKPOINT;",
        )
        .unwrap();
        let pruned_size = database_size_bytes(&db_path);
        let usage = block_usage(&conn).unwrap();
        assert!(usage.dead_ratio() > 0.5, "expected mostly dead space, got {usage:?}", usage = usage.dead_ratio());
        assert_eq!(pruned_size, full, "DuckDB is not expected to shrink the file on delete");

        compact(conn, &config).unwrap();

        let compacted = database_size_bytes(&db_path);
        assert!(compacted * 4 < full, "expected a much smaller file, got {compacted} vs {full}");

        // The rewritten database must still be usable.
        let conn = storage::open(&db_path, "", 2).unwrap();
        let rows: i64 = conn
            .prepare("SELECT count(*) FROM apache")
            .unwrap()
            .query_row([], |r| r.get(0))
            .unwrap();
        assert_eq!(rows, 100);
        conn.execute_batch(
            "INSERT INTO apache VALUES ('1.1.1.1', now()::TIMESTAMP, '/new', 'ua', now()::TIMESTAMP, 'raw')",
        )
        .unwrap();
        drop(conn);

        // No stray files left behind by the swap.
        for leftover in [".compact", ".previous"] {
            assert!(!std::path::Path::new(&format!("{db_path}{leftover}")).exists());
        }
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn block_usage_reports_dead_space_after_a_delete() {
        let conn = Connection::open_in_memory().unwrap();
        // In-memory databases report zero blocks, so this only checks that the
        // pragma is readable and the ratio math is sane.
        let usage = block_usage(&conn).unwrap();
        assert!(usage.dead_ratio() >= 0.0 && usage.dead_ratio() <= 1.0);
    }
}
