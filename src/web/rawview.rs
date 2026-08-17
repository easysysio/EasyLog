// =============================================================================
// web/rawview.rs — the original log lines behind a dashboard
//
// Every log type stores the line it parsed, so a dashboard can always show its
// evidence: filter to what you're investigating, then switch to Raw and read the
// actual lines, newest first. The view is a mode of the dashboard rather than a
// page of its own — it reuses the caller's WHERE clause and bound values, so the
// time range, every drill-down filter and the search term all still apply, and
// `?view=raw` in the URL keeps it shareable.
//
// Two entry points share that clause:
//   render    the on-screen table, newest first, `limit` lines at a time
//   download  the same lines as a .log file, streamed
//
// The download reads in batches and releases the database lock between them: a
// large export must not hold the single connection long enough to stall
// ingestion, which is still writing while someone downloads.
// =============================================================================

use std::sync::Arc;

use axum::body::Body;
use axum::http::header;
use axum::response::{Html, IntoResponse, Response};
use duckdb::params_from_iter;
use duckdb::types::Value;
use serde::Serialize;

use super::AppError;
use crate::state::AppState;

/// How many lines a page shows, and how many "Load more" adds.
pub(crate) const PAGE: usize = 200;

// Rows are read in chunks for the download so the DB lock can be released
// between them.
const EXPORT_BATCH: usize = 5_000;

// A hard stop for an export, so a filter that matches everything can't stream
// for hours. The file says so when it is reached.
const EXPORT_MAX: usize = 500_000;

// One line as shown in the table.
#[derive(Serialize)]
struct RawRow {
    ts: String,
    line: String,
}

// ─────────────────────────────────────────────────────────────────────────────
// render(state, ctx, table, where_clause, vals, limit)
// Renders the raw-lines table into `ctx` (which the caller has already filled
// with the shared dashboard furniture: nav, chips, range and search) and returns
// the page. One extra row is fetched to tell whether more exist.
// ─────────────────────────────────────────────────────────────────────────────
pub(crate) fn render(
    state: &Arc<AppState>,
    mut ctx: tera::Context,
    table: &str,
    where_clause: &str,
    vals: &[Value],
    limit: usize,
) -> Result<Html<String>, AppError> {
    let conn = state.db.lock().expect("db mutex poisoned");
    let sql = format!(
        "SELECT CAST(ts AS VARCHAR), raw FROM {table} {where_clause} \
         ORDER BY ts DESC LIMIT {}",
        limit + 1
    );
    let mut stmt = conn.prepare(&sql)?;
    let mut rows: Vec<RawRow> = stmt
        .query_map(params_from_iter(vals.iter()), |r| {
            Ok(RawRow {
                ts: r.get::<_, Option<String>>(0)?.unwrap_or_default(),
                line: r.get::<_, Option<String>>(1)?.unwrap_or_default(),
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;
    drop(stmt);
    drop(conn);

    let has_more = rows.len() > limit;
    rows.truncate(limit);

    ctx.insert("raw_rows", &rows);
    ctx.insert("raw_shown", &rows.len());
    ctx.insert("raw_has_more", &has_more);
    Ok(Html(state.tera.render("raw.html", &ctx)?))
}

// ─────────────────────────────────────────────────────────────────────────────
// download(state, table, where_clause, vals, filename)
// Streams every matching line, newest first, as a plain .log attachment. Reads
// EXPORT_BATCH rows at a time, taking and releasing the database lock for each
// batch so ingestion keeps flowing during a long export.
// ─────────────────────────────────────────────────────────────────────────────
pub(crate) fn download(
    state: &Arc<AppState>,
    table: &str,
    where_clause: &str,
    vals: &[Value],
    filename: String,
) -> Response {
    let (tx, rx) = tokio::sync::mpsc::channel::<Result<String, std::io::Error>>(4);
    let state = state.clone();
    let table = table.to_string();
    let where_clause = where_clause.to_string();
    let vals = vals.to_vec();

    // Blocking DuckDB work belongs off the async runtime's worker threads.
    tokio::task::spawn_blocking(move || {
        let mut sent = 0usize;
        loop {
            let batch = {
                let conn = match state.db.lock() {
                    Ok(conn) => conn,
                    Err(_) => break,
                };
                let sql = format!(
                    "SELECT CAST(ts AS VARCHAR), raw FROM {table} {where_clause} \
                     ORDER BY ts DESC LIMIT {EXPORT_BATCH} OFFSET {sent}"
                );
                let read = (|| -> anyhow::Result<Vec<String>> {
                    let mut stmt = conn.prepare(&sql)?;
                    let rows = stmt
                        .query_map(params_from_iter(vals.iter()), |r| {
                            let ts: Option<String> = r.get(0)?;
                            let line: Option<String> = r.get(1)?;
                            Ok(format!(
                                "{} {}\n",
                                ts.unwrap_or_default(),
                                line.unwrap_or_default()
                            ))
                        })?
                        .collect::<Result<Vec<_>, _>>()?;
                    Ok(rows)
                })();
                match read {
                    Ok(rows) => rows,
                    Err(e) => {
                        tracing::error!("raw export failed: {e:#}");
                        break;
                    }
                }
            }; // lock released here, before anything is sent

            if batch.is_empty() {
                break;
            }
            sent += batch.len();
            if tx.blocking_send(Ok(batch.concat())).is_err() {
                // The client went away mid-download.
                return;
            }
            if batch.len() < EXPORT_BATCH {
                break;
            }
            if sent >= EXPORT_MAX {
                let _ = tx.blocking_send(Ok(format!(
                    "# truncated: export limit of {EXPORT_MAX} lines reached — narrow the filters for the rest\n"
                )));
                break;
            }
        }
        tracing::info!("raw export: {sent} line(s) from {table}");
    });

    (
        [
            (header::CONTENT_TYPE, "text/plain; charset=utf-8".to_string()),
            (
                header::CONTENT_DISPOSITION,
                format!("attachment; filename=\"{filename}\""),
            ),
        ],
        Body::from_stream(tokio_stream::wrappers::ReceiverStream::new(rx)),
    )
        .into_response()
}

// Names the download after the log type and the moment it was taken, so several
// exports don't collide in a downloads folder.
pub(crate) fn filename(table: &str) -> String {
    format!("easylog-{table}-{}.log", chrono::Utc::now().format("%Y%m%d-%H%M%S"))
}
