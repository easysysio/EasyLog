// =============================================================================
// web/apache.rs — Apache dashboard (GET /apache)
//
// Renders the Apache log dashboard by running live aggregation queries over the
// parsed `apache` rows in DuckDB (no pre-computed aggregates): KPI cards, a
// per-hour requests timeline, a status-code-class breakdown, and top-10 URLs and
// client IPs. All bars are rendered server-side as CSS widths (no JS libraries).
// =============================================================================

use std::sync::Arc;

use axum::{extract::State, response::Html};
use serde::Serialize;

use super::AppError;
use crate::state::AppState;

// Headline counters shown as KPI cards.
#[derive(Serialize, Default)]
struct Kpis {
    requests: i64,
    unique_ips: i64,
    total_bytes: String, // human-readable
    error_rate: String,  // e.g. "4.2%"
}

// One bar in a chart/list: a label, its count, and a 0–100 percentage used as
// the CSS bar size (relative to the largest value in the series).
#[derive(Serialize)]
struct Bar {
    label: String,
    count: i64,
    pct: i64,
    css: String, // colour class, used by the status breakdown
}

// ─────────────────────────────────────────────────────────────────────────────
// GET /apache
// Builds the Apache dashboard context from live DuckDB aggregations and renders
// templates/apache.html.
// ─────────────────────────────────────────────────────────────────────────────
pub async fn dashboard(State(state): State<Arc<AppState>>) -> Result<Html<String>, AppError> {
    let conn = state.db.lock().expect("db mutex poisoned");

    // KPIs in a single pass over the table.
    let (requests, unique_ips, total_bytes, errors): (i64, i64, i64, i64) = {
        let mut stmt = conn.prepare(
            r#"SELECT count(*),
                      count(DISTINCT remote_host),
                      CAST(coalesce(sum(bytes), 0) AS BIGINT),
                      count(*) FILTER (WHERE status >= 400)
               FROM apache"#,
        )?;
        let mut rows = stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))?;
        rows.next().transpose()?.unwrap_or((0, 0, 0, 0))
    };

    let error_rate = if requests > 0 {
        format!("{:.1}%", errors as f64 * 100.0 / requests as f64)
    } else {
        "0.0%".to_string()
    };
    let kpis = Kpis {
        requests,
        unique_ips,
        total_bytes: human_bytes(total_bytes),
        error_rate,
    };

    // Requests per hour over the last 24 hours of data (relative to the most
    // recent event timestamp), ordered oldest → newest.
    let timeline_raw: Vec<(String, i64)> = {
        let mut stmt = conn.prepare(
            r#"SELECT strftime(date_trunc('hour', ts), '%H:%M') AS bucket, count(*)
               FROM apache
               WHERE ts IS NOT NULL
                 AND ts >= (SELECT max(ts) FROM apache) - INTERVAL '23 hours'
               GROUP BY date_trunc('hour', ts)
               ORDER BY date_trunc('hour', ts)"#,
        )?;
        collect_pairs(&mut stmt)?
    };
    let timeline = to_bars(timeline_raw, "");

    // Status-code class breakdown (2xx/3xx/4xx/5xx).
    let status_raw: Vec<(i32, i64)> = {
        let mut stmt = conn.prepare(
            r#"SELECT CAST(status / 100 AS INTEGER) AS klass, count(*)
               FROM apache
               WHERE status IS NOT NULL
               GROUP BY klass
               ORDER BY klass"#,
        )?;
        let rows = stmt.query_map([], |r| Ok((r.get::<_, i32>(0)?, r.get::<_, i64>(1)?)))?;
        rows.collect::<Result<Vec<_>, _>>()?
    };
    let max_status = status_raw.iter().map(|(_, c)| *c).max().unwrap_or(0);
    let statuses: Vec<Bar> = status_raw
        .into_iter()
        .map(|(klass, count)| Bar {
            label: format!("{klass}xx"),
            count,
            pct: pct(count, max_status),
            css: status_class(klass),
        })
        .collect();

    // Top 10 requested paths and top 10 client IPs.
    let top_urls = {
        let mut stmt = conn.prepare(
            r#"SELECT path, count(*) c FROM apache
               GROUP BY path ORDER BY c DESC, path LIMIT 10"#,
        )?;
        to_bars(collect_pairs(&mut stmt)?, "")
    };
    let top_ips = {
        let mut stmt = conn.prepare(
            r#"SELECT remote_host, count(*) c FROM apache
               GROUP BY remote_host ORDER BY c DESC, remote_host LIMIT 10"#,
        )?;
        to_bars(collect_pairs(&mut stmt)?, "")
    };

    let mut ctx = tera::Context::new();
    ctx.insert("active", "apache");
    ctx.insert("kpis", &kpis);
    ctx.insert("timeline", &timeline);
    ctx.insert("statuses", &statuses);
    ctx.insert("top_urls", &top_urls);
    ctx.insert("top_ips", &top_ips);
    ctx.insert("has_data", &(requests > 0));
    Ok(Html(state.tera.render("apache.html", &ctx)?))
}

// Runs a "(text, count)" query and collects the rows.
fn collect_pairs(stmt: &mut duckdb::Statement) -> Result<Vec<(String, i64)>, AppError> {
    let rows = stmt.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?)))?;
    Ok(rows.collect::<Result<Vec<_>, _>>()?)
}

// Converts "(label, count)" pairs into Bars, scaling pct to the series max.
fn to_bars(pairs: Vec<(String, i64)>, css: &str) -> Vec<Bar> {
    let max = pairs.iter().map(|(_, c)| *c).max().unwrap_or(0);
    pairs
        .into_iter()
        .map(|(label, count)| Bar {
            label,
            count,
            pct: pct(count, max),
            css: css.to_string(),
        })
        .collect()
}

// Percentage of `count` relative to `max`, clamped to [0, 100].
fn pct(count: i64, max: i64) -> i64 {
    if max <= 0 {
        0
    } else {
        (count * 100 / max).clamp(0, 100)
    }
}

// Maps an HTTP status class (2,3,4,5) to a Bootstrap background-colour class.
fn status_class(klass: i32) -> String {
    match klass {
        2 => "bg-success",
        3 => "bg-info",
        4 => "bg-warning",
        _ => "bg-danger",
    }
    .to_string()
}

// Formats a byte count as a human-readable string (B/KB/MB/GB/TB).
fn human_bytes(n: i64) -> String {
    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let mut v = n as f64;
    let mut i = 0;
    while v >= 1024.0 && i < UNITS.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    if i == 0 {
        format!("{n} B")
    } else {
        format!("{v:.1} {}", UNITS[i])
    }
}
