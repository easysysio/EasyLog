// =============================================================================
// web/apache.rs — Apache dashboard (GET /apache)
//
// Renders the Apache log dashboard by running live aggregation queries over the
// parsed `apache` rows in DuckDB (no pre-computed aggregates): KPI cards, a
// requests timeline, a status-code-class breakdown, and top-10 URLs and client
// IPs. All bars are rendered server-side as CSS widths (no JS libraries).
//
// Time range: a `range` param (1h / 24h / 7d / 30d / 1y; default 24h) bounds the
// whole dashboard to events newer than now − range, and the timeline buckets
// adapt to it. Drill-down: ?ip= / ?path= / ?status= filter to matching requests;
// filters stack and show as removable chips. The range and filters compose into
// one shared SQL WHERE clause; all values are bound as parameters.
// =============================================================================

use std::sync::Arc;

use axum::{
    extract::{Query, State},
    response::Html,
};
use chrono::{Duration, Utc};
use duckdb::params_from_iter;
use duckdb::types::Value;
use serde::{Deserialize, Serialize};

use super::AppError;
use crate::state::AppState;

// Dashboard filter, parsed from the query string and re-serialized into links.
// `ip`/`path`/`status` are drill-down filters; `range` selects the time window.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub(crate) struct Filter {
    #[serde(skip_serializing_if = "Option::is_none")]
    ip: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    status: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    range: Option<String>,
}

impl Filter {
    // Trim string fields, drop empties, and reject an unknown range (→ default).
    fn normalized(self) -> Filter {
        let clean = |o: Option<String>| o.map(|s| s.trim().to_string()).filter(|s| !s.is_empty());
        let range = clean(self.range).filter(|r| matches!(r.as_str(), "1h" | "24h" | "7d" | "30d" | "1y"));
        Filter {
            ip: clean(self.ip),
            path: clean(self.path),
            status: self.status,
            range,
        }
    }

    // Serialize back to a `/apache?...` URL (values percent-encoded by serde).
    fn href(&self) -> String {
        match serde_urlencoded::to_string(self) {
            Ok(q) if !q.is_empty() => format!("/apache?{q}"),
            _ => "/apache".to_string(),
        }
    }

    fn with_ip(&self, v: &str) -> Filter {
        Filter { ip: Some(v.to_string()), ..self.clone() }
    }
    fn with_path(&self, v: &str) -> Filter {
        Filter { path: Some(v.to_string()), ..self.clone() }
    }
    fn with_status(&self, v: i32) -> Filter {
        Filter { status: Some(v), ..self.clone() }
    }
    fn with_range(&self, v: &str) -> Filter {
        Filter { range: Some(v.to_string()), ..self.clone() }
    }
    fn without_ip(&self) -> Filter {
        Filter { ip: None, ..self.clone() }
    }
    fn without_path(&self) -> Filter {
        Filter { path: None, ..self.clone() }
    }
    fn without_status(&self) -> Filter {
        Filter { status: None, ..self.clone() }
    }

    // Effective time range key (defaults to 24h).
    fn range_key(&self) -> &str {
        self.range.as_deref().unwrap_or("24h")
    }

    // SQL conditions + bound values for the active filter and time window. The
    // window is computed from now() once, here, so every query shares one cutoff.
    fn sql(&self) -> (Vec<String>, Vec<Value>) {
        let mut conds = Vec::new();
        let mut vals = Vec::new();
        if let Some(ip) = &self.ip {
            conds.push("remote_host = ?".to_string());
            vals.push(Value::Text(ip.clone()));
        }
        if let Some(path) = &self.path {
            conds.push("path = ?".to_string());
            vals.push(Value::Text(path.clone()));
        }
        if let Some(status) = self.status {
            conds.push("CAST(status / 100 AS INTEGER) = ?".to_string());
            vals.push(Value::Int(status));
        }
        let dur = match self.range_key() {
            "1h" => Duration::hours(1),
            "7d" => Duration::days(7),
            "30d" => Duration::days(30),
            "1y" => Duration::days(365),
            _ => Duration::hours(24),
        };
        let cutoff = (Utc::now() - dur).format("%Y-%m-%d %H:%M:%S").to_string();
        conds.push("ts >= CAST(? AS TIMESTAMP)".to_string());
        vals.push(Value::Text(cutoff));
        (conds, vals)
    }
}

// Time-bucket SQL expression + strftime label format for the timeline, per range.
fn bucketing(range: &str) -> (&'static str, &'static str) {
    match range {
        "1h" => ("time_bucket(INTERVAL '5 minutes', ts)", "%H:%M"),
        "7d" => ("date_trunc('day', ts)", "%m-%d"),
        "30d" => ("date_trunc('day', ts)", "%m-%d"),
        "1y" => ("date_trunc('month', ts)", "%Y-%m"),
        _ => ("date_trunc('hour', ts)", "%H:%M"), // 24h
    }
}

// Human label for the active range, shown on the timeline.
fn range_label(range: &str) -> &'static str {
    match range {
        "1h" => "last hour",
        "7d" => "last 7 days",
        "30d" => "last 30 days",
        "1y" => "last year",
        _ => "last 24 hours",
    }
}

// One option in the time-range selector.
#[derive(Serialize)]
struct RangeOpt {
    label: String,
    href: String,
    active: bool,
}

// An active-filter pill: its label and the URL that removes just that filter.
#[derive(Serialize)]
struct Chip {
    label: String,
    remove: String,
}

// Headline counters shown as KPI cards.
#[derive(Serialize, Default)]
struct Kpis {
    requests: i64,
    unique_ips: i64,
    total_bytes: String, // human-readable
    error_rate: String,  // e.g. "4.2%"
}

// One bar in a chart/list. `href`, when non-empty, makes the row a drill-down
// link; `css` is an optional Bootstrap colour class (status breakdown).
#[derive(Serialize)]
struct Bar {
    label: String,
    count: i64,
    pct: i64,
    css: String,
    href: String,
}

// ─────────────────────────────────────────────────────────────────────────────
// GET /apache  (optional ?range= time window and ?ip= &path= &status= filters)
// Builds the Apache dashboard context from live, range- and filter-bounded
// DuckDB aggregations and renders templates/apache.html.
// ─────────────────────────────────────────────────────────────────────────────
pub async fn dashboard(
    State(state): State<Arc<AppState>>,
    Query(filter): Query<Filter>,
) -> Result<Html<String>, AppError> {
    let filter = filter.normalized();
    let range = filter.range_key().to_string();
    let (conds, vals) = filter.sql();
    let where_clause = build_where(&conds);

    let conn = state.db.lock().expect("db mutex poisoned");

    // Whether any rows exist at all (ignoring range/filter) — decides the "no
    // logs yet" empty state vs. a window/filter that simply matched nothing.
    let total_rows: i64 = {
        let mut stmt = conn.prepare("SELECT count(*) FROM apache")?;
        let mut rows = stmt.query_map([], |r| r.get(0))?;
        rows.next().transpose()?.unwrap_or(0)
    };

    // KPIs over the bounded set, in a single pass.
    let (requests, unique_ips, total_bytes, errors): (i64, i64, i64, i64) = {
        let sql = format!(
            "SELECT count(*), count(DISTINCT remote_host), \
             CAST(coalesce(sum(bytes), 0) AS BIGINT), \
             count(*) FILTER (WHERE status >= 400) FROM apache {where_clause}"
        );
        let mut stmt = conn.prepare(&sql)?;
        let mut rows = stmt.query_map(params_from_iter(vals.iter()), |r| {
            Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?))
        })?;
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

    // Requests over time, bucketed to suit the selected range.
    let (bucket_expr, label_fmt) = bucketing(&range);
    let timeline: Vec<Bar> = {
        let sql = format!(
            "SELECT strftime({bucket_expr}, '{label_fmt}'), count(*) FROM apache {where_clause} \
             GROUP BY {bucket_expr} ORDER BY {bucket_expr}"
        );
        let mut stmt = conn.prepare(&sql)?;
        let pairs = stmt
            .query_map(params_from_iter(vals.iter()), |r| {
                Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        to_bars(pairs)
    };

    // Status-code class breakdown (2xx/3xx/4xx/5xx) — each clickable to filter.
    let statuses: Vec<Bar> = {
        let mut sconds = conds.clone();
        sconds.push("status IS NOT NULL".to_string());
        let sql = format!(
            "SELECT CAST(status / 100 AS INTEGER) k, count(*) FROM apache {} \
             GROUP BY k ORDER BY k",
            build_where(&sconds)
        );
        let mut stmt = conn.prepare(&sql)?;
        let pairs = stmt
            .query_map(params_from_iter(vals.iter()), |r| {
                Ok((r.get::<_, i32>(0)?, r.get::<_, i64>(1)?))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        let max = pairs.iter().map(|(_, c)| *c).max().unwrap_or(0);
        pairs
            .into_iter()
            .map(|(klass, count)| Bar {
                label: format!("{klass}xx"),
                count,
                pct: pct(count, max),
                css: status_class(klass),
                href: filter.with_status(klass).href(),
            })
            .collect()
    };

    // Top 10 paths and client IPs — each clickable to add a filter.
    let top_urls = top_n(&conn, "path", &where_clause, &vals, |label| {
        filter.with_path(label).href()
    })?;
    let top_ips = top_n(&conn, "remote_host", &where_clause, &vals, |label| {
        filter.with_ip(label).href()
    })?;

    // Time-range selector options.
    let range_defs = [
        ("1h", "Hour"),
        ("24h", "24 h"),
        ("7d", "Week"),
        ("30d", "Month"),
        ("1y", "Year"),
    ];
    let range_options: Vec<RangeOpt> = range_defs
        .iter()
        .map(|&(value, label)| RangeOpt {
            label: label.to_string(),
            href: filter.with_range(value).href(),
            active: range == value,
        })
        .collect();

    // Active-filter chips (ip/path/status; the range has its own selector).
    let mut chips: Vec<Chip> = Vec::new();
    if let Some(ip) = &filter.ip {
        chips.push(Chip { label: format!("Client IP: {ip}"), remove: filter.without_ip().href() });
    }
    if let Some(path) = &filter.path {
        chips.push(Chip { label: format!("URL: {path}"), remove: filter.without_path().href() });
    }
    if let Some(status) = filter.status {
        chips.push(Chip {
            label: format!("Status: {status}xx"),
            remove: filter.without_status().href(),
        });
    }

    let mut ctx = tera::Context::new();
    ctx.insert("active", "apache");
    ctx.insert("kpis", &kpis);
    ctx.insert("timeline", &timeline);
    ctx.insert("statuses", &statuses);
    ctx.insert("top_urls", &top_urls);
    ctx.insert("top_ips", &top_ips);
    ctx.insert("chips", &chips);
    ctx.insert("range_options", &range_options);
    ctx.insert("range_label", range_label(&range));
    ctx.insert("has_filters", &!chips.is_empty());
    ctx.insert("has_data", &(total_rows > 0));
    Ok(Html(state.tera.render("apache.html", &ctx)?))
}

// Runs a "top N by count" query for `column` over the bounded set, turning each
// row into a clickable Bar via `href_for(label)`.
fn top_n(
    conn: &duckdb::Connection,
    column: &str,
    where_clause: &str,
    vals: &[Value],
    href_for: impl Fn(&str) -> String,
) -> Result<Vec<Bar>, AppError> {
    let sql = format!(
        "SELECT {column}, count(*) c FROM apache {where_clause} \
         GROUP BY {column} ORDER BY c DESC, {column} LIMIT 10"
    );
    let mut stmt = conn.prepare(&sql)?;
    let pairs = stmt
        .query_map(params_from_iter(vals.iter()), |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    let max = pairs.iter().map(|(_, c)| *c).max().unwrap_or(0);
    Ok(pairs
        .into_iter()
        .map(|(label, count)| Bar {
            pct: pct(count, max),
            count,
            href: href_for(&label),
            css: String::new(),
            label,
        })
        .collect())
}

// Joins conditions into a SQL WHERE clause (empty string when there are none).
fn build_where(conds: &[String]) -> String {
    if conds.is_empty() {
        String::new()
    } else {
        format!("WHERE {}", conds.join(" AND "))
    }
}

// Converts "(label, count)" pairs into non-clickable Bars (used for the timeline).
fn to_bars(pairs: Vec<(String, i64)>) -> Vec<Bar> {
    let max = pairs.iter().map(|(_, c)| *c).max().unwrap_or(0);
    pairs
        .into_iter()
        .map(|(label, count)| Bar {
            pct: pct(count, max),
            count,
            css: String::new(),
            href: String::new(),
            label,
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
