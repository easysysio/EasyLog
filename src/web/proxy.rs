// =============================================================================
// web/proxy.rs — shared dashboard for request logs that carry a duration
//
// Traefik, Caddy (and later HAProxy) all log the same shape: a request with a
// status, a size and a service time, plus one or two routing dimensions of their
// own — Traefik's router/service, HAProxy's backend/server. This module renders
// that dashboard once; each type supplies a `Spec` describing its table, its
// route, how it labels itself, and which extra dimensions to panel and filter on.
//
// Apache and nginx use the simpler renderer in web/apache.rs — they have no
// duration to report.
//
// Everything is a live DuckDB aggregation over the type's table: KPI cards
// (incl. avg and p95 duration), a requests timeline, a status-code breakdown,
// top paths / client IPs / countries, the world map, and the spec's extra
// panels. The time range (?range=) and every drill-down filter compose into one
// parameterized WHERE clause.
// =============================================================================

use std::sync::Arc;

use axum::response::{Html, IntoResponse, Response};
use chrono::{Duration, Utc};
use duckdb::params_from_iter;
use duckdb::types::Value;
use serde::{Deserialize, Serialize};

use super::AppError;
use crate::state::AppState;

/// A routing dimension a log type can be filtered and panelled by, beyond the
/// fields every request log shares.
pub(crate) struct ExtraDim {
    /// Query-string parameter and column name, e.g. "router".
    pub key: &'static str,
    /// Panel heading, e.g. "Top routers".
    pub title: &'static str,
    pub icon: &'static str,
    /// Chip prefix when the filter is active, e.g. "Router".
    pub chip: &'static str,
}

/// Everything that differs between one duration-carrying request log and another.
pub(crate) struct Spec {
    /// DuckDB table (and log-type name).
    pub table: &'static str,
    /// Route this dashboard is served at, e.g. "/web/traefik".
    pub base: &'static str,
    /// Navigation category slug, e.g. "web".
    pub category: &'static str,
    /// Display name, e.g. "Traefik".
    pub label: &'static str,
    pub icon: &'static str,
    /// Badge shown next to the heading, e.g. "JSON access log".
    pub badge: &'static str,
    /// Sentence completing the empty state, telling the user what to forward.
    pub hint: &'static str,
    pub extra: &'static [ExtraDim],
    /// Columns the search box matches against. Listed per type rather than
    /// shared, because these tables genuinely differ — HAProxy logs no user
    /// agent, and only the JSON types record the requested host.
    pub search: &'static [&'static str],
}

// Drill-down + time-range filter. The extra dimensions of every supported type
// share this struct; a type only ever reads the ones in its own spec, so an
// unrelated parameter in the URL is simply ignored.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub(crate) struct Filter {
    #[serde(skip_serializing_if = "Option::is_none")]
    ip: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    status: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    country: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    router: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    service: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    backend: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    server: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    range: Option<String>,
    /// "raw" lists the matching log lines instead of the charts; "download"
    /// streams them as a file. Anything else renders the dashboard.
    #[serde(skip_serializing_if = "Option::is_none")]
    view: Option<String>,
    /// How many raw lines to show; grows as "Load more" is used.
    #[serde(skip_serializing_if = "Option::is_none")]
    limit: Option<usize>,
    /// Free-text search across this type's searchable columns.
    #[serde(skip_serializing_if = "Option::is_none")]
    q: Option<String>,
}

// One preserved filter value, rendered as a hidden input in the search form.
#[derive(Serialize)]
struct HiddenField {
    name: String,
    value: String,
}

impl Filter {
    fn normalized(self) -> Filter {
        let clean = |o: Option<String>| o.map(|s| s.trim().to_string()).filter(|s| !s.is_empty());
        let range = clean(self.range).filter(|r| matches!(r.as_str(), "1h" | "24h" | "7d" | "30d" | "1y"));
        Filter {
            ip: clean(self.ip),
            path: clean(self.path),
            status: self.status,
            country: clean(self.country),
            router: clean(self.router),
            service: clean(self.service),
            backend: clean(self.backend),
            server: clean(self.server),
            range,
            q: clean(self.q),
            view: clean(self.view),
            limit: self.limit,
        }
    }
    // Raw-view helpers: the toggle in and out, and the growing page size.
    fn view_key(&self) -> &str {
        self.view.as_deref().unwrap_or("")
    }
    fn raw_limit(&self) -> usize {
        self.limit
            .unwrap_or(super::rawview::PAGE)
            .clamp(super::rawview::PAGE, 20_000)
    }
    fn with_view(&self, v: &str) -> Filter {
        Filter { view: Some(v.to_string()), limit: None, ..self.clone() }
    }
    fn without_view(&self) -> Filter {
        Filter { view: None, limit: None, ..self.clone() }
    }
    fn with_limit(&self, n: usize) -> Filter {
        Filter { limit: Some(n), ..self.clone() }
    }


    // The active filter minus the search term, as form fields — so submitting
    // the search box keeps the range and any drill-down instead of dropping it.
    fn hidden_fields(&self) -> Vec<HiddenField> {
        let without_q = Filter { q: None, ..self.clone() };
        serde_urlencoded::to_string(&without_q)
            .ok()
            .and_then(|s| serde_urlencoded::from_str::<Vec<(String, String)>>(&s).ok())
            .unwrap_or_default()
            .into_iter()
            .map(|(name, value)| HiddenField { name, value })
            .collect()
    }

    fn without_q(&self) -> Filter {
        Filter { q: None, ..self.clone() }
    }

    // Serialize back to a `<base>?...` URL (values percent-encoded by serde).
    fn href(&self, base: &str) -> String {
        match serde_urlencoded::to_string(self) {
            Ok(q) if !q.is_empty() => format!("{base}?{q}"),
            _ => base.to_string(),
        }
    }

    // The extra dimensions are addressed by key so one renderer can serve types
    // with different routing fields.
    fn extra(&self, key: &str) -> Option<&String> {
        match key {
            "router" => self.router.as_ref(),
            "service" => self.service.as_ref(),
            "backend" => self.backend.as_ref(),
            "server" => self.server.as_ref(),
            _ => None,
        }
    }

    fn set_extra(&self, key: &str, value: Option<String>) -> Filter {
        let mut next = self.clone();
        match key {
            "router" => next.router = value,
            "service" => next.service = value,
            "backend" => next.backend = value,
            "server" => next.server = value,
            _ => {}
        }
        next
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
    fn with_country(&self, v: &str) -> Filter {
        Filter { country: Some(v.to_string()), ..self.clone() }
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
    fn without_country(&self) -> Filter {
        Filter { country: None, ..self.clone() }
    }

    fn range_key(&self) -> &str {
        self.range.as_deref().unwrap_or("24h")
    }

    // SQL conditions + bound values for the active filter and time window, using
    // only the extra dimensions this type declares.
    fn sql(&self, spec: &Spec) -> (Vec<String>, Vec<Value>) {
        let extra = spec.extra;
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
        if let Some(country) = &self.country {
            conds.push("coalesce(nullif(country, ''), 'Unknown') = ?".to_string());
            vals.push(Value::Text(country.clone()));
        }
        for dim in extra {
            if let Some(value) = self.extra(dim.key) {
                conds.push(format!("{} = ?", dim.key));
                vals.push(Value::Text(value.clone()));
            }
        }
        let dur = match self.range_key() {
            "1h" => Duration::hours(1),
            "7d" => Duration::days(7),
            "30d" => Duration::days(30),
            "1y" => Duration::days(365),
            _ => Duration::hours(24),
        };
        // Free text matches any searchable column; the term is bound once per
        // column so it can never be interpolated into the SQL.
        if let Some(q) = &self.q {
            let ors: Vec<String> = spec.search.iter().map(|c| format!("{c} ILIKE ?")).collect();
            conds.push(format!("({})", ors.join(" OR ")));
            for _ in spec.search {
                vals.push(Value::Text(format!("%{q}%")));
            }
        }
        let cutoff = (Utc::now() - dur).format("%Y-%m-%d %H:%M:%S").to_string();
        conds.push("ts >= CAST(? AS TIMESTAMP)".to_string());
        vals.push(Value::Text(cutoff));
        (conds, vals)
    }
}

#[derive(Serialize)]
struct RangeOpt {
    label: String,
    href: String,
    active: bool,
}

#[derive(Serialize)]
struct Chip {
    label: String,
    remove: String,
}

#[derive(Serialize, Default)]
struct Kpis {
    requests: i64,
    unique_ips: i64,
    countries: i64,
    total_bytes: String,
    error_rate: String,
    avg_ms: String,
    p95_ms: String,
}

#[derive(Serialize)]
struct Bar {
    label: String,
    count: i64,
    pct: i64,
    css: String,
    href: String,
    /// Bucket start as a UTC epoch (seconds); 0 for non-timeline bars.
    ts_epoch: i64,
}

// One of the spec's extra dimensions, rendered as a top-N panel.
#[derive(Serialize)]
struct Panel {
    title: &'static str,
    icon: &'static str,
    bars: Vec<Bar>,
}

// ─────────────────────────────────────────────────────────────────────────────
// render(state, raw, spec)
// Builds the dashboard described by `spec` from live, range- and filter-bounded
// DuckDB aggregations, and renders proxy.html.
// ─────────────────────────────────────────────────────────────────────────────
pub(crate) fn render(
    state: &Arc<AppState>,
    raw: Filter,
    spec: &Spec,
) -> Result<Response, AppError> {
    let filter = raw.normalized();
    let table = spec.table;
    let base = spec.base;
    let range = filter.range_key().to_string();
    let (conds, vals) = filter.sql(spec);
    let where_clause = build_where(&conds);


    let (range_options, chips) = furniture(&filter, spec, base, &range);

    // Raw mode reuses this dashboard's WHERE clause, so the lines listed are
    // exactly the events the charts summarise. Handled before the database lock
    // is taken: rawview does its own locking, and the aggregations below would
    // be wasted work.
    if matches!(filter.view_key(), "raw" | "download") {
        if filter.view_key() == "download" {
            return Ok(super::rawview::download(
                state,
                table,
                &where_clause,
                &vals,
                super::rawview::filename(table),
            ));
        }
        let mut ctx = tera::Context::new();
        ctx.insert("active", table);
        ctx.insert("active_category", spec.category);
        ctx.insert("nav", &state.nav);
        ctx.insert("type_label", spec.label);
        ctx.insert("base", base);
        ctx.insert("chips", &chips);
        ctx.insert("range_options", &range_options);
        ctx.insert("range_label", range_label(&range));
        ctx.insert("has_filters", &!chips.is_empty());
        ctx.insert("search", &filter.q.clone().unwrap_or_default());
        ctx.insert("search_fields", &filter.hidden_fields());
        ctx.insert("search_placeholder", "Search URL, client IP, agent…");
    ctx.insert("raw_href", &filter.with_view("raw").href(base));
        ctx.insert("dashboard_href", &filter.without_view().href(base));
        ctx.insert(
            "more_href",
            &filter.with_limit(filter.raw_limit() + super::rawview::PAGE).href(base),
        );
        ctx.insert("download_href", &filter.with_view("download").href(base));
        return Ok(super::rawview::render(
            state,
            ctx,
            table,
            &where_clause,
            &vals,
            filter.raw_limit(),
        )?
        .into_response());
    }

    let conn = state.db.lock().expect("db mutex poisoned");

    // Any rows at all (ignoring range/filter) — decides the "no logs yet" state.
    let total_rows: i64 = {
        let mut stmt = conn.prepare(&format!("SELECT count(*) FROM {table}"))?;
        let mut rows = stmt.query_map([], |r| r.get(0))?;
        rows.next().transpose()?.unwrap_or(0)
    };

    // KPIs incl. average and p95 duration (NULL durations are ignored).
    let (requests, unique_ips, countries, total_bytes, errors, avg_ms, p95_ms): (
        i64,
        i64,
        i64,
        i64,
        i64,
        Option<f64>,
        Option<f64>,
    ) = {
        let sql = format!(
            "SELECT count(*), count(DISTINCT remote_host), \
             count(DISTINCT country_code) FILTER (WHERE country_code IS NOT NULL AND country_code <> ''), \
             CAST(coalesce(sum(bytes), 0) AS BIGINT), \
             count(*) FILTER (WHERE status >= 400), \
             avg(duration_ms), quantile_cont(duration_ms, 0.95) \
             FROM {table} {where_clause}"
        );
        let mut stmt = conn.prepare(&sql)?;
        let mut rows = stmt.query_map(params_from_iter(vals.iter()), |r| {
            Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?, r.get(6)?))
        })?;
        rows.next().transpose()?.unwrap_or((0, 0, 0, 0, 0, None, None))
    };

    let error_rate = if requests > 0 {
        format!("{:.1}%", errors as f64 * 100.0 / requests as f64)
    } else {
        "0.0%".to_string()
    };
    let kpis = Kpis {
        requests,
        unique_ips,
        countries,
        total_bytes: human_bytes(total_bytes),
        error_rate,
        avg_ms: fmt_ms(avg_ms),
        p95_ms: fmt_ms(p95_ms),
    };

    // Requests over time, zero-filled onto the full series for the range.
    let (bucket_expr, tl_gran) = bucketing(&range);
    let counts: std::collections::HashMap<i64, i64> = {
        let sql = format!(
            "SELECT CAST(epoch({bucket_expr}) AS BIGINT), count(*) FROM {table} {where_clause} \
             GROUP BY {bucket_expr}"
        );
        let mut stmt = conn.prepare(&sql)?;
        stmt.query_map(params_from_iter(vals.iter()), |r| {
            Ok((r.get::<_, i64>(0)?, r.get::<_, i64>(1)?))
        })?
        .collect::<Result<std::collections::HashMap<i64, i64>, _>>()?
    };
    let series = super::timeline_series(&range);
    let timeline_max = series
        .iter()
        .map(|(e, _)| counts.get(e).copied().unwrap_or(0))
        .max()
        .unwrap_or(0);
    let timeline: Vec<Bar> = series
        .into_iter()
        .map(|(epoch, label)| {
            let count = counts.get(&epoch).copied().unwrap_or(0);
            Bar {
                pct: pct(count, timeline_max),
                count,
                css: String::new(),
                href: String::new(),
                label,
                ts_epoch: epoch,
            }
        })
        .collect();

    // Status-code class breakdown.
    let statuses: Vec<Bar> = {
        let mut sconds = conds.clone();
        sconds.push("status IS NOT NULL".to_string());
        let sql = format!(
            "SELECT CAST(status / 100 AS INTEGER) k, count(*) FROM {table} {} \
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
                href: filter.with_status(klass).href(base),
                ts_epoch: 0,
            })
            .collect()
    };

    // Top-N panels (each clickable to add the matching filter).
    let top_urls = top_n(&conn, table, "path", &where_clause, &vals, |l| {
        filter.with_path(l).href(base)
    })?;
    let top_ips = top_n(&conn, table, "remote_host", &where_clause, &vals, |l| {
        filter.with_ip(l).href(base)
    })?;
    let top_countries = top_n(
        &conn,
        table,
        "coalesce(nullif(country, ''), 'Unknown')",
        &where_clause,
        &vals,
        |l| filter.with_country(l).href(base),
    )?;

    // The type's own routing dimensions (Traefik routers/services, HAProxy
    // backends/servers, …) — same treatment, driven by the spec.
    let mut extra_panels: Vec<Panel> = Vec::new();
    for dim in spec.extra {
        let bars = top_n(&conn, table, dim.key, &where_clause, &vals, |l| {
            filter.set_extra(dim.key, Some(l.to_string())).href(base)
        })?;
        extra_panels.push(Panel { title: dim.title, icon: dim.icon, bars });
    }

    // World map, shaded from every country in the bounded set (not just the top
    // 10); clicking a country applies the same filter as the panel above.
    let country_rows = super::geomap::counts(&conn, table, &where_clause, &vals)?;
    let map = super::geomap::build(&country_rows, Some(&|name: &str| {
        filter.with_country(name).href(base)
    }));

    let mut ctx = tera::Context::new();
    ctx.insert("active", spec.table);
    ctx.insert("active_category", spec.category);
    ctx.insert("nav", &state.nav);
    ctx.insert("type_label", spec.label);
    ctx.insert("type_icon", spec.icon);
    ctx.insert("badge", spec.badge);
    ctx.insert("hint", spec.hint);
    ctx.insert("base", base);
    ctx.insert("kpis", &kpis);
    ctx.insert("timeline", &timeline);
    ctx.insert("timeline_max", &timeline_max);
    ctx.insert("timeline_mid", &(timeline_max / 2));
    ctx.insert("tl_gran", tl_gran);
    ctx.insert("statuses", &statuses);
    ctx.insert("top_urls", &top_urls);
    ctx.insert("top_ips", &top_ips);
    ctx.insert("top_countries", &top_countries);
    ctx.insert("extra_panels", &extra_panels);
    ctx.insert("map", &map);
    ctx.insert("chips", &chips);
    ctx.insert("search", &filter.q.clone().unwrap_or_default());
    ctx.insert("search_fields", &filter.hidden_fields());
    ctx.insert("search_placeholder", "Search URL, client IP, agent…");
    ctx.insert("raw_href", &filter.with_view("raw").href(base));
    ctx.insert("range_options", &range_options);
    ctx.insert("range_label", range_label(&range));
    ctx.insert("has_filters", &!chips.is_empty());
    ctx.insert("has_data", &(total_rows > 0));
    Ok(Html(state.tera.render("proxy.html", &ctx)?).into_response())
}

// Runs a "top N by count" query for `column` over the bounded set, turning each
// row into a clickable Bar via `href_for(label)`.
// The furniture every view of this dashboard shares: the range selector and the
// chips for whatever filters are active. Pure functions of the filter, so the
// raw view can build them without touching the database.
fn furniture(filter: &Filter, spec: &Spec, base: &str, range: &str) -> (Vec<RangeOpt>, Vec<Chip>) {
    // Time-range selector.
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
            href: filter.with_range(value).href(base),
            active: range == value,
        })
        .collect();

    // Active-filter chips.
    let mut chips: Vec<Chip> = Vec::new();
    if let Some(ip) = &filter.ip {
        chips.push(Chip { label: format!("Client IP: {ip}"), remove: filter.without_ip().href(base) });
    }
    if let Some(path) = &filter.path {
        chips.push(Chip { label: format!("URL: {path}"), remove: filter.without_path().href(base) });
    }
    if let Some(status) = filter.status {
        chips.push(Chip { label: format!("Status: {status}xx"), remove: filter.without_status().href(base) });
    }
    for dim in spec.extra {
        if let Some(value) = filter.extra(dim.key) {
            chips.push(Chip {
                label: format!("{}: {value}", dim.chip),
                remove: filter.set_extra(dim.key, None).href(base),
            });
        }
    }
    if let Some(country) = &filter.country {
        chips.push(Chip { label: format!("Country: {country}"), remove: filter.without_country().href(base) });
    }
    if let Some(q) = &filter.q {
        chips.push(Chip { label: format!("Search: {q}"), remove: filter.without_q().href(base) });
    }
    (range_options, chips)
}

fn top_n(
    conn: &duckdb::Connection,
    table: &str,
    column: &str,
    where_clause: &str,
    vals: &[Value],
    href_for: impl Fn(&str) -> String,
) -> Result<Vec<Bar>, AppError> {
    let sql = format!(
        "SELECT {column}, count(*) c FROM {table} {where_clause} \
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
            ts_epoch: 0,
        })
        .collect())
}

fn build_where(conds: &[String]) -> String {
    if conds.is_empty() {
        String::new()
    } else {
        format!("WHERE {}", conds.join(" AND "))
    }
}

fn pct(count: i64, max: i64) -> i64 {
    if max <= 0 {
        0
    } else {
        (count * 100 / max).clamp(0, 100)
    }
}

fn status_class(klass: i32) -> String {
    match klass {
        2 => "bg-success",
        3 => "bg-info",
        4 => "bg-warning",
        _ => "bg-danger",
    }
    .to_string()
}

fn bucketing(range: &str) -> (&'static str, &'static str) {
    match range {
        "1h" => ("time_bucket(INTERVAL '5 minutes', ts)", "time"),
        "7d" => ("date_trunc('day', ts)", "day"),
        "30d" => ("date_trunc('day', ts)", "day"),
        "1y" => ("date_trunc('month', ts)", "month"),
        _ => ("date_trunc('hour', ts)", "time"),
    }
}

fn range_label(range: &str) -> &'static str {
    match range {
        "1h" => "last hour",
        "7d" => "last 7 days",
        "30d" => "last 30 days",
        "1y" => "last year",
        _ => "last 24 hours",
    }
}

// Formats an optional millisecond duration for display.
fn fmt_ms(ms: Option<f64>) -> String {
    match ms {
        Some(v) => format!("{v:.0} ms"),
        None => "—".to_string(),
    }
}

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
