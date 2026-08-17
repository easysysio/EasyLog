// =============================================================================
// web/firewall.rs — shared dashboard for firewall log types
//
// Firewall logs answer a different question from access logs: not "how fast did
// this respond" but "what got in, what got blocked, and from where". So this
// dashboard is built around the allow/deny split — a deny rate KPI, an action
// breakdown, top sources, destinations and ports, and the rule that decided —
// over the same shared schema every firewall type normalizes into (see
// logtype/firewall.rs).
//
// Vendors supply a `Spec` describing their table, route and labelling, plus any
// extra dimension they alone have (PAN-OS applications, say). Geolocation is on
// the source address, so the world map shows where traffic is coming from.
// =============================================================================

use std::sync::Arc;

use axum::response::{Html, IntoResponse, Response};
use chrono::{Duration, Utc};
use duckdb::params_from_iter;
use duckdb::types::Value;
use serde::{Deserialize, Serialize};

use super::AppError;
use crate::state::AppState;

/// A dimension only some firewall vendors log, panelled and filtered when the
/// spec declares it.
pub(crate) struct ExtraDim {
    /// Query parameter and column name, e.g. "application".
    pub key: &'static str,
    pub title: &'static str,
    pub icon: &'static str,
    pub chip: &'static str,
}

/// Everything that differs between one firewall log type and another.
pub(crate) struct Spec {
    pub table: &'static str,
    pub base: &'static str,
    pub category: &'static str,
    pub label: &'static str,
    pub icon: &'static str,
    pub badge: &'static str,
    /// Sentence completing the empty state, telling the user what to forward.
    pub hint: &'static str,
    pub extra: &'static [ExtraDim],
}

// Columns the search box looks in. Ports are cast so that typing "443" finds
// traffic to it, alongside addresses, rules, zones and applications.
const SEARCH_COLUMNS: [&str; 9] = [
    "src_ip",
    "dst_ip",
    "rule",
    "application",
    "protocol",
    "src_zone",
    "dst_zone",
    "country",
    "CAST(dst_port AS VARCHAR)",
];

// Drill-down + time-range filter shared by every firewall dashboard.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub(crate) struct Filter {
    #[serde(skip_serializing_if = "Option::is_none")]
    src: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    dst: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    port: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    action: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    protocol: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    rule: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    country: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    application: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    range: Option<String>,
    /// "raw" lists the matching log lines instead of the charts; "download"
    /// streams them as a file. Anything else renders the dashboard.
    #[serde(skip_serializing_if = "Option::is_none")]
    view: Option<String>,
    /// How many raw lines to show; grows as "Load more" is used.
    #[serde(skip_serializing_if = "Option::is_none")]
    limit: Option<usize>,
    /// Free-text search across SEARCH_COLUMNS.
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
        let action = clean(self.action).filter(|a| matches!(a.as_str(), "allow" | "deny"));
        Filter {
            src: clean(self.src),
            dst: clean(self.dst),
            port: self.port,
            action,
            protocol: clean(self.protocol),
            rule: clean(self.rule),
            country: clean(self.country),
            application: clean(self.application),
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
        // `view` and `limit` are deliberately dropped: the template that needs a
        // view emits its own hidden input (two would be a duplicate field and a
        // 400), and a fresh search should start at the first page of results.
        let without_q = Filter { q: None, view: None, limit: None, ..self.clone() };
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

    fn href(&self, base: &str) -> String {
        match serde_urlencoded::to_string(self) {
            Ok(q) if !q.is_empty() => format!("{base}?{q}"),
            _ => base.to_string(),
        }
    }

    fn extra(&self, key: &str) -> Option<&String> {
        match key {
            "application" => self.application.as_ref(),
            "rule" => self.rule.as_ref(),
            _ => None,
        }
    }

    fn set_extra(&self, key: &str, value: Option<String>) -> Filter {
        let mut next = self.clone();
        match key {
            "application" => next.application = value,
            "rule" => next.rule = value,
            _ => {}
        }
        next
    }

    fn with_src(&self, v: &str) -> Filter {
        Filter { src: Some(v.to_string()), ..self.clone() }
    }
    fn with_dst(&self, v: &str) -> Filter {
        Filter { dst: Some(v.to_string()), ..self.clone() }
    }
    fn with_port(&self, v: i32) -> Filter {
        Filter { port: Some(v), ..self.clone() }
    }
    fn with_action(&self, v: &str) -> Filter {
        Filter { action: Some(v.to_string()), ..self.clone() }
    }
    fn with_rule(&self, v: &str) -> Filter {
        Filter { rule: Some(v.to_string()), ..self.clone() }
    }
    fn with_country(&self, v: &str) -> Filter {
        Filter { country: Some(v.to_string()), ..self.clone() }
    }
    fn with_range(&self, v: &str) -> Filter {
        Filter { range: Some(v.to_string()), ..self.clone() }
    }
    fn without_src(&self) -> Filter {
        Filter { src: None, ..self.clone() }
    }
    fn without_dst(&self) -> Filter {
        Filter { dst: None, ..self.clone() }
    }
    fn without_port(&self) -> Filter {
        Filter { port: None, ..self.clone() }
    }
    fn without_action(&self) -> Filter {
        Filter { action: None, ..self.clone() }
    }
    fn without_protocol(&self) -> Filter {
        Filter { protocol: None, ..self.clone() }
    }
    fn without_country(&self) -> Filter {
        Filter { country: None, ..self.clone() }
    }

    fn range_key(&self) -> &str {
        self.range.as_deref().unwrap_or("24h")
    }

    fn sql(&self, extra: &[ExtraDim]) -> (Vec<String>, Vec<Value>) {
        let mut conds = Vec::new();
        let mut vals = Vec::new();
        if let Some(src) = &self.src {
            conds.push("src_ip = ?".to_string());
            vals.push(Value::Text(src.clone()));
        }
        if let Some(dst) = &self.dst {
            conds.push("dst_ip = ?".to_string());
            vals.push(Value::Text(dst.clone()));
        }
        if let Some(port) = self.port {
            conds.push("dst_port = ?".to_string());
            vals.push(Value::Int(port));
        }
        if let Some(action) = &self.action {
            conds.push("action = ?".to_string());
            vals.push(Value::Text(action.clone()));
        }
        if let Some(protocol) = &self.protocol {
            conds.push("protocol = ?".to_string());
            vals.push(Value::Text(protocol.clone()));
        }
        if let Some(country) = &self.country {
            conds.push("coalesce(nullif(country, ''), 'Unknown') = ?".to_string());
            vals.push(Value::Text(country.clone()));
        }
        // `rule` is filtered here for every vendor; the extra list decides
        // whether it also gets a panel of its own.
        if let Some(rule) = &self.rule {
            conds.push("rule = ?".to_string());
            vals.push(Value::Text(rule.clone()));
        }
        for dim in extra {
            if dim.key == "rule" {
                continue; // already applied above
            }
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
            let ors: Vec<String> = SEARCH_COLUMNS.iter().map(|c| format!("{c} ILIKE ?")).collect();
            conds.push(format!("({})", ors.join(" OR ")));
            for _ in SEARCH_COLUMNS {
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
    events: i64,
    denied: i64,
    deny_rate: String,
    sources: i64,
    countries: i64,
    total_bytes: String,
}

#[derive(Serialize)]
struct Bar {
    label: String,
    count: i64,
    pct: i64,
    css: String,
    href: String,
    ts_epoch: i64,
}

#[derive(Serialize)]
struct Panel {
    title: &'static str,
    icon: &'static str,
    bars: Vec<Bar>,
}

// ─────────────────────────────────────────────────────────────────────────────
// render(state, raw, spec)
// Builds the firewall dashboard described by `spec` from live, range- and
// filter-bounded DuckDB aggregations, and renders firewall.html.
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
    let (conds, vals) = filter.sql(spec.extra);
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
        ctx.insert("search_placeholder", "Search source, destination, rule…");
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

    let total_rows: i64 = {
        let mut stmt = conn.prepare(&format!("SELECT count(*) FROM {table}"))?;
        let mut rows = stmt.query_map([], |r| r.get(0))?;
        rows.next().transpose()?.unwrap_or(0)
    };

    // Headline counters in a single pass.
    let (events, denied, sources, countries, total_bytes): (i64, i64, i64, i64, i64) = {
        let sql = format!(
            "SELECT count(*), count(*) FILTER (WHERE action = 'deny'), \
             count(DISTINCT src_ip), \
             count(DISTINCT country_code) FILTER (WHERE country_code IS NOT NULL AND country_code <> ''), \
             CAST(coalesce(sum(bytes), 0) AS BIGINT) FROM {table} {where_clause}"
        );
        let mut stmt = conn.prepare(&sql)?;
        let mut rows = stmt.query_map(params_from_iter(vals.iter()), |r| {
            Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?))
        })?;
        rows.next().transpose()?.unwrap_or((0, 0, 0, 0, 0))
    };
    let kpis = Kpis {
        events,
        denied,
        deny_rate: if events > 0 {
            format!("{:.1}%", denied as f64 * 100.0 / events as f64)
        } else {
            "0.0%".to_string()
        },
        sources,
        countries,
        total_bytes: human_bytes(total_bytes),
    };

    // Events over time, zero-filled across the whole range.
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

    // Allow vs deny — the headline split, clickable to filter.
    let actions: Vec<Bar> = {
        let sql = format!(
            "SELECT action, count(*) c FROM {table} {where_clause} GROUP BY action ORDER BY c DESC"
        );
        let mut stmt = conn.prepare(&sql)?;
        let pairs = stmt
            .query_map(params_from_iter(vals.iter()), |r| {
                Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        let max = pairs.iter().map(|(_, c)| *c).max().unwrap_or(0);
        pairs
            .into_iter()
            .map(|(action, count)| Bar {
                pct: pct(count, max),
                count,
                css: if action == "deny" { "bg-danger".into() } else { "bg-success".into() },
                href: filter.with_action(&action).href(base),
                label: action,
                ts_epoch: 0,
            })
            .collect()
    };

    let top_sources = top_n(&conn, table, "src_ip", &where_clause, &vals, |l| {
        filter.with_src(l).href(base)
    })?;
    let top_destinations = top_n(&conn, table, "dst_ip", &where_clause, &vals, |l| {
        filter.with_dst(l).href(base)
    })?;
    let top_ports = top_n(
        &conn,
        table,
        "CAST(dst_port AS VARCHAR)",
        &where_clause,
        &vals,
        |l| match l.parse::<i32>() {
            Ok(p) => filter.with_port(p).href(base),
            Err(_) => filter.href(base),
        },
    )?;
    let top_countries = top_n(
        &conn,
        table,
        "coalesce(nullif(country, ''), 'Unknown')",
        &where_clause,
        &vals,
        |l| filter.with_country(l).href(base),
    )?;

    let mut extra_panels: Vec<Panel> = Vec::new();
    for dim in spec.extra {
        let bars = top_n(&conn, table, dim.key, &where_clause, &vals, |l| {
            if dim.key == "rule" {
                filter.with_rule(l).href(base)
            } else {
                filter.set_extra(dim.key, Some(l.to_string())).href(base)
            }
        })?;
        extra_panels.push(Panel { title: dim.title, icon: dim.icon, bars });
    }

    // Where the traffic came from — the source address decides the country.
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
    ctx.insert("actions", &actions);
    ctx.insert("top_sources", &top_sources);
    ctx.insert("top_destinations", &top_destinations);
    ctx.insert("top_ports", &top_ports);
    ctx.insert("top_countries", &top_countries);
    ctx.insert("extra_panels", &extra_panels);
    ctx.insert("map", &map);
    ctx.insert("chips", &chips);
    ctx.insert("search", &filter.q.clone().unwrap_or_default());
    ctx.insert("search_fields", &filter.hidden_fields());
    ctx.insert("search_placeholder", "Search source, destination, rule…");
    ctx.insert("raw_href", &filter.with_view("raw").href(base));
    ctx.insert("range_options", &range_options);
    ctx.insert("range_label", range_label(&range));
    ctx.insert("has_filters", &!chips.is_empty());
    ctx.insert("has_data", &(total_rows > 0));
    Ok(Html(state.tera.render("firewall.html", &ctx)?).into_response())
}

// The furniture every view of this dashboard shares: the range selector and the
// chips for whatever filters are active. Pure functions of the filter, so the
// raw view can build them without touching the database.
fn furniture(filter: &Filter, spec: &Spec, base: &str, range: &str) -> (Vec<RangeOpt>, Vec<Chip>) {
    let range_defs = [("1h", "Hour"), ("24h", "24 h"), ("7d", "Week"), ("30d", "Month"), ("1y", "Year")];
    let range_options: Vec<RangeOpt> = range_defs
        .iter()
        .map(|&(value, label)| RangeOpt {
            label: label.to_string(),
            href: filter.with_range(value).href(base),
            active: range == value,
        })
        .collect();

    let mut chips: Vec<Chip> = Vec::new();
    if let Some(src) = &filter.src {
        chips.push(Chip { label: format!("Source: {src}"), remove: filter.without_src().href(base) });
    }
    if let Some(dst) = &filter.dst {
        chips.push(Chip { label: format!("Destination: {dst}"), remove: filter.without_dst().href(base) });
    }
    if let Some(port) = filter.port {
        chips.push(Chip { label: format!("Port: {port}"), remove: filter.without_port().href(base) });
    }
    if let Some(action) = &filter.action {
        chips.push(Chip { label: format!("Action: {action}"), remove: filter.without_action().href(base) });
    }
    if let Some(protocol) = &filter.protocol {
        chips.push(Chip { label: format!("Protocol: {protocol}"), remove: filter.without_protocol().href(base) });
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
    // Rows with no value for this dimension would otherwise show as an empty
    // label; they're excluded rather than presented as a mystery entry.
    let extra_cond = format!("{column} IS NOT NULL AND {column} <> ''");
    let scoped = if where_clause.is_empty() {
        format!("WHERE {extra_cond}")
    } else {
        format!("{where_clause} AND {extra_cond}")
    };
    let sql = format!(
        "SELECT {column}, count(*) c FROM {table} {scoped} \
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
