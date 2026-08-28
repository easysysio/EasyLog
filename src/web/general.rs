// =============================================================================
// web/general.rs — dashboard for general (unparsed) logs
//
// There are no parsed fields here, so this dashboard answers the only questions
// the data can: how much is arriving, who is sending it, under what hostname and
// tag — and what the lines actually say. The last part is the raw view (see
// web/rawview.rs), which this dashboard leans on rather than duplicating.
//
// Search covers the message text itself, since that is all there is to search.
// =============================================================================

use std::sync::Arc;

use axum::{
    extract::{Query, State},
    response::{Html, IntoResponse, Response},
};
use chrono::{Duration, Utc};
use duckdb::params_from_iter;
use duckdb::types::Value;
use serde::{Deserialize, Serialize};

use super::AppError;
use crate::state::AppState;

const TABLE: &str = "syslog";
const BASE: &str = "/general/syslog";

// The message is the point here, so it is searched alongside the envelope.
const SEARCH_COLUMNS: [&str; 3] = ["raw", "hostname", "tag"];

// Drill-down + time-range filter.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub(crate) struct Filter {
    /// Sending address (the syslog peer).
    #[serde(skip_serializing_if = "Option::is_none")]
    sender: Option<String>,
    /// Hostname the sender put in the syslog header.
    #[serde(skip_serializing_if = "Option::is_none")]
    host: Option<String>,
    /// Syslog tag / APP-NAME.
    #[serde(skip_serializing_if = "Option::is_none")]
    tag: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    range: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    view: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    limit: Option<usize>,
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
            sender: clean(self.sender),
            host: clean(self.host),
            tag: clean(self.tag),
            range,
            view: clean(self.view),
            limit: self.limit,
            q: clean(self.q),
        }
    }

    // Same contract as the other dashboards: the search form carries the active
    // filters, but leaves view and limit to the template that needs them.
    fn hidden_fields(&self) -> Vec<HiddenField> {
        let without_q = Filter { q: None, view: None, limit: None, ..self.clone() };
        serde_urlencoded::to_string(&without_q)
            .ok()
            .and_then(|s| serde_urlencoded::from_str::<Vec<(String, String)>>(&s).ok())
            .unwrap_or_default()
            .into_iter()
            .map(|(name, value)| HiddenField { name, value })
            .collect()
    }

    fn href(&self) -> String {
        match serde_urlencoded::to_string(self) {
            Ok(q) if !q.is_empty() => format!("{BASE}?{q}"),
            _ => BASE.to_string(),
        }
    }

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
    fn with_sender(&self, v: &str) -> Filter {
        Filter { sender: Some(v.to_string()), ..self.clone() }
    }
    fn with_host(&self, v: &str) -> Filter {
        Filter { host: Some(v.to_string()), ..self.clone() }
    }
    fn with_tag(&self, v: &str) -> Filter {
        Filter { tag: Some(v.to_string()), ..self.clone() }
    }
    fn with_range(&self, v: &str) -> Filter {
        Filter { range: Some(v.to_string()), ..self.clone() }
    }
    fn without_sender(&self) -> Filter {
        Filter { sender: None, ..self.clone() }
    }
    fn without_host(&self) -> Filter {
        Filter { host: None, ..self.clone() }
    }
    fn without_tag(&self) -> Filter {
        Filter { tag: None, ..self.clone() }
    }
    fn without_q(&self) -> Filter {
        Filter { q: None, ..self.clone() }
    }

    fn range_key(&self) -> &str {
        self.range.as_deref().unwrap_or("24h")
    }

    fn sql(&self) -> (Vec<String>, Vec<Value>) {
        let mut conds = Vec::new();
        let mut vals = Vec::new();
        if let Some(sender) = &self.sender {
            conds.push("source_ip = ?".to_string());
            vals.push(Value::Text(sender.clone()));
        }
        if let Some(host) = &self.host {
            conds.push("hostname = ?".to_string());
            vals.push(Value::Text(host.clone()));
        }
        if let Some(tag) = &self.tag {
            conds.push("tag = ?".to_string());
            vals.push(Value::Text(tag.clone()));
        }
        if let Some(q) = &self.q {
            let ors: Vec<String> = SEARCH_COLUMNS.iter().map(|c| format!("{c} ILIKE ?")).collect();
            conds.push(format!("({})", ors.join(" OR ")));
            for _ in SEARCH_COLUMNS {
                vals.push(Value::Text(format!("%{q}%")));
            }
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
    senders: i64,
    hosts: i64,
    tags: i64,
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

// The range selector and chips, built without touching the database so the raw
// view can have them too.
fn furniture(filter: &Filter, range: &str) -> (Vec<RangeOpt>, Vec<Chip>) {
    let range_defs = [("1h", "Hour"), ("24h", "24 h"), ("7d", "Week"), ("30d", "Month"), ("1y", "Year")];
    let range_options: Vec<RangeOpt> = range_defs
        .iter()
        .map(|&(value, label)| RangeOpt {
            label: label.to_string(),
            href: filter.with_range(value).href(),
            active: range == value,
        })
        .collect();

    let mut chips: Vec<Chip> = Vec::new();
    if let Some(sender) = &filter.sender {
        chips.push(Chip { label: format!("Sender: {sender}"), remove: filter.without_sender().href() });
    }
    if let Some(host) = &filter.host {
        chips.push(Chip { label: format!("Host: {host}"), remove: filter.without_host().href() });
    }
    if let Some(tag) = &filter.tag {
        chips.push(Chip { label: format!("Tag: {tag}"), remove: filter.without_tag().href() });
    }
    if let Some(q) = &filter.q {
        chips.push(Chip { label: format!("Search: {q}"), remove: filter.without_q().href() });
    }
    (range_options, chips)
}

// ─────────────────────────────────────────────────────────────────────────────
// GET /general/syslog  (?range= plus ?sender= ?host= ?tag= ?q= filters, and
// ?view=raw / ?view=download for the lines themselves)
// ─────────────────────────────────────────────────────────────────────────────
pub async fn dashboard(
    State(state): State<Arc<AppState>>,
    Query(filter): Query<Filter>,
) -> Result<Response, AppError> {
    let filter = filter.normalized();
    let range = filter.range_key().to_string();
    let (conds, vals) = filter.sql();
    let where_clause = build_where(&conds);
    let (range_options, chips) = furniture(&filter, &range);

    // Raw and download come first: rawview takes its own lock, and none of the
    // aggregation below is needed for them.
    if matches!(filter.view_key(), "raw" | "download") {
        if filter.view_key() == "download" {
            return Ok(super::rawview::download(
                &state,
                TABLE,
                &where_clause,
                &vals,
                super::rawview::filename(TABLE),
            ));
        }
        let mut ctx = tera::Context::new();
        ctx.insert("active", TABLE);
        ctx.insert("active_category", "general");
        ctx.insert("nav", &state.nav);
        ctx.insert("type_label", "General logs");
        ctx.insert("base", BASE);
        ctx.insert("chips", &chips);
        ctx.insert("range_options", &range_options);
        ctx.insert("range_label", range_label(&range));
        ctx.insert("has_filters", &!chips.is_empty());
        ctx.insert("search", &filter.q.clone().unwrap_or_default());
        ctx.insert("search_fields", &filter.hidden_fields());
        ctx.insert("search_placeholder", "Search the message, host or tag…");
        ctx.insert("dashboard_href", &filter.without_view().href());
        ctx.insert(
            "more_href",
            &filter.with_limit(filter.raw_limit() + super::rawview::PAGE).href(),
        );
        ctx.insert("download_href", &filter.with_view("download").href());
        return Ok(super::rawview::render(
            &state,
            ctx,
            TABLE,
            &where_clause,
            &vals,
            filter.raw_limit(),
        )?
        .into_response());
    }

    let conn = state.db.lock().expect("db mutex poisoned");

    let total_rows: i64 = {
        let mut stmt = conn.prepare(&format!("SELECT count(*) FROM {TABLE}"))?;
        let mut rows = stmt.query_map([], |r| r.get(0))?;
        rows.next().transpose()?.unwrap_or(0)
    };

    let (events, senders, hosts, tags): (i64, i64, i64, i64) = {
        let sql = format!(
            "SELECT count(*), count(DISTINCT source_ip), \
             count(DISTINCT hostname) FILTER (WHERE hostname <> ''), \
             count(DISTINCT tag) FILTER (WHERE tag <> '') FROM {TABLE} {where_clause}"
        );
        let mut stmt = conn.prepare(&sql)?;
        let mut rows = stmt.query_map(params_from_iter(vals.iter()), |r| {
            Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?))
        })?;
        rows.next().transpose()?.unwrap_or((0, 0, 0, 0))
    };
    let kpis = Kpis { events, senders, hosts, tags };

    // Lines over time, zero-filled across the whole range.
    let (bucket_expr, tl_gran) = bucketing(&range);
    let counts: std::collections::HashMap<i64, i64> = {
        let sql = format!(
            "SELECT CAST(epoch({bucket_expr}) AS BIGINT), count(*) FROM {TABLE} {where_clause} \
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

    let top_senders = top_n(&conn, "source_ip", &where_clause, &vals, |l| filter.with_sender(l).href())?;
    let top_hosts = top_n(&conn, "hostname", &where_clause, &vals, |l| filter.with_host(l).href())?;
    let top_tags = top_n(&conn, "tag", &where_clause, &vals, |l| filter.with_tag(l).href())?;

    let mut ctx = tera::Context::new();
    ctx.insert("active", TABLE);
    ctx.insert("active_category", "general");
    ctx.insert("nav", &state.nav);
    ctx.insert("type_label", "General logs");
    ctx.insert("base", BASE);
    ctx.insert("kpis", &kpis);
    ctx.insert("timeline", &timeline);
    ctx.insert("timeline_max", &timeline_max);
    ctx.insert("timeline_mid", &(timeline_max / 2));
    ctx.insert("tl_gran", tl_gran);
    ctx.insert("top_senders", &top_senders);
    ctx.insert("top_hosts", &top_hosts);
    ctx.insert("top_tags", &top_tags);
    ctx.insert("chips", &chips);
    ctx.insert("range_options", &range_options);
    ctx.insert("range_label", range_label(&range));
    ctx.insert("has_filters", &!chips.is_empty());
    ctx.insert("has_data", &(total_rows > 0));
    ctx.insert("search", &filter.q.clone().unwrap_or_default());
    ctx.insert("search_fields", &filter.hidden_fields());
    ctx.insert("search_placeholder", "Search the message, host or tag…");
    ctx.insert("raw_href", &filter.with_view("raw").href());
    Ok(Html(state.tera.render("general.html", &ctx)?).into_response())
}

fn top_n(
    conn: &duckdb::Connection,
    column: &str,
    where_clause: &str,
    vals: &[Value],
    href_for: impl Fn(&str) -> String,
) -> Result<Vec<Bar>, AppError> {
    // Senders that gave no hostname or tag would otherwise show as a blank row.
    let scoped = if where_clause.is_empty() {
        format!("WHERE {column} <> ''")
    } else {
        format!("{where_clause} AND {column} <> ''")
    };
    let sql = format!(
        "SELECT {column}, count(*) c FROM {TABLE} {scoped} \
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
    if max <= 0 { 0 } else { (count * 100 / max).clamp(0, 100) }
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
