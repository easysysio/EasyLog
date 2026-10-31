// =============================================================================
// web/linux.rs — Linux dashboard (GET /system/linux)
//
// A Linux server's log is mostly routine — cron, the kernel, systemd — with the
// security story scattered through it. This dashboard pulls that story to the
// top and leaves the rest one click away:
//
//   * who is trying to get in: failed and invalid-user SSH attempts, the
//     addresses behind them, the usernames they guess, and where in the world
//     they come from;
//   * who did get in: every successful login, with the method and the address
//     — the table to read after a burst of failures;
//   * what they did with it: sudo and su, including the refusals, and changes
//     to accounts and groups;
//   * everything else, by server and by program, and as raw lines.
//
// The timeline stacks every line by kind — failed logins, refused privilege,
// account changes, privilege used, logins, other — so an attack shows as a red
// band against the normal grey of routine logging.
//
// Every panel is a drill-down link, filters stack as removable chips, and the
// range, the pinned timeline window (?from=&to=) and search compose into one
// parameterized WHERE clause — the same contract as every other dashboard.
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
use crate::logtype::linux::EVENTS;
use crate::state::AppState;

const TABLE: &str = "linux";
const BASE: &str = "/system/linux";

/// The events that are someone failing to log in remotely or locally. A
/// password brute force produces several per attempt (Invalid user, Failed
/// password, a preauth close), which is why "Failed logins" counts only the
/// rejections and "Attacking IPs" counts addresses instead.
const LOGIN_FAILURES: &str = "event IN ('login_failed', 'invalid_user', 'preauth')";

/// The `event` filter value for lines that are not security events.
const OTHER: &str = "other";

// Columns the search box looks in. The raw line holds every parsed field; the
// country is the one thing added on arrival.
const SEARCH_COLUMNS: [&str; 2] = ["raw", "country"];

// Dashboard filter, parsed from the query string and re-serialized into links.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub(crate) struct Filter {
    /// One of EVENTS, or "other" for lines that are none of them.
    #[serde(skip_serializing_if = "Option::is_none")]
    event: Option<String>,
    /// "failure": every failed login of any kind — what the attack panels show.
    #[serde(skip_serializing_if = "Option::is_none")]
    outcome: Option<String>,
    /// Hostname the server put in its syslog header.
    #[serde(skip_serializing_if = "Option::is_none")]
    host: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    program: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    user: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    client: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    country: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    range: Option<String>,
    /// Pinned window from clicking a timeline bar: UTC epoch seconds, half-open
    /// [from, to). When set it bounds the query instead of the range.
    #[serde(skip_serializing_if = "Option::is_none")]
    from: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    to: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    view: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    limit: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    q: Option<String>,
}

impl Filter {
    // Trim string fields, drop empties, and reject an unknown range (→ default).
    fn normalized(self) -> Filter {
        let clean = |o: Option<String>| o.map(|s| s.trim().to_string()).filter(|s| !s.is_empty());
        let range = clean(self.range).filter(|r| matches!(r.as_str(), "1h" | "24h" | "7d" | "30d" | "1y"));
        Filter {
            event: clean(self.event),
            outcome: clean(self.outcome).filter(|o| o == "failure"),
            host: clean(self.host),
            program: clean(self.program),
            user: clean(self.user),
            client: clean(self.client),
            country: clean(self.country),
            range,
            from: self.from,
            to: self.to,
            view: clean(self.view),
            limit: self.limit,
            q: clean(self.q),
        }
    }

    // The pinned window, if a timeline bar was clicked.
    fn window(&self) -> Option<(i64, i64)> {
        match (self.from, self.to) {
            (Some(from), Some(to)) if to > from => Some((from, to)),
            _ => None,
        }
    }
    fn with_window(&self, from: i64, to: i64) -> Filter {
        Filter { from: Some(from), to: Some(to), ..self.clone() }
    }
    fn without_window(&self) -> Filter {
        Filter { from: None, to: None, ..self.clone() }
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
        // `view` and `limit` are dropped: the raw template emits its own view
        // field, and a fresh search should start at the first page.
        let without_q = Filter { q: None, view: None, limit: None, ..self.clone() };
        serde_urlencoded::to_string(&without_q)
            .ok()
            .and_then(|s| serde_urlencoded::from_str::<Vec<(String, String)>>(&s).ok())
            .unwrap_or_default()
            .into_iter()
            .map(|(name, value)| HiddenField { name, value })
            .collect()
    }

    // Serialize back to a `<base>?...` URL (values percent-encoded by serde).
    fn href(&self) -> String {
        match serde_urlencoded::to_string(self) {
            Ok(q) if !q.is_empty() => format!("{BASE}?{q}"),
            _ => BASE.to_string(),
        }
    }

    fn with_event(&self, v: &str) -> Filter {
        Filter { event: Some(v.to_string()), ..self.clone() }
    }
    fn with_failures(&self) -> Filter {
        Filter { outcome: Some("failure".to_string()), ..self.clone() }
    }
    fn with_host(&self, v: &str) -> Filter {
        Filter { host: Some(v.to_string()), ..self.clone() }
    }
    fn with_program(&self, v: &str) -> Filter {
        Filter { program: Some(v.to_string()), ..self.clone() }
    }
    fn with_user(&self, v: &str) -> Filter {
        Filter { user: Some(v.to_string()), ..self.clone() }
    }
    fn with_client(&self, v: &str) -> Filter {
        Filter { client: Some(v.to_string()), ..self.clone() }
    }
    fn with_country(&self, v: &str) -> Filter {
        Filter { country: Some(v.to_string()), ..self.clone() }
    }
    // Picking a range clears any pinned window — the two would contradict.
    fn with_range(&self, v: &str) -> Filter {
        Filter { range: Some(v.to_string()), from: None, to: None, ..self.clone() }
    }
    fn without_q(&self) -> Filter {
        Filter { q: None, ..self.clone() }
    }

    // Effective time range key (defaults to 24h).
    fn range_key(&self) -> &str {
        self.range.as_deref().unwrap_or("24h")
    }

    // SQL conditions + bound values for the active filter and time window.
    fn sql(&self) -> (Vec<String>, Vec<Value>) {
        let mut conds = Vec::new();
        let mut vals = Vec::new();
        match self.event.as_deref() {
            Some(OTHER) => conds.push("coalesce(event, '') = ''".to_string()),
            Some(v) => {
                conds.push("event = ?".to_string());
                vals.push(Value::Text(v.to_string()));
            }
            None => {}
        }
        if self.outcome.is_some() {
            conds.push(LOGIN_FAILURES.to_string());
        }
        let mut eq = |column: &str, value: &Option<String>| {
            if let Some(v) = value {
                conds.push(format!("{column} = ?"));
                vals.push(Value::Text(v.clone()));
            }
        };
        eq("hostname", &self.host);
        eq("program", &self.program);
        eq("\"user\"", &self.user);
        eq("client", &self.client);
        if let Some(country) = &self.country {
            conds.push("coalesce(nullif(country, ''), 'Unknown') = ?".to_string());
            vals.push(Value::Text(country.clone()));
        }
        if let Some(q) = &self.q {
            let ors: Vec<String> = SEARCH_COLUMNS.iter().map(|c| format!("{c} ILIKE ?")).collect();
            conds.push(format!("({})", ors.join(" OR ")));
            for _ in SEARCH_COLUMNS {
                vals.push(Value::Text(format!("%{q}%")));
            }
        }
        // A pinned window (a clicked timeline bar) bounds the query; the range
        // then only decides how the timeline is bucketed.
        match self.window() {
            Some((from, to)) => {
                let (cond, bounds) = super::window_sql(from, to);
                conds.push(cond);
                vals.extend(bounds.into_iter().map(Value::Text));
            }
            None => {
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
            }
        }
        (conds, vals)
    }
}

// Time-bucket SQL expression (matching timeline_series alignment) and a client
// granularity hint ("time"/"day"/"month") for browser-local formatting.
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

// ─────────────────────────────────────────────────────────────────────────────
// Kinds: the timeline's stacking. Each event belongs to one kind; ordered so
// failed logins sit at the foot of a bar, where they compare across buckets,
// and routine lines on top.
// ─────────────────────────────────────────────────────────────────────────────
const KINDS: [(&str, &str, &str); 6] = [
    ("failed", "failed logins", "k-failed"),
    ("refused", "refused sudo / su", "k-refused"),
    ("account", "account changes", "k-account"),
    ("privilege", "sudo / su", "k-privilege"),
    ("login", "logins", "k-login"),
    ("other", "other lines", "k-other"),
];

/// SQL mapping a row to its kind, matching KINDS.
const KIND_SQL: &str = "CASE \
    WHEN event IN ('login_failed', 'invalid_user', 'preauth') THEN 'failed' \
    WHEN event IN ('sudo_failed', 'su_failed') THEN 'refused' \
    WHEN event = 'account' THEN 'account' \
    WHEN event IN ('sudo', 'su') THEN 'privilege' \
    WHEN event = 'login_ok' THEN 'login' \
    ELSE 'other' END";

fn kind_of(event: &str) -> &'static str {
    match event {
        "login_failed" | "invalid_user" | "preauth" => "failed",
        "sudo_failed" | "su_failed" => "refused",
        "account" => "account",
        "sudo" | "su" => "privilege",
        "login_ok" => "login",
        _ => "other",
    }
}

fn kind_rank(kind: &str) -> usize {
    KINDS.iter().position(|(k, _, _)| *k == kind).unwrap_or(KINDS.len())
}

fn kind_css(kind: &str) -> &'static str {
    KINDS.iter().find(|(k, _, _)| *k == kind).map(|(_, _, c)| *c).unwrap_or("k-other")
}

// Display name for an event value.
fn event_label(event: &str) -> &'static str {
    match event {
        "login_failed" => "failed login",
        "invalid_user" => "invalid user",
        "preauth" => "dropped before auth",
        "login_ok" => "login",
        "sudo" => "sudo",
        "sudo_failed" => "sudo refused",
        "su" => "su",
        "su_failed" => "su refused",
        "account" => "account change",
        _ => "other",
    }
}

// One option in the time-range selector.
#[derive(Serialize)]
struct RangeOpt {
    label: String,
    href: String,
    active: bool,
}

// One preserved filter value, rendered as a hidden input in the search form.
#[derive(Serialize)]
struct HiddenField {
    name: String,
    value: String,
}

// An active-filter pill: its label and the URL that removes just that filter.
#[derive(Serialize)]
struct Chip {
    label: String,
    remove: String,
}

// Headline counters shown as KPI cards, each with the link that shows them.
#[derive(Serialize, Default)]
struct Kpis {
    lines: i64,
    failed_logins: i64,
    logins: i64,
    attackers: i64,
    invalid_users: i64,
    sudo: i64,
    refused: i64,
    failed_href: String,
    logins_href: String,
    attackers_href: String,
    invalid_href: String,
    sudo_href: String,
}

// One bar in a chart/list. `href`, when non-empty, makes the row a drill-down
// link; `css` is an optional colour class; `note` is secondary text.
#[derive(Serialize)]
struct Bar {
    label: String,
    count: i64,
    pct: i64,
    css: String,
    href: String,
    note: String,
}

// One segment of a stacked timeline bar: a kind's share of that bucket.
#[derive(Serialize)]
struct Segment {
    label: String,
    count: i64,
    /// Percent of this bucket's total — the segment's share of the bar.
    share: i64,
    css: String,
}

// One bucket of the stacked timeline.
#[derive(Serialize)]
struct StackedBar {
    ts_epoch: i64,
    label: String,
    count: i64,
    /// Percent of the tallest bucket — the bar's height.
    pct: i64,
    href: String,
    segments: Vec<Segment>,
}

// One legend entry for the timeline.
#[derive(Serialize)]
struct LegendItem {
    label: &'static str,
    css: &'static str,
}

// One row of the logins / privilege / account tables. Fields a table does not
// use stay empty.
#[derive(Serialize)]
struct EventRow {
    ts: String,
    host: String,
    host_href: String,
    user: String,
    user_href: String,
    target: String,
    client: String,
    client_href: String,
    country: String,
    method: String,
    detail: String,
    event: String,
    failed: bool,
}

// ─────────────────────────────────────────────────────────────────────────────
// GET /system/linux  (?range= ?from= ?to= plus ?event= ?outcome= ?host=
// ?program= ?user= ?client= ?country= drill-down filters, ?q= search and
// ?view=raw|download)
// ─────────────────────────────────────────────────────────────────────────────
pub async fn dashboard(
    State(state): State<Arc<AppState>>,
    Query(filter): Query<Filter>,
) -> Result<Response, AppError> {
    render(&state, filter)
}

// ─────────────────────────────────────────────────────────────────────────────
// render(state, raw)
// Builds the Linux dashboard from live, range- and filter-bounded DuckDB
// aggregations, and renders linux.html.
// ─────────────────────────────────────────────────────────────────────────────
fn render(state: &Arc<AppState>, raw: Filter) -> Result<Response, AppError> {
    let filter = raw.normalized();
    let range = filter.range_key().to_string();
    let (conds, vals) = filter.sql();
    let where_clause = build_where(&conds);

    let (range_options, chips, window_chip) = furniture(&filter, &range);

    // Raw mode reuses this dashboard's WHERE clause, so the lines listed are
    // exactly the ones the panels summarise. Handled before the database lock
    // is taken: rawview does its own locking.
    if matches!(filter.view_key(), "raw" | "download") {
        if filter.view_key() == "download" {
            return Ok(super::rawview::download(
                state,
                TABLE,
                &where_clause,
                &vals,
                super::rawview::filename(TABLE),
            ));
        }
        let mut ctx = tera::Context::new();
        ctx.insert("active", TABLE);
        ctx.insert("active_category", "system");
        ctx.insert("nav", &state.nav);
        ctx.insert("type_label", "Linux");
        ctx.insert("base", BASE);
        ctx.insert("chips", &chips);
        ctx.insert("range_options", &range_options);
        ctx.insert("range_label", range_label(&range));
        ctx.insert("window", &window_chip);
        ctx.insert("has_filters", &(!chips.is_empty() || window_chip.is_some()));
        ctx.insert("search", &filter.q.clone().unwrap_or_default());
        ctx.insert("search_fields", &filter.hidden_fields());
        ctx.insert("search_placeholder", "Search lines, users, addresses…");
        ctx.insert("raw_href", &filter.with_view("raw").href());
        ctx.insert("dashboard_href", &filter.without_view().href());
        ctx.insert(
            "more_href",
            &filter.with_limit(filter.raw_limit() + super::rawview::PAGE).href(),
        );
        ctx.insert("download_href", &filter.with_view("download").href());
        return Ok(super::rawview::render(
            state,
            ctx,
            TABLE,
            &where_clause,
            &vals,
            filter.raw_limit(),
        )?
        .into_response());
    }

    let conn = state.db.lock().expect("db mutex poisoned");

    // Any rows at all (ignoring range/filter) — decides the "no logs yet" state.
    let total_rows: i64 = {
        let mut stmt = conn.prepare(&format!("SELECT count(*) FROM {TABLE}"))?;
        let mut rows = stmt.query_map([], |r| r.get(0))?;
        rows.next().transpose()?.unwrap_or(0)
    };

    // Headline counters in a single pass.
    let (lines, failed_logins, logins, attackers, invalid_users, sudo, refused): (
        i64,
        i64,
        i64,
        i64,
        i64,
        i64,
        i64,
    ) = {
        let sql = format!(
            "SELECT count(*), \
             count(*) FILTER (WHERE event = 'login_failed'), \
             count(*) FILTER (WHERE event = 'login_ok'), \
             count(DISTINCT client) FILTER (WHERE {LOGIN_FAILURES} AND client <> ''), \
             count(DISTINCT \"user\") FILTER (WHERE event = 'invalid_user' AND \"user\" <> ''), \
             count(*) FILTER (WHERE event = 'sudo'), \
             count(*) FILTER (WHERE event IN ('sudo_failed', 'su_failed')) \
             FROM {TABLE} {where_clause}"
        );
        let mut stmt = conn.prepare(&sql)?;
        let mut rows = stmt.query_map(params_from_iter(vals.iter()), |r| {
            Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?, r.get(6)?))
        })?;
        rows.next().transpose()?.unwrap_or((0, 0, 0, 0, 0, 0, 0))
    };
    let kpis = Kpis {
        lines,
        failed_logins,
        logins,
        attackers,
        invalid_users,
        sudo,
        refused,
        failed_href: filter.with_event("login_failed").href(),
        logins_href: filter.with_event("login_ok").href(),
        attackers_href: filter.with_failures().href(),
        invalid_href: filter.with_event("invalid_user").href(),
        sudo_href: filter.with_event("sudo").href(),
    };

    // Every line over time, stacked by kind and zero-filled across the range.
    // Pinned to a window, the timeline buckets inside it, so a click zooms in.
    let (series, bucket_expr, tl_gran) = match filter.window() {
        Some((from, to)) => super::timeline_window(from, to),
        None => {
            let (expr, gran) = bucketing(&range);
            (super::timeline_series(&range), expr.to_string(), gran)
        }
    };
    let bucket_span = series
        .windows(2)
        .next()
        .map(|w| w[1].0 - w[0].0)
        .unwrap_or(60 * 60);
    // (bucket epoch, kind) → count.
    let counts: Vec<(i64, String, i64)> = {
        let sql = format!(
            "SELECT CAST(epoch({bucket_expr}) AS BIGINT), {KIND_SQL}, count(*) FROM {TABLE} \
             {where_clause} GROUP BY 1, 2"
        );
        let mut stmt = conn.prepare(&sql)?;
        stmt.query_map(params_from_iter(vals.iter()), |r| {
            Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?, r.get::<_, i64>(2)?))
        })?
        .collect::<Result<Vec<_>, _>>()?
    };
    let bucket_total = |epoch: i64| -> i64 {
        counts.iter().filter(|(e, _, _)| *e == epoch).map(|(_, _, c)| c).sum()
    };
    let timeline_max = series.iter().map(|(e, _)| bucket_total(*e)).max().unwrap_or(0);
    let timeline: Vec<StackedBar> = series
        .into_iter()
        .map(|(epoch, label)| {
            let total = bucket_total(epoch);
            let mut segments: Vec<(usize, Segment)> = counts
                .iter()
                .filter(|(e, _, _)| *e == epoch)
                .map(|(_, kind, count)| {
                    let def = KINDS.iter().find(|(k, _, _)| k == kind);
                    (
                        kind_rank(kind),
                        Segment {
                            share: pct(*count, total),
                            count: *count,
                            css: kind_css(kind).to_string(),
                            label: def.map(|(_, l, _)| *l).unwrap_or("other").to_string(),
                        },
                    )
                })
                .collect();
            segments.sort_by_key(|(rank, _)| *rank);
            let end = match filter.window() {
                Some((_, to)) => (epoch + bucket_span).min(to),
                None => super::bucket_end(&range, epoch),
            };
            StackedBar {
                pct: pct(total, timeline_max),
                count: total,
                href: filter.with_window(epoch, end).href(),
                segments: segments.into_iter().map(|(_, s)| s).collect(),
                label,
                ts_epoch: epoch,
            }
        })
        .collect();
    let legend: Vec<LegendItem> = KINDS
        .iter()
        .map(|(_, label, css)| LegendItem { label, css })
        .collect();

    // The event split, clickable to filter, in EVENTS order with "other" last.
    let events: Vec<Bar> = {
        let sql = format!(
            "SELECT coalesce(nullif(event, ''), '{OTHER}'), count(*) FROM {TABLE} {where_clause} GROUP BY 1"
        );
        let mut stmt = conn.prepare(&sql)?;
        let mut pairs = stmt
            .query_map(params_from_iter(vals.iter()), |r| {
                Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        let rank = |e: &str| EVENTS.iter().position(|x| *x == e).unwrap_or(EVENTS.len());
        pairs.sort_by_key(|(e, _)| rank(e));
        let max = pairs.iter().map(|(_, c)| *c).max().unwrap_or(0);
        pairs
            .into_iter()
            .map(|(event, count)| Bar {
                pct: pct(count, max),
                count,
                css: kind_css(kind_of(&event)).to_string(),
                href: filter.with_event(&event).href(),
                label: event_label(&event).to_string(),
                note: String::new(),
            })
            .collect()
    };

    // Who is attacking: addresses behind failed logins, with their country.
    // The usernames panel counts every failure; the address, country and map
    // panels only the remote ones — a console login has no address to place.
    let failures = scope(&where_clause, LOGIN_FAILURES);
    let remote = scope(&failures, "client <> ''");
    let top_attackers: Vec<Bar> = {
        let sql = format!(
            "SELECT client, any_value(coalesce(nullif(country, ''), 'Unknown')), count(*) c \
             FROM {TABLE} {remote} \
             GROUP BY client ORDER BY c DESC, client LIMIT 10"
        );
        let mut stmt = conn.prepare(&sql)?;
        let rows = stmt
            .query_map(params_from_iter(vals.iter()), |r| {
                Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get::<_, i64>(2)?))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        let max = rows.iter().map(|(_, _, c)| *c).max().unwrap_or(0);
        rows.into_iter()
            .map(|(client, country, count)| Bar {
                pct: pct(count, max),
                count,
                css: "k-failed".to_string(),
                href: filter.with_client(&client).href(),
                label: client,
                note: country,
            })
            .collect()
    };
    let top_usernames = top_n(
        &conn,
        "\"user\"",
        &failures,
        &vals,
        "k-failed",
        |l| filter.with_user(l).href(),
    )?;
    let top_countries = top_n(
        &conn,
        "coalesce(nullif(country, ''), 'Unknown')",
        &remote,
        &vals,
        "k-failed",
        |l| filter.with_country(l).href(),
    )?;
    let top_hosts = top_n(&conn, "hostname", &where_clause, &vals, "", |l| filter.with_host(l).href())?;
    let top_programs = top_n(&conn, "program", &where_clause, &vals, "", |l| filter.with_program(l).href())?;

    // The world map shows where failed logins come from — the question a
    // server's map answers. Successful logins are listed in full below.
    let country_rows = super::geomap::counts(&conn, TABLE, &remote, &vals)?;
    let map = super::geomap::build_counting(
        &country_rows,
        Some(&|name: &str| filter.with_country(name).href()),
        ("failed login", "failed logins"),
    );

    let logins = event_rows(&conn, &filter, &where_clause, &vals, "event = 'login_ok'", 15)?;
    let privilege = event_rows(
        &conn,
        &filter,
        &where_clause,
        &vals,
        "event IN ('sudo', 'sudo_failed', 'su', 'su_failed')",
        15,
    )?;
    let accounts = event_rows(&conn, &filter, &where_clause, &vals, "event = 'account'", 10)?;

    let mut ctx = tera::Context::new();
    ctx.insert("active", TABLE);
    ctx.insert("active_category", "system");
    ctx.insert("nav", &state.nav);
    ctx.insert("type_label", "Linux");
    ctx.insert("base", BASE);
    ctx.insert("kpis", &kpis);
    ctx.insert("timeline", &timeline);
    ctx.insert("timeline_max", &timeline_max);
    ctx.insert("timeline_mid", &(timeline_max / 2));
    ctx.insert("tl_gran", tl_gran);
    ctx.insert("legend", &legend);
    ctx.insert("events", &events);
    ctx.insert("top_attackers", &top_attackers);
    ctx.insert("top_usernames", &top_usernames);
    ctx.insert("top_countries", &top_countries);
    ctx.insert("top_hosts", &top_hosts);
    ctx.insert("top_programs", &top_programs);
    ctx.insert("logins", &logins);
    ctx.insert("privilege", &privilege);
    ctx.insert("accounts", &accounts);
    ctx.insert("map", &map);
    ctx.insert("map_title", "Failed logins by country");
    ctx.insert("map_unit", "failed logins");
    ctx.insert("chips", &chips);
    ctx.insert("range_options", &range_options);
    ctx.insert("range_label", range_label(&range));
    ctx.insert("window", &window_chip);
    ctx.insert("has_filters", &(!chips.is_empty() || window_chip.is_some()));
    ctx.insert("has_data", &(total_rows > 0));
    ctx.insert("search", &filter.q.clone().unwrap_or_default());
    ctx.insert("search_fields", &filter.hidden_fields());
    ctx.insert("search_placeholder", "Search lines, users, addresses…");
    ctx.insert("raw_href", &filter.with_view("raw").href());
    Ok(Html(state.tera.render("linux.html", &ctx)?).into_response())
}

// ─────────────────────────────────────────────────────────────────────────────
// event_rows(conn, filter, where_clause, vals, only, limit)
// The newest `limit` events matching `only` within the filter, for the logins,
// privilege and account tables. Each name and address links to its filter.
// ─────────────────────────────────────────────────────────────────────────────
fn event_rows(
    conn: &duckdb::Connection,
    filter: &Filter,
    where_clause: &str,
    vals: &[Value],
    only: &str,
    limit: usize,
) -> Result<Vec<EventRow>, AppError> {
    let scoped = scope(where_clause, only);
    let sql = format!(
        "SELECT strftime(ts, '%Y-%m-%d %H:%M:%S'), coalesce(hostname, ''), coalesce(\"user\", ''), \
         coalesce(target_user, ''), coalesce(client, ''), coalesce(nullif(country, ''), ''), \
         coalesce(method, ''), coalesce(command, ''), coalesce(event, '') \
         FROM {TABLE} {scoped} ORDER BY ts DESC LIMIT {limit}"
    );
    let mut stmt = conn.prepare(&sql)?;
    let rows = stmt
        .query_map(params_from_iter(vals.iter()), |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, String>(3)?,
                r.get::<_, String>(4)?,
                r.get::<_, String>(5)?,
                r.get::<_, String>(6)?,
                r.get::<_, String>(7)?,
                r.get::<_, String>(8)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    let link = |v: &str, f: &dyn Fn(&str) -> Filter| if v.is_empty() { String::new() } else { f(v).href() };
    Ok(rows
        .into_iter()
        .map(|(ts, host, user, target, client, country, method, detail, event)| EventRow {
            host_href: link(&host, &|v| filter.with_host(v)),
            user_href: link(&user, &|v| filter.with_user(v)),
            client_href: link(&client, &|v| filter.with_client(v)),
            failed: event.ends_with("_failed"),
            event: event_label(&event).to_string(),
            ts,
            host,
            user,
            target,
            client,
            country,
            method,
            detail,
        })
        .collect())
}

// The furniture every view of this dashboard shares: the range selector and the
// chips for whatever filters are active. Pure functions of the filter, so the
// raw view can build them without touching the database.
fn furniture(filter: &Filter, range: &str) -> (Vec<RangeOpt>, Vec<Chip>, Option<super::WindowChip>) {
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
    let mut chip = |label: String, remove: Filter| {
        chips.push(Chip { label, remove: remove.href() });
    };
    if let Some(v) = &filter.event {
        chip(format!("Event: {}", event_label(v)), Filter { event: None, ..filter.clone() });
    }
    if filter.outcome.is_some() {
        chip("Failed logins".to_string(), Filter { outcome: None, ..filter.clone() });
    }
    if let Some(v) = &filter.host {
        chip(format!("Host: {v}"), Filter { host: None, ..filter.clone() });
    }
    if let Some(v) = &filter.program {
        chip(format!("Program: {v}"), Filter { program: None, ..filter.clone() });
    }
    if let Some(v) = &filter.user {
        chip(format!("User: {v}"), Filter { user: None, ..filter.clone() });
    }
    if let Some(v) = &filter.client {
        chip(format!("Client: {v}"), Filter { client: None, ..filter.clone() });
    }
    if let Some(v) = &filter.country {
        chip(format!("Country: {v}"), Filter { country: None, ..filter.clone() });
    }
    if let Some(q) = &filter.q {
        chip(format!("Search: {q}"), filter.without_q());
    }
    // The pinned window is a chip of its own: it carries the bucket's epochs so
    // the page can restate them in the reader's timezone.
    let window_chip = filter.window().map(|(from, to)| super::WindowChip {
        from,
        to,
        label: super::window_label(from, to),
        remove: filter.without_window().href(),
    });

    (range_options, chips, window_chip)
}

// Runs a "top N by count" query for `column` over the bounded set, turning each
// row into a clickable Bar via `href_for(label)`.
fn top_n(
    conn: &duckdb::Connection,
    column: &str,
    where_clause: &str,
    vals: &[Value],
    css: &str,
    href_for: impl Fn(&str) -> String,
) -> Result<Vec<Bar>, AppError> {
    // Rows with no value for this dimension are excluded rather than shown as
    // an empty label.
    let scoped = scope(where_clause, &format!("{column} IS NOT NULL AND {column} <> ''"));
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
            css: css.to_string(),
            label,
            note: String::new(),
        })
        .collect())
}

// Adds one more condition to a WHERE clause without disturbing the bound values.
fn scope(where_clause: &str, extra: &str) -> String {
    if where_clause.is_empty() {
        format!("WHERE {extra}")
    } else {
        format!("{where_clause} AND {extra}")
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_event_has_a_kind_and_a_label() {
        for e in EVENTS {
            assert_ne!(kind_of(e), "other", "{e} should not fall into other");
            assert_ne!(event_label(e), "other", "{e} needs a label");
        }
        assert_eq!(kind_of(""), "other");
    }

    #[test]
    fn the_other_filter_matches_lines_without_an_event() {
        let f = Filter { event: Some(OTHER.into()), ..Default::default() }.normalized();
        let (conds, vals) = f.sql();
        assert!(conds.iter().any(|c| c == "coalesce(event, '') = ''"));
        // Only the range cutoff is bound — "other" is not a value.
        assert_eq!(vals.len(), 1);
    }

    #[test]
    fn the_failure_filter_covers_every_kind_of_failed_login() {
        let f = Filter::default().with_failures().normalized();
        let (conds, _) = f.sql();
        assert!(conds.iter().any(|c| c == LOGIN_FAILURES));
        // Anything but "failure" is dropped rather than trusted into SQL.
        let bogus = Filter { outcome: Some("x' OR 1=1".into()), ..Default::default() }.normalized();
        assert!(bogus.outcome.is_none());
    }
}
