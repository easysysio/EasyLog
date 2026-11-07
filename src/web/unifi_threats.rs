// =============================================================================
// web/unifi_threats.rs — UniFi threats dashboard (GET /firewall/unifi/threats)
//
// The UniFi gateway's IDS/IPS reports each detection as a CEF "Threat Detected"
// event, stored in full in `unifi_threats` (see logtype/unifi.rs). The firewall
// dashboard already counts them as allowed or denied traffic; this page asks
// the questions a detection raises instead:
//
//   * how bad — the risk UniFi assigns, stacked on the timeline so a burst of
//     high-risk detections stands out;
//   * did it get through — blocked by IPS, or only detected (an IDS in
//     detect-only mode lets the traffic pass);
//   * which way — incoming attacks, and outgoing detections, where a device
//     inside contacted something malicious: the likeliest sign of an infected
//     device, so it has a KPI of its own;
//   * who and what — the signatures that fired, the outside addresses, the
//     inside hosts involved, the ports and applications, and where in the
//     world the outside party is.
//
// "Remote" is the outside party and "local" the inside one, whichever way the
// traffic flowed. Every panel is a drill-down link, filters stack as removable
// chips, and the range, the pinned timeline window (?from=&to=) and search
// compose into one parameterized WHERE clause — the same contract as every
// other dashboard. Tabs link it with the UniFi firewall page.
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
use crate::logtype::unifi::THREATS_TABLE as TABLE;
use crate::state::AppState;

const BASE: &str = "/firewall/unifi/threats";

// Columns the search box looks in. The raw record holds every CEF field; the
// country is the one thing added on arrival.
const SEARCH_COLUMNS: [&str; 2] = ["raw", "country"];

/// Risk classes, in timeline stacking order (high at the foot of a bar), with
/// their legend label and colour class. UniFi rates low, medium or high;
/// anything else — "critical", or no rating — is folded in by RISK_SQL.
const RISKS: [(&str, &str, &str); 4] = [
    ("high", "high risk", "r-high"),
    ("medium", "medium risk", "r-medium"),
    ("low", "low risk", "r-low"),
    ("other", "unrated", "r-other"),
];

/// SQL mapping a row to its risk class, matching RISKS.
const RISK_SQL: &str = "CASE \
    WHEN risk IN ('high', 'critical') THEN 'high' \
    WHEN risk = 'medium' THEN 'medium' \
    WHEN risk = 'low' THEN 'low' \
    ELSE 'other' END";

/// SQL for the direction, with no value read as "unknown".
const DIRECTION_SQL: &str = "coalesce(nullif(direction, ''), 'unknown')";

// Dashboard filter, parsed from the query string and re-serialized into links.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub(crate) struct Filter {
    /// A risk class from RISKS.
    #[serde(skip_serializing_if = "Option::is_none")]
    risk: Option<String>,
    /// "deny" (blocked by IPS) or "allow" (detected only).
    #[serde(skip_serializing_if = "Option::is_none")]
    action: Option<String>,
    /// "incoming", "outgoing" or "unknown".
    #[serde(skip_serializing_if = "Option::is_none")]
    direction: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    signature: Option<String>,
    /// The outside party's address.
    #[serde(skip_serializing_if = "Option::is_none")]
    remote: Option<String>,
    /// The inside host's address.
    #[serde(skip_serializing_if = "Option::is_none")]
    local: Option<String>,
    /// Destination port.
    #[serde(skip_serializing_if = "Option::is_none")]
    port: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    app: Option<String>,
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
    // Trim string fields, drop empties, and reject values that are not one of a
    // closed set (→ no filter), so nothing unexpected reaches the SQL.
    fn normalized(self) -> Filter {
        let clean = |o: Option<String>| o.map(|s| s.trim().to_string()).filter(|s| !s.is_empty());
        Filter {
            risk: clean(self.risk).filter(|r| RISKS.iter().any(|(k, _, _)| k == r)),
            action: clean(self.action).filter(|a| matches!(a.as_str(), "allow" | "deny")),
            direction: clean(self.direction).filter(|d| matches!(d.as_str(), "incoming" | "outgoing" | "unknown")),
            signature: clean(self.signature),
            remote: clean(self.remote),
            local: clean(self.local),
            port: self.port,
            app: clean(self.app),
            country: clean(self.country),
            range: clean(self.range).filter(|r| matches!(r.as_str(), "1h" | "24h" | "7d" | "30d" | "1y")),
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

    fn with_risk(&self, v: &str) -> Filter {
        Filter { risk: Some(v.to_string()), ..self.clone() }
    }
    fn with_action(&self, v: &str) -> Filter {
        Filter { action: Some(v.to_string()), ..self.clone() }
    }
    fn with_direction(&self, v: &str) -> Filter {
        Filter { direction: Some(v.to_string()), ..self.clone() }
    }
    fn with_signature(&self, v: &str) -> Filter {
        Filter { signature: Some(v.to_string()), ..self.clone() }
    }
    fn with_remote(&self, v: &str) -> Filter {
        Filter { remote: Some(v.to_string()), ..self.clone() }
    }
    fn with_local(&self, v: &str) -> Filter {
        Filter { local: Some(v.to_string()), ..self.clone() }
    }
    fn with_port(&self, v: &str) -> Filter {
        Filter { port: v.parse().ok(), ..self.clone() }
    }
    fn with_app(&self, v: &str) -> Filter {
        Filter { app: Some(v.to_string()), ..self.clone() }
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
        let mut eq = |column: &str, value: &Option<String>| {
            if let Some(v) = value {
                conds.push(format!("{column} = ?"));
                vals.push(Value::Text(v.clone()));
            }
        };
        eq(RISK_SQL, &self.risk);
        eq("action", &self.action);
        eq(DIRECTION_SQL, &self.direction);
        eq("signature", &self.signature);
        eq("remote_ip", &self.remote);
        eq("local_ip", &self.local);
        eq("application", &self.app);
        eq("coalesce(nullif(country, ''), 'Unknown')", &self.country);
        if let Some(port) = self.port {
            conds.push("dst_port = ?".to_string());
            vals.push(Value::Int(port));
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

fn risk_rank(risk: &str) -> usize {
    RISKS.iter().position(|(k, _, _)| *k == risk).unwrap_or(RISKS.len())
}

fn risk_label(risk: &str) -> &'static str {
    RISKS.iter().find(|(k, _, _)| *k == risk).map(|(_, l, _)| *l).unwrap_or("unrated")
}

fn risk_css(risk: &str) -> &'static str {
    RISKS.iter().find(|(k, _, _)| *k == risk).map(|(_, _, c)| *c).unwrap_or("r-other")
}

// Risk class of a stored risk value, matching RISK_SQL.
fn risk_class(risk: &str) -> &'static str {
    match risk {
        "high" | "critical" => "high",
        "medium" => "medium",
        "low" => "low",
        _ => "other",
    }
}

fn action_label(action: &str) -> &'static str {
    match action {
        "deny" => "blocked",
        _ => "detected only",
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

// Headline counters shown as KPI cards, with the links that show them.
#[derive(Serialize, Default)]
struct Kpis {
    threats: i64,
    blocked: i64,
    detected: i64,
    high: i64,
    remotes: i64,
    signatures: i64,
    locals: i64,
    outgoing: i64,
    blocked_href: String,
    detected_href: String,
    high_href: String,
    incoming_href: String,
    outgoing_href: String,
}

// One bar in a chart/list. `href` makes the row a drill-down link; `css` is an
// optional colour class; `note` is secondary text.
#[derive(Serialize)]
struct Bar {
    label: String,
    count: i64,
    pct: i64,
    css: String,
    href: String,
    note: String,
}

// A titled card of bars: one of the splits, or one of the ranked panels.
// `mono` sets addresses and ports in a fixed-width font; `wrap` lets long
// labels (signatures) wrap instead of running on.
#[derive(Serialize)]
struct Panel {
    title: &'static str,
    icon: &'static str,
    mono: bool,
    wrap: bool,
    bars: Vec<Bar>,
}

// One segment of a stacked timeline bar: a risk class's share of that bucket.
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

// One row of the recent-threats table.
#[derive(Serialize)]
struct ThreatRow {
    ts: String,
    direction: String,
    remote: String,
    remote_href: String,
    country: String,
    local: String,
    local_href: String,
    port: String,
    app: String,
    signature: String,
    signature_href: String,
    risk: String,
    risk_css: String,
    blocked: bool,
}

// ─────────────────────────────────────────────────────────────────────────────
// GET /firewall/unifi/threats  (?range= ?from= ?to= plus ?risk= ?action=
// ?direction= ?signature= ?remote= ?local= ?port= ?app= ?country= drill-down
// filters, ?q= search and ?view=raw|download)
// ─────────────────────────────────────────────────────────────────────────────
pub async fn dashboard(
    State(state): State<Arc<AppState>>,
    Query(filter): Query<Filter>,
) -> Result<Response, AppError> {
    render(&state, filter)
}

// ─────────────────────────────────────────────────────────────────────────────
// render(state, raw)
// Builds the threats dashboard from live, range- and filter-bounded DuckDB
// aggregations, and renders unifi_threats.html.
// ─────────────────────────────────────────────────────────────────────────────
fn render(state: &Arc<AppState>, raw: Filter) -> Result<Response, AppError> {
    let filter = raw.normalized();
    let range = filter.range_key().to_string();
    let (conds, vals) = filter.sql();
    let where_clause = build_where(&conds);

    let (range_options, chips, window_chip) = furniture(&filter, &range);

    // Raw mode reuses this dashboard's WHERE clause, so the records listed are
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
        ctx.insert("active", "unifi");
        ctx.insert("active_category", "firewall");
        ctx.insert("nav", &state.nav);
        ctx.insert("type_label", "UniFi threats");
        ctx.insert("base", BASE);
        ctx.insert("chips", &chips);
        ctx.insert("range_options", &range_options);
        ctx.insert("range_label", range_label(&range));
        ctx.insert("window", &window_chip);
        ctx.insert("has_filters", &(!chips.is_empty() || window_chip.is_some()));
        ctx.insert("search", &filter.q.clone().unwrap_or_default());
        ctx.insert("search_fields", &filter.hidden_fields());
        ctx.insert("search_placeholder", "Search signatures, addresses, messages…");
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

    // Any rows at all (ignoring range/filter) — decides the "no threats yet" state.
    let total_rows: i64 = conn.query_row(&format!("SELECT count(*) FROM {TABLE}"), [], |r| r.get(0))?;

    // Headline counters in a single pass.
    let kpis = {
        let sql = format!(
            "SELECT count(*), \
             count(*) FILTER (WHERE action = 'deny'), \
             count(*) FILTER (WHERE action <> 'deny'), \
             count(*) FILTER (WHERE {RISK_SQL} = 'high'), \
             count(DISTINCT remote_ip) FILTER (WHERE remote_ip <> ''), \
             count(DISTINCT signature) FILTER (WHERE signature <> ''), \
             count(DISTINCT local_ip) FILTER (WHERE local_ip <> ''), \
             count(*) FILTER (WHERE direction = 'outgoing') \
             FROM {TABLE} {where_clause}"
        );
        let mut stmt = conn.prepare(&sql)?;
        let mut rows = stmt.query_map(params_from_iter(vals.iter()), |r| {
            Ok(Kpis {
                threats: r.get(0)?,
                blocked: r.get(1)?,
                detected: r.get(2)?,
                high: r.get(3)?,
                remotes: r.get(4)?,
                signatures: r.get(5)?,
                locals: r.get(6)?,
                outgoing: r.get(7)?,
                ..Kpis::default()
            })
        })?;
        let counts = rows.next().transpose()?.unwrap_or_default();
        Kpis {
            blocked_href: filter.with_action("deny").href(),
            detected_href: filter.with_action("allow").href(),
            high_href: filter.with_risk("high").href(),
            incoming_href: filter.with_direction("incoming").href(),
            outgoing_href: filter.with_direction("outgoing").href(),
            ..counts
        }
    };

    // Every detection over time, stacked by risk and zero-filled across the
    // range. Pinned to a window, the timeline buckets inside it, so a click
    // zooms in.
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
    // (bucket epoch, risk class) → count.
    let counts: Vec<(i64, String, i64)> = {
        let sql = format!(
            "SELECT CAST(epoch({bucket_expr}) AS BIGINT), {RISK_SQL}, count(*) FROM {TABLE} \
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
                .map(|(_, risk, count)| {
                    (
                        risk_rank(risk),
                        Segment {
                            share: pct(*count, total),
                            count: *count,
                            css: risk_css(risk).to_string(),
                            label: risk_label(risk).to_string(),
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
    let legend: Vec<LegendItem> = RISKS
        .iter()
        .map(|(_, label, css)| LegendItem { label, css })
        .collect();

    // The three splits: how risky, whether it was stopped, which way it went.
    let risks = split(&conn, RISK_SQL, &where_clause, &vals, |risk| {
        (risk_rank(risk), risk_label(risk).to_string(), risk_css(risk).to_string(), filter.with_risk(risk).href())
    })?;
    let outcomes = split(&conn, "action", &where_clause, &vals, |action| {
        let blocked = action == "deny";
        (
            usize::from(!blocked),
            action_label(action).to_string(),
            if blocked { "o-blocked" } else { "o-detected" }.to_string(),
            filter.with_action(action).href(),
        )
    })?;
    let directions = split(&conn, DIRECTION_SQL, &where_clause, &vals, |direction| {
        let (rank, css) = match direction {
            "incoming" => (0, "d-incoming"),
            "outgoing" => (1, "d-outgoing"),
            _ => (2, "r-other"),
        };
        (rank, direction.to_string(), css.to_string(), filter.with_direction(direction).href())
    })?;

    // Signatures, with their ID and the policy that carries them.
    let top_signatures: Vec<Bar> = {
        let scoped = scope(&where_clause, "signature <> ''");
        let sql = format!(
            "SELECT signature, coalesce(any_value(nullif(signature_id, '')), ''), \
             coalesce(any_value(nullif(policy, '')), ''), count(*) c \
             FROM {TABLE} {scoped} GROUP BY signature ORDER BY c DESC, signature LIMIT 10"
        );
        let mut stmt = conn.prepare(&sql)?;
        let rows = stmt
            .query_map(params_from_iter(vals.iter()), |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, i64>(3)?,
                ))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        let max = rows.iter().map(|(_, _, _, c)| *c).max().unwrap_or(0);
        rows.into_iter()
            .map(|(signature, id, policy, count)| Bar {
                pct: pct(count, max),
                count,
                css: "r-high".to_string(),
                href: filter.with_signature(&signature).href(),
                note: [(!id.is_empty()).then(|| format!("ID {id}")), (!policy.is_empty()).then_some(policy)]
                    .into_iter()
                    .flatten()
                    .collect::<Vec<_>>()
                    .join(" · "),
                label: signature,
            })
            .collect()
    };
    // The outside addresses, with their country.
    let top_remotes: Vec<Bar> = {
        let scoped = scope(&where_clause, "remote_ip <> ''");
        let sql = format!(
            "SELECT remote_ip, any_value(coalesce(nullif(country, ''), 'Unknown')), count(*) c \
             FROM {TABLE} {scoped} GROUP BY remote_ip ORDER BY c DESC, remote_ip LIMIT 10"
        );
        let mut stmt = conn.prepare(&sql)?;
        let rows = stmt
            .query_map(params_from_iter(vals.iter()), |r| {
                Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get::<_, i64>(2)?))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        let max = rows.iter().map(|(_, _, c)| *c).max().unwrap_or(0);
        rows.into_iter()
            .map(|(remote, country, count)| Bar {
                pct: pct(count, max),
                count,
                css: "r-high".to_string(),
                href: filter.with_remote(&remote).href(),
                label: remote,
                note: country,
            })
            .collect()
    };
    let top_locals = top_n(&conn, "local_ip", &where_clause, &vals, "d-incoming", |l| filter.with_local(l).href())?;
    let top_ports = top_n(&conn, "CAST(dst_port AS VARCHAR)", &where_clause, &vals, "", |l| {
        filter.with_port(l).href()
    })?;
    let top_apps = top_n(&conn, "application", &where_clause, &vals, "", |l| filter.with_app(l).href())?;
    let top_countries = top_n(
        &conn,
        "coalesce(nullif(country, ''), 'Unknown')",
        &where_clause,
        &vals,
        "r-high",
        |l| filter.with_country(l).href(),
    )?;

    // The world map places the outside party of each detection.
    let country_rows = super::geomap::counts(&conn, TABLE, &where_clause, &vals)?;
    let map = super::geomap::build_counting(
        &country_rows,
        Some(&|name: &str| filter.with_country(name).href()),
        ("threat", "threats"),
    );

    let recent = recent_threats(&conn, &filter, &where_clause, &vals, 20)?;

    let mut ctx = tera::Context::new();
    ctx.insert("active", "unifi");
    ctx.insert("active_category", "firewall");
    ctx.insert("nav", &state.nav);
    ctx.insert("type_label", "UniFi Gateway");
    ctx.insert("tabs", &super::firewall::tabs(super::unifi::TABS, BASE));
    ctx.insert("base", BASE);
    ctx.insert("kpis", &kpis);
    ctx.insert("timeline", &timeline);
    ctx.insert("timeline_max", &timeline_max);
    ctx.insert("timeline_mid", &(timeline_max / 2));
    ctx.insert("tl_gran", tl_gran);
    ctx.insert("legend", &legend);
    let panel = |title, icon, mono, wrap, bars| Panel { title, icon, mono, wrap, bars };
    let splits = vec![
        panel("Risk", "bi-exclamation-triangle", false, false, risks),
        panel("Outcome", "bi-shield-check", false, false, outcomes),
        panel("Direction", "bi-arrow-left-right", false, false, directions),
    ];
    let panels = vec![
        panel("Signatures", "bi-fingerprint", false, true, top_signatures),
        panel("Remote addresses", "bi-crosshair", true, false, top_remotes),
        panel("Local hosts", "bi-pc-display", true, false, top_locals),
        panel("Ports", "bi-door-open", true, false, top_ports),
        panel("Applications", "bi-app-indicator", false, false, top_apps),
        panel("Countries", "bi-globe2", false, false, top_countries),
    ];
    ctx.insert("splits", &splits);
    ctx.insert("panels", &panels);
    ctx.insert("recent", &recent);
    ctx.insert("map", &map);
    ctx.insert("map_title", "Threats by country");
    ctx.insert("map_unit", "threats");
    ctx.insert("chips", &chips);
    ctx.insert("range_options", &range_options);
    ctx.insert("range_label", range_label(&range));
    ctx.insert("window", &window_chip);
    ctx.insert("has_filters", &(!chips.is_empty() || window_chip.is_some()));
    ctx.insert("has_data", &(total_rows > 0));
    ctx.insert("search", &filter.q.clone().unwrap_or_default());
    ctx.insert("search_fields", &filter.hidden_fields());
    ctx.insert("search_placeholder", "Search signatures, addresses, messages…");
    ctx.insert("raw_href", &filter.with_view("raw").href());
    Ok(Html(state.tera.render("unifi_threats.html", &ctx)?).into_response())
}

// ─────────────────────────────────────────────────────────────────────────────
// split(conn, expr, where_clause, vals, describe)
// Counts by `expr` and turns each value into a bar; `describe(value)` gives its
// (sort rank, label, colour class, href).
// ─────────────────────────────────────────────────────────────────────────────
fn split(
    conn: &duckdb::Connection,
    expr: &str,
    where_clause: &str,
    vals: &[Value],
    describe: impl Fn(&str) -> (usize, String, String, String),
) -> Result<Vec<Bar>, AppError> {
    let sql = format!("SELECT {expr}, count(*) FROM {TABLE} {where_clause} GROUP BY 1");
    let mut stmt = conn.prepare(&sql)?;
    let pairs = stmt
        .query_map(params_from_iter(vals.iter()), |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    let max = pairs.iter().map(|(_, c)| *c).max().unwrap_or(0);
    let mut bars: Vec<(usize, Bar)> = pairs
        .into_iter()
        .map(|(value, count)| {
            let (rank, label, css, href) = describe(&value);
            (rank, Bar { label, count, pct: pct(count, max), css, href, note: String::new() })
        })
        .collect();
    bars.sort_by_key(|(rank, _)| *rank);
    Ok(bars.into_iter().map(|(_, b)| b).collect())
}

// ─────────────────────────────────────────────────────────────────────────────
// recent_threats(conn, filter, where_clause, vals, limit)
// The newest `limit` detections within the filter. Each address, port and
// signature links to its filter.
// ─────────────────────────────────────────────────────────────────────────────
fn recent_threats(
    conn: &duckdb::Connection,
    filter: &Filter,
    where_clause: &str,
    vals: &[Value],
    limit: usize,
) -> Result<Vec<ThreatRow>, AppError> {
    let sql = format!(
        "SELECT strftime(ts, '%Y-%m-%d %H:%M:%S'), coalesce(direction, ''), coalesce(remote_ip, ''), \
         coalesce(nullif(country, ''), ''), coalesce(local_ip, ''), coalesce(CAST(dst_port AS VARCHAR), ''), \
         coalesce(application, ''), coalesce(nullif(signature, ''), nullif(policy, ''), event, ''), \
         coalesce(signature, ''), coalesce(risk, ''), coalesce(action, '') \
         FROM {TABLE} {where_clause} ORDER BY ts DESC LIMIT {limit}"
    );
    let mut stmt = conn.prepare(&sql)?;
    let rows = stmt
        .query_map(params_from_iter(vals.iter()), |r| {
            Ok((
                (
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, String>(3)?,
                    r.get::<_, String>(4)?,
                    r.get::<_, String>(5)?,
                ),
                (
                    r.get::<_, String>(6)?,
                    r.get::<_, String>(7)?,
                    r.get::<_, String>(8)?,
                    r.get::<_, String>(9)?,
                    r.get::<_, String>(10)?,
                ),
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    let link = |v: &str, f: &dyn Fn(&str) -> Filter| if v.is_empty() { String::new() } else { f(v).href() };
    Ok(rows
        .into_iter()
        .map(|((ts, direction, remote, country, local, port), (app, shown, signature, risk, action))| {
            let class = risk_class(&risk);
            ThreatRow {
                remote_href: link(&remote, &|v| filter.with_remote(v)),
                local_href: link(&local, &|v| filter.with_local(v)),
                signature_href: link(&signature, &|v| filter.with_signature(v)),
                risk: if risk.is_empty() { "unrated".to_string() } else { risk },
                risk_css: risk_css(class).to_string(),
                blocked: action == "deny",
                signature: shown,
                ts,
                direction,
                remote,
                country,
                local,
                port,
                app,
            }
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
    if let Some(v) = &filter.risk {
        chip(format!("Risk: {}", risk_label(v)), Filter { risk: None, ..filter.clone() });
    }
    if let Some(v) = &filter.action {
        chip(format!("Outcome: {}", action_label(v)), Filter { action: None, ..filter.clone() });
    }
    if let Some(v) = &filter.direction {
        chip(format!("Direction: {v}"), Filter { direction: None, ..filter.clone() });
    }
    if let Some(v) = &filter.signature {
        chip(format!("Signature: {v}"), Filter { signature: None, ..filter.clone() });
    }
    if let Some(v) = &filter.remote {
        chip(format!("Remote: {v}"), Filter { remote: None, ..filter.clone() });
    }
    if let Some(v) = &filter.local {
        chip(format!("Local host: {v}"), Filter { local: None, ..filter.clone() });
    }
    if let Some(v) = filter.port {
        chip(format!("Port: {v}"), Filter { port: None, ..filter.clone() });
    }
    if let Some(v) = &filter.app {
        chip(format!("Application: {v}"), Filter { app: None, ..filter.clone() });
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
    fn closed_filters_only_accept_known_values() {
        let f = Filter {
            risk: Some("high".into()),
            action: Some("deny".into()),
            direction: Some("outgoing".into()),
            ..Default::default()
        }
        .normalized();
        assert_eq!(f.risk.as_deref(), Some("high"));
        assert_eq!(f.action.as_deref(), Some("deny"));
        assert_eq!(f.direction.as_deref(), Some("outgoing"));
        let bogus = Filter {
            risk: Some("x' OR 1=1".into()),
            action: Some("drop".into()),
            direction: Some("sideways".into()),
            ..Default::default()
        }
        .normalized();
        assert!(bogus.risk.is_none() && bogus.action.is_none() && bogus.direction.is_none());
    }

    #[test]
    fn filters_bind_their_values() {
        let f = Filter {
            risk: Some("high".into()),
            remote: Some("203.0.113.41".into()),
            port: Some(25),
            ..Default::default()
        }
        .normalized();
        let (conds, vals) = f.sql();
        assert!(conds.contains(&format!("{RISK_SQL} = ?")));
        assert!(conds.iter().any(|c| c == "remote_ip = ?"));
        assert!(conds.iter().any(|c| c == "dst_port = ?"));
        // risk, remote, port and the range cutoff — no value spliced into SQL.
        assert_eq!(vals.len(), 4);
        assert!(conds.iter().all(|c| !c.contains("203.0.113.41")));
    }

    #[test]
    fn risk_classes_match_the_sql() {
        for (risk, class) in [("high", "high"), ("critical", "high"), ("medium", "medium"), ("low", "low"), ("", "other")] {
            assert_eq!(risk_class(risk), class, "{risk:?}");
        }
        assert!(RISKS.iter().all(|(k, _, _)| RISK_SQL.contains(&format!("'{k}'"))));
    }
}
