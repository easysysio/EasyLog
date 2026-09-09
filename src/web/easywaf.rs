// =============================================================================
// web/easywaf.rs — EasyWAF dashboard (GET /waf/easywaf)
//
// A WAF dashboard answers a different question from a firewall's. A firewall
// asks what got in and what was blocked; a WAF also has to show what was
// **served that shouldn't have been** — `would_block` and `would_challenge` on a
// DetectionOnly policy, and `scored` requests that stayed under the threshold.
// Those are attacks that reached the application, so they get their own KPI
// rather than being folded into a two-way allow/deny split.
//
// Built, in the order the EasyWAF specification puts them in:
//   1. verdicts over time, stacked — the shape of an attack shows here first;
//   2. the same split per appliance and site, which a single EasyWAF cannot
//      show itself and is the reason to ship logs at all;
//   3. top rules fired (the `rules` list unnested), so a rule dominating the
//      `scored` bucket against ordinary traffic can be spotted for tuning;
//   4. top clients, countries, paths and hosts.
//
// Every panel is a drill-down link, filters stack as removable chips, and the
// range, the pinned timeline window (?from=&to=) and search compose into one
// parameterized WHERE clause — the same contract as every other dashboard.
//
// Counts are of *received* events: EasyWAF drops rather than blocking its
// request path, so this is a sample of traffic, never a complete tally.
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
use crate::logtype::easywaf::VERDICTS;
use crate::state::AppState;

const TABLE: &str = "easywaf";
const BASE: &str = "/waf/easywaf";

// Columns the search box looks in. Status is cast so that typing "403" finds the
// blocks, alongside addresses, paths, sites, rules and the block reason.
const SEARCH_COLUMNS: [&str; 9] = [
    "client",
    "path",
    "host",
    "site",
    "rules",
    "reason",
    "verdict",
    "country",
    "CAST(status AS VARCHAR)",
];

// Dashboard filter, parsed from the query string and re-serialized into links.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub(crate) struct Filter {
    #[serde(skip_serializing_if = "Option::is_none")]
    verdict: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    client: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    site: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    host: Option<String>,
    /// The EasyWAF instance that sent the event (the syslog peer).
    #[serde(skip_serializing_if = "Option::is_none")]
    appliance: Option<String>,
    /// A single catalogue rule number, matched within the comma-separated list.
    #[serde(skip_serializing_if = "Option::is_none")]
    rule: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    path: Option<String>,
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
            verdict: clean(self.verdict),
            client: clean(self.client),
            site: clean(self.site),
            host: clean(self.host),
            appliance: clean(self.appliance),
            rule: clean(self.rule),
            path: clean(self.path),
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

    // Serialize back to a `<base>?...` URL (values percent-encoded by serde).
    fn href(&self) -> String {
        match serde_urlencoded::to_string(self) {
            Ok(q) if !q.is_empty() => format!("{BASE}?{q}"),
            _ => BASE.to_string(),
        }
    }

    fn with_verdict(&self, v: &str) -> Filter {
        Filter { verdict: Some(v.to_string()), ..self.clone() }
    }
    fn with_client(&self, v: &str) -> Filter {
        Filter { client: Some(v.to_string()), ..self.clone() }
    }
    fn with_site(&self, v: &str) -> Filter {
        Filter { site: Some(v.to_string()), ..self.clone() }
    }
    fn with_host(&self, v: &str) -> Filter {
        Filter { host: Some(v.to_string()), ..self.clone() }
    }
    fn with_appliance(&self, v: &str) -> Filter {
        Filter { appliance: Some(v.to_string()), ..self.clone() }
    }
    fn with_rule(&self, v: &str) -> Filter {
        Filter { rule: Some(v.to_string()), ..self.clone() }
    }
    fn with_path(&self, v: &str) -> Filter {
        Filter { path: Some(v.to_string()), ..self.clone() }
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
        // "would" is not a verdict EasyWAF sends: it is the pair the "Served
        // anyway" figures count, so filtering to it has to mean both.
        match self.verdict.as_deref() {
            Some(WOULD) => conds.push("verdict IN ('would_block', 'would_challenge')".to_string()),
            Some(v) => {
                conds.push("verdict = ?".to_string());
                vals.push(Value::Text(v.to_string()));
            }
            None => {}
        }
        let mut eq = |column: &str, value: &Option<String>| {
            if let Some(v) = value {
                conds.push(format!("{column} = ?"));
                vals.push(Value::Text(v.clone()));
            }
        };
        eq("client", &self.client);
        eq("site", &self.site);
        eq("host", &self.host);
        eq("source_ip", &self.appliance);
        eq("path", &self.path);
        if let Some(country) = &self.country {
            conds.push("coalesce(nullif(country, ''), 'Unknown') = ?".to_string());
            vals.push(Value::Text(country.clone()));
        }
        // `rules` is stored as EasyWAF sent it, comma-separated; a rule filter
        // matches one element of that list rather than a substring, so 942100
        // cannot also match 9421001.
        if let Some(rule) = &self.rule {
            conds.push("list_contains(string_split(coalesce(rules, ''), ','), ?)".to_string());
            vals.push(Value::Text(rule.clone()));
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

// How each verdict is coloured and ordered, worst outcome first. An unknown
// verdict from a newer EasyWAF falls through to a neutral colour rather than
// being hidden.
fn verdict_css(verdict: &str) -> &'static str {
    match verdict {
        "blocked" => "v-blocked",
        "would_block" => "v-would-block",
        "would_challenge" => "v-would-challenge",
        "challenged" => "v-challenged",
        "scored" => "v-scored",
        "passed" => "v-passed",
        _ => "v-other",
    }
}

// Display name: the wire values are snake_case.
fn verdict_label(verdict: &str) -> String {
    if verdict == WOULD {
        return "would block / challenge".to_string();
    }
    verdict.replace('_', " ")
}

// Display order: worst outcome first, so `blocked` and the two "would have"
// verdicts sit together at the top of the split and at the foot of a stacked
// bar, where they are easiest to compare across buckets.
const BY_SEVERITY: [&str; 6] =
    ["blocked", "would_block", "would_challenge", "challenged", "scored", "passed"];

fn verdict_rank(verdict: &str) -> usize {
    debug_assert!(BY_SEVERITY.len() == VERDICTS.len());
    BY_SEVERITY.iter().position(|v| *v == verdict).unwrap_or(BY_SEVERITY.len())
}

/// The pseudo-verdict behind the "Served anyway" figures: both DetectionOnly
/// verdicts at once, since counting them together and filtering to only one of
/// them would disagree.
const WOULD: &str = "would";

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

// Headline counters shown as KPI cards.
#[derive(Serialize, Default)]
struct Kpis {
    events: i64,
    blocked: i64,
    block_rate: String,
    /// would_block + would_challenge: attacks an enforcing policy would have
    /// stopped, served because it isn't enforcing.
    served_anyway: i64,
    clients: i64,
    countries: i64,
}

// One bar in a chart/list. `href`, when non-empty, makes the row a drill-down
// link; `css` is an optional colour class.
#[derive(Serialize)]
struct Bar {
    label: String,
    count: i64,
    pct: i64,
    css: String,
    href: String,
    ts_epoch: i64,
}

// One segment of a stacked timeline bar: a verdict's share of that bucket.
#[derive(Serialize)]
struct Segment {
    verdict: String,
    label: String,
    count: i64,
    /// Percent of this bucket's total — the segment's share of the bar.
    share: i64,
    css: String,
}

// One bucket of the stacked verdict timeline.
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

// One row of the per-appliance table: the verdict split for one EasyWAF
// instance and site, which is the view a single appliance cannot produce.
#[derive(Serialize)]
struct FleetRow {
    appliance: String,
    appliance_href: String,
    site: String,
    site_href: String,
    events: i64,
    scored: i64,
    blocked: i64,
    would: i64,
    blocked_href: String,
    would_href: String,
}

// ─────────────────────────────────────────────────────────────────────────────
// GET /waf/easywaf  (?range= ?from= ?to= plus ?verdict= ?client= ?site= ?host=
// ?appliance= ?rule= ?path= ?country= drill-down filters, ?q= search and
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
// Builds the EasyWAF dashboard from live, range- and filter-bounded DuckDB
// aggregations, and renders easywaf.html.
// ─────────────────────────────────────────────────────────────────────────────
fn render(state: &Arc<AppState>, raw: Filter) -> Result<Response, AppError> {
    let filter = raw.normalized();
    let range = filter.range_key().to_string();
    let (conds, vals) = filter.sql();
    let where_clause = build_where(&conds);

    let (range_options, chips, window_chip) = furniture(&filter, &range);

    // Raw mode reuses this dashboard's WHERE clause, so the lines listed are
    // exactly the events the charts summarise. Handled before the database lock
    // is taken: rawview does its own locking, and the aggregations below would
    // be wasted work.
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
        ctx.insert("active_category", "waf");
        ctx.insert("nav", &state.nav);
        ctx.insert("type_label", "EasyWAF");
        ctx.insert("base", BASE);
        ctx.insert("chips", &chips);
        ctx.insert("range_options", &range_options);
        ctx.insert("range_label", range_label(&range));
        ctx.insert("window", &window_chip);
        ctx.insert("has_filters", &(!chips.is_empty() || window_chip.is_some()));
        ctx.insert("search", &filter.q.clone().unwrap_or_default());
        ctx.insert("search_fields", &filter.hidden_fields());
        ctx.insert("search_placeholder", "Search client, path, site, rule…");
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

    // Headline counters in a single pass. "Served anyway" counts the two
    // DetectionOnly verdicts together — the number that justifies enforcing.
    let (events, blocked, served_anyway, clients, countries): (i64, i64, i64, i64, i64) = {
        let sql = format!(
            "SELECT count(*), \
             count(*) FILTER (WHERE verdict = 'blocked'), \
             count(*) FILTER (WHERE verdict IN ('would_block', 'would_challenge')), \
             count(DISTINCT client), \
             count(DISTINCT country_code) FILTER (WHERE country_code IS NOT NULL AND country_code <> '') \
             FROM {TABLE} {where_clause}"
        );
        let mut stmt = conn.prepare(&sql)?;
        let mut rows = stmt.query_map(params_from_iter(vals.iter()), |r| {
            Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?))
        })?;
        rows.next().transpose()?.unwrap_or((0, 0, 0, 0, 0))
    };
    let kpis = Kpis {
        events,
        blocked,
        block_rate: if events > 0 {
            format!("{:.1}%", blocked as f64 * 100.0 / events as f64)
        } else {
            "0.0%".to_string()
        },
        served_anyway,
        clients,
        countries,
    };

    // Verdicts over time, stacked and zero-filled across the whole range. This
    // is the panel the specification puts first: the shape of an attack — a
    // block wall, a slow climb of `scored` — is visible here before anywhere.
    // Pinned to a window the timeline buckets inside it, so a click zooms in.
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
    // (bucket epoch, verdict) → count.
    let counts: Vec<(i64, String, i64)> = {
        let sql = format!(
            "SELECT CAST(epoch({bucket_expr}) AS BIGINT), verdict, count(*) FROM {TABLE} \
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
    // Every bar links to its own window, so a click pins the dashboard to it and
    // a further click narrows again.
    let timeline: Vec<StackedBar> = series
        .into_iter()
        .map(|(epoch, label)| {
            let total = bucket_total(epoch);
            let mut segments: Vec<Segment> = counts
                .iter()
                .filter(|(e, _, _)| *e == epoch)
                .map(|(_, verdict, count)| Segment {
                    share: pct(*count, total),
                    count: *count,
                    css: verdict_css(verdict).to_string(),
                    label: verdict_label(verdict),
                    verdict: verdict.clone(),
                })
                .collect();
            segments.sort_by_key(|s| verdict_rank(&s.verdict));
            let end = match filter.window() {
                Some((_, to)) => (epoch + bucket_span).min(to),
                None => super::bucket_end(&range, epoch),
            };
            StackedBar {
                pct: pct(total, timeline_max),
                count: total,
                href: filter.with_window(epoch, end).href(),
                segments,
                label,
                ts_epoch: epoch,
            }
        })
        .collect();

    // The verdict split itself, clickable to filter. Ordered worst-first rather
    // than by count, so `blocked` and `would_block` sit together at the top.
    let verdicts: Vec<Bar> = {
        let sql = format!(
            "SELECT verdict, count(*) c FROM {TABLE} {where_clause} GROUP BY verdict"
        );
        let mut stmt = conn.prepare(&sql)?;
        let mut pairs = stmt
            .query_map(params_from_iter(vals.iter()), |r| {
                Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        pairs.sort_by_key(|(v, _)| verdict_rank(v));
        let max = pairs.iter().map(|(_, c)| *c).max().unwrap_or(0);
        pairs
            .into_iter()
            .map(|(verdict, count)| Bar {
                pct: pct(count, max),
                count,
                css: verdict_css(&verdict).to_string(),
                href: filter.with_verdict(&verdict).href(),
                label: verdict_label(&verdict),
                ts_epoch: 0,
            })
            .collect()
    };

    // The fleet view: the same split per appliance and site. A single EasyWAF
    // cannot show this, and it is the main reason to ship logs at all.
    let fleet: Vec<FleetRow> = {
        let sql = format!(
            "SELECT source_ip, coalesce(nullif(site, ''), '—'), count(*) c, \
             count(*) FILTER (WHERE verdict = 'scored'), \
             count(*) FILTER (WHERE verdict = 'blocked'), \
             count(*) FILTER (WHERE verdict IN ('would_block', 'would_challenge')) \
             FROM {TABLE} {where_clause} GROUP BY 1, 2 ORDER BY c DESC LIMIT 10"
        );
        let mut stmt = conn.prepare(&sql)?;
        stmt.query_map(params_from_iter(vals.iter()), |r| {
            let appliance: String = r.get(0)?;
            let site: String = r.get(1)?;
            Ok((appliance, site, r.get::<_, i64>(2)?, r.get::<_, i64>(3)?, r.get::<_, i64>(4)?, r.get::<_, i64>(5)?))
        })?
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .map(|(appliance, site, events, scored, blocked, would)| {
            let scoped = filter.with_appliance(&appliance);
            let scoped = if site == "—" { scoped } else { scoped.with_site(&site) };
            FleetRow {
                appliance_href: filter.with_appliance(&appliance).href(),
                site_href: if site == "—" { String::new() } else { filter.with_site(&site).href() },
                blocked_href: scoped.with_verdict("blocked").href(),
                would_href: scoped.with_verdict(WOULD).href(),
                appliance,
                site,
                events,
                scored,
                blocked,
                would,
            }
        })
        .collect()
    };

    // Top rules fired. `rules` arrives comma-separated, so it is split and
    // unnested — one row per rule — before counting.
    let top_rules: Vec<Bar> = {
        let scoped = scope(&where_clause, "rules IS NOT NULL AND rules <> ''");
        let sql = format!(
            "SELECT rule, count(*) c FROM ( \
               SELECT unnest(string_split(rules, ',')) AS rule FROM {TABLE} {scoped} \
             ) WHERE rule <> '' GROUP BY rule ORDER BY c DESC, rule LIMIT 10"
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
            .map(|(rule, count)| Bar {
                pct: pct(count, max),
                count,
                css: String::new(),
                href: filter.with_rule(&rule).href(),
                label: rule,
                ts_epoch: 0,
            })
            .collect()
    };

    let top_clients = top_n(&conn, "client", &where_clause, &vals, |l| filter.with_client(l).href())?;
    let top_paths = top_n(&conn, "path", &where_clause, &vals, |l| filter.with_path(l).href())?;
    let top_hosts = top_n(&conn, "host", &where_clause, &vals, |l| filter.with_host(l).href())?;
    let top_countries = top_n(
        &conn,
        "coalesce(nullif(country, ''), 'Unknown')",
        &where_clause,
        &vals,
        |l| filter.with_country(l).href(),
    )?;

    // Where the requests came from — the client address decides the country.
    let country_rows = super::geomap::counts(&conn, TABLE, &where_clause, &vals)?;
    let map = super::geomap::build(&country_rows, Some(&|name: &str| filter.with_country(name).href()));

    let mut ctx = tera::Context::new();
    ctx.insert("active", TABLE);
    ctx.insert("active_category", "waf");
    ctx.insert("nav", &state.nav);
    ctx.insert("type_label", "EasyWAF");
    ctx.insert("base", BASE);
    ctx.insert("kpis", &kpis);
    ctx.insert("timeline", &timeline);
    ctx.insert("timeline_max", &timeline_max);
    ctx.insert("timeline_mid", &(timeline_max / 2));
    ctx.insert("tl_gran", tl_gran);
    ctx.insert("verdicts", &verdicts);
    ctx.insert("fleet", &fleet);
    ctx.insert("top_rules", &top_rules);
    ctx.insert("top_clients", &top_clients);
    ctx.insert("top_paths", &top_paths);
    ctx.insert("top_hosts", &top_hosts);
    ctx.insert("top_countries", &top_countries);
    ctx.insert("map", &map);
    ctx.insert("chips", &chips);
    ctx.insert("range_options", &range_options);
    ctx.insert("range_label", range_label(&range));
    ctx.insert("window", &window_chip);
    ctx.insert("has_filters", &(!chips.is_empty() || window_chip.is_some()));
    ctx.insert("has_data", &(total_rows > 0));
    ctx.insert("search", &filter.q.clone().unwrap_or_default());
    ctx.insert("search_fields", &filter.hidden_fields());
    ctx.insert("search_placeholder", "Search client, path, site, rule…");
    ctx.insert("raw_href", &filter.with_view("raw").href());
    Ok(Html(state.tera.render("easywaf.html", &ctx)?).into_response())
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
    if let Some(v) = &filter.verdict {
        chip(format!("Verdict: {}", verdict_label(v)), Filter { verdict: None, ..filter.clone() });
    }
    if let Some(v) = &filter.client {
        chip(format!("Client: {v}"), Filter { client: None, ..filter.clone() });
    }
    if let Some(v) = &filter.site {
        chip(format!("Site: {v}"), Filter { site: None, ..filter.clone() });
    }
    if let Some(v) = &filter.host {
        chip(format!("Host: {v}"), Filter { host: None, ..filter.clone() });
    }
    if let Some(v) = &filter.appliance {
        chip(format!("Appliance: {v}"), Filter { appliance: None, ..filter.clone() });
    }
    if let Some(v) = &filter.rule {
        chip(format!("Rule: {v}"), Filter { rule: None, ..filter.clone() });
    }
    if let Some(v) = &filter.path {
        chip(format!("Path: {v}"), Filter { path: None, ..filter.clone() });
    }
    if let Some(v) = &filter.country {
        chip(format!("Country: {v}"), Filter { country: None, ..filter.clone() });
    }
    if let Some(q) = &filter.q {
        chip(format!("Search: {q}"), filter.without_q());
    }
    // The pinned window is a chip of its own: it carries the bucket's epochs so
    // the page can restate them in the reader's timezone, and removing it drops
    // back to the plain range.
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
    href_for: impl Fn(&str) -> String,
) -> Result<Vec<Bar>, AppError> {
    // Rows with no value for this dimension would otherwise show as an empty
    // label; they're excluded rather than presented as a mystery entry.
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
            css: String::new(),
            label,
            ts_epoch: 0,
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
