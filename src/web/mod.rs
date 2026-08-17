// =============================================================================
// web/mod.rs — Axum web server (UI + JSON)
//
// Builds and serves the EasyLog web app. Provides the home page, the log-source
// management UI (list / add / remove sources, backed by DuckDB), and a temporary
// GET /apache/recent JSON endpoint for verifying ingestion. Pages are rendered
// with Tera (templates/). Per-type dashboards arrive in a later stage.
// =============================================================================

use std::sync::Arc;

use std::sync::atomic::Ordering;

use chrono::{Datelike, Duration, NaiveDate, Timelike, Utc};

use std::net::SocketAddr;

use axum::{
    Form, Json, Router,
    extract::{ConnectInfo, Path, Request, State},
    http::Uri,
    http::{StatusCode, header},
    middleware::{self, Next},
    response::{Html, IntoResponse, Redirect, Response},
    routing::{get, post},
};
use axum_extra::extract::cookie::{Cookie, SameSite, SignedCookieJar};
use serde::{Deserialize, Serialize};
use tokio::net::TcpListener;

use crate::auth;
use crate::logging::audit::{self, Actor};
use crate::sources::{self, Source};
use crate::state::{AppState, WebState};

mod apache;
mod caddy;
mod cisco_asa;
mod firewall;
mod geomap;
mod haproxy;
mod nginx;
mod panos;
mod proxy;
mod rawview;
mod traefik;

// Web assets compiled into the binary so the UI is served with no static/
// directory on disk (single self-contained binary).
const BOOTSTRAP_CSS: &[u8] = include_bytes!("../../static/bootstrap.min.css");
const BOOTSTRAP_JS: &[u8] = include_bytes!("../../static/bootstrap.bundle.min.js");
const ICONS_CSS: &[u8] = include_bytes!("../../static/bootstrap-icons.css");
const ICONS_FONT: &[u8] = include_bytes!("../../static/fonts/bootstrap-icons.woff2");
const FAVICON: &[u8] = include_bytes!("../../static/favicon.svg");

// ─────────────────────────────────────────────────────────────────────────────
// serve(state)
// Binds the web port and serves the Axum app until the process is terminated.
// ─────────────────────────────────────────────────────────────────────────────
pub async fn serve(state: Arc<AppState>) -> anyhow::Result<()> {
    let port = state.config.web_port;

    // Routes that require an authenticated session. Dashboards live under their
    // navigation category (/web/apache, later /firewall/…); the old flat paths
    // redirect so existing bookmarks and shared filter links keep working.
    let protected = Router::new()
        .route("/", get(home))
        .route("/sources", get(sources_page).post(add_source))
        .route("/sources/delete", post(delete_source))
        .route("/web/apache", get(apache::dashboard))
        .route("/web/apache/recent", get(apache_recent))
        .route("/web/nginx", get(nginx::dashboard))
        .route("/web/traefik", get(traefik::dashboard))
        .route("/web/caddy", get(caddy::dashboard))
        .route("/web/haproxy", get(haproxy::dashboard))
        .route("/firewall/cisco_asa", get(cisco_asa::dashboard))
        .route("/firewall/panos", get(panos::dashboard))
        .route("/apache", get(|uri: Uri| moved(uri, "/web/apache")))
        .route("/apache/recent", get(|uri: Uri| moved(uri, "/web/apache/recent")))
        .route("/nginx", get(|uri: Uri| moved(uri, "/web/nginx")))
        .route("/traefik", get(|uri: Uri| moved(uri, "/web/traefik")))
        .route_layer(middleware::from_fn_with_state(
            WebState(state.clone()),
            require_auth,
        ));

    // Public routes: auth pages, health probe, and the embedded assets needed to
    // render the login/setup pages.
    let app = Router::new()
        .route("/login", get(login_page).post(login_submit))
        .route("/setup", get(setup_page).post(setup_submit))
        .route("/logout", post(logout))
        .route("/health", get(health))
        .route("/favicon.ico", get(favicon))
        .route("/static/{*path}", get(static_asset))
        .merge(protected)
        .with_state(WebState(state));

    let addr = format!("0.0.0.0:{port}");
    let listener = TcpListener::bind(&addr).await?;
    tracing::info!("EasyLog web listening on http://{addr}");
    // into_make_service_with_connect_info exposes the peer address, which the
    // audit log records alongside each action.
    axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>()).await?;
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// GET /health
// Liveness probe — returns 200 "ok".
// ─────────────────────────────────────────────────────────────────────────────
async fn health() -> &'static str {
    "ok"
}

// Permanent redirect from a dashboard's old flat path to its category-scoped
// one, carrying the query string over so drill-down filters survive the move.
async fn moved(uri: Uri, target: &'static str) -> Redirect {
    match uri.query() {
        Some(q) if !q.is_empty() => Redirect::permanent(&format!("{target}?{q}")),
        _ => Redirect::permanent(target),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// GET /static/{*path}
// Serves a compiled-in web asset by path with the right content type; 404 for
// anything not embedded.
// ─────────────────────────────────────────────────────────────────────────────
async fn static_asset(Path(path): Path<String>) -> Response {
    let (bytes, ctype): (&'static [u8], &str) = match path.as_str() {
        "bootstrap.min.css" => (BOOTSTRAP_CSS, "text/css; charset=utf-8"),
        "bootstrap.bundle.min.js" => (BOOTSTRAP_JS, "text/javascript; charset=utf-8"),
        "bootstrap-icons.css" => (ICONS_CSS, "text/css; charset=utf-8"),
        "fonts/bootstrap-icons.woff2" => (ICONS_FONT, "font/woff2"),
        "favicon.svg" => (FAVICON, "image/svg+xml"),
        _ => return StatusCode::NOT_FOUND.into_response(),
    };
    ([(header::CONTENT_TYPE, ctype)], bytes).into_response()
}

// ─────────────────────────────────────────────────────────────────────────────
// GET /favicon.ico
// Serves the embedded SVG favicon (the navbar's bi-stack mark) for browsers that
// request /favicon.ico directly rather than honouring the <link rel="icon">.
// ─────────────────────────────────────────────────────────────────────────────
async fn favicon() -> Response {
    ([(header::CONTENT_TYPE, "image/svg+xml")], FAVICON).into_response()
}

// ─────────────────────────────────────────────────────────────────────────────
// timeline_series(range)
// Returns the full, zero-fillable list of timeline buckets for a range as
// (UTC epoch, fallback label), aligned to the same boundaries DuckDB's bucketing
// produces. Dashboards left-join their per-bucket counts onto this so the chart
// always spans the whole window even where there's no data:
//   1h → 12×5min, 24h → 24×hour, 7d → 7×day, 30d → 30×day, 1y → 12×month.
// ─────────────────────────────────────────────────────────────────────────────
pub(crate) fn timeline_series(range: &str) -> Vec<(i64, String)> {
    let now = Utc::now().naive_utc();
    let mut out: Vec<(i64, String)> = Vec::new();
    match range {
        "1h" => {
            let m = now.minute() - now.minute() % 5;
            let end = now.with_minute(m).unwrap().with_second(0).unwrap().with_nanosecond(0).unwrap();
            for i in (0..12).rev() {
                let t = end - Duration::minutes(5 * i);
                out.push((t.and_utc().timestamp(), t.format("%H:%M").to_string()));
            }
        }
        "7d" | "30d" => {
            let days: i64 = if range == "7d" { 7 } else { 30 };
            let end = now.date().and_hms_opt(0, 0, 0).unwrap();
            for i in (0..days).rev() {
                let t = end - Duration::days(i);
                out.push((t.and_utc().timestamp(), t.format("%m-%d").to_string()));
            }
        }
        "1y" => {
            let (mut y, mut m) = (now.year(), now.month());
            let mut months = Vec::new();
            for _ in 0..12 {
                months.push((y, m));
                if m == 1 {
                    y -= 1;
                    m = 12;
                } else {
                    m -= 1;
                }
            }
            months.reverse();
            for (yy, mm) in months {
                let t = NaiveDate::from_ymd_opt(yy, mm, 1).unwrap().and_hms_opt(0, 0, 0).unwrap();
                out.push((t.and_utc().timestamp(), t.format("%Y-%m").to_string()));
            }
        }
        _ => {
            // 24h: 24 hourly buckets ending at the current hour.
            let end = now.with_minute(0).unwrap().with_second(0).unwrap().with_nanosecond(0).unwrap();
            for i in (0..24).rev() {
                let t = end - Duration::hours(i);
                out.push((t.and_utc().timestamp(), t.format("%H:%M").to_string()));
            }
        }
    }
    out
}

// ─────────────────────────────────────────────────────────────────────────────
// require_auth — middleware guarding the protected routes
// Redirects to /setup until the admin exists, then to /login unless a valid
// signed session cookie is present.
// ─────────────────────────────────────────────────────────────────────────────
async fn require_auth(
    State(state): State<Arc<AppState>>,
    jar: SignedCookieJar,
    req: Request,
    next: Next,
) -> Response {
    if state.needs_setup.load(Ordering::Relaxed) {
        return Redirect::to("/setup").into_response();
    }
    if jar.get("session").is_some() {
        next.run(req).await
    } else {
        Redirect::to("/login").into_response()
    }
}

// The account behind a request, for the audit log: the signed session cookie's
// username, or "-" when there is no session yet (sign-in, first-run setup).
fn actor(jar: &SignedCookieJar, addr: SocketAddr) -> Actor {
    let name = jar.get("session").map(|c| c.value().to_string()).unwrap_or_default();
    Actor::new(name, addr.ip().to_string())
}

// Builds a signed session cookie carrying the logged-in username.
fn session_cookie(username: String) -> Cookie<'static> {
    Cookie::build(("session", username))
        .http_only(true)
        .same_site(SameSite::Lax)
        .path("/")
        .build()
}

// ─────────────────────────────────────────────────────────────────────────────
// GET /login  — sign-in form (redirects to /setup on first run).
// ─────────────────────────────────────────────────────────────────────────────
async fn login_page(State(state): State<Arc<AppState>>) -> Result<Response, AppError> {
    if state.needs_setup.load(Ordering::Relaxed) {
        return Ok(Redirect::to("/setup").into_response());
    }
    Ok(Html(state.tera.render("login.html", &tera::Context::new())?).into_response())
}

#[derive(Deserialize)]
struct LoginForm {
    username: String,
    password: String,
}

// ─────────────────────────────────────────────────────────────────────────────
// POST /login — verify credentials; on success set the session cookie.
// ─────────────────────────────────────────────────────────────────────────────
async fn login_submit(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    jar: SignedCookieJar,
    Form(form): Form<LoginForm>,
) -> Result<Response, AppError> {
    let ok = {
        let conn = state.db.lock().expect("db mutex poisoned");
        auth::verify_credentials(&conn, &form.username, &form.password)?
    };
    let username = form.username.trim().to_string();
    let who = Actor::new(username.clone(), addr.ip().to_string());
    if ok {
        audit::record("login.success", &who, "signed in");
        let jar = jar.add(session_cookie(username));
        Ok((jar, Redirect::to("/")).into_response())
    } else {
        // Failed attempts are the ones worth having a record of.
        audit::record("login.failure", &who, "invalid username or password");
        let mut ctx = tera::Context::new();
        ctx.insert("error", "Invalid username or password.");
        Ok(Html(state.tera.render("login.html", &ctx)?).into_response())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// GET /setup — first-run admin creation (refuses once an admin exists).
// ─────────────────────────────────────────────────────────────────────────────
async fn setup_page(State(state): State<Arc<AppState>>) -> Result<Response, AppError> {
    if !state.needs_setup.load(Ordering::Relaxed) {
        return Ok(Redirect::to("/login").into_response());
    }
    Ok(Html(state.tera.render("setup.html", &tera::Context::new())?).into_response())
}

#[derive(Deserialize)]
struct SetupForm {
    username: String,
    password: String,
    confirm: String,
}

// ─────────────────────────────────────────────────────────────────────────────
// POST /setup — create the admin, then log in. No-op once an admin exists.
// ─────────────────────────────────────────────────────────────────────────────
async fn setup_submit(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    jar: SignedCookieJar,
    Form(form): Form<SetupForm>,
) -> Result<Response, AppError> {
    if !state.needs_setup.load(Ordering::Relaxed) {
        return Ok(Redirect::to("/login").into_response());
    }
    let render_err = |msg: &str| -> Result<Response, AppError> {
        let mut ctx = tera::Context::new();
        ctx.insert("error", msg);
        Ok(Html(state.tera.render("setup.html", &ctx)?).into_response())
    };
    if form.password != form.confirm {
        return render_err("Passwords do not match.");
    }
    let result = {
        let conn = state.db.lock().expect("db mutex poisoned");
        auth::create_admin(&conn, &form.username, &form.password)
    };
    match result {
        Ok(()) => {
            state.needs_setup.store(false, Ordering::Relaxed);
            let username = form.username.trim().to_string();
            let who = Actor::new(username.clone(), addr.ip().to_string());
            audit::record("admin.create", &who, "first-run administrator created");
            let jar = jar.add(session_cookie(username));
            Ok((jar, Redirect::to("/")).into_response())
        }
        Err(e) => render_err(&e.to_string()),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// POST /logout — clear the session cookie.
// ─────────────────────────────────────────────────────────────────────────────
async fn logout(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    jar: SignedCookieJar,
) -> (SignedCookieJar, Redirect) {
    audit::record("logout", &actor(&jar, addr), "signed out");
    let removal = Cookie::build(("session", "")).path("/").build();
    (jar.remove(removal), Redirect::to("/login"))
}

// ─────────────────────────────────────────────────────────────────────────────
// GET /
// Home page — short intro plus source/log-type counts.
// ─────────────────────────────────────────────────────────────────────────────
async fn home(State(state): State<Arc<AppState>>) -> Result<Html<String>, AppError> {
    let cutoff = (Utc::now() - Duration::hours(24))
        .naive_utc()
        .format("%Y-%m-%d %H:%M:%S")
        .to_string();

    let mut total: i64 = 0;
    let mut last24: i64 = 0;
    let mut by_type: Vec<(String, i64)> = Vec::new();
    let mut by_ip: std::collections::HashMap<String, i64> = std::collections::HashMap::new();
    // Keyed by (ISO-2 code, display name) — the code shades the map, the name
    // labels the pie. The code is empty for private/unknown addresses.
    let mut by_country: std::collections::HashMap<(String, String), i64> =
        std::collections::HashMap::new();
    let mut country_codes: std::collections::HashSet<String> = std::collections::HashSet::new();

    // Every log type's table has source_ip, ts, country and country_code, so the
    // overview reads them as one union rather than querying each table
    // separately: three scans total instead of four per registered type, which
    // matters as vendors are added.
    let union_sql = state
        .registry
        .names()
        .iter()
        .map(|name| {
            format!("SELECT '{name}' AS log_type, source_ip, ts, country, country_code FROM {name}")
        })
        .collect::<Vec<_>>()
        .join(" UNION ALL ");

    {
        let conn = state.db.lock().expect("db mutex poisoned");

        // Totals and the last-24h count, per type, in one pass.
        let mut s = conn.prepare(&format!(
            "SELECT log_type, count(*), count(*) FILTER (WHERE ts >= CAST(? AS TIMESTAMP)) \
             FROM ({union_sql}) GROUP BY log_type"
        ))?;
        let rows = s.query_map(duckdb::params![cutoff], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?, row.get::<_, i64>(2)?))
        })?;
        for row in rows {
            let (name, count, recent) = row?;
            total += count;
            last24 += recent;
            by_type.push((name, count));
        }
        // Registered types with no rows yet still belong in the legend.
        for name in state.registry.names() {
            if !by_type.iter().any(|(t, _)| t == name) {
                by_type.push((name.to_string(), 0));
            }
        }

        let mut s = conn.prepare(&format!(
            "SELECT source_ip, count(*) FROM ({union_sql}) GROUP BY source_ip"
        ))?;
        let rows = s.query_map([], |row| Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?)))?;
        for row in rows {
            let (ip, c) = row?;
            *by_ip.entry(ip).or_insert(0) += c;
        }

        // Events by country (across all types) for the overview pie and map, plus
        // the set of distinct real country codes for the "Countries" KPI.
        let mut s = conn.prepare(&format!(
            "SELECT coalesce(nullif(country, ''), 'Unknown'), coalesce(country_code, ''), count(*) \
             FROM ({union_sql}) GROUP BY 1, 2"
        ))?;
        let rows = s.query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?, row.get::<_, i64>(2)?))
        })?;
        for row in rows {
            let (country, code, c) = row?;
            if !code.is_empty() {
                country_codes.insert(code.clone());
            }
            *by_country.entry((code, country)).or_insert(0) += c;
        }
    }

    // Map each source IP to its friendly name for the "by source" pie.
    let by_source: Vec<(String, i64)> = {
        let sources = state.sources.read().expect("sources lock poisoned");
        by_ip
            .into_iter()
            .map(|(ip, c)| (sources.get(&ip).map(|s| s.name.clone()).unwrap_or(ip), c))
            .collect()
    };
    // The overview map covers every log type at once. It's display-only: unlike
    // the dashboards, the home page has no filter for a country to drill into.
    let country_rows: Vec<geomap::CountryCount> = by_country
        .iter()
        .map(|((code, name), count)| geomap::CountryCount {
            code: code.clone(),
            name: name.clone(),
            count: *count,
        })
        .collect();
    let map = geomap::build(&country_rows, None);

    let (source_gradient, source_slices) = build_pie(by_source);
    let (type_gradient, type_slices) = build_pie(by_type);
    let (country_gradient, country_slices) =
        build_pie(by_country.into_iter().map(|((_, name), c)| (name, c)).collect());

    let mut ctx = tera::Context::new();
    ctx.insert("active", "home");
    ctx.insert("active_category", "");
    ctx.insert("nav", &state.nav);
    ctx.insert("source_count", &state.sources.read().expect("sources lock poisoned").len());
    ctx.insert("log_types", &state.registry.names());
    ctx.insert("total_logs", &total);
    ctx.insert("last24", &last24);
    ctx.insert("avg_per_min", &format!("{:.2}", last24 as f64 / 1440.0));
    ctx.insert("country_count", &country_codes.len());
    // Storage: what the database occupies on disk, and the retention window
    // that bounds it (DuckDB reuses freed space but never shrinks the file, so
    // this is a high-water mark between compactions).
    ctx.insert(
        "db_size",
        &apache::human_bytes(crate::retention::database_size_bytes(&state.config.db_path) as i64),
    );
    ctx.insert("retention_days", &state.config.retention_days);
    ctx.insert("source_gradient", &source_gradient);
    ctx.insert("source_slices", &source_slices);
    ctx.insert("type_gradient", &type_gradient);
    ctx.insert("type_slices", &type_slices);
    ctx.insert("country_gradient", &country_gradient);
    ctx.insert("country_slices", &country_slices);
    ctx.insert("map", &map);
    ctx.insert("has_data", &(total > 0));
    Ok(Html(state.tera.render("index.html", &ctx)?))
}

// One pie slice: label, count, percent (formatted), and colour.
#[derive(Serialize)]
struct Slice {
    label: String,
    count: i64,
    pct: String,
    color: String,
}

// Builds a CSS conic-gradient string + legend slices from "(label, count)" items.
// Caps at the top 7 by count, rolling the rest into an "Other" slice.
fn build_pie(mut items: Vec<(String, i64)>) -> (String, Vec<Slice>) {
    items.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
    let palette = [
        "#4f9cf9", "#3fb950", "#d8a02a", "#a371f7", "#2dd4bf", "#f78166", "#e2555a", "#8b949e",
    ];
    let other: i64 = if items.len() > 8 {
        items.split_off(7).iter().map(|(_, c)| c).sum()
    } else {
        0
    };
    let total: i64 = items.iter().map(|(_, c)| c).sum::<i64>() + other;

    let mut slices = Vec::new();
    let mut parts = Vec::new();
    let mut cum = 0.0f64;
    for (i, (label, count)) in items.into_iter().enumerate() {
        let pct = if total > 0 { count as f64 * 100.0 / total as f64 } else { 0.0 };
        let color = palette[i % palette.len()].to_string();
        let end = cum + pct;
        parts.push(format!("{color} {cum:.3}% {end:.3}%"));
        cum = end;
        slices.push(Slice { label, count, pct: format!("{pct:.1}"), color });
    }
    if other > 0 {
        let pct = other as f64 * 100.0 / total as f64;
        parts.push(format!("#6e7681 {cum:.3}% 100%"));
        slices.push(Slice { label: "Other".into(), count: other, pct: format!("{pct:.1}"), color: "#6e7681".into() });
    }
    (parts.join(", "), slices)
}

// ─────────────────────────────────────────────────────────────────────────────
// GET /sources
// Renders the source-management page: a table of configured sources plus the
// add form. Used directly and as the re-render target on validation errors.
// ─────────────────────────────────────────────────────────────────────────────
async fn sources_page(State(state): State<Arc<AppState>>) -> Result<Html<String>, AppError> {
    render_sources(&state, None)
}

// Form body for adding a source.
#[derive(Deserialize)]
struct AddForm {
    name: String,
    ip: String,
    log_type: String,
}

// ─────────────────────────────────────────────────────────────────────────────
// POST /sources
// Adds (or updates) a source. Validates the log type against the registry and
// the IP/name via sources::add. On success redirects back (PRG); on a bad input
// re-renders the page with an error banner.
// ─────────────────────────────────────────────────────────────────────────────
async fn add_source(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    jar: SignedCookieJar,
    Form(form): Form<AddForm>,
) -> Result<axum::response::Response, AppError> {
    if !state.registry.names().contains(&form.log_type.as_str()) {
        return Ok(render_sources(&state, Some(format!("unknown log type '{}'", form.log_type)))?
            .into_response());
    }

    let result = {
        let conn = state.db.lock().expect("db mutex poisoned");
        sources::add(&conn, &form.name, &form.ip, &form.log_type)
    };
    match result {
        Ok(()) => {
            state.reload_sources()?;
            audit::record(
                "source.add",
                &actor(&jar, addr),
                &format!("{} ({}) as {}", form.name, form.ip, form.log_type),
            );
            Ok(Redirect::to("/sources").into_response())
        }
        // Validation errors (bad IP, empty name) are shown to the user inline.
        Err(e) => Ok(render_sources(&state, Some(e.to_string()))?.into_response()),
    }
}

// Form body for removing a source.
#[derive(Deserialize)]
struct DeleteForm {
    ip: String,
}

// ─────────────────────────────────────────────────────────────────────────────
// POST /sources/delete
// Removes the source with the given IP, then redirects back.
// ─────────────────────────────────────────────────────────────────────────────
async fn delete_source(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    jar: SignedCookieJar,
    Form(form): Form<DeleteForm>,
) -> Result<Redirect, AppError> {
    {
        let conn = state.db.lock().expect("db mutex poisoned");
        sources::remove(&conn, &form.ip)?;
    }
    state.reload_sources()?;
    audit::record("source.remove", &actor(&jar, addr), &form.ip);
    Ok(Redirect::to("/sources"))
}

// Renders the sources page with the current source list and an optional error.
fn render_sources(state: &Arc<AppState>, error: Option<String>) -> Result<Html<String>, AppError> {
    let mut list: Vec<Source> = state
        .sources
        .read()
        .expect("sources lock poisoned")
        .values()
        .cloned()
        .collect();
    list.sort_by(|a, b| a.name.cmp(&b.name));

    let mut ctx = tera::Context::new();
    ctx.insert("active", "sources");
    ctx.insert("active_category", "");
    ctx.insert("nav", &state.nav);
    ctx.insert("sources", &list);
    ctx.insert("log_types", &state.registry.names());
    if let Some(e) = error {
        ctx.insert("error", &e);
    }
    Ok(Html(state.tera.render("sources.html", &ctx)?))
}

// One row of the temporary /apache/recent inspection feed.
#[derive(Serialize)]
struct RecentRow {
    source_ip: String,
    remote_host: String,
    auth_user: String,
    ts: Option<String>,
    method: String,
    path: String,
    protocol: String,
    status: Option<i32>,
    bytes: Option<i64>,
    user_agent: String,
    received_at: Option<String>,
}

// ─────────────────────────────────────────────────────────────────────────────
// GET /apache/recent
// Returns the 50 most recently received Apache rows as JSON. Temporary endpoint
// for verifying ingestion; superseded by the dashboard later.
// ─────────────────────────────────────────────────────────────────────────────
async fn apache_recent(
    State(state): State<Arc<AppState>>,
) -> Result<Json<Vec<RecentRow>>, AppError> {
    let conn = state.db.lock().expect("db mutex poisoned");
    let mut stmt = conn.prepare(
        r#"SELECT source_ip, remote_host, auth_user, CAST(ts AS VARCHAR),
                  method, path, protocol, status, bytes, user_agent,
                  CAST(received_at AS VARCHAR)
           FROM apache
           ORDER BY received_at DESC
           LIMIT 50"#,
    )?;
    let rows = stmt
        .query_map([], |row| {
            Ok(RecentRow {
                source_ip: row.get(0)?,
                remote_host: row.get(1)?,
                auth_user: row.get(2)?,
                ts: row.get(3)?,
                method: row.get(4)?,
                path: row.get(5)?,
                protocol: row.get(6)?,
                status: row.get(7)?,
                bytes: row.get(8)?,
                user_agent: row.get(9)?,
                received_at: row.get(10)?,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Json(rows))
}

// Error wrapper that turns any internal error into a logged 500 response.
struct AppError(anyhow::Error);

impl<E: Into<anyhow::Error>> From<E> for AppError {
    fn from(e: E) -> Self {
        AppError(e.into())
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> axum::response::Response {
        tracing::error!("request failed: {:#}", self.0);
        (StatusCode::INTERNAL_SERVER_ERROR, "internal error").into_response()
    }
}
