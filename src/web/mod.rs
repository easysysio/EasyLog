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

use axum::{
    Form, Json, Router,
    extract::{Path, Request, State},
    http::{StatusCode, header},
    middleware::{self, Next},
    response::{Html, IntoResponse, Redirect, Response},
    routing::{get, post},
};
use axum_extra::extract::cookie::{Cookie, SameSite, SignedCookieJar};
use serde::{Deserialize, Serialize};
use tokio::net::TcpListener;

use crate::auth;
use crate::sources::{self, Source};
use crate::state::{AppState, WebState};

mod apache;
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

    // Routes that require an authenticated session.
    let protected = Router::new()
        .route("/", get(home))
        .route("/sources", get(sources_page).post(add_source))
        .route("/sources/delete", post(delete_source))
        .route("/apache", get(apache::dashboard))
        .route("/apache/recent", get(apache_recent))
        .route("/traefik", get(traefik::dashboard))
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
    axum::serve(listener, app).await?;
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// GET /health
// Liveness probe — returns 200 "ok".
// ─────────────────────────────────────────────────────────────────────────────
async fn health() -> &'static str {
    "ok"
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
    jar: SignedCookieJar,
    Form(form): Form<LoginForm>,
) -> Result<Response, AppError> {
    let ok = {
        let conn = state.db.lock().expect("db mutex poisoned");
        auth::verify_credentials(&conn, &form.username, &form.password)?
    };
    if ok {
        let jar = jar.add(session_cookie(form.username.trim().to_string()));
        Ok((jar, Redirect::to("/")).into_response())
    } else {
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
            let jar = jar.add(session_cookie(form.username.trim().to_string()));
            Ok((jar, Redirect::to("/")).into_response())
        }
        Err(e) => render_err(&e.to_string()),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// POST /logout — clear the session cookie.
// ─────────────────────────────────────────────────────────────────────────────
async fn logout(jar: SignedCookieJar) -> (SignedCookieJar, Redirect) {
    let removal = Cookie::build(("session", "")).path("/").build();
    (jar.remove(removal), Redirect::to("/login"))
}

// ─────────────────────────────────────────────────────────────────────────────
// GET /
// Home page — short intro plus source/log-type counts.
// ─────────────────────────────────────────────────────────────────────────────
async fn home(State(state): State<Arc<AppState>>) -> Result<Html<String>, AppError> {
    let count = state.sources.read().expect("sources lock poisoned").len();
    let mut ctx = tera::Context::new();
    ctx.insert("active", "home");
    ctx.insert("source_count", &count);
    ctx.insert("log_types", &state.registry.names());
    Ok(Html(state.tera.render("index.html", &ctx)?))
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
    Form(form): Form<DeleteForm>,
) -> Result<Redirect, AppError> {
    {
        let conn = state.db.lock().expect("db mutex poisoned");
        sources::remove(&conn, &form.ip)?;
    }
    state.reload_sources()?;
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
