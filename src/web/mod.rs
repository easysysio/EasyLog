// =============================================================================
// web/mod.rs — Axum web server (UI + JSON)
//
// Builds and serves the EasyLog web app. Provides the home page, the log-source
// management UI (list / add / remove sources, backed by DuckDB), and a temporary
// GET /apache/recent JSON endpoint for verifying ingestion. Pages are rendered
// with Tera (templates/). Per-type dashboards arrive in a later stage.
// =============================================================================

use std::sync::Arc;

use axum::{
    Form, Json, Router,
    extract::State,
    http::StatusCode,
    response::{Html, IntoResponse, Redirect},
    routing::{get, post},
};
use serde::{Deserialize, Serialize};
use tokio::net::TcpListener;

use crate::sources::{self, Source};
use crate::state::AppState;

// ─────────────────────────────────────────────────────────────────────────────
// serve(state)
// Binds the web port and serves the Axum app until the process is terminated.
// ─────────────────────────────────────────────────────────────────────────────
pub async fn serve(state: Arc<AppState>) -> anyhow::Result<()> {
    let port = state.config.web_port;
    let app = Router::new()
        .route("/", get(home))
        .route("/health", get(health))
        .route("/sources", get(sources_page).post(add_source))
        .route("/sources/delete", post(delete_source))
        .route("/apache/recent", get(apache_recent))
        .with_state(state);

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
// GET /
// Home page — short intro plus source/log-type counts.
// ─────────────────────────────────────────────────────────────────────────────
async fn home(State(state): State<Arc<AppState>>) -> Result<Html<String>, AppError> {
    let count = state.sources.read().expect("sources lock poisoned").len();
    let mut ctx = tera::Context::new();
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
