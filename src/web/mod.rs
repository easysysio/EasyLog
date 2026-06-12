// =============================================================================
// web/mod.rs — Axum web server (Stage 1: health + raw inspection)
//
// Builds the HTTP router and serves it. Stage 1 exposes only liveness routes and
// a temporary GET /apache/recent JSON endpoint used to confirm that parsed rows
// are landing in DuckDB. The real per-type dashboards arrive in Stage 2.
// =============================================================================

use std::sync::Arc;

use axum::{
    Json, Router,
    extract::State,
    http::StatusCode,
    routing::get,
};
use serde::Serialize;
use tokio::net::TcpListener;

use crate::state::AppState;

// ─────────────────────────────────────────────────────────────────────────────
// serve(state)
// Binds the web port and serves the Axum app until the process is terminated.
// ─────────────────────────────────────────────────────────────────────────────
pub async fn serve(state: Arc<AppState>) -> anyhow::Result<()> {
    let port = state.config.web_port;
    let app = Router::new()
        .route("/", get(root))
        .route("/health", get(health))
        .route("/apache/recent", get(apache_recent))
        .with_state(state);

    let addr = format!("0.0.0.0:{port}");
    let listener = TcpListener::bind(&addr).await?;
    tracing::info!("EasyLog web listening on http://{addr}");
    axum::serve(listener, app).await?;
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// GET /
// Landing route — plain-text service banner.
// ─────────────────────────────────────────────────────────────────────────────
async fn root() -> &'static str {
    "EasyLog — Log analyzer"
}

// ─────────────────────────────────────────────────────────────────────────────
// GET /health
// Liveness probe — returns 200 "ok".
// ─────────────────────────────────────────────────────────────────────────────
async fn health() -> &'static str {
    "ok"
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
// Returns the 50 most recently received Apache rows as JSON. Temporary Stage-1
// endpoint for verifying ingestion; superseded by the dashboard in Stage 2.
// ─────────────────────────────────────────────────────────────────────────────
async fn apache_recent(
    State(state): State<Arc<AppState>>,
) -> Result<Json<Vec<RecentRow>>, (StatusCode, String)> {
    let conn = state.db.lock().expect("db mutex poisoned");
    let mut stmt = conn
        .prepare(
            r#"SELECT source_ip, remote_host, auth_user, CAST(ts AS VARCHAR),
                      method, path, protocol, status, bytes, user_agent,
                      CAST(received_at AS VARCHAR)
               FROM apache
               ORDER BY received_at DESC
               LIMIT 50"#,
        )
        .map_err(internal)?;

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
        })
        .map_err(internal)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(internal)?;

    Ok(Json(rows))
}

// Maps any error into a 500 response while logging the detail.
fn internal<E: std::fmt::Display>(e: E) -> (StatusCode, String) {
    tracing::error!("apache_recent query failed: {e}");
    (StatusCode::INTERNAL_SERVER_ERROR, "query failed".to_string())
}
