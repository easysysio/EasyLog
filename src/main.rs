// =============================================================================
// main.rs — EasyLog web service entry point
//
// Boots the Axum HTTP server for the EasyLog log analyzer. Initializes tracing,
// builds the router, and serves on 0.0.0.0:3000. This is the minimal scaffold:
// only root and health routes exist so far — parsing/analysis comes later.
// =============================================================================

use axum::{Router, routing::get};
use tokio::net::TcpListener;

// Address the server binds to. Kept as a const for now; will move to config later.
const BIND_ADDR: &str = "0.0.0.0:3000";

// ─────────────────────────────────────────────────────────────────────────────
// main()
// Process entry point. Sets up logging, constructs the router, binds the TCP
// listener, and runs the Axum server until the process is terminated.
// ─────────────────────────────────────────────────────────────────────────────
#[tokio::main]
async fn main() {
    // Initialize tracing. RUST_LOG controls verbosity; defaults to `info`.
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .init();

    let app = build_router();

    let listener = TcpListener::bind(BIND_ADDR)
        .await
        .expect("failed to bind listener");

    tracing::info!("EasyLog listening on http://{BIND_ADDR}");

    axum::serve(listener, app)
        .await
        .expect("server error");
}

// ─────────────────────────────────────────────────────────────────────────────
// build_router()
// Assembles the application's route table. Centralized here so routes are easy
// to find and unit-test as the service grows.
// ─────────────────────────────────────────────────────────────────────────────
fn build_router() -> Router {
    Router::new()
        .route("/", get(root))
        .route("/health", get(health))
}

// ─────────────────────────────────────────────────────────────────────────────
// GET /
// Landing route — returns a plain-text banner identifying the service.
// ─────────────────────────────────────────────────────────────────────────────
async fn root() -> &'static str {
    "EasyLog — Log analyzer"
}

// ─────────────────────────────────────────────────────────────────────────────
// GET /health
// Liveness probe — returns 200 "ok" so orchestrators can check the service.
// ─────────────────────────────────────────────────────────────────────────────
async fn health() -> &'static str {
    "ok"
}
