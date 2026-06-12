// =============================================================================
// main.rs — EasyLog entry point
//
// Boots the EasyLog multi-log analyzer: loads config, opens DuckDB, initializes
// every log type's schema, then runs the syslog listeners (UDP + TCP) and the
// Axum web server concurrently over shared state. Stage 1 supports the Apache
// log type end-to-end (ingest → store); dashboards arrive in Stage 2.
// =============================================================================

mod config;
mod logtype;
mod state;
mod storage;
mod syslog;
mod web;

use std::sync::{Arc, Mutex};

use anyhow::Result;

use crate::config::Config;
use crate::logtype::Registry;
use crate::state::AppState;

// Default config path; overridable via the EASYLOG_CONFIG env var.
const DEFAULT_CONFIG: &str = "config/easylog.toml";

// ─────────────────────────────────────────────────────────────────────────────
// main()
// Process entry point: initialize logging and shared state, then run the syslog
// listeners and web server until either exits.
// ─────────────────────────────────────────────────────────────────────────────
#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    let config_path = std::env::var("EASYLOG_CONFIG").unwrap_or_else(|_| DEFAULT_CONFIG.to_string());
    let config = Config::load(&config_path)?;
    tracing::info!(
        "config: syslog {}:{} (udp+tcp), web :{}, db {}, {} host route(s)",
        config.syslog_bind,
        config.syslog_port,
        config.web_port,
        config.db_path,
        config.hosts.len(),
    );

    let registry = Registry::with_defaults();
    let conn = storage::open(&config.db_path)?;
    registry.init_all(&conn)?;

    let state = Arc::new(AppState {
        config,
        registry,
        db: Mutex::new(conn),
    });

    // Run syslog ingestion and the web server concurrently; if either fails,
    // propagate the error and shut down.
    let syslog_state = state.clone();
    let web_state = state.clone();
    tokio::try_join!(
        syslog::serve(syslog_state),
        web::serve(web_state),
    )?;

    Ok(())
}
