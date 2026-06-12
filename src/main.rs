// =============================================================================
// main.rs — EasyLog entry point
//
// Boots the EasyLog multi-log analyzer: loads config, opens DuckDB, initializes
// each log type's schema and the source registry, loads sources into memory,
// builds the Tera template engine, then runs the syslog listeners (UDP + TCP)
// and the Axum web server concurrently over shared state.
// =============================================================================

mod config;
mod logtype;
mod sources;
mod state;
mod storage;
mod syslog;
mod web;

use std::collections::HashMap;
use std::sync::{Arc, Mutex, RwLock};

use anyhow::{Context, Result};
use tera::Tera;

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

    // Open storage and initialize schemas: one table per log type, plus sources.
    let registry = Registry::with_defaults();
    let conn = storage::open(&config.db_path)?;
    registry.init_all(&conn)?;
    sources::init_schema(&conn)?;
    let source_map: HashMap<String, sources::Source> = sources::load_map(&conn)?;

    // Load the web templates.
    let tera = Tera::new("templates/**/*.html").context("loading templates")?;

    tracing::info!(
        "config: syslog {}:{} (udp+tcp), web :{}, db {}, {} source(s)",
        config.syslog_bind,
        config.syslog_port,
        config.web_port,
        config.db_path,
        source_map.len(),
    );

    let state = Arc::new(AppState {
        config,
        registry,
        db: Mutex::new(conn),
        sources: RwLock::new(source_map),
        tera,
    });

    // Run syslog ingestion and the web server concurrently; if either fails,
    // propagate the error and shut down.
    tokio::try_join!(syslog::serve(state.clone()), web::serve(state.clone()))?;

    Ok(())
}
