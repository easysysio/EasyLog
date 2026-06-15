// =============================================================================
// main.rs — EasyLog entry point
//
// Boots the EasyLog multi-log analyzer: loads config, opens DuckDB, initializes
// each log type's schema and the source registry, loads sources into memory,
// builds the Tera engine from templates embedded in the binary, then runs the
// syslog listeners (UDP + TCP) and the Axum web server over shared state. The
// web templates and static assets are compiled in, so EasyLog runs as a single
// self-contained binary with nothing to install alongside it.
// =============================================================================

mod auth;
mod config;
mod logtype;
mod sources;
mod state;
mod storage;
mod syslog;
mod web;

use std::collections::HashMap;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex, RwLock};

use anyhow::{Context, Result};
use tera::Tera;

use crate::config::Config;
use crate::logtype::Registry;
use crate::state::AppState;

// Default config path; overridable via the EASYLOG_CONFIG env var.
const DEFAULT_CONFIG: &str = "config/easylog.toml";

// ─────────────────────────────────────────────────────────────────────────────
// load_templates()
// Builds the Tera engine from templates compiled into the binary (include_str!),
// so EasyLog needs no templates/ directory on disk at runtime.
// ─────────────────────────────────────────────────────────────────────────────
fn load_templates() -> Result<Tera> {
    let mut tera = Tera::default();
    tera.add_raw_templates(vec![
        ("base.html", include_str!("../templates/base.html")),
        ("index.html", include_str!("../templates/index.html")),
        ("sources.html", include_str!("../templates/sources.html")),
        ("apache.html", include_str!("../templates/apache.html")),
        ("traefik.html", include_str!("../templates/traefik.html")),
        ("login.html", include_str!("../templates/login.html")),
        ("setup.html", include_str!("../templates/setup.html")),
    ])
    .context("registering embedded templates")?;
    // Preserve HTML auto-escaping (Tera::new enables this for .html by default).
    tera.autoescape_on(vec![".html"]);
    // Expose the crate version to templates as {{ version() }}.
    tera.register_function(
        "version",
        |_args: &std::collections::HashMap<String, tera::Value>| {
            Ok(tera::Value::String(env!("CARGO_PKG_VERSION").to_string()))
        },
    );
    Ok(tera)
}

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

    // Auth: schema, persisted cookie-signing key, and first-run setup flag.
    auth::init_schema(&conn)?;
    let cookie_key = auth::load_or_create_cookie_key(&conn)?;
    let needs_setup = !auth::admin_exists(&conn)?;

    // Build the Tera engine from templates embedded in the binary.
    let tera = load_templates()?;

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
        cookie_key,
        needs_setup: AtomicBool::new(needs_setup),
    });

    // Run syslog ingestion and the web server concurrently; if either fails,
    // propagate the error and shut down.
    tokio::try_join!(syslog::serve(state.clone()), web::serve(state.clone()))?;

    Ok(())
}
