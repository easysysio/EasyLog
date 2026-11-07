// =============================================================================
// main.rs — EasyLog entry point
//
// Boots the EasyLog multi-log analyzer: loads config, opens DuckDB, initializes
// each log type's schema and the source registry, loads sources into memory,
// builds the Tera engine from templates embedded in the binary, then runs the
// syslog listeners (UDP + TCP) and the Axum web server over shared state. The
// web templates and static assets are compiled in, so EasyLog runs as a single
// self-contained binary with nothing to install alongside it.
//
// The only command-line arguments are --help and --version; settings come from
// the config file named by EASYLOG_CONFIG.
// =============================================================================

mod auth;
mod config;
mod geo;
mod logging;
mod logtype;
mod retention;
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

// What --help prints. EasyLog takes no other arguments: everything is in the
// config file.
const USAGE: &str = "\
Usage: easylog [--help | --version]

EasyLog collects syslog and serves a dashboard per log type. It takes no other
arguments: settings live in a TOML config file, read from the path in the
EASYLOG_CONFIG environment variable (default: config/easylog.toml). The
packaged service uses /etc/easylog/easylog.toml.

  -h, --help       print this help and exit
  -V, --version    print the version and exit";

/// What the command line asks for.
#[derive(Debug, PartialEq, Eq)]
enum Cli {
    Run,
    Help,
    Version,
    Unknown(String),
}

// ─────────────────────────────────────────────────────────────────────────────
// parse_args(args)
// Reads the command line (without the program name). No argument runs the
// server; anything unrecognized is reported rather than ignored, so a mistyped
// flag can't quietly start a second instance.
// ─────────────────────────────────────────────────────────────────────────────
fn parse_args(mut args: impl Iterator<Item = String>) -> Cli {
    match args.next().as_deref() {
        None => Cli::Run,
        Some("-h" | "--help") => Cli::Help,
        Some("-V" | "--version") => Cli::Version,
        Some(other) => Cli::Unknown(other.to_string()),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// load_templates()
// Builds the Tera engine from templates compiled into the binary (include_str!),
// so EasyLog needs no templates/ directory on disk at runtime.
// ─────────────────────────────────────────────────────────────────────────────
fn load_templates() -> Result<Tera> {
    let mut tera = Tera::default();
    tera.add_raw_templates(vec![
        ("base.html", include_str!("../templates/base.html")),
        ("_worldmap.html", include_str!("../templates/_worldmap.html")),
        ("index.html", include_str!("../templates/index.html")),
        ("sources.html", include_str!("../templates/sources.html")),
        ("apache.html", include_str!("../templates/apache.html")),
        ("proxy.html", include_str!("../templates/proxy.html")),
        ("firewall.html", include_str!("../templates/firewall.html")),
        ("unifi_threats.html", include_str!("../templates/unifi_threats.html")),
        ("easywaf.html", include_str!("../templates/easywaf.html")),
        ("linux.html", include_str!("../templates/linux.html")),
        ("general.html", include_str!("../templates/general.html")),
        ("raw.html", include_str!("../templates/raw.html")),
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
    match parse_args(std::env::args().skip(1)) {
        Cli::Run => {}
        Cli::Help => {
            println!("{USAGE}");
            return Ok(());
        }
        Cli::Version => {
            println!("easylog {}", env!("CARGO_PKG_VERSION"));
            return Ok(());
        }
        Cli::Unknown(arg) => {
            eprintln!("easylog: unknown argument '{arg}'\n\n{USAGE}");
            std::process::exit(2);
        }
    }

    // The config decides where logs go, so it is read before the subscriber is
    // installed; anything that goes wrong here is reported by the returned error.
    let config_path = std::env::var("EASYLOG_CONFIG").unwrap_or_else(|_| DEFAULT_CONFIG.to_string());
    let config = Config::load(&config_path)?;
    // Held for the life of the process: dropping it stops the file writers.
    let _log_guards = logging::init(&config);
    tracing::info!("EasyLog v{} starting (config {config_path})", env!("CARGO_PKG_VERSION"));

    // Load the IP geolocation database (bundled DB-IP Lite, or an external mmdb).
    geo::init(&config.geo_db_path);

    // Open storage and initialize schemas: one table per log type, plus sources.
    let registry = Registry::with_defaults();
    let conn = storage::open(&config.db_path, &config.duckdb_memory_limit, config.duckdb_threads)?;
    registry.init_all(&conn)?;

    // Apply retention and reclaim disk before anything can write: pruning here
    // means a restart always enforces the configured window, and compaction is
    // only safe while there are no concurrent writers.
    if let Err(e) = retention::prune(&conn, &registry, config.retention_days) {
        tracing::warn!("retention: startup prune failed: {e:#}");
    }
    let conn = retention::compact_if_needed(conn, &config)?;
    sources::init_schema(&conn)?;
    let source_map: HashMap<String, sources::Source> = sources::load_map(&conn)?;

    // Auth: schema, persisted cookie-signing key, and first-run setup flag.
    auth::init_schema(&conn)?;
    let cookie_key = auth::load_or_create_cookie_key(&conn)?;
    let needs_setup = !auth::admin_exists(&conn)?;

    // Build the Tera engine from templates embedded in the binary.
    let tera = load_templates()?;

    tracing::info!(
        "config: syslog {}:{} (udp+tcp), web :{}, db {}, duckdb mem {}, {} source(s)",
        config.syslog_bind,
        config.syslog_port,
        config.web_port,
        config.db_path,
        config.duckdb_memory_limit,
        source_map.len(),
    );

    let nav = registry.nav();
    let state = Arc::new(AppState {
        config,
        registry,
        nav,
        db: Mutex::new(conn),
        sources: RwLock::new(source_map),
        tera,
        cookie_key,
        needs_setup: AtomicBool::new(needs_setup),
    });

    // Run syslog ingestion, the web server and the retention sweep concurrently;
    // if any of them fails, propagate the error and shut down.
    tokio::try_join!(
        syslog::serve(state.clone()),
        web::serve(state.clone()),
        retention::serve(state.clone())
    )?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cli(args: &[&str]) -> Cli {
        parse_args(args.iter().map(|a| a.to_string()))
    }

    #[test]
    fn reads_the_command_line() {
        assert_eq!(cli(&[]), Cli::Run);
        assert_eq!(cli(&["--help"]), Cli::Help);
        assert_eq!(cli(&["-h"]), Cli::Help);
        assert_eq!(cli(&["--version"]), Cli::Version);
        assert_eq!(cli(&["-V"]), Cli::Version);
        assert_eq!(cli(&["--port"]), Cli::Unknown("--port".into()));
        assert_eq!(cli(&["serve"]), Cli::Unknown("serve".into()));
    }
}
