// =============================================================================
// config.rs — EasyLog runtime configuration
//
// Loads server settings from a TOML file (default: config/easylog.toml): the
// syslog listener bind address/port, the web server port, and the DuckDB path.
// Source-host → log-type routing is NOT here — sources are managed in the
// database via the web UI (see src/sources.rs).
// =============================================================================

use anyhow::{Context, Result};
use serde::Deserialize;
use std::path::Path;

// Top-level configuration loaded from TOML. Fields default (see `default_*`)
// so a partial or missing config still yields a runnable server.
#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    /// Address the syslog listeners bind to (UDP + TCP).
    #[serde(default = "default_bind")]
    pub syslog_bind: String,
    /// Syslog port. Standard is 514 (requires privileges to bind <1024).
    #[serde(default = "default_syslog_port")]
    pub syslog_port: u16,
    /// Port the Axum web/dashboard server listens on.
    #[serde(default = "default_web_port")]
    pub web_port: u16,
    /// Path to the DuckDB database file.
    #[serde(default = "default_db_path")]
    pub db_path: String,
}

fn default_bind() -> String {
    "0.0.0.0".to_string()
}
fn default_syslog_port() -> u16 {
    514
}
fn default_web_port() -> u16 {
    3000
}
fn default_db_path() -> String {
    "easylog.duckdb".to_string()
}

impl Default for Config {
    fn default() -> Self {
        Config {
            syslog_bind: default_bind(),
            syslog_port: default_syslog_port(),
            web_port: default_web_port(),
            db_path: default_db_path(),
        }
    }
}

impl Config {
    // ─────────────────────────────────────────────────────────────────────────
    // Config::load(path)
    // Reads and parses the TOML config at `path`. If the file does not exist,
    // returns defaults so the server can still boot for local experimentation.
    // ─────────────────────────────────────────────────────────────────────────
    pub fn load(path: impl AsRef<Path>) -> Result<Config> {
        let path = path.as_ref();
        if !path.exists() {
            tracing::warn!("config {} not found — using defaults", path.display());
            return Ok(Config::default());
        }
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("reading config {}", path.display()))?;
        let cfg: Config =
            toml::from_str(&text).with_context(|| format!("parsing config {}", path.display()))?;
        Ok(cfg)
    }
}
