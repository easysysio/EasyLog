// =============================================================================
// state.rs — shared application state
//
// Bundles the loaded config, the log-type registry, the DuckDB connection (under
// a mutex), the in-memory source routing map (under an RwLock), and the Tera
// template engine into a single `AppState`, shared as an Arc across the syslog
// listeners and the Axum web server.
// =============================================================================

use std::collections::HashMap;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex, RwLock};

use axum::extract::FromRef;
use axum_extra::extract::cookie::Key;
use duckdb::Connection;
use tera::Tera;

use crate::config::Config;
use crate::logtype::Registry;
use crate::sources::{self, Source};

// Process-wide shared state. The DuckDB connection is guarded by a std Mutex;
// the source map by an RwLock (read on every packet, written on UI edits).
// Neither lock is ever held across an await point.
pub struct AppState {
    pub config: Config,
    pub registry: Registry,
    pub db: Mutex<Connection>,
    pub sources: RwLock<HashMap<String, Source>>,
    pub tera: Tera,
    /// Signing key for session cookies (persisted; see auth.rs).
    pub cookie_key: Key,
    /// True until the admin account is created (first-run setup).
    pub needs_setup: AtomicBool,
}

// Router state: a local wrapper around the shared AppState. It exists so the
// SignedCookieJar extractor can pull the cookie key via FromRef — the orphan
// rule forbids implementing the foreign FromRef/Key pair against Arc<AppState>
// directly, but a FromRef whose generic arg is our local WebState is allowed.
#[derive(Clone)]
pub struct WebState(pub Arc<AppState>);

impl FromRef<WebState> for Arc<AppState> {
    fn from_ref(s: &WebState) -> Self {
        s.0.clone()
    }
}

impl FromRef<WebState> for Key {
    fn from_ref(s: &WebState) -> Self {
        s.0.cookie_key.clone()
    }
}

impl AppState {
    // ─────────────────────────────────────────────────────────────────────────
    // AppState::reload_sources()
    // Rebuilds the in-memory source routing map from DuckDB. Called after every
    // add/remove so the syslog router sees changes immediately.
    // ─────────────────────────────────────────────────────────────────────────
    pub fn reload_sources(&self) -> anyhow::Result<()> {
        let map = {
            let conn = self.db.lock().expect("db mutex poisoned");
            sources::load_map(&conn)?
        };
        *self.sources.write().expect("sources lock poisoned") = map;
        Ok(())
    }
}
