// =============================================================================
// state.rs — shared application state
//
// Bundles the loaded config, the log-type registry, and the DuckDB connection
// (behind a mutex) into a single `AppState`, shared as an Arc across the syslog
// listeners and the Axum web server.
// =============================================================================

use duckdb::Connection;
use std::sync::Mutex;

use crate::config::Config;
use crate::logtype::Registry;

// Process-wide shared state. The DuckDB connection is guarded by a std Mutex;
// critical sections are short and never held across an await point.
pub struct AppState {
    pub config: Config,
    pub registry: Registry,
    pub db: Mutex<Connection>,
}
