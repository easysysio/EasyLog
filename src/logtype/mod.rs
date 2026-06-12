// =============================================================================
// logtype/mod.rs — log-type plugin abstraction + registry
//
// Defines the `LogType` trait, the pluggable seam of EasyLog: each supported log
// format (apache, …) implements it to own its DuckDB schema and how a raw line
// is parsed and inserted. The `Registry` holds all known types by name so the
// syslog router can dispatch a message to the right handler.
// =============================================================================

use anyhow::Result;
use chrono::{DateTime, Utc};
use duckdb::Connection;
use std::collections::HashMap;

pub mod apache;

// Envelope metadata extracted from the syslog layer, passed to every parser.
#[derive(Debug, Clone)]
pub struct Meta {
    /// Network peer IP the datagram/connection arrived from.
    pub source_ip: String,
    /// Hostname as reported inside the syslog header, if any. Available to
    /// parsers; not yet consumed by the Apache type.
    #[allow(dead_code)]
    pub hostname: Option<String>,
    /// Time EasyLog received the message.
    pub received_at: DateTime<Utc>,
}

/// A pluggable log type. Implementors own their storage schema and the mapping
/// from a raw log line (the syslog MSG field) into typed DuckDB rows.
pub trait LogType: Send + Sync {
    /// Stable identifier, e.g. "apache". Used as the host-map value and route.
    fn name(&self) -> &'static str;

    /// Create this type's table(s) if they do not already exist.
    fn init_schema(&self, conn: &Connection) -> Result<()>;

    /// Parse `raw` and insert the resulting row(s). Returns Ok(false) when the
    /// line could not be parsed (counted as a drop, not a hard error).
    fn ingest(&self, raw: &str, meta: &Meta, conn: &Connection) -> Result<bool>;
}

/// Holds every known log type keyed by name.
pub struct Registry {
    types: HashMap<&'static str, Box<dyn LogType>>,
}

impl Registry {
    // ─────────────────────────────────────────────────────────────────────────
    // Registry::with_defaults()
    // Builds the registry with all built-in log types registered. Apache is the
    // first; add new types here as they are implemented.
    // ─────────────────────────────────────────────────────────────────────────
    pub fn with_defaults() -> Self {
        let mut types: HashMap<&'static str, Box<dyn LogType>> = HashMap::new();
        let apache = apache::Apache;
        types.insert(apache.name(), Box::new(apache));
        Registry { types }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Registry::get(name)
    // Looks up a registered log type by its name.
    // ─────────────────────────────────────────────────────────────────────────
    pub fn get(&self, name: &str) -> Option<&dyn LogType> {
        self.types.get(name).map(|b| b.as_ref())
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Registry::names()
    // Returns the names of all registered log types (for UI dropdowns, etc.).
    // ─────────────────────────────────────────────────────────────────────────
    pub fn names(&self) -> Vec<&'static str> {
        let mut names: Vec<&'static str> = self.types.keys().copied().collect();
        names.sort_unstable();
        names
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Registry::init_all(conn)
    // Initializes the storage schema for every registered log type at startup.
    // ─────────────────────────────────────────────────────────────────────────
    pub fn init_all(&self, conn: &Connection) -> Result<()> {
        for t in self.types.values() {
            t.init_schema(conn)?;
        }
        Ok(())
    }
}
