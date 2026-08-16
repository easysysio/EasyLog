// =============================================================================
// logtype/mod.rs — log-type plugin abstraction + registry
//
// Defines the `LogType` trait, the pluggable seam of EasyLog: each supported log
// format (apache, …) implements it to own its DuckDB schema and how a raw line
// is parsed and inserted. The `Registry` holds all known types by name so the
// syslog router can dispatch a message to the right handler.
//
// A type also declares how it presents itself: which `Category` it belongs to
// (web servers, firewalls, …), its display label and icon. The navigation is
// built from that metadata (see `Registry::nav`), so adding a log type never
// means editing templates.
// =============================================================================

use anyhow::Result;
use chrono::{DateTime, Utc};
use duckdb::Connection;
use serde::Serialize;
use std::collections::HashMap;

pub mod apache;
pub mod caddy;
pub mod cisco_asa;
pub mod firewall;
pub mod haproxy;
pub mod nginx;
pub mod traefik;

// Envelope metadata extracted from the syslog layer, passed to every parser.
#[derive(Debug, Clone)]
pub struct Meta {
    /// Network peer IP the datagram/connection arrived from.
    pub source_ip: String,
    /// Hostname as reported inside the syslog header, if any. Available to
    /// parsers; not yet consumed by the Apache type.
    #[allow(dead_code)]
    pub hostname: Option<String>,
    /// Syslog tag / APP-NAME, e.g. "apache" or "%ASA-4-106023". Cisco puts the
    /// message ID here, and syslog_loose strips it from the body, so parsers
    /// that need it read it from the envelope.
    pub tag: Option<String>,
    /// Time EasyLog received the message.
    pub received_at: DateTime<Utc>,
}

/// Where a log type sits in the navigation. Dashboards are grouped by category
/// so the type list stays navigable as formats are added; the order here is the
/// order the categories appear in the UI.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Category {
    Web,
    Firewall,
    ThirdParty,
}

impl Category {
    /// Every category, in display order. A category with no registered types is
    /// skipped when the navigation is built, so this can list planned ones.
    pub const ALL: [Category; 3] = [Category::Web, Category::Firewall, Category::ThirdParty];

    /// URL segment, e.g. "web" in /web/apache.
    pub fn slug(self) -> &'static str {
        match self {
            Category::Web => "web",
            Category::Firewall => "firewall",
            Category::ThirdParty => "third-party",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Category::Web => "Web",
            Category::Firewall => "Firewalls",
            Category::ThirdParty => "3rd parties",
        }
    }

    pub fn icon(self) -> &'static str {
        match self {
            Category::Web => "bi-globe2",
            Category::Firewall => "bi-shield-lock",
            Category::ThirdParty => "bi-puzzle",
        }
    }
}

/// One dashboard entry in the second navigation row.
#[derive(Debug, Clone, Serialize)]
pub struct NavType {
    pub slug: &'static str,
    pub label: &'static str,
    pub icon: &'static str,
    pub href: String,
}

/// One category in the first navigation row, with the dashboards it holds.
#[derive(Debug, Clone, Serialize)]
pub struct NavCategory {
    pub slug: &'static str,
    pub label: &'static str,
    pub icon: &'static str,
    pub types: Vec<NavType>,
}

/// A pluggable log type. Implementors own their storage schema and the mapping
/// from a raw log line (the syslog MSG field) into typed DuckDB rows.
pub trait LogType: Send + Sync {
    /// Stable identifier, e.g. "apache". Used as the host-map value, the table
    /// name, and the last segment of the dashboard route.
    fn name(&self) -> &'static str;

    /// Navigation group this type belongs to.
    fn category(&self) -> Category;

    /// Display name for the UI, e.g. "Cisco ASA" for the `cisco_asa` type.
    fn label(&self) -> &'static str;

    /// Bootstrap icon class for the navigation entry.
    fn icon(&self) -> &'static str;

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
        let traefik = traefik::Traefik;
        types.insert(traefik.name(), Box::new(traefik));
        let nginx = nginx::Nginx;
        types.insert(nginx.name(), Box::new(nginx));
        let caddy = caddy::Caddy;
        types.insert(caddy.name(), Box::new(caddy));
        let haproxy = haproxy::HAProxy;
        types.insert(haproxy.name(), Box::new(haproxy));
        let cisco_asa = cisco_asa::CiscoAsa;
        types.insert(cisco_asa.name(), Box::new(cisco_asa));
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
    // Registry::nav()
    // Builds the two-row navigation model: every category that has at least one
    // registered type, each holding its dashboards sorted by label. Computed
    // once at startup and handed to the templates, so the navbar is data — not
    // markup that has to be edited for every new format.
    // ─────────────────────────────────────────────────────────────────────────
    pub fn nav(&self) -> Vec<NavCategory> {
        let mut nav = Vec::new();
        for category in Category::ALL {
            let mut types: Vec<NavType> = self
                .types
                .values()
                .filter(|t| t.category() == category)
                .map(|t| NavType {
                    slug: t.name(),
                    label: t.label(),
                    icon: t.icon(),
                    href: format!("/{}/{}", category.slug(), t.name()),
                })
                .collect();
            if types.is_empty() {
                continue;
            }
            types.sort_by_key(|t| t.label);
            nav.push(NavCategory {
                slug: category.slug(),
                label: category.label(),
                icon: category.icon(),
                types,
            });
        }
        nav
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
