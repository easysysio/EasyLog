// =============================================================================
// sources.rs — log source registry (DuckDB-backed)
//
// A "source" maps a sending host to a log type: a friendly name, the source IP
// (the routing key, matched against the syslog peer address), and the log type
// to parse it as (e.g. "apache"). Sources are stored in DuckDB and managed from
// the web UI (/sources). At startup they are loaded into an in-memory map held
// in AppState so the syslog router can resolve a log type per packet cheaply.
// =============================================================================

use std::collections::HashMap;

use anyhow::{Result, bail};
use duckdb::{Connection, params};
use serde::Serialize;

// A single configured log source. `ip` is unique and used for routing; `name`
// is a human label shown in the UI; `log_type` must match a registered type.
#[derive(Debug, Clone, Serialize)]
pub struct Source {
    pub name: String,
    pub ip: String,
    pub log_type: String,
}

// ─────────────────────────────────────────────────────────────────────────────
// init_schema(conn)
// Creates the `sources` table if absent. `ip` is the primary key so each source
// IP maps to exactly one log type.
// ─────────────────────────────────────────────────────────────────────────────
pub fn init_schema(conn: &Connection) -> Result<()> {
    conn.execute_batch(
        r#"
        CREATE TABLE IF NOT EXISTS sources (
            ip          VARCHAR PRIMARY KEY,
            name        VARCHAR NOT NULL,
            log_type    VARCHAR NOT NULL,
            created_at  TIMESTAMP DEFAULT now()
        );
        "#,
    )?;
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// load_map(conn)
// Loads all sources into a map keyed by IP, used as the in-memory routing table.
// ─────────────────────────────────────────────────────────────────────────────
pub fn load_map(conn: &Connection) -> Result<HashMap<String, Source>> {
    let mut stmt = conn.prepare("SELECT name, ip, log_type FROM sources")?;
    let rows = stmt.query_map([], |row| {
        Ok(Source {
            name: row.get(0)?,
            ip: row.get(1)?,
            log_type: row.get(2)?,
        })
    })?;
    let mut map = HashMap::new();
    for s in rows {
        let s = s?;
        map.insert(s.ip.clone(), s);
    }
    Ok(map)
}

// ─────────────────────────────────────────────────────────────────────────────
// add(conn, name, ip, log_type)
// Inserts a source, or updates name/log_type if the IP already exists. Validates
// that name/ip are non-empty and that the IP parses; the caller validates that
// the log type is registered.
// ─────────────────────────────────────────────────────────────────────────────
pub fn add(conn: &Connection, name: &str, ip: &str, log_type: &str) -> Result<()> {
    let name = name.trim();
    let ip = ip.trim();
    if name.is_empty() {
        bail!("name is required");
    }
    if ip.parse::<std::net::IpAddr>().is_err() {
        bail!("'{ip}' is not a valid IP address");
    }
    conn.execute(
        r#"INSERT INTO sources (ip, name, log_type) VALUES (?, ?, ?)
           ON CONFLICT (ip) DO UPDATE SET name = excluded.name,
                                          log_type = excluded.log_type"#,
        params![ip, name, log_type],
    )?;
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// remove(conn, ip)
// Deletes the source with the given IP, if present.
// ─────────────────────────────────────────────────────────────────────────────
pub fn remove(conn: &Connection, ip: &str) -> Result<()> {
    conn.execute("DELETE FROM sources WHERE ip = ?", params![ip.trim()])?;
    Ok(())
}
