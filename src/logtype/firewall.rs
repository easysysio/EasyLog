// =============================================================================
// logtype/firewall.rs — shared storage for firewall log types
//
// Firewall vendors log wildly different syntax but the same facts: a connection
// or packet, from somewhere to somewhere, permitted or denied, by some rule.
// This module owns that common shape — the table schema and the insert — so each
// vendor module is only a parser producing a `FirewallEvent`, and every firewall
// dashboard can be rendered by the same code (see web/firewall.rs).
//
// Geolocation is resolved on the **source** address: on a firewall the question
// is where traffic is coming from.
// =============================================================================

use anyhow::Result;
use chrono::NaiveDateTime;
use duckdb::{Connection, params};

use super::Meta;

/// Normalized outcome. Vendors spell this many ways ("Deny", "denied", "drop",
/// "reset-both"); dashboards only care whether the traffic got through.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    Allow,
    Deny,
}

impl Action {
    pub fn as_str(self) -> &'static str {
        match self {
            Action::Allow => "allow",
            Action::Deny => "deny",
        }
    }
}

/// One firewall event, as every supported vendor is normalized into.
#[derive(Debug, Clone, PartialEq)]
pub struct FirewallEvent {
    /// Event time from the log line; None falls back to arrival time.
    pub ts: Option<NaiveDateTime>,
    pub action: Action,
    /// Lowercased transport: tcp, udp, icmp, …
    pub protocol: String,
    pub src_ip: String,
    pub src_port: Option<i32>,
    pub dst_ip: String,
    pub dst_port: Option<i32>,
    /// Interface (ASA) or zone (PAN-OS) the traffic came from / went to.
    pub src_zone: String,
    pub dst_zone: String,
    /// ACL, policy or rule name that made the decision.
    pub rule: String,
    pub bytes: Option<i64>,
    /// Vendor message identity — an ASA message ID, a PAN-OS subtype — so a
    /// dashboard can distinguish "connection built" from "packet denied".
    pub event_type: String,
    /// Layer-7 application, where the vendor identifies one (PAN-OS App-ID).
    /// Empty for firewalls that only see ports.
    pub application: String,
}

// ─────────────────────────────────────────────────────────────────────────────
// init_schema(conn, table)
// Creates a vendor's firewall table. Every firewall type shares these columns,
// which is what lets one dashboard serve all of them.
// ─────────────────────────────────────────────────────────────────────────────
pub fn init_schema(conn: &Connection, table: &str) -> Result<()> {
    conn.execute_batch(&format!(
        r#"
        CREATE TABLE IF NOT EXISTS {table} (
            source_ip    VARCHAR,
            ts           TIMESTAMP,
            action       VARCHAR,
            protocol     VARCHAR,
            src_ip       VARCHAR,
            src_port     INTEGER,
            dst_ip       VARCHAR,
            dst_port     INTEGER,
            src_zone     VARCHAR,
            dst_zone     VARCHAR,
            rule         VARCHAR,
            bytes        BIGINT,
            event_type   VARCHAR,
            application  VARCHAR,
            country      VARCHAR,
            country_code VARCHAR,
            received_at  TIMESTAMP,
            raw          VARCHAR
        );
        "#
    ))?;
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// insert(conn, table, event, meta, raw)
// Stores one parsed event, resolving the source address to a country as it goes.
// Falls back to the arrival time when the line carried no usable timestamp.
// ─────────────────────────────────────────────────────────────────────────────
pub fn insert(
    conn: &Connection,
    table: &str,
    event: &FirewallEvent,
    meta: &Meta,
    raw: &str,
) -> Result<()> {
    let (country_code, country) = crate::geo::lookup(&event.src_ip);
    let ts = event.ts.unwrap_or_else(|| meta.received_at.naive_utc());
    conn.execute(
        &format!(
            r#"INSERT INTO {table}
               (source_ip, ts, action, protocol, src_ip, src_port, dst_ip, dst_port,
                src_zone, dst_zone, rule, bytes, event_type, application, country,
                country_code, received_at, raw)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)"#
        ),
        params![
            meta.source_ip,
            ts,
            event.action.as_str(),
            event.protocol,
            event.src_ip,
            event.src_port,
            event.dst_ip,
            event.dst_port,
            event.src_zone,
            event.dst_zone,
            event.rule,
            event.bytes,
            event.event_type,
            event.application,
            country,
            country_code,
            meta.received_at.naive_utc(),
            raw,
        ],
    )?;
    Ok(())
}
