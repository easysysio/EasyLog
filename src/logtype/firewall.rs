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
//
// A device's own timestamp is trusted only when it agrees with the arrival time
// to within MAX_CLOCK_SKEW. ASA and PAN-OS stamp their *local* time with no
// zone, and any device can have a wrong clock; either would put events hours
// off on the timeline, so those fall back to when EasyLog received the line.
// =============================================================================

use anyhow::Result;
use chrono::{Duration, NaiveDateTime};
use duckdb::{Connection, params};

use super::Meta;

/// How far a device's timestamp may be from the arrival time and still be used.
/// Syslog arrives within seconds; anything further off is a wrong clock or a
/// local time with no zone.
const MAX_CLOCK_SKEW: Duration = Duration::minutes(10);

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
        -- Columns added after a table may already exist in the field: CREATE
        -- TABLE IF NOT EXISTS won't add them, so each one is applied explicitly.
        ALTER TABLE {table} ADD COLUMN IF NOT EXISTS application VARCHAR;
        "#
    ))?;
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// event_time(device, received)
// The time to file an event under: the device's own timestamp when it is within
// MAX_CLOCK_SKEW of the arrival time (it is the more precise of the two),
// otherwise the arrival time.
// ─────────────────────────────────────────────────────────────────────────────
pub(crate) fn event_time(device: Option<NaiveDateTime>, received: NaiveDateTime) -> NaiveDateTime {
    match device {
        Some(ts) if (ts - received).abs() <= MAX_CLOCK_SKEW => ts,
        _ => received,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// insert(conn, table, event, meta, raw)
// Stores one parsed event, resolving the source address to a country as it goes.
// Files it under the device's time when that is trustworthy, else the arrival
// time (see event_time).
// ─────────────────────────────────────────────────────────────────────────────
pub fn insert(
    conn: &Connection,
    table: &str,
    event: &FirewallEvent,
    meta: &Meta,
    raw: &str,
) -> Result<()> {
    let (country_code, country) = crate::geo::lookup(&event.src_ip);
    let ts = event_time(event.ts, meta.received_at.naive_utc());
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

#[cfg(test)]
mod tests {
    use super::*;

    fn at(s: &str) -> NaiveDateTime {
        NaiveDateTime::parse_from_str(s, "%Y-%m-%d %H:%M:%S%.f").unwrap()
    }

    #[test]
    fn trusts_a_device_clock_only_when_it_agrees() {
        let received = at("2026-11-07 09:00:00.0");
        // A few seconds early or late: the device's own, more precise, time.
        assert_eq!(event_time(Some(at("2026-11-07 08:59:58.4")), received), at("2026-11-07 08:59:58.4"));
        assert_eq!(event_time(Some(at("2026-11-07 09:09:59.0")), received), at("2026-11-07 09:09:59.0"));
        // A local time two hours ahead of UTC, or a clock far off: arrival time.
        assert_eq!(event_time(Some(at("2026-11-07 11:00:00.0")), received), received);
        assert_eq!(event_time(Some(at("2025-01-01 00:00:00.0")), received), received);
        // No timestamp at all.
        assert_eq!(event_time(None, received), received);
    }
}
