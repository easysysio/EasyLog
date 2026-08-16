// =============================================================================
// logtype/panos.rs — Palo Alto Networks (PAN-OS) traffic-log parser
//
// PAN-OS forwards logs as comma-separated values, with the log family in field
// 4 (TYPE) and its shape decided by that value. This parser handles **TRAFFIC**
// logs — the firewall's allow/deny record — and ignores THREAT, SYSTEM, CONFIG
// and the rest, which have different layouts and belong on different dashboards.
//
// The TRAFFIC field order has been stable since PAN-OS 7, with newer releases
// appending fields rather than reordering, so positions are read by index:
//
//    1 FUTURE_USE      2 receive time    3 serial       4 type (TRAFFIC)
//    5 subtype (start/end/drop/deny)     6 FUTURE_USE   7 generated time
//    8 source address  9 destination     10/11 NAT addresses
//   12 rule           13 source user    14 dest user   15 application
//   16 vsys           17 source zone    18 dest zone   19/20 interfaces
//   21 log action     22 FUTURE_USE     23 session id  24 repeat count
//   25 source port    26 dest port      27/28 NAT ports
//   29 flags          30 protocol       31 action      32 bytes
//
// Values may be quoted (rule names and applications often contain commas), so
// the line is split with quote awareness rather than a plain `split(',')`.
// Events normalize into the shared shape in logtype/firewall.rs.
// =============================================================================

use anyhow::Result;
use chrono::NaiveDateTime;
use duckdb::Connection;

use super::firewall::{self, Action, FirewallEvent};
use super::{Category, LogType, Meta};

/// PAN-OS traffic-log handler (zero-sized).
pub struct PanOs;

// Field positions (0-based) within a TRAFFIC record.
const F_TYPE: usize = 3;
const F_SUBTYPE: usize = 4;
const F_GENERATED: usize = 6;
const F_SRC: usize = 7;
const F_DST: usize = 8;
const F_RULE: usize = 11;
const F_APP: usize = 14;
const F_SRC_ZONE: usize = 16;
const F_DST_ZONE: usize = 17;
const F_SRC_PORT: usize = 24;
const F_DST_PORT: usize = 25;
const F_PROTOCOL: usize = 29;
const F_ACTION: usize = 30;
const F_BYTES: usize = 31;

// ─────────────────────────────────────────────────────────────────────────────
// split_csv(line)
// Splits a PAN-OS record on commas, honouring double-quoted values (rule names
// and application names regularly contain commas) and unescaping doubled quotes.
// ─────────────────────────────────────────────────────────────────────────────
fn split_csv(line: &str) -> Vec<String> {
    let mut fields = Vec::new();
    let mut current = String::new();
    let mut in_quotes = false;
    let mut chars = line.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '"' if in_quotes && chars.peek() == Some(&'"') => {
                current.push('"');
                chars.next();
            }
            '"' => in_quotes = !in_quotes,
            ',' if !in_quotes => fields.push(std::mem::take(&mut current)),
            _ => current.push(c),
        }
    }
    fields.push(current);
    fields
}

fn field<'a>(fields: &'a [String], index: usize) -> &'a str {
    fields.get(index).map(|s| s.trim()).unwrap_or("")
}

// PAN-OS spells the outcome several ways; only "allow" lets traffic through.
fn action_of(value: &str) -> Action {
    match value.to_ascii_lowercase().as_str() {
        "allow" => Action::Allow,
        _ => Action::Deny, // deny, drop, reset-client, reset-server, reset-both, block-*
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// parse_line(line)
// Parses one PAN-OS TRAFFIC record into a normalized firewall event, or None for
// any other log family (or a truncated line).
// ─────────────────────────────────────────────────────────────────────────────
pub fn parse_line(line: &str) -> Option<FirewallEvent> {
    let fields = split_csv(line.trim());
    // A TRAFFIC record runs to at least the bytes field; anything shorter is
    // either another family or truncated.
    if fields.len() <= F_BYTES {
        return None;
    }
    if !field(&fields, F_TYPE).eq_ignore_ascii_case("TRAFFIC") {
        return None;
    }
    // Generated time is the firewall's own clock: "2026/08/16 10:00:00".
    let ts = NaiveDateTime::parse_from_str(field(&fields, F_GENERATED), "%Y/%m/%d %H:%M:%S").ok();

    let src_ip = field(&fields, F_SRC).to_string();
    if src_ip.is_empty() {
        return None;
    }

    Some(FirewallEvent {
        ts,
        action: action_of(field(&fields, F_ACTION)),
        protocol: field(&fields, F_PROTOCOL).to_lowercase(),
        src_ip,
        src_port: field(&fields, F_SRC_PORT).parse().ok(),
        dst_ip: field(&fields, F_DST).to_string(),
        dst_port: field(&fields, F_DST_PORT).parse().ok(),
        src_zone: field(&fields, F_SRC_ZONE).to_string(),
        dst_zone: field(&fields, F_DST_ZONE).to_string(),
        rule: field(&fields, F_RULE).to_string(),
        bytes: field(&fields, F_BYTES).parse().ok(),
        // The subtype distinguishes a session end from a drop or a deny.
        event_type: field(&fields, F_SUBTYPE).to_string(),
        application: field(&fields, F_APP).to_string(),
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// parse_event(body, tag)
// Parses a record that has been through a syslog parser. PAN-OS lines have no
// syslog tag, but they *start* with "1,<receive time>", and syslog_loose reads
// that leading token as the APP-NAME and strips it — which would silently shift
// every field. When the body alone doesn't parse, the tag is put back and the
// line retried.
// ─────────────────────────────────────────────────────────────────────────────
pub fn parse_event(body: &str, tag: Option<&str>) -> Option<FirewallEvent> {
    if let Some(event) = parse_line(body) {
        return Some(event);
    }
    parse_line(&format!("{} {}", tag?, body))
}

impl LogType for PanOs {
    fn name(&self) -> &'static str {
        "panos"
    }

    fn category(&self) -> Category {
        Category::Firewall
    }

    fn label(&self) -> &'static str {
        "Palo Alto"
    }

    fn icon(&self) -> &'static str {
        "bi-fire"
    }

    fn init_schema(&self, conn: &Connection) -> Result<()> {
        firewall::init_schema(conn, "panos")
    }

    fn ingest(&self, raw: &str, meta: &Meta, conn: &Connection) -> Result<bool> {
        let Some(event) = parse_event(raw, meta.tag.as_deref()) else {
            return Ok(false);
        };
        firewall::insert(conn, "panos", &event, meta, raw)?;
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // A realistic TRAFFIC record (PAN-OS 9/10 field order).
    const TRAFFIC: &str = "1,2026/08/16 10:00:05,001801234567,TRAFFIC,end,2561,2026/08/16 10:00:00,203.0.113.9,10.0.0.5,0.0.0.0,0.0.0.0,allow-web,,,web-browsing,vsys1,untrust,trust,ethernet1/1,ethernet1/2,log-forwarding,2026/08/16 10:00:04,12345,1,45678,443,0,0,0x19,tcp,allow,98765,1234,97531,12,2026/08/16 09:59:30,15,any,0,0,0,0,,fw01,from-policy";

    #[test]
    fn parses_a_traffic_record() {
        let e = parse_line(TRAFFIC).expect("should parse");
        assert_eq!(e.action, Action::Allow);
        assert_eq!(e.src_ip, "203.0.113.9");
        assert_eq!(e.dst_ip, "10.0.0.5");
        assert_eq!(e.src_port, Some(45678));
        assert_eq!(e.dst_port, Some(443));
        assert_eq!(e.protocol, "tcp");
        assert_eq!(e.rule, "allow-web");
        assert_eq!(e.application, "web-browsing");
        assert_eq!(e.src_zone, "untrust");
        assert_eq!(e.dst_zone, "trust");
        assert_eq!(e.bytes, Some(98765));
        assert_eq!(e.event_type, "end");
        assert_eq!(e.ts.map(|t| t.to_string()), Some("2026-08-16 10:00:00".to_string()));
    }

    #[test]
    fn treats_every_blocking_verdict_as_a_deny() {
        for verdict in ["deny", "drop", "reset-both", "reset-client", "block-url"] {
            let line = TRAFFIC.replacen(",allow,", &format!(",{verdict},"), 1);
            let e = parse_line(&line).expect("should parse");
            assert_eq!(e.action, Action::Deny, "verdict {verdict} should deny");
        }
        // …and only "allow" lets it through.
        assert_eq!(parse_line(TRAFFIC).unwrap().action, Action::Allow);
    }

    #[test]
    fn handles_quoted_values_containing_commas() {
        // Rule names with commas are common and would break a naive split.
        let line = TRAFFIC.replacen("allow-web", r#""allow web, dns and mail""#, 1);
        let e = parse_line(&line).expect("should parse");
        assert_eq!(e.rule, "allow web, dns and mail");
        assert_eq!(e.dst_port, Some(443), "later fields must not shift");
    }

    #[test]
    fn ignores_other_log_families_and_short_lines() {
        let threat = TRAFFIC.replacen(",TRAFFIC,", ",THREAT,", 1);
        assert!(parse_line(&threat).is_none());
        let system = "1,2026/08/16 10:00:05,001801234567,SYSTEM,general,0,2026/08/16 10:00:00,,,,,,,,,,,,,,";
        assert!(parse_line(system).is_none());
        assert!(parse_line("not,a,pan,os,line").is_none());
        assert!(parse_line("").is_none());
    }

    #[test]
    fn rejoins_a_record_split_by_the_syslog_tag_parser() {
        // syslog_loose reads the leading "1,<receive time>" token as the
        // APP-NAME, leaving the body starting mid-timestamp.
        let (tag, rest) = TRAFFIC.split_once(' ').unwrap();
        assert!(parse_line(rest).is_none(), "the split body must not parse as-is");
        let e = parse_event(rest, Some(tag)).expect("should parse once rejoined");
        assert_eq!(e.src_ip, "203.0.113.9");
        assert_eq!(e.dst_port, Some(443), "fields must not be shifted");
        assert_eq!(e.application, "web-browsing");
    }

    #[test]
    fn ingests_into_the_table() {
        use crate::logtype::Registry;
        use chrono::Utc;

        let conn = Connection::open_in_memory().unwrap();
        Registry::with_defaults().init_all(&conn).unwrap();
        let meta = Meta {
            source_ip: "192.168.1.2".into(),
            hostname: None,
            tag: None,
            received_at: Utc::now(),
        };
        assert!(PanOs.ingest(TRAFFIC, &meta, &conn).unwrap());

        let (action, src, app, bytes): (String, String, String, i64) = conn
            .prepare("SELECT action, src_ip, application, bytes FROM panos")
            .unwrap()
            .query_row([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))
            .unwrap();
        assert_eq!(action, "allow");
        assert_eq!(src, "203.0.113.9");
        assert_eq!(app, "web-browsing");
        assert_eq!(bytes, 98765);
    }
}
