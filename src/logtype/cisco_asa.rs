// =============================================================================
// logtype/cisco_asa.rs — Cisco ASA syslog parser
//
// The ASA emits one syslog message per event, identified by a message ID in a
// "%ASA-<level>-<id>:" tag. Each ID has its own sentence structure, so this
// parser handles the IDs that carry connection and access decisions — the ones a
// firewall dashboard is built from:
//
//   106023  Deny tcp src outside:1.2.3.4/45678 dst inside:10.0.0.5/443
//             by access-group "outside_access_in"
//   106100  access-list acl_in permitted tcp outside/1.2.3.4(45678)
//             -> inside/10.0.0.5(443) hit-cnt 1
//   106001  Inbound TCP connection denied from 1.2.3.4/45678 to 10.0.0.5/443
//             flags SYN on interface outside
//   302013  Built inbound TCP connection 1234 for outside:1.2.3.4/45678
//             (…) to inside:10.0.0.5/443 (…)
//   302014  Teardown TCP connection 1234 for outside:1.2.3.4/45678 to
//             inside:10.0.0.5/443 duration 0:00:30 bytes 1234 TCP FINs
//   302015 / 302016  the UDP equivalents of 302013 / 302014
//
// Everything else the ASA logs (VPN, failover, NAT, chatter) is ignored rather
// than stored as half-parsed rows. Events normalize into the shared shape in
// logtype/firewall.rs, so the firewall dashboard renders them unchanged.
// =============================================================================

use anyhow::Result;
use chrono::NaiveDateTime;
use duckdb::Connection;
use regex::Regex;
use std::sync::OnceLock;

use super::firewall::{self, Action, FirewallEvent};
use super::{Category, LogType, Meta};

/// Cisco ASA syslog handler (zero-sized).
pub struct CiscoAsa;

// Message-ID tag plus the timestamp the ASA optionally prefixes it with.
fn tag_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?:(?P<ts>[A-Z][a-z]{2} +\d{1,2} +\d{4} +\d{2}:\d{2}:\d{2})[^%]*)?%(?:ASA|FTD|PIX)-\d-(?P<id>\d{6}):\s*(?P<body>.*)$")
            .expect("asa tag regex is valid")
    })
}

// 106023: Deny tcp src outside:1.2.3.4/45678 dst inside:10.0.0.5/443 by access-group "acl"
fn deny_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r#"(?x)
            ^Deny\s+(?P<proto>\S+)\s+src\s+
            (?P<szone>[^:]+):(?P<sip>[^/\s]+)(?:/(?P<sport>\d+))?\s+
            dst\s+(?P<dzone>[^:]+):(?P<dip>[^/\s]+)(?:/(?P<dport>\d+))?
            (?:\s+.*?by\s+access-group\s+"?(?P<rule>[^"\s\]]+)"?)?
            "#,
        )
        .expect("asa 106023 regex is valid")
    })
}

// 106100: access-list acl permitted|denied tcp outside/1.2.3.4(45678) -> inside/10.0.0.5(443)
fn acl_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r#"(?x)
            ^access-list\s+(?P<rule>\S+)\s+(?P<verdict>permitted|denied)\s+(?P<proto>\S+)\s+
            (?P<szone>[^/\s]+)/(?P<sip>[^\s(]+)\((?P<sport>\d+)\)\s*->\s*
            (?P<dzone>[^/\s]+)/(?P<dip>[^\s(]+)\((?P<dport>\d+)\)
            "#,
        )
        .expect("asa 106100 regex is valid")
    })
}

// 302013/302015: Built … connection 1234 for outside:1.2.3.4/45678 (…) to inside:10.0.0.5/443
// 302014/302016: Teardown … connection 1234 for outside:… to inside:… bytes 1234
fn conn_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r#"(?x)
            ^(?P<verb>Built|Teardown)\s+(?:\S+\s+)?(?P<proto>TCP|UDP|ICMP)\s+connection\s+\S+\s+
            for\s+(?P<szone>[^:]+):(?P<sip>[^/\s]+)/(?P<sport>\d+)
            (?:\s+\([^)]*\))?\s+to\s+
            (?P<dzone>[^:]+):(?P<dip>[^/\s]+)/(?P<dport>\d+)
            (?:.*?\bbytes\s+(?P<bytes>\d+))?
            "#,
        )
        .expect("asa 302xxx regex is valid")
    })
}

// 106001: Inbound TCP connection denied from 1.2.3.4/45678 to 10.0.0.5/443 flags … on interface outside
fn inbound_deny_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r#"(?x)
            ^(?P<dir>Inbound|Outbound)\s+(?P<proto>\S+)\s+connection\s+denied\s+
            from\s+(?P<sip>[^/\s]+)/(?P<sport>\d+)\s+
            to\s+(?P<dip>[^/\s]+)/(?P<dport>\d+)
            (?:.*?\bon\s+interface\s+(?P<zone>\S+))?
            "#,
        )
        .expect("asa 106001 regex is valid")
    })
}

fn port(caps: &regex::Captures, name: &str) -> Option<i32> {
    caps.name(name).and_then(|m| m.as_str().parse().ok())
}

fn text(caps: &regex::Captures, name: &str) -> String {
    caps.name(name).map(|m| m.as_str().to_string()).unwrap_or_default()
}

// ─────────────────────────────────────────────────────────────────────────────
// parse_line(line)
// Parses a full ASA message — one that still carries its "%ASA-x-nnnnnn:" tag.
// Ingestion goes through parse_event, which also accepts the ID from the syslog
// envelope; this is the whole-line form, used by the tests.
// ─────────────────────────────────────────────────────────────────────────────
#[cfg(test)]
pub fn parse_line(line: &str) -> Option<FirewallEvent> {
    parse_event(line, None)
}

// Extracts the six-digit message ID from a "%ASA-4-106023" style tag.
fn id_from_tag(tag: &str) -> Option<String> {
    let id = tag.trim().trim_end_matches(':').rsplit('-').next()?;
    (id.len() == 6 && id.chars().all(|c| c.is_ascii_digit())).then(|| id.to_string())
}

// ─────────────────────────────────────────────────────────────────────────────
// parse_event(body, tag)
// Parses one ASA message into a normalized firewall event, or None when it isn't
// one of the connection/access IDs we report on.
//
// The message ID may arrive two ways: inline in the body, or — because
// syslog_loose reads "%ASA-4-106023:" as the syslog APP-NAME and strips it —
// in the envelope tag. Both are accepted, inline first.
// ─────────────────────────────────────────────────────────────────────────────
pub fn parse_event(body: &str, tag: Option<&str>) -> Option<FirewallEvent> {
    let line = body.trim();
    let (id, body, ts) = match tag_regex().captures(line) {
        Some(c) => {
            // The ASA's own timestamp, when it was configured to include one.
            let ts = c
                .name("ts")
                .and_then(|m| NaiveDateTime::parse_from_str(m.as_str().trim(), "%b %e %Y %H:%M:%S").ok());
            (c["id"].to_string(), c["body"].trim().to_string(), ts)
        }
        None => (id_from_tag(tag?)?, line.to_string(), None),
    };
    let body = body.as_str();

    let event = match id.as_str() {
        "106023" => {
            let c = deny_regex().captures(body)?;
            FirewallEvent {
                ts,
                action: Action::Deny,
                protocol: c["proto"].to_lowercase(),
                src_ip: c["sip"].to_string(),
                src_port: port(&c, "sport"),
                dst_ip: c["dip"].to_string(),
                dst_port: port(&c, "dport"),
                src_zone: text(&c, "szone"),
                dst_zone: text(&c, "dzone"),
                rule: text(&c, "rule"),
                bytes: None,
                event_type: id,
                application: String::new(),
            }
        }
        "106100" => {
            let c = acl_regex().captures(body)?;
            FirewallEvent {
                ts,
                action: if &c["verdict"] == "permitted" { Action::Allow } else { Action::Deny },
                protocol: c["proto"].to_lowercase(),
                src_ip: c["sip"].to_string(),
                src_port: port(&c, "sport"),
                dst_ip: c["dip"].to_string(),
                dst_port: port(&c, "dport"),
                src_zone: text(&c, "szone"),
                dst_zone: text(&c, "dzone"),
                rule: text(&c, "rule"),
                bytes: None,
                event_type: id,
                application: String::new(),
            }
        }
        "302013" | "302014" | "302015" | "302016" => {
            let c = conn_regex().captures(body)?;
            FirewallEvent {
                ts,
                // A built or torn-down connection is traffic that was allowed.
                action: Action::Allow,
                protocol: c["proto"].to_lowercase(),
                src_ip: c["sip"].to_string(),
                src_port: port(&c, "sport"),
                dst_ip: c["dip"].to_string(),
                dst_port: port(&c, "dport"),
                src_zone: text(&c, "szone"),
                dst_zone: text(&c, "dzone"),
                rule: String::new(),
                bytes: c.name("bytes").and_then(|m| m.as_str().parse().ok()),
                event_type: id,
                application: String::new(),
            }
        }
        "106001" => {
            let c = inbound_deny_regex().captures(body)?;
            FirewallEvent {
                ts,
                action: Action::Deny,
                protocol: c["proto"].to_lowercase(),
                src_ip: c["sip"].to_string(),
                src_port: port(&c, "sport"),
                dst_ip: c["dip"].to_string(),
                dst_port: port(&c, "dport"),
                src_zone: text(&c, "zone"),
                dst_zone: String::new(),
                rule: String::new(),
                bytes: None,
                event_type: id,
                application: String::new(),
            }
        }
        _ => return None,
    };
    Some(event)
}

impl LogType for CiscoAsa {
    fn name(&self) -> &'static str {
        "cisco_asa"
    }

    fn category(&self) -> Category {
        Category::Firewall
    }

    fn label(&self) -> &'static str {
        "Cisco ASA"
    }

    fn icon(&self) -> &'static str {
        "bi-bricks"
    }

    fn init_schema(&self, conn: &Connection) -> Result<()> {
        firewall::init_schema(conn, "cisco_asa")
    }

    fn ingest(&self, raw: &str, meta: &Meta, conn: &Connection) -> Result<bool> {
        let Some(event) = parse_event(raw, meta.tag.as_deref()) else {
            return Ok(false);
        };
        firewall::insert(conn, "cisco_asa", &event, meta, raw)?;
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_deny_by_access_group() {
        let line = r#"%ASA-4-106023: Deny tcp src outside:203.0.113.9/45678 dst inside:10.0.0.5/443 by access-group "outside_access_in" [0x0, 0x0]"#;
        let e = parse_line(line).expect("should parse");
        assert_eq!(e.action, Action::Deny);
        assert_eq!(e.protocol, "tcp");
        assert_eq!(e.src_ip, "203.0.113.9");
        assert_eq!(e.src_port, Some(45678));
        assert_eq!(e.dst_ip, "10.0.0.5");
        assert_eq!(e.dst_port, Some(443));
        assert_eq!(e.src_zone, "outside");
        assert_eq!(e.dst_zone, "inside");
        assert_eq!(e.rule, "outside_access_in");
        assert_eq!(e.event_type, "106023");
    }

    #[test]
    fn parses_both_access_list_verdicts() {
        let permitted = "%ASA-6-106100: access-list acl_in permitted tcp outside/8.8.8.8(53) -> inside/10.0.0.5(443) hit-cnt 1 first hit [0xabc, 0x0]";
        let e = parse_line(permitted).expect("should parse");
        assert_eq!(e.action, Action::Allow);
        assert_eq!(e.rule, "acl_in");
        assert_eq!(e.src_ip, "8.8.8.8");
        assert_eq!(e.dst_port, Some(443));

        let denied = "%ASA-6-106100: access-list acl_in denied udp outside/1.2.3.4(1234) -> inside/10.0.0.9(53) hit-cnt 5 300-second interval [0x0, 0x0]";
        let e = parse_line(denied).expect("should parse");
        assert_eq!(e.action, Action::Deny);
        assert_eq!(e.protocol, "udp");
    }

    #[test]
    fn parses_built_and_teardown_with_bytes() {
        let built = "%ASA-6-302013: Built inbound TCP connection 1234567 for outside:203.0.113.9/45678 (203.0.113.9/45678) to inside:10.0.0.5/443 (10.0.0.5/443)";
        let e = parse_line(built).expect("should parse");
        assert_eq!(e.action, Action::Allow);
        assert_eq!(e.event_type, "302013");
        assert_eq!(e.src_ip, "203.0.113.9");
        assert_eq!(e.dst_ip, "10.0.0.5");
        assert_eq!(e.bytes, None);

        let teardown = "%ASA-6-302014: Teardown TCP connection 1234567 for outside:203.0.113.9/45678 to inside:10.0.0.5/443 duration 0:00:30 bytes 98765 TCP FINs";
        let e = parse_line(teardown).expect("should parse");
        assert_eq!(e.bytes, Some(98765));
        assert_eq!(e.event_type, "302014");

        let udp = "%ASA-6-302015: Built outbound UDP connection 987 for outside:8.8.8.8/53 (8.8.8.8/53) to inside:10.0.0.9/51234 (10.0.0.9/51234)";
        assert_eq!(parse_line(udp).unwrap().protocol, "udp");
    }

    #[test]
    fn parses_an_inbound_denial_and_an_embedded_timestamp() {
        let line = "Aug 16 2026 10:00:00: %ASA-2-106001: Inbound TCP connection denied from 198.51.100.7/44321 to 10.0.0.5/22 flags SYN on interface outside";
        let e = parse_line(line).expect("should parse");
        assert_eq!(e.action, Action::Deny);
        assert_eq!(e.src_ip, "198.51.100.7");
        assert_eq!(e.dst_port, Some(22));
        assert_eq!(e.src_zone, "outside");
        assert_eq!(
            e.ts.map(|t| t.to_string()),
            Some("2026-08-16 10:00:00".to_string())
        );
    }

    #[test]
    fn ignores_messages_that_are_not_connection_decisions() {
        // Real ASA chatter we deliberately don't store.
        assert!(parse_line("%ASA-6-605005: Login permitted from 10.0.0.2/50 to inside:10.0.0.1/ssh for user \"admin\"").is_none());
        assert!(parse_line("%ASA-5-111008: User 'admin' executed the 'write memory' command.").is_none());
        assert!(parse_line("%ASA-6-302020: Built inbound ICMP connection for faddr 1.2.3.4/0 gaddr 10.0.0.1/0").is_none());
        assert!(parse_line("not an asa line at all").is_none());
    }

    #[test]
    fn reads_the_message_id_from_the_syslog_tag_when_stripped() {
        // syslog_loose parses "%ASA-4-106023:" as the APP-NAME and removes it
        // from the body, so the ID has to come from the envelope.
        let body = r#"Deny tcp src outside:203.0.113.9/45678 dst inside:10.0.0.5/443 by access-group "outside_access_in""#;
        assert!(parse_event(body, None).is_none(), "no ID anywhere: not ours to parse");
        let e = parse_event(body, Some("%ASA-4-106023")).expect("should parse via the tag");
        assert_eq!(e.action, Action::Deny);
        assert_eq!(e.src_ip, "203.0.113.9");
        assert_eq!(e.event_type, "106023");

        // An ID we don't report on stays ignored even when the body would match.
        assert!(parse_event(body, Some("%ASA-6-605005")).is_none());
    }

    #[test]
    fn ingests_into_the_table() {
        use crate::logtype::Registry;
        use chrono::Utc;

        let conn = Connection::open_in_memory().unwrap();
        Registry::with_defaults().init_all(&conn).unwrap();
        let meta = Meta {
            source_ip: "192.168.1.1".into(),
            hostname: None,
            tag: None,
            received_at: Utc::now(),
        };
        let line = r#"%ASA-4-106023: Deny tcp src outside:203.0.113.9/45678 dst inside:10.0.0.5/443 by access-group "outside_access_in""#;
        assert!(CiscoAsa.ingest(line, &meta, &conn).unwrap());

        let (action, src, dport, rule): (String, String, i32, String) = conn
            .prepare("SELECT action, src_ip, dst_port, rule FROM cisco_asa")
            .unwrap()
            .query_row([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))
            .unwrap();
        assert_eq!(action, "deny");
        assert_eq!(src, "203.0.113.9");
        assert_eq!(dport, 443);
        assert_eq!(rule, "outside_access_in");
    }
}
