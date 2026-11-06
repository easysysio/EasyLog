// =============================================================================
// logtype/unifi.rs — UniFi gateway firewall-log parser
//
// UniFi gateways (UDM, UDM Pro/SE, UCG, UXG and the older USG) are Linux boxes
// whose firewall is iptables. When "syslog logging" is enabled on a firewall
// rule, every packet the rule matches is written as a kernel log line:
//
//   kernel: [WAN_LOCAL-D-2147483647] DESCR="Block All Traffic" IN=eth8 OUT=
//       MAC=… SRC=203.0.113.5 DST=198.51.100.2 LEN=60 … PROTO=TCP SPT=51234 DPT=22
//
// The bracketed log prefix names the chain, the rule and the verdict. Firmware
// has spelled it two ways:
//
//   newer   [CHAIN-VERDICT-RULE]   e.g. [WAN_LOCAL-D-2147483647]
//   older   [CHAIN-RULE-VERDICT]   e.g. [WAN_IN-2000-D], [WAN_LOCAL-default-D]
//
// Verdicts are A (accept), D (drop), R (reject) and B (block). A prefix with any
// other verdict (a NAT or return marker) is not an allow/deny decision and is
// left unparsed, as are the gateway's other messages (DHCP, system, …).
// The rest of the line is iptables' KEY=value fields; DESCR, when present, is
// the rule's name as typed in the UniFi UI and is preferred as the rule label.
// Events normalize into the shared shape in logtype/firewall.rs.
// =============================================================================

use std::sync::OnceLock;

use anyhow::Result;
use duckdb::Connection;
use regex::Regex;

use super::firewall::{self, Action, FirewallEvent};
use super::{Category, LogType, Meta};

/// UniFi gateway firewall-log handler (zero-sized).
pub struct UniFi;

// ─────────────────────────────────────────────────────────────────────────────
// prefix_re()
// The iptables log prefix: a bracketed CHAIN-…-… tag. A kernel uptime stamp
// ("[ 1234.567]") never matches, since it holds spaces and dots.
// ─────────────────────────────────────────────────────────────────────────────
fn prefix_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"\[([A-Za-z0-9_]+(?:-[A-Za-z0-9_]+)+)\]").expect("valid regex"))
}

// ─────────────────────────────────────────────────────────────────────────────
// verdict(token)
// Maps a prefix verdict letter to an action; None for anything that isn't one.
// ─────────────────────────────────────────────────────────────────────────────
fn verdict(token: &str) -> Option<Action> {
    match token {
        "A" => Some(Action::Allow),
        "D" | "R" | "B" => Some(Action::Deny),
        _ => None,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// split_prefix(prefix)
// Splits "WAN_LOCAL-D-2147483647" or "WAN_IN-2000-D" into (chain, rule id,
// action), trying the newer verdict-second layout before the older
// verdict-last one.
// ─────────────────────────────────────────────────────────────────────────────
fn split_prefix(prefix: &str) -> Option<(&str, String, Action)> {
    let parts: Vec<&str> = prefix.split('-').collect();
    let chain = parts[0];
    if let Some(action) = parts.get(1).and_then(|t| verdict(t)) {
        return Some((chain, parts[2..].join("-"), action));
    }
    let last = parts.last()?;
    let action = verdict(last)?;
    Some((chain, parts[1..parts.len() - 1].join("-"), action))
}

// ─────────────────────────────────────────────────────────────────────────────
// fields(text)
// Reads iptables' KEY=value pairs. Values run to the next space, except quoted
// ones (DESCR="Block All Traffic"), which run to the closing quote. Bare flags
// such as SYN or DF carry no "=" and are skipped.
// ─────────────────────────────────────────────────────────────────────────────
fn fields(text: &str) -> Vec<(&str, &str)> {
    let mut out = Vec::new();
    let mut rest = text;
    while let Some(eq) = rest.find('=') {
        // The key is the word immediately before the "=".
        let key_start = rest[..eq].rfind(char::is_whitespace).map_or(0, |i| i + 1);
        let key = rest[key_start..eq].trim_start_matches(']');
        let after = &rest[eq + 1..];
        let (value, next) = if let Some(quoted) = after.strip_prefix('"') {
            let end = quoted.find('"').unwrap_or(quoted.len());
            (&quoted[..end], &quoted[(end + 1).min(quoted.len())..])
        } else {
            let end = after.find(char::is_whitespace).unwrap_or(after.len());
            (&after[..end], &after[end..])
        };
        out.push((key, value));
        rest = next;
    }
    out
}

// ─────────────────────────────────────────────────────────────────────────────
// parse_line(line)
// Parses one UniFi firewall log line into a normalized firewall event, or None
// for lines that aren't an allow/deny decision.
// ─────────────────────────────────────────────────────────────────────────────
pub fn parse_line(line: &str) -> Option<FirewallEvent> {
    let caps = prefix_re().captures(line)?;
    let (chain, rule_id, action) = split_prefix(caps.get(1)?.as_str())?;
    let kv = fields(&line[caps.get(0)?.end()..]);
    let get = |key: &str| kv.iter().find(|(k, _)| *k == key).map(|(_, v)| *v).unwrap_or("");
    let num = |key: &str| get(key).parse::<i32>().ok();

    let (src_ip, dst_ip) = (get("SRC"), get("DST"));
    if src_ip.is_empty() || dst_ip.is_empty() {
        return None;
    }
    let rule = match get("DESCR") {
        "" if rule_id.is_empty() => chain.to_string(),
        "" => format!("{chain}-{rule_id}"),
        descr => descr.to_string(),
    };
    Some(FirewallEvent {
        // Kernel lines carry no clock of their own; arrival time is used.
        ts: None,
        action,
        protocol: get("PROTO").to_lowercase(),
        src_ip: src_ip.to_string(),
        src_port: num("SPT"),
        dst_ip: dst_ip.to_string(),
        dst_port: num("DPT"),
        src_zone: get("IN").to_string(),
        dst_zone: get("OUT").to_string(),
        rule,
        // Each line is one packet; LEN is its size in bytes.
        bytes: get("LEN").parse().ok(),
        event_type: chain.to_string(),
        application: String::new(),
    })
}

impl LogType for UniFi {
    fn name(&self) -> &'static str {
        "unifi"
    }

    fn category(&self) -> Category {
        Category::Firewall
    }

    fn label(&self) -> &'static str {
        "UniFi Gateway"
    }

    fn icon(&self) -> &'static str {
        "bi-router"
    }

    fn init_schema(&self, conn: &Connection) -> Result<()> {
        firewall::init_schema(conn, "unifi")
    }

    fn ingest(&self, raw: &str, meta: &Meta, conn: &Connection) -> Result<bool> {
        // The body keeps the "kernel:" tag the syslog parser strips, so the
        // stored line is what the gateway sent; the prefix is found either way.
        let line = if meta.body.is_empty() { raw } else { meta.body.as_str() };
        let Some(event) = parse_line(line) else {
            return Ok(false);
        };
        firewall::insert(conn, "unifi", &event, meta, line.trim())?;
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Newer firmware: verdict second, rule name in DESCR.
    const NEW: &str = r#"kernel: [WAN_LOCAL-D-2147483647] DESCR="Block All Traffic" IN=eth8 OUT= MAC=24:5a:4c:11:22:33:00:11:22:33:44:55:08:00 SRC=203.0.113.5 DST=198.51.100.2 LEN=60 TOS=0x00 PREC=0x00 TTL=51 ID=4242 DF PROTO=TCP SPT=51234 DPT=22 WINDOW=64240 RES=0x00 SYN URGP=0 MARK=1a0000"#;
    // Older firmware: verdict last, no space before the fields, no DESCR.
    const OLD: &str = "kernel: [WAN_IN-2000-A]IN=eth0 OUT=eth1 MAC=00:11:22:33:44:55:66:77:88:99:aa:bb:08:00 SRC=198.51.100.7 DST=192.168.1.20 LEN=1500 TOS=0x00 PREC=0x00 TTL=60 ID=0 DF PROTO=UDP SPT=53 DPT=40000 LEN=1480";

    #[test]
    fn parses_the_newer_prefix() {
        let e = parse_line(NEW).expect("should parse");
        assert_eq!(e.action, Action::Deny);
        assert_eq!(e.src_ip, "203.0.113.5");
        assert_eq!(e.dst_ip, "198.51.100.2");
        assert_eq!(e.src_port, Some(51234));
        assert_eq!(e.dst_port, Some(22));
        assert_eq!(e.protocol, "tcp");
        assert_eq!(e.rule, "Block All Traffic");
        assert_eq!(e.event_type, "WAN_LOCAL");
        assert_eq!(e.src_zone, "eth8");
        assert_eq!(e.dst_zone, "", "traffic to the gateway itself has no OUT");
        assert_eq!(e.bytes, Some(60));
        assert_eq!(e.ts, None);
    }

    #[test]
    fn parses_the_older_prefix() {
        let e = parse_line(OLD).expect("should parse");
        assert_eq!(e.action, Action::Allow);
        assert_eq!(e.rule, "WAN_IN-2000", "no DESCR: the prefix names the rule");
        assert_eq!(e.event_type, "WAN_IN");
        assert_eq!(e.protocol, "udp");
        assert_eq!(e.src_zone, "eth0");
        assert_eq!(e.dst_zone, "eth1");
        // The IP length comes first; the UDP header repeats LEN later.
        assert_eq!(e.bytes, Some(1500));

        let default = parse_line(&NEW.replace("[WAN_LOCAL-D-2147483647] DESCR=\"Block All Traffic\"", "[WAN_LOCAL-default-D]"))
            .expect("should parse");
        assert_eq!(default.rule, "WAN_LOCAL-default");
        assert_eq!(default.action, Action::Deny);
    }

    #[test]
    fn maps_every_verdict() {
        for (letter, action) in [("A", Action::Allow), ("D", Action::Deny), ("R", Action::Deny), ("B", Action::Deny)] {
            let line = NEW.replace("-D-", &format!("-{letter}-"));
            assert_eq!(parse_line(&line).unwrap().action, action, "verdict {letter}");
        }
        // A NAT or return marker isn't an allow/deny decision.
        assert!(parse_line(&NEW.replace("-D-", "-RET-")).is_none());
        assert!(parse_line(&NEW.replace("[WAN_LOCAL-D-2147483647]", "[PREROUTING-DNAT-1]")).is_none());
    }

    #[test]
    fn handles_ipv6_and_icmp() {
        let line = "kernel: [ 8812.441210] [LAN_IN-D-30000] DESCR=\"Isolate IoT\" IN=br20 OUT=br0 MAC= SRC=2001:0db8:0000:0000:0000:0000:0000:0001 DST=2001:0db8:0000:0001:0000:0000:0000:0002 LEN=104 TC=0 HOPLIMIT=64 FLOWLBL=0 PROTO=ICMPv6 TYPE=128 CODE=0 ID=1 SEQ=1";
        let e = parse_line(line).expect("should parse");
        assert_eq!(e.src_ip, "2001:0db8:0000:0000:0000:0000:0000:0001");
        assert_eq!(e.protocol, "icmpv6");
        assert_eq!(e.src_port, None);
        assert_eq!(e.dst_port, None);
        assert_eq!(e.rule, "Isolate IoT");
        assert_eq!(e.event_type, "LAN_IN", "the kernel uptime stamp is not the prefix");
    }

    #[test]
    fn ignores_other_gateway_messages() {
        for line in [
            "dnsmasq-dhcp[1234]: DHCPACK(br0) 192.168.1.50 aa:bb:cc:dd:ee:ff phone",
            "kernel: [ 123.456] eth8: link up",
            "mcad: mcad[2345]: ace_reporter.reporter_fail(): Server returned 404",
            "kernel: [WAN_LOCAL-D-2147483647] DESCR=\"x\" IN=eth8 OUT=",
            "",
        ] {
            assert!(parse_line(line).is_none(), "{line:?}");
        }
    }

    #[test]
    fn ingests_into_the_table() {
        use crate::logtype::Registry;
        use chrono::Utc;

        let conn = Connection::open_in_memory().unwrap();
        Registry::with_defaults().init_all(&conn).unwrap();
        let meta = Meta {
            source_ip: "192.168.1.1".into(),
            hostname: Some("UDM-Pro".into()),
            tag: Some("kernel".into()),
            body: NEW.to_string(),
            received_at: Utc::now(),
        };
        // `raw` is the syslog-stripped body; the parser reads `meta.body`.
        let stripped = NEW.trim_start_matches("kernel: ");
        assert!(UniFi.ingest(stripped, &meta, &conn).unwrap());

        let (action, rule, chain, raw): (String, String, String, String) = conn
            .prepare("SELECT action, rule, event_type, raw FROM unifi")
            .unwrap()
            .query_row([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))
            .unwrap();
        assert_eq!(action, "deny");
        assert_eq!(rule, "Block All Traffic");
        assert_eq!(chain, "WAN_LOCAL");
        assert_eq!(raw, NEW, "the stored line keeps the kernel tag");
    }
}
