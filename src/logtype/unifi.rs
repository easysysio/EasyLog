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
// So are the gateway's own UniFi discovery broadcasts (UDP 10001 to
// 255.255.255.255), which each network's "Block All" rule logs every few
// seconds and which would otherwise bury the blocks worth seeing.
// The rest of the line is iptables' KEY=value fields; DESCR, when present, is
// the rule's name as typed in the UniFi UI and is preferred as the rule label.
//
// The UniFi Network application (9.x and later) also sends events in CEF
// through its SIEM-server setting:
//
//   CEF:0|Ubiquiti|UniFi Network|10.6.109|200|Threat Detected|7|proto=TCP
//       spt=61160 dpt=25 act=allowed app=SMTP … src=… dst=… UNIFIutcTime=…
//
// CEF events that describe traffic — those carrying src and dst, such as the
// IDS/IPS "Threat Detected" — are read too: act gives the verdict (an IDS in
// detect-only mode reports "allowed"), the IPS signature names the rule, and
// the CEF event name takes the chain's place. Events about clients, devices
// and admins carry no traffic and are left unparsed.
// Events normalize into the shared shape in logtype/firewall.rs.
// =============================================================================

use std::sync::OnceLock;

use anyhow::Result;
use chrono::DateTime;
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
// is_discovery_broadcast(protocol, dst, dst_port)
// UniFi device discovery: a UDP broadcast to port 10001. Only that exact shape
// is dropped — other broadcasts and other traffic to 10001 are kept.
// ─────────────────────────────────────────────────────────────────────────────
fn is_discovery_broadcast(protocol: &str, dst: &str, dst_port: Option<i32>) -> bool {
    protocol.eq_ignore_ascii_case("udp") && dst == "255.255.255.255" && dst_port == Some(10001)
}

// ─────────────────────────────────────────────────────────────────────────────
// parse_line(line)
// Parses one UniFi firewall log line into a normalized firewall event, or None
// for lines that aren't an allow/deny decision.
// ─────────────────────────────────────────────────────────────────────────────
pub fn parse_line(line: &str) -> Option<FirewallEvent> {
    if let Some(start) = line.find("CEF:") {
        return parse_cef(&line[start..]);
    }
    let caps = prefix_re().captures(line)?;
    let (chain, rule_id, action) = split_prefix(caps.get(1)?.as_str())?;
    let kv = fields(&line[caps.get(0)?.end()..]);
    let get = |key: &str| kv.iter().find(|(k, _)| *k == key).map(|(_, v)| *v).unwrap_or("");
    let num = |key: &str| get(key).parse::<i32>().ok();

    let (src_ip, dst_ip) = (get("SRC"), get("DST"));
    if src_ip.is_empty() || dst_ip.is_empty() || is_discovery_broadcast(get("PROTO"), dst_ip, num("DPT")) {
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

// ─────────────────────────────────────────────────────────────────────────────
// cef_key_re()
// The start of a CEF extension pair: a key preceded by a space (or the start)
// and followed by "=". An escaped "\=" inside a value never matches, since a
// backslash can't be part of a key.
// ─────────────────────────────────────────────────────────────────────────────
fn cef_key_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?:^|\s)([A-Za-z_][A-Za-z0-9_.]*)=").expect("valid regex"))
}

// ─────────────────────────────────────────────────────────────────────────────
// cef_unescape(value)
// Undoes CEF's escaping: \= \| \\ and \n / \r.
// ─────────────────────────────────────────────────────────────────────────────
fn cef_unescape(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    let mut chars = value.chars();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match chars.next() {
            Some('n') | Some('r') => out.push(' '),
            Some(other) => out.push(other),
            None => out.push('\\'),
        }
    }
    out
}

// ─────────────────────────────────────────────────────────────────────────────
// cef_split(record)
// Splits "CEF:0|vendor|product|version|id|name|severity|extension" into its
// seven header fields and the extension, honouring "\|" inside header fields.
// ─────────────────────────────────────────────────────────────────────────────
fn cef_split(record: &str) -> Option<(Vec<String>, &str)> {
    let mut header = Vec::with_capacity(7);
    let mut start = 0;
    let mut escaped = false;
    for (i, c) in record.char_indices() {
        match c {
            '\\' if !escaped => escaped = true,
            '|' if !escaped => {
                header.push(cef_unescape(&record[start..i]));
                start = i + 1;
                if header.len() == 7 {
                    return Some((header, &record[start..]));
                }
            }
            _ => escaped = false,
        }
    }
    None
}

// ─────────────────────────────────────────────────────────────────────────────
// cef_fields(extension)
// Reads the extension's key=value pairs. Values may contain spaces
// ("UNIFIhost=Cloud Gateway Fiber"), so each runs up to the next key.
// ─────────────────────────────────────────────────────────────────────────────
fn cef_fields(extension: &str) -> Vec<(String, String)> {
    let keys: Vec<_> = cef_key_re().captures_iter(extension).collect();
    keys.iter()
        .enumerate()
        .map(|(i, caps)| {
            let key = caps.get(1).expect("group 1 always matches");
            let end = keys.get(i + 1).map_or(extension.len(), |next| next.get(0).expect("whole match").start());
            let value = extension[key.end() + 1..end].trim();
            (key.as_str().to_string(), cef_unescape(value))
        })
        .collect()
}

// ─────────────────────────────────────────────────────────────────────────────
// cef_action(act)
// UniFi reports "allowed" for an IDS that only detects, and "blocked" once IPS
// stops the flow; any refusing verb is a deny.
// ─────────────────────────────────────────────────────────────────────────────
fn cef_action(act: &str) -> Action {
    let act = act.to_ascii_lowercase();
    if ["block", "drop", "den", "reject"].iter().any(|v| act.contains(v)) {
        Action::Deny
    } else {
        Action::Allow
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// parse_cef(record)
// Parses a UniFi CEF record that describes traffic into a firewall event; None
// for malformed records and for events without a source and destination.
// ─────────────────────────────────────────────────────────────────────────────
fn parse_cef(record: &str) -> Option<FirewallEvent> {
    let (header, extension) = cef_split(record)?;
    let kv = cef_fields(extension);
    let get = |key: &str| kv.iter().find(|(k, _)| k == key).map(|(_, v)| v.as_str()).unwrap_or("");
    let first = |keys: &[&str]| keys.iter().map(|k| get(k)).find(|v| !v.is_empty()).unwrap_or("").to_string();

    let (src_ip, dst_ip) = (get("src"), get("dst"));
    if src_ip.is_empty() || dst_ip.is_empty() {
        return None;
    }
    let name = header[5].clone();
    Some(FirewallEvent {
        ts: DateTime::parse_from_rfc3339(get("UNIFIutcTime")).ok().map(|t| t.naive_utc()),
        action: cef_action(get("act")),
        protocol: get("proto").to_lowercase(),
        src_ip: src_ip.to_string(),
        src_port: get("spt").parse().ok(),
        dst_ip: dst_ip.to_string(),
        dst_port: get("dpt").parse().ok(),
        src_zone: first(&["UNIFIsrcZone", "deviceInboundInterface"]),
        dst_zone: first(&["UNIFIdstZone", "deviceOutboundInterface"]),
        rule: match first(&["UNIFIipsSignature", "UNIFIpolicyName"]) {
            rule if rule.is_empty() => name.clone(),
            rule => rule,
        },
        bytes: get("UNIFItotalBytes").parse().ok(),
        event_type: name,
        application: get("app").to_string(),
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// full_line(raw, meta)
// Rebuilds the line the gateway sent. The body keeps the tag the syslog parser
// strips ("kernel:", or the "CEF:" a CEF record starts with). UniFi sends CEF
// with no hostname, so the parser takes the record's first word
// ("CEF:0|Ubiquiti|UniFi") as the hostname and the next as the tag; that word
// is put back in front of the body.
// ─────────────────────────────────────────────────────────────────────────────
fn full_line(raw: &str, meta: &Meta) -> String {
    let body = if meta.body.is_empty() { raw } else { meta.body.as_str() };
    match meta.hostname.as_deref() {
        Some(host) if host.starts_with("CEF:") && !body.contains("CEF:") => format!("{host} {body}"),
        _ => body.to_string(),
    }
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
        let line = full_line(raw, meta);
        let Some(event) = parse_line(&line) else {
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

    // CEF from the UniFi Network SIEM setting (made-up addresses).
    const THREAT: &str = r"CEF:0|Ubiquiti|UniFi Network|10.6.109|200|Threat Detected|7|UNIFIcategory=Security UNIFIhost=Cloud Gateway Fiber proto=TCP spt=61160 dpt=25 act=allowed app=SMTP UNIFIrisk=medium UNIFIpolicyName=DShield Block List UNIFIpolicyType=IDS/IPS UNIFIdirection=incoming deviceOutboundInterface=DMZ UNIFIdeviceIp=192.168.1.1 src=203.0.113.41 dst=192.168.3.13 UNIFIsrcRegion=AE UNIFIdstZone=Dmz UNIFItotalBytes=58 UNIFItotalPackets=1 UNIFIflowStartTime=Nov 7, 2026 at 10:59:03.542 AM UNIFIipsSignature=ET DROP Dshield Block Listed Source group 1 UNIFIipsSignatureId=2402000 UNIFIutcTime=2026-11-07T08:59:04.647Z msg=A network intrusion attempt from 203.0.113.41 to 192.168.3.13 has been detected.";

    #[test]
    fn parses_a_cef_threat() {
        let e = parse_line(THREAT).expect("should parse");
        assert_eq!(e.action, Action::Allow, "detect-only IDS lets it through");
        assert_eq!(e.src_ip, "203.0.113.41");
        assert_eq!(e.dst_ip, "192.168.3.13");
        assert_eq!(e.src_port, Some(61160));
        assert_eq!(e.dst_port, Some(25));
        assert_eq!(e.protocol, "tcp");
        assert_eq!(e.application, "SMTP");
        assert_eq!(e.rule, "ET DROP Dshield Block Listed Source group 1");
        assert_eq!(e.event_type, "Threat Detected");
        assert_eq!(e.dst_zone, "Dmz");
        assert_eq!(e.bytes, Some(58));
        assert_eq!(e.ts.map(|t| t.to_string()), Some("2026-11-07 08:59:04.647".to_string()));
    }

    #[test]
    fn a_blocking_ips_is_a_deny() {
        for act in ["blocked", "dropped", "denied", "rejected"] {
            let line = THREAT.replace("act=allowed", &format!("act={act}"));
            assert_eq!(parse_line(&line).unwrap().action, Action::Deny, "act={act}");
        }
    }

    #[test]
    fn cef_values_keep_spaces_and_escapes() {
        let line = THREAT.replace("UNIFIipsSignature=ET DROP Dshield Block Listed Source group 1", r"UNIFIipsSignature=GPL a\=b c\\d");
        assert_eq!(parse_line(&line).unwrap().rule, r"GPL a=b c\d");
        // Without a signature, the policy names the rule.
        let line = THREAT.replace("UNIFIipsSignature=ET DROP Dshield Block Listed Source group 1 ", "");
        assert_eq!(parse_line(&line).unwrap().rule, "DShield Block List");
        // An escaped pipe in the header doesn't shift the event name.
        let line = THREAT.replace("|Threat Detected|", r"|Threat \| Detected|");
        assert_eq!(parse_line(&line).unwrap().event_type, "Threat | Detected");
    }

    #[test]
    fn skips_cef_events_without_traffic() {
        let wifi = "CEF:0|Ubiquiti|UniFi Network|10.6.109|401|WiFi Client Disconnected|2|UNIFIcategory=Client Devices UNIFIhost=Cloud Gateway Fiber UNIFIclientIp=192.168.1.107 UNIFIduration=4m 51s msg=Watch disconnected.";
        assert!(parse_line(wifi).is_none());
        assert!(parse_line("CEF:0|Ubiquiti|truncated").is_none());
    }

    #[test]
    fn ingests_a_cef_record_split_by_the_syslog_parser() {
        use crate::logtype::Registry;
        use chrono::Utc;

        let conn = Connection::open_in_memory().unwrap();
        Registry::with_defaults().init_all(&conn).unwrap();
        // syslog_loose reads "CEF:" as a tag; the body puts it back.
        let meta = Meta {
            source_ip: "192.168.1.1".into(),
            hostname: None,
            tag: Some("CEF".into()),
            body: THREAT.to_string(),
            received_at: Utc::now(),
        };
        assert!(UniFi.ingest(THREAT.trim_start_matches("CEF:"), &meta, &conn).unwrap());
        let (rule, app, raw): (String, String, String) = conn
            .prepare("SELECT rule, application, raw FROM unifi")
            .unwrap()
            .query_row([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
            .unwrap();
        assert_eq!(rule, "ET DROP Dshield Block Listed Source group 1");
        assert_eq!(app, "SMTP");
        assert_eq!(raw, THREAT);
    }

    #[test]
    fn rejoins_a_cef_record_sent_without_a_hostname() {
        use crate::logtype::Registry;
        use chrono::Utc;

        // How syslog_loose splits "<13>Nov  7 10:59:04 CEF:0|Ubiquiti|UniFi Network|…".
        let (host, rest) = THREAT.split_once(' ').unwrap();
        let conn = Connection::open_in_memory().unwrap();
        Registry::with_defaults().init_all(&conn).unwrap();
        let meta = Meta {
            source_ip: "192.168.1.1".into(),
            hostname: Some(host.into()),
            tag: Some("Network|10.6.109|200|Threat".into()),
            body: rest.to_string(),
            received_at: Utc::now(),
        };
        assert_eq!(full_line("Detected|7|…", &meta), THREAT);
        assert!(UniFi.ingest("Detected|7|…", &meta, &conn).unwrap());
        let raw: String = conn.prepare("SELECT raw FROM unifi").unwrap().query_row([], |r| r.get(0)).unwrap();
        assert_eq!(raw, THREAT, "the stored line is the whole record");
    }

    // The gateway's own discovery broadcast, as a UCG logs it: no "kernel:"
    // tag, and a DESCR carrying the chain and cut short.
    const DISCOVERY: &str = r#"[GUEST_LOCAL-D-2147483647] DESCR="[GUEST_LOCAL]Block All Traff" IN=br99 OUT= MAC=45:00:00:20:67:d3:40:00:40:11:af:50:c0:a8 SRC=192.168.99.1 DST=255.255.255.255 LEN=32 TOS=00 PREC=0x00 TTL=64 ID=26579 DF PROTO=UDP SPT=53350 DPT=10001 LEN=12 MARK=1a0000 "#;
    // A real block between zones, in the same untagged UCG form.
    const UCG_BLOCK: &str = r#"[DMZ_LAN-D-2147483647] DESCR="[DMZ_LAN]Block All Traffic" IN=br3 OUT=br0 MAC=74:f9:2c:00:00:01:bc:24:11:00:00:02:08:00 SRC=192.168.3.11 DST=192.168.1.53 LEN=205 TOS=00 PREC=0x00 TTL=63 ID=13602 DF PROTO=UDP SPT=50414 DPT=514 LEN=185 MARK=1a0000 "#;

    #[test]
    fn parses_an_untagged_ucg_line() {
        let e = parse_line(UCG_BLOCK).expect("should parse");
        assert_eq!(e.action, Action::Deny);
        assert_eq!(e.event_type, "DMZ_LAN");
        assert_eq!(e.src_zone, "br3");
        assert_eq!(e.dst_port, Some(514));
    }

    #[test]
    fn skips_only_the_discovery_broadcast() {
        assert!(parse_line(DISCOVERY).is_none());
        // Other broadcasts, and unicast traffic to 10001, are kept.
        assert!(parse_line(&DISCOVERY.replace("DPT=10001", "DPT=67")).is_some());
        assert!(parse_line(&DISCOVERY.replace("DST=255.255.255.255", "DST=192.168.99.20")).is_some());
        assert!(parse_line(&DISCOVERY.replace("PROTO=UDP", "PROTO=TCP")).is_some());
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
