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
// Newer firmware prefixes it with the chain ("[DMZ_LAN]Block All Traffic");
// that prefix is dropped, since the chain is its own field.
//
// The UniFi Network application (9.x and later) also sends events in CEF
// through its SIEM-server setting:
//
//   CEF:0|Ubiquiti|UniFi Network|10.6.109|200|Threat Detected|7|proto=TCP
//       spt=61160 dpt=25 act=allowed app=SMTP … src=… dst=… UNIFIutcTime=…
//
// CEF events that describe traffic — those carrying src and dst, such as the
// IDS/IPS "Threat Detected" — are read too, and stored twice: once in the
// firewall shape (act gives the verdict — an IDS in detect-only mode reports
// "allowed" — the IPS signature names the rule, and the CEF event name takes
// the chain's place), and once in full in `unifi_threats`, which keeps what a
// threats dashboard needs and the firewall shape has no room for: risk,
// severity, signature ID, policy, direction and message. Events about clients,
// devices and admins carry no traffic and are left unparsed.
// Events normalize into the shared shape in logtype/firewall.rs.
// =============================================================================

use std::sync::OnceLock;

use anyhow::Result;
use chrono::{DateTime, NaiveDateTime};
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
// rule_name(descr, chain)
// The rule's own name from DESCR, without the "[CHAIN]" UniFi puts in front.
// Only the line's own chain is removed, so a rule the user named "[Plex] …"
// keeps its bracket; a DESCR that is nothing but the label is kept whole.
// ─────────────────────────────────────────────────────────────────────────────
fn rule_name<'a>(descr: &'a str, chain: &str) -> &'a str {
    descr
        .strip_prefix('[')
        .and_then(|rest| rest.strip_prefix(chain))
        .and_then(|rest| rest.strip_prefix(']'))
        .map(str::trim_start)
        .filter(|name| !name.is_empty())
        .unwrap_or(descr)
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
        return parse_threat(&line[start..]).map(|t| t.firewall_event());
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
        descr => rule_name(descr, chain).to_string(),
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

/// Table holding UniFi's security detections in full.
pub const THREATS_TABLE: &str = "unifi_threats";

/// One security detection (IDS/IPS "Threat Detected" and any other CEF event
/// that carries traffic), with everything the CEF record says about it.
#[derive(Debug, Clone, PartialEq)]
pub struct Threat {
    /// The gateway's own time (UNIFIutcTime); None falls back to arrival time.
    pub ts: Option<NaiveDateTime>,
    /// CEF event name, e.g. "Threat Detected".
    pub event: String,
    /// CEF severity, 0–10.
    pub severity: Option<i32>,
    /// UniFi's rating, lowercased: low, medium, high (or empty).
    pub risk: String,
    pub action: Action,
    pub signature: String,
    pub signature_id: String,
    /// The policy that matched, e.g. "DShield Block List", and its kind, "IDS/IPS".
    pub policy: String,
    pub policy_type: String,
    /// "incoming" or "outgoing", as UniFi reports it (or empty).
    pub direction: String,
    pub src_ip: String,
    pub src_port: Option<i32>,
    pub dst_ip: String,
    pub dst_port: Option<i32>,
    pub protocol: String,
    pub application: String,
    pub src_zone: String,
    pub dst_zone: String,
    pub bytes: Option<i64>,
    pub packets: Option<i64>,
    pub message: String,
}

impl Threat {
    // ─────────────────────────────────────────────────────────────────────────
    // Threat::remote_and_local()
    // The outside party and the inside one. An incoming threat comes from the
    // source; an outgoing one is a device inside reaching out to the
    // destination — the likeliest sign of an infected device.
    // ─────────────────────────────────────────────────────────────────────────
    pub fn remote_and_local(&self) -> (&str, &str) {
        if self.direction == "outgoing" {
            (&self.dst_ip, &self.src_ip)
        } else {
            (&self.src_ip, &self.dst_ip)
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Threat::firewall_event()
    // The same detection in the shared firewall shape, for the firewall
    // dashboard: the signature (or policy) is the rule, the event name the chain.
    // ─────────────────────────────────────────────────────────────────────────
    pub fn firewall_event(&self) -> FirewallEvent {
        let rule = [&self.signature, &self.policy]
            .into_iter()
            .find(|v| !v.is_empty())
            .unwrap_or(&self.event)
            .clone();
        FirewallEvent {
            ts: self.ts,
            action: self.action,
            protocol: self.protocol.clone(),
            src_ip: self.src_ip.clone(),
            src_port: self.src_port,
            dst_ip: self.dst_ip.clone(),
            dst_port: self.dst_port,
            src_zone: self.src_zone.clone(),
            dst_zone: self.dst_zone.clone(),
            rule,
            bytes: self.bytes,
            event_type: self.event.clone(),
            application: self.application.clone(),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// parse_threat(record)
// Parses a UniFi CEF record that describes traffic; None for malformed records
// and for events without a source and destination.
// ─────────────────────────────────────────────────────────────────────────────
pub fn parse_threat(record: &str) -> Option<Threat> {
    let (header, extension) = cef_split(record)?;
    let kv = cef_fields(extension);
    let get = |key: &str| kv.iter().find(|(k, _)| k == key).map(|(_, v)| v.as_str()).unwrap_or("");
    let first = |keys: &[&str]| keys.iter().map(|k| get(k)).find(|v| !v.is_empty()).unwrap_or("").to_string();

    let (src_ip, dst_ip) = (get("src"), get("dst"));
    if src_ip.is_empty() || dst_ip.is_empty() {
        return None;
    }
    Some(Threat {
        ts: DateTime::parse_from_rfc3339(get("UNIFIutcTime")).ok().map(|t| t.naive_utc()),
        event: header[5].clone(),
        severity: header[6].trim().parse().ok(),
        risk: get("UNIFIrisk").to_lowercase(),
        action: cef_action(get("act")),
        signature: get("UNIFIipsSignature").to_string(),
        signature_id: get("UNIFIipsSignatureId").to_string(),
        policy: get("UNIFIpolicyName").to_string(),
        policy_type: get("UNIFIpolicyType").to_string(),
        direction: get("UNIFIdirection").to_lowercase(),
        src_ip: src_ip.to_string(),
        src_port: get("spt").parse().ok(),
        dst_ip: dst_ip.to_string(),
        dst_port: get("dpt").parse().ok(),
        protocol: get("proto").to_lowercase(),
        application: get("app").to_string(),
        src_zone: first(&["UNIFIsrcZone", "deviceInboundInterface"]),
        dst_zone: first(&["UNIFIdstZone", "deviceOutboundInterface"]),
        bytes: get("UNIFItotalBytes").parse().ok(),
        packets: get("UNIFItotalPackets").parse().ok(),
        message: get("msg").to_string(),
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// init_threats(conn)
// Creates the threats table.
// ─────────────────────────────────────────────────────────────────────────────
fn init_threats(conn: &Connection) -> Result<()> {
    conn.execute_batch(&format!(
        r#"
        CREATE TABLE IF NOT EXISTS {THREATS_TABLE} (
            source_ip     VARCHAR,
            ts            TIMESTAMP,
            event         VARCHAR,
            severity      INTEGER,
            risk          VARCHAR,
            action        VARCHAR,
            signature     VARCHAR,
            signature_id  VARCHAR,
            policy        VARCHAR,
            policy_type   VARCHAR,
            direction     VARCHAR,
            src_ip        VARCHAR,
            src_port      INTEGER,
            dst_ip        VARCHAR,
            dst_port      INTEGER,
            protocol      VARCHAR,
            application   VARCHAR,
            src_zone      VARCHAR,
            dst_zone      VARCHAR,
            remote_ip     VARCHAR,
            local_ip      VARCHAR,
            bytes         BIGINT,
            packets       BIGINT,
            message       VARCHAR,
            country       VARCHAR,
            country_code  VARCHAR,
            received_at   TIMESTAMP,
            raw           VARCHAR
        );
        "#
    ))?;
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// insert_threat(conn, source_ip, received_at, threat, raw)
// Stores one detection. The country is the outside party's, and the time is
// the gateway's when it agrees with the arrival time (see firewall::event_time).
// ─────────────────────────────────────────────────────────────────────────────
fn insert_threat(
    conn: &Connection,
    source_ip: &str,
    received_at: NaiveDateTime,
    threat: &Threat,
    raw: &str,
) -> Result<()> {
    let (remote, local) = threat.remote_and_local();
    let (country_code, country) = crate::geo::lookup(remote);
    conn.execute(
        &format!(
            "INSERT INTO {THREATS_TABLE}
             (source_ip, ts, event, severity, risk, action, signature, signature_id, policy,
              policy_type, direction, src_ip, src_port, dst_ip, dst_port, protocol, application,
              src_zone, dst_zone, remote_ip, local_ip, bytes, packets, message, country,
              country_code, received_at, raw)
             VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)"
        ),
        duckdb::params![
            source_ip,
            firewall::event_time(threat.ts, received_at),
            threat.event,
            threat.severity,
            threat.risk,
            threat.action.as_str(),
            threat.signature,
            threat.signature_id,
            threat.policy,
            threat.policy_type,
            threat.direction,
            threat.src_ip,
            threat.src_port,
            threat.dst_ip,
            threat.dst_port,
            threat.protocol,
            threat.application,
            threat.src_zone,
            threat.dst_zone,
            remote,
            local,
            threat.bytes,
            threat.packets,
            threat.message,
            country,
            country_code,
            received_at,
            raw,
        ],
    )?;
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// backfill_threats(conn)
// Fills an empty threats table from the CEF lines already in the firewall
// table — every UniFi detection stored before the table existed keeps its raw
// record — so the threats dashboard starts with that history. Each row keeps
// its stored time. A no-op once the table has rows.
// ─────────────────────────────────────────────────────────────────────────────
fn backfill_threats(conn: &Connection) -> Result<usize> {
    let existing: i64 = conn.query_row(&format!("SELECT count(*) FROM {THREATS_TABLE}"), [], |r| r.get(0))?;
    if existing > 0 {
        return Ok(0);
    }
    let rows: Vec<(String, NaiveDateTime, NaiveDateTime, String)> = conn
        .prepare(
            "SELECT coalesce(source_ip, ''), coalesce(ts, received_at), received_at, raw
             FROM unifi WHERE raw LIKE 'CEF:%' AND received_at IS NOT NULL",
        )?
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))?
        .collect::<Result<_, _>>()?;
    let mut filled = 0;
    for (source_ip, ts, received_at, raw) in rows {
        let Some(mut threat) = parse_threat(&raw) else { continue };
        threat.ts = Some(ts); // the time already decided for it
        insert_threat(conn, &source_ip, received_at, &threat, &raw)?;
        filled += 1;
    }
    Ok(filled)
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
        firewall::init_schema(conn, "unifi")?;
        // Rows stored before 0.11.2 kept UniFi's "[CHAIN]" in front of the rule
        // name; renaming them keeps the rules panel from listing each rule
        // twice. Once done, nothing matches and this is a no-op.
        // The chain is in event_type, so only that exact label is removed.
        conn.execute_batch(
            "UPDATE unifi
             SET rule = ltrim(substr(rule, length(event_type) + 3))
             WHERE starts_with(rule, '[' || event_type || ']')
               AND ltrim(substr(rule, length(event_type) + 3)) <> '';",
        )?;
        init_threats(conn)?;
        let filled = backfill_threats(conn)?;
        if filled > 0 {
            tracing::info!("unifi: filled the threats table with {filled} stored detection(s)");
        }
        Ok(())
    }

    fn tables(&self) -> Vec<&'static str> {
        vec!["unifi", THREATS_TABLE]
    }

    fn ingest(&self, raw: &str, meta: &Meta, conn: &Connection) -> Result<bool> {
        let line = full_line(raw, meta);
        let line = line.trim();
        // A detection goes to both tables: the firewall view and the threats view.
        if let Some(start) = line.find("CEF:") {
            let Some(threat) = parse_threat(&line[start..]) else {
                return Ok(false);
            };
            firewall::insert(conn, "unifi", &threat.firewall_event(), meta, line)?;
            insert_threat(conn, &meta.source_ip, meta.received_at.naive_utc(), &threat, line)?;
            return Ok(true);
        }
        let Some(event) = parse_line(line) else {
            return Ok(false);
        };
        firewall::insert(conn, "unifi", &event, meta, line)?;
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
        assert_eq!(e.rule, "Block All Traffic", "the [DMZ_LAN] prefix is dropped");
        assert_eq!(e.src_zone, "br3");
        assert_eq!(e.dst_port, Some(514));
    }

    #[test]
    fn rule_names_lose_only_their_own_chain() {
        assert_eq!(rule_name("[DMZ_LAN]Block All Traffic", "DMZ_LAN"), "Block All Traffic");
        assert_eq!(rule_name("[GUEST_LOCAL] Block All Traff", "GUEST_LOCAL"), "Block All Traff");
        assert_eq!(rule_name("Allow LAN to Internet", "LAN_IN"), "Allow LAN to Internet");
        // A bracket that isn't this line's chain is part of the user's name.
        assert_eq!(rule_name("[Plex] port forward", "WAN_IN"), "[Plex] port forward");
        assert_eq!(rule_name("[DMZ_LAN]Block", "DMZ_LOCAL"), "[DMZ_LAN]Block");
        // Nothing but the label: kept whole rather than emptied.
        assert_eq!(rule_name("[WAN_LOCAL]", "WAN_LOCAL"), "[WAN_LOCAL]");
    }

    #[test]
    fn renames_rules_stored_with_a_chain_prefix() {
        let conn = Connection::open_in_memory().unwrap();
        UniFi.init_schema(&conn).unwrap();
        for (rule, chain) in [
            ("[DMZ_LAN]Block All Traffic", "DMZ_LAN"),
            ("[WAN_LOCAL]", "WAN_LOCAL"),
            ("Allow LAN", "LAN_IN"),
            ("[Plex] port forward", "WAN_IN"),
            ("ET DROP Dshield Block Listed Source group 1", "Threat Detected"),
        ] {
            conn.execute("INSERT INTO unifi (rule, event_type) VALUES (?, ?)", [rule, chain]).unwrap();
        }
        UniFi.init_schema(&conn).unwrap(); // as at the next startup
        let rules: Vec<String> = conn
            .prepare("SELECT rule FROM unifi ORDER BY rule")
            .unwrap()
            .query_map([], |r| r.get(0))
            .unwrap()
            .map(Result::unwrap)
            .collect();
        assert_eq!(
            rules,
            ["Allow LAN", "Block All Traffic", "ET DROP Dshield Block Listed Source group 1", "[Plex] port forward", "[WAN_LOCAL]"]
        );
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
    fn reads_a_threat_in_full() {
        let t = parse_threat(THREAT).expect("should parse");
        assert_eq!(t.event, "Threat Detected");
        assert_eq!(t.severity, Some(7));
        assert_eq!(t.risk, "medium");
        assert_eq!(t.signature_id, "2402000");
        assert_eq!(t.policy, "DShield Block List");
        assert_eq!(t.policy_type, "IDS/IPS");
        assert_eq!(t.direction, "incoming");
        assert_eq!(t.packets, Some(1));
        assert_eq!(t.message, "A network intrusion attempt from 203.0.113.41 to 192.168.3.13 has been detected.");
        assert_eq!(t.remote_and_local(), ("203.0.113.41", "192.168.3.13"));
        // Outgoing: a device inside reaching a bad address — the outside party
        // is the destination.
        let out = parse_threat(&THREAT.replace("UNIFIdirection=incoming", "UNIFIdirection=outgoing")).unwrap();
        assert_eq!(out.remote_and_local(), ("192.168.3.13", "203.0.113.41"));
    }

    // A threats-table row for the tests: (remote, local, risk, signature_id, raw).
    fn threat_rows(conn: &Connection) -> Vec<(String, String, String, String, String)> {
        conn.prepare("SELECT remote_ip, local_ip, risk, signature_id, raw FROM unifi_threats ORDER BY remote_ip")
            .unwrap()
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)))
            .unwrap()
            .map(Result::unwrap)
            .collect()
    }

    #[test]
    fn a_detection_lands_in_both_tables() {
        use crate::logtype::Registry;
        use chrono::Utc;

        let conn = Connection::open_in_memory().unwrap();
        Registry::with_defaults().init_all(&conn).unwrap();
        let meta = Meta {
            source_ip: "192.168.1.1".into(),
            hostname: None,
            tag: Some("CEF".into()),
            body: THREAT.to_string(),
            received_at: Utc::now(),
        };
        assert!(UniFi.ingest(THREAT.trim_start_matches("CEF:"), &meta, &conn).unwrap());
        let firewall: i64 = conn.query_row("SELECT count(*) FROM unifi", [], |r| r.get(0)).unwrap();
        assert_eq!(firewall, 1, "still on the firewall dashboard");
        let rows = threat_rows(&conn);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].0, "203.0.113.41");
        assert_eq!(rows[0].2, "medium");
        assert_eq!(rows[0].3, "2402000");
        assert_eq!(rows[0].4, THREAT);
        // A firewall-rule hit is not a threat.
        let meta = Meta { body: UCG_BLOCK.to_string(), tag: None, ..meta };
        assert!(UniFi.ingest(UCG_BLOCK, &meta, &conn).unwrap());
        assert_eq!(threat_rows(&conn).len(), 1);
    }

    #[test]
    fn fills_the_threats_table_from_stored_detections_once() {
        let conn = Connection::open_in_memory().unwrap();
        UniFi.init_schema(&conn).unwrap();
        // As stored by 0.11.x: CEF lines in the firewall table only.
        let outgoing = THREAT.replace("UNIFIdirection=incoming", "UNIFIdirection=outgoing");
        for raw in [THREAT, outgoing.as_str(), UCG_BLOCK] {
            conn.execute(
                "INSERT INTO unifi (source_ip, ts, received_at, raw)
                 VALUES ('192.168.1.1', TIMESTAMP '2026-11-07 08:59:04', TIMESTAMP '2026-11-07 08:59:05', ?)",
                [raw],
            )
            .unwrap();
        }
        UniFi.init_schema(&conn).unwrap(); // the upgrade's first start
        let rows = threat_rows(&conn);
        assert_eq!(rows.len(), 2, "both detections, not the firewall hit");
        assert_eq!(rows[0].0, "192.168.3.13", "outgoing: the outside party is the destination");
        let ts: String = conn
            .query_row("SELECT CAST(min(ts) AS VARCHAR) FROM unifi_threats", [], |r| r.get(0))
            .unwrap();
        assert_eq!(ts, "2026-11-07 08:59:04", "each row keeps its stored time");
        UniFi.init_schema(&conn).unwrap(); // every later start
        assert_eq!(threat_rows(&conn).len(), 2, "never filled twice");
    }

    #[test]
    fn retention_covers_the_threats_table() {
        use crate::logtype::Registry;
        assert!(Registry::with_defaults().tables().contains(&THREATS_TABLE));
        assert_eq!(UniFi.tables(), ["unifi", THREATS_TABLE]);
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
