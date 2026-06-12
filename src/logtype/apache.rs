// =============================================================================
// logtype/apache.rs — Apache Combined Log Format parser + DuckDB storage
//
// Implements the first EasyLog log type. Parses the Apache "combined" access
// log line (the syslog MSG field), splits the request into method/path/protocol,
// parses the timestamp, and inserts a typed row into the `apache` DuckDB table.
// Combined format:
//   %h %l %u %t "%r" %>s %b "%{Referer}i" "%{User-agent}i"
// =============================================================================

use anyhow::Result;
use chrono::NaiveDateTime;
use duckdb::{Connection, params};
use regex::Regex;
use std::sync::OnceLock;

use super::{LogType, Meta};

/// Apache combined-log-format handler (zero-sized; holds no state).
pub struct Apache;

// One parsed Apache access-log line. `bytes` is None when the field is "-".
#[derive(Debug, Clone, PartialEq)]
pub struct ApacheEntry {
    pub remote_host: String,
    pub ident: String,
    pub auth_user: String,
    pub ts: Option<NaiveDateTime>,
    pub method: String,
    pub path: String,
    pub protocol: String,
    pub status: Option<i32>,
    pub bytes: Option<i64>,
    pub referer: String,
    pub user_agent: String,
}

// Lazily-compiled regex for the combined log format. Compiled once, reused for
// every line. Capture groups map 1:1 to the format fields above.
fn line_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r#"^(?P<host>\S+) (?P<ident>\S+) (?P<user>\S+) \[(?P<time>[^\]]+)\] "(?P<req>[^"]*)" (?P<status>\d{3}|-) (?P<bytes>\d+|-) "(?P<ref>[^"]*)" "(?P<ua>[^"]*)""#,
        )
        .expect("apache combined-format regex is valid")
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// parse_combined(line)
// Parses a single Apache combined-format access-log line into an ApacheEntry.
// Returns None if the line does not match the expected shape.
// ─────────────────────────────────────────────────────────────────────────────
pub fn parse_combined(line: &str) -> Option<ApacheEntry> {
    let caps = line_regex().captures(line.trim())?;

    // Request line "METHOD PATH PROTOCOL" — may be malformed or "-".
    let req = &caps["req"];
    let mut parts = req.splitn(3, ' ');
    let method = parts.next().unwrap_or("").to_string();
    let path = parts.next().unwrap_or("").to_string();
    let protocol = parts.next().unwrap_or("").to_string();

    // Apache time: "10/Oct/2000:13:55:36 -0700" → store as UTC-naive timestamp.
    let ts = chrono::DateTime::parse_from_str(&caps["time"], "%d/%b/%Y:%H:%M:%S %z")
        .ok()
        .map(|dt| dt.naive_utc());

    let status = caps["status"].parse::<i32>().ok();
    let bytes = caps["bytes"].parse::<i64>().ok();

    Some(ApacheEntry {
        remote_host: caps["host"].to_string(),
        ident: caps["ident"].to_string(),
        auth_user: caps["user"].to_string(),
        ts,
        method,
        path,
        protocol,
        status,
        bytes,
        referer: caps["ref"].to_string(),
        user_agent: caps["ua"].to_string(),
    })
}

impl LogType for Apache {
    fn name(&self) -> &'static str {
        "apache"
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Apache::init_schema(conn)
    // Creates the `apache` table if absent. Columns mirror ApacheEntry plus the
    // syslog envelope (source_ip, received_at) and the original raw line.
    // ─────────────────────────────────────────────────────────────────────────
    fn init_schema(&self, conn: &Connection) -> Result<()> {
        conn.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS apache (
                source_ip   VARCHAR,
                remote_host VARCHAR,
                ident       VARCHAR,
                auth_user   VARCHAR,
                ts          TIMESTAMP,
                method      VARCHAR,
                path        VARCHAR,
                protocol    VARCHAR,
                status      INTEGER,
                bytes       BIGINT,
                referer     VARCHAR,
                user_agent  VARCHAR,
                received_at TIMESTAMP,
                raw         VARCHAR
            );
            "#,
        )?;
        Ok(())
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Apache::ingest(raw, meta, conn)
    // Parses one combined-format line and inserts it into the `apache` table.
    // Returns Ok(false) when the line cannot be parsed (a drop, not an error).
    // ─────────────────────────────────────────────────────────────────────────
    fn ingest(&self, raw: &str, meta: &Meta, conn: &Connection) -> Result<bool> {
        let Some(e) = parse_combined(raw) else {
            return Ok(false);
        };
        conn.execute(
            r#"INSERT INTO apache
               (source_ip, remote_host, ident, auth_user, ts, method, path,
                protocol, status, bytes, referer, user_agent, received_at, raw)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)"#,
            params![
                meta.source_ip,
                e.remote_host,
                e.ident,
                e.auth_user,
                e.ts,
                e.method,
                e.path,
                e.protocol,
                e.status,
                e.bytes,
                e.referer,
                e.user_agent,
                meta.received_at.naive_utc(),
                raw,
            ],
        )?;
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_canonical_combined_line() {
        let line = r#"127.0.0.1 - frank [10/Oct/2000:13:55:36 -0700] "GET /apache_pb.gif HTTP/1.0" 200 2326 "http://www.example.com/start.html" "Mozilla/4.08 [en] (Win98; I ;Nav)""#;
        let e = parse_combined(line).expect("should parse");
        assert_eq!(e.remote_host, "127.0.0.1");
        assert_eq!(e.auth_user, "frank");
        assert_eq!(e.method, "GET");
        assert_eq!(e.path, "/apache_pb.gif");
        assert_eq!(e.protocol, "HTTP/1.0");
        assert_eq!(e.status, Some(200));
        assert_eq!(e.bytes, Some(2326));
        assert_eq!(e.referer, "http://www.example.com/start.html");
        assert!(e.user_agent.starts_with("Mozilla/4.08"));
        assert!(e.ts.is_some());
    }

    #[test]
    fn handles_dash_bytes_and_empty_user() {
        let line = r#"10.0.0.5 - - [12/Jun/2026:09:00:00 +0000] "POST /api/login HTTP/1.1" 401 - "-" "curl/8.0""#;
        let e = parse_combined(line).expect("should parse");
        assert_eq!(e.auth_user, "-");
        assert_eq!(e.method, "POST");
        assert_eq!(e.status, Some(401));
        assert_eq!(e.bytes, None);
        assert_eq!(e.referer, "-");
    }

    #[test]
    fn rejects_non_apache_line() {
        assert!(parse_combined("this is not an apache log line").is_none());
    }
}
