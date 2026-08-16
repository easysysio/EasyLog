// =============================================================================
// logtype/haproxy.rs — HAProxy HTTP log parser + DuckDB storage
//
// Parses HAProxy's `option httplog` line, which is positional rather than
// structured:
//
//   203.0.113.7:54321 [16/Aug/2026:10:00:00.123] https-in~ web-back/srv1
//     12/0/1/45/58 200 1234 - - ---- 10/10/0/1/0 0/0 "GET /path HTTP/1.1"
//    └client:port  └accept date      └frontend  └backend/server
//     └timers Tq/Tw/Tc/Tr/Tt (ms)  └status └bytes  └cookies └termination
//     └actconn/feconn/beconn/srv_conn/retries └queues └request
//
// The last timer (Tt) is the total session time and becomes duration_ms, so
// HAProxy shares the duration-carrying dashboard with Traefik and Caddy, with
// backend and server as its routing dimensions. A timer of -1 means the request
// never completed and is stored as NULL rather than a negative duration.
//
// Captured request/response headers (`capture request header …`) appear as
// {a|b} blocks before the quoted request and are skipped. `option tcplog` lines
// carry no status or request and are rejected.
// =============================================================================

use anyhow::Result;
use chrono::NaiveDateTime;
use duckdb::{Connection, params};
use regex::Regex;
use std::sync::OnceLock;

use super::{Category, LogType, Meta};

/// HAProxy HTTP-log handler (zero-sized).
pub struct HAProxy;

/// One parsed HAProxy HTTP log line.
#[derive(Debug, Clone, PartialEq)]
pub struct HAProxyEntry {
    pub remote_host: String,
    pub ts: Option<NaiveDateTime>,
    pub frontend: String,
    pub backend: String,
    pub server: String,
    pub method: String,
    pub path: String,
    pub protocol: String,
    pub status: Option<i32>,
    pub bytes: Option<i64>,
    /// Total session time (Tt), in milliseconds; None when HAProxy logged -1.
    pub duration_ms: Option<f64>,
    /// Four-character session termination state, e.g. "----" or "sHVN".
    pub termination: String,
}

// Lazily-compiled regex for the httplog format. Compiled once, reused per line.
fn line_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r#"(?x)
            ^(?:\S+\[\d+\]:\s+)?                    # optional "haproxy[1234]: " tag
            (?P<client>\S+):(?P<cport>\d+)\s+       # client ip:port (IPv6 keeps its colons)
            \[(?P<ts>[^\]]+)\]\s+
            (?P<frontend>\S+)\s+                    # frontend, may carry a ~ suffix
            (?P<backend>[^/\s]+)/(?P<server>\S+)\s+
            (?P<t1>-?\d+)/(?P<t2>-?\d+)/(?P<t3>-?\d+)/(?P<t4>-?\d+)/(?P<tt>-?\d+)\s+
            (?P<status>-?\d+)\s+
            (?P<bytes>-?\d+)\s+
            (?P<reqcookie>\S+)\s+(?P<respcookie>\S+)\s+
            (?P<term>\S{4})\s+
            \d+/\d+/\d+/\d+/\d+\s+                  # actconn/feconn/beconn/srv_conn/retries
            \d+/\d+                                 # srv_queue/backend_queue
            (?:\s+\{[^}]*\})*                       # captured headers, if configured
            \s+"(?P<req>[^"]*)"
            "#,
        )
        .expect("haproxy httplog regex is valid")
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// parse_line(line)
// Parses one HAProxy HTTP log line. Returns None for anything that isn't one —
// tcplog lines, HAProxy's own notices, or another daemon's output.
// ─────────────────────────────────────────────────────────────────────────────
pub fn parse_line(line: &str) -> Option<HAProxyEntry> {
    let caps = line_regex().captures(line.trim())?;

    // Request line "METHOD PATH PROTOCOL"; HAProxy logs "<BADREQ>" for junk.
    let req = &caps["req"];
    let mut parts = req.splitn(3, ' ');
    let method = parts.next().unwrap_or("").to_string();
    let path = parts.next().unwrap_or("").to_string();
    let protocol = parts.next().unwrap_or("").to_string();

    // Accept date: "16/Aug/2026:10:00:00.123" (always local time, no offset).
    let ts = NaiveDateTime::parse_from_str(&caps["ts"], "%d/%b/%Y:%H:%M:%S%.3f").ok();

    // Tt is -1 when the session ended before completing.
    let duration_ms = caps["tt"].parse::<i64>().ok().filter(|&t| t >= 0).map(|t| t as f64);

    Some(HAProxyEntry {
        remote_host: caps["client"].to_string(),
        ts,
        frontend: caps["frontend"].to_string(),
        backend: caps["backend"].to_string(),
        server: caps["server"].to_string(),
        method,
        path,
        protocol,
        status: caps["status"].parse::<i32>().ok().filter(|&s| s > 0),
        bytes: caps["bytes"].parse::<i64>().ok().filter(|&b| b >= 0),
        duration_ms,
        termination: caps["term"].to_string(),
    })
}

impl LogType for HAProxy {
    fn name(&self) -> &'static str {
        "haproxy"
    }

    fn category(&self) -> Category {
        Category::Web
    }

    fn label(&self) -> &'static str {
        "HAProxy"
    }

    fn icon(&self) -> &'static str {
        "bi-shuffle"
    }

    // ─────────────────────────────────────────────────────────────────────────
    // HAProxy::init_schema(conn)
    // Creates the `haproxy` table if absent. Column names match the other
    // request logs where they overlap, so the shared dashboard just works.
    // ─────────────────────────────────────────────────────────────────────────
    fn init_schema(&self, conn: &Connection) -> Result<()> {
        conn.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS haproxy (
                source_ip    VARCHAR,
                remote_host  VARCHAR,
                ts           TIMESTAMP,
                method       VARCHAR,
                path         VARCHAR,
                protocol     VARCHAR,
                status       INTEGER,
                bytes        BIGINT,
                duration_ms  DOUBLE,
                frontend     VARCHAR,
                backend      VARCHAR,
                server       VARCHAR,
                termination  VARCHAR,
                country      VARCHAR,
                country_code VARCHAR,
                received_at  TIMESTAMP,
                raw          VARCHAR
            );
            "#,
        )?;
        Ok(())
    }

    // ─────────────────────────────────────────────────────────────────────────
    // HAProxy::ingest(raw, meta, conn)
    // Parses one httplog line and inserts it. Returns Ok(false) when the line
    // isn't an HTTP log record (a drop, not an error).
    // ─────────────────────────────────────────────────────────────────────────
    fn ingest(&self, raw: &str, meta: &Meta, conn: &Connection) -> Result<bool> {
        let Some(e) = parse_line(raw) else {
            return Ok(false);
        };
        let (country_code, country) = crate::geo::lookup(&e.remote_host);
        conn.execute(
            r#"INSERT INTO haproxy
               (source_ip, remote_host, ts, method, path, protocol, status, bytes,
                duration_ms, frontend, backend, server, termination, country,
                country_code, received_at, raw)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)"#,
            params![
                meta.source_ip,
                e.remote_host,
                e.ts,
                e.method,
                e.path,
                e.protocol,
                e.status,
                e.bytes,
                e.duration_ms,
                e.frontend,
                e.backend,
                e.server,
                e.termination,
                country,
                country_code,
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

    const LINE: &str = r#"haproxy[1234]: 203.0.113.7:54321 [16/Aug/2026:10:00:00.123] https-in~ web-back/srv1 12/0/1/45/58 200 1234 - - ---- 10/10/0/1/0 0/0 "GET /api/items?page=2 HTTP/1.1""#;

    #[test]
    fn parses_a_canonical_httplog_line() {
        let e = parse_line(LINE).expect("should parse");
        assert_eq!(e.remote_host, "203.0.113.7");
        assert_eq!(e.frontend, "https-in~");
        assert_eq!(e.backend, "web-back");
        assert_eq!(e.server, "srv1");
        assert_eq!(e.method, "GET");
        assert_eq!(e.path, "/api/items?page=2");
        assert_eq!(e.protocol, "HTTP/1.1");
        assert_eq!(e.status, Some(200));
        assert_eq!(e.bytes, Some(1234));
        assert_eq!(e.duration_ms, Some(58.0)); // Tt, the last timer
        assert_eq!(e.termination, "----");
        assert_eq!(
            e.ts.map(|t| t.to_string()),
            Some("2026-08-16 10:00:00.123".to_string())
        );
    }

    #[test]
    fn parses_without_the_process_tag() {
        // rsyslog templates often forward the message without "haproxy[pid]:".
        let bare = LINE.strip_prefix("haproxy[1234]: ").unwrap();
        let e = parse_line(bare).expect("should parse");
        assert_eq!(e.backend, "web-back");
        assert_eq!(e.status, Some(200));
    }

    #[test]
    fn handles_ipv6_clients_captured_headers_and_aborted_sessions() {
        // IPv6 client, two capture blocks, Tt = -1 (client gave up), no status.
        let line = r#"haproxy[9]: 2001:db8::10:443 [16/Aug/2026:10:00:00.500] fe be/<NOSRV> 0/0/-1/-1/-1 -1 0 - - CC-- 5/5/0/0/0 0/0 {example.net|curl/8.4.0} {} "GET /slow HTTP/1.1""#;
        let e = parse_line(line).expect("should parse");
        assert_eq!(e.remote_host, "2001:db8::10");
        assert_eq!(e.server, "<NOSRV>");
        assert_eq!(e.duration_ms, None, "-1 must not become a negative duration");
        assert_eq!(e.status, None, "-1 status means no response was sent");
        assert_eq!(e.bytes, Some(0));
        assert_eq!(e.termination, "CC--");
    }

    #[test]
    fn rejects_lines_that_are_not_http_logs() {
        // tcplog: no status, no request.
        let tcp = r#"haproxy[1]: 203.0.113.7:1234 [16/Aug/2026:10:00:00.000] fe be/srv 1/0/5 333 -- 1/1/0/0/0 0/0"#;
        assert!(parse_line(tcp).is_none());
        // HAProxy's own notices.
        assert!(parse_line("haproxy[1]: Proxy web-back started.").is_none());
        // A different log format entirely.
        assert!(
            parse_line(r#"127.0.0.1 - frank [10/Oct/2000:13:55:36 -0700] "GET /a HTTP/1.0" 200 2326"#)
                .is_none()
        );
    }

    #[test]
    fn ingests_into_the_haproxy_table() {
        use crate::logtype::Registry;
        use chrono::Utc;

        let conn = Connection::open_in_memory().unwrap();
        Registry::with_defaults().init_all(&conn).unwrap();
        let meta = Meta {
            source_ip: "192.168.1.30".into(),
            hostname: None,
            received_at: Utc::now(),
        };
        assert!(HAProxy.ingest(LINE, &meta, &conn).unwrap());

        let (host, backend, server, status, duration): (String, String, String, i32, f64) = conn
            .prepare("SELECT remote_host, backend, server, status, duration_ms FROM haproxy")
            .unwrap()
            .query_row([], |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?))
            })
            .unwrap();
        assert_eq!(host, "203.0.113.7");
        assert_eq!(backend, "web-back");
        assert_eq!(server, "srv1");
        assert_eq!(status, 200);
        assert_eq!(duration, 58.0);
    }
}
