// =============================================================================
// logtype/caddy.rs — Caddy JSON access-log parser + DuckDB storage
//
// Caddy v2 writes structured JSON access logs (one object per syslog MSG), with
// the request under a nested `request` object and timings at the top level:
//   {"level":"info","ts":1696067106.82,"logger":"http.log.access","msg":"handled
//    request","request":{"remote_ip":"…","client_ip":"…","proto":"HTTP/1.1",
//    "method":"GET","host":"…","uri":"/","headers":{"User-Agent":["…"]}},
//    "bytes_read":0,"user_id":"","duration":0.0032,"size":32,"status":302}
//
// Columns mirror the traefik table where they overlap (remote_host, path, status,
// bytes, duration_ms, …) so both share the proxy dashboard. Caddy reports the
// duration in seconds — it is stored in milliseconds like every other type.
//
// Enable in a Caddyfile with:  log { output … format json }
// =============================================================================

use std::collections::HashMap;

use anyhow::Result;
use chrono::NaiveDateTime;
use duckdb::{Connection, params};
use serde::Deserialize;

use super::{Category, LogType, Meta};

/// Caddy JSON-access-log handler (zero-sized).
pub struct Caddy;

// The subset of Caddy's access-log entry we store. Everything is optional:
// fields come and go across Caddy versions and configurations.
#[derive(Debug, Deserialize)]
struct CaddyJson {
    msg: Option<String>,
    /// Epoch seconds (default) or an RFC3339 string when `time_format` is set.
    ts: Option<serde_json::Value>,
    request: Option<CaddyRequest>,
    status: Option<i64>,
    /// Response body size in bytes.
    size: Option<i64>,
    /// Request duration in **seconds**.
    duration: Option<f64>,
    bytes_read: Option<i64>,
}

#[derive(Debug, Deserialize)]
struct CaddyRequest {
    /// Real client IP once trusted proxies are configured (Caddy ≥ 2.7).
    client_ip: Option<String>,
    /// Peer IP (Caddy ≥ 2.5).
    remote_ip: Option<String>,
    /// Peer "ip:port" on older Caddy versions.
    remote_addr: Option<String>,
    proto: Option<String>,
    method: Option<String>,
    host: Option<String>,
    uri: Option<String>,
    headers: Option<HashMap<String, Vec<String>>>,
}

// ─────────────────────────────────────────────────────────────────────────────
// client_ip(request)
// The best available client address: the trusted-proxy-resolved `client_ip`,
// else the peer `remote_ip`, else the older `remote_addr` with its port removed
// ("1.2.3.4:5678" and "[::1]:5678" both yield the bare address).
// ─────────────────────────────────────────────────────────────────────────────
fn client_ip(request: &CaddyRequest) -> String {
    if let Some(ip) = request.client_ip.as_deref().filter(|s| !s.is_empty()) {
        return ip.to_string();
    }
    if let Some(ip) = request.remote_ip.as_deref().filter(|s| !s.is_empty()) {
        return ip.to_string();
    }
    let Some(addr) = request.remote_addr.as_deref().filter(|s| !s.is_empty()) else {
        return String::new();
    };
    match addr.rsplit_once(':') {
        // "[::1]:5678" → "::1"; a bare IPv6 literal has no port to strip.
        Some((host, _)) => host.trim_start_matches('[').trim_end_matches(']').to_string(),
        None => addr.to_string(),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// timestamp(value)
// Caddy logs `ts` as fractional epoch seconds by default, or as an RFC3339
// string when `time_format` is configured. Both become UTC-naive timestamps.
// ─────────────────────────────────────────────────────────────────────────────
fn timestamp(value: Option<&serde_json::Value>) -> Option<NaiveDateTime> {
    match value? {
        serde_json::Value::Number(n) => {
            let secs = n.as_f64()?;
            let nanos = ((secs - secs.floor()) * 1_000_000_000.0).round() as u32;
            chrono::DateTime::from_timestamp(secs.floor() as i64, nanos).map(|dt| dt.naive_utc())
        }
        serde_json::Value::String(s) => chrono::DateTime::parse_from_rfc3339(s)
            .ok()
            .map(|dt| dt.naive_utc()),
        _ => None,
    }
}

// First value of a request header, or "" when absent.
fn header(headers: &Option<HashMap<String, Vec<String>>>, name: &str) -> String {
    headers
        .as_ref()
        .and_then(|h| h.get(name))
        .and_then(|v| v.first())
        .cloned()
        .unwrap_or_default()
}

impl LogType for Caddy {
    fn name(&self) -> &'static str {
        "caddy"
    }

    fn category(&self) -> Category {
        Category::Web
    }

    fn label(&self) -> &'static str {
        "Caddy"
    }

    fn icon(&self) -> &'static str {
        "bi-shield-check"
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Caddy::init_schema(conn)
    // Creates the `caddy` table if absent.
    // ─────────────────────────────────────────────────────────────────────────
    fn init_schema(&self, conn: &Connection) -> Result<()> {
        conn.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS caddy (
                source_ip    VARCHAR,
                remote_host  VARCHAR,
                ts           TIMESTAMP,
                method       VARCHAR,
                path         VARCHAR,
                protocol     VARCHAR,
                status       INTEGER,
                bytes        BIGINT,
                bytes_read   BIGINT,
                duration_ms  DOUBLE,
                user_agent   VARCHAR,
                referer      VARCHAR,
                host         VARCHAR,
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
    // Caddy::ingest(raw, meta, conn)
    // Parses one JSON access-log entry and inserts it. Returns Ok(false) for
    // anything that isn't a Caddy access record — Caddy writes other structured
    // messages (startup, TLS, admin) to the same stream.
    // ─────────────────────────────────────────────────────────────────────────
    fn ingest(&self, raw: &str, meta: &Meta, conn: &Connection) -> Result<bool> {
        let Ok(j) = serde_json::from_str::<CaddyJson>(raw.trim()) else {
            return Ok(false);
        };
        let Some(request) = j.request else {
            return Ok(false);
        };
        // A request object alone isn't enough — an error entry can carry one
        // too. Access records always report the outcome.
        if j.status.is_none() && request.method.is_none() {
            return Ok(false);
        }
        if let Some(msg) = j.msg.as_deref() {
            if msg != "handled request" {
                return Ok(false);
            }
        }

        let remote_host = client_ip(&request);
        let (country_code, country) = crate::geo::lookup(&remote_host);
        // Caddy reports seconds; every other log type stores milliseconds.
        let duration_ms = j.duration.map(|s| s * 1000.0);
        let status = j.status.map(|s| s as i32);
        let user_agent = header(&request.headers, "User-Agent");
        let referer = header(&request.headers, "Referer");

        conn.execute(
            r#"INSERT INTO caddy
               (source_ip, remote_host, ts, method, path, protocol, status, bytes,
                bytes_read, duration_ms, user_agent, referer, host, country,
                country_code, received_at, raw)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)"#,
            params![
                meta.source_ip,
                remote_host,
                timestamp(j.ts.as_ref()),
                request.method.unwrap_or_default(),
                request.uri.unwrap_or_default(),
                request.proto.unwrap_or_default(),
                status,
                j.size,
                j.bytes_read,
                duration_ms,
                user_agent,
                referer,
                request.host.unwrap_or_default(),
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
    use crate::logtype::Registry;
    use chrono::Utc;

    fn meta() -> Meta {
        Meta {
            source_ip: "192.168.1.20".into(),
            hostname: None,
            received_at: Utc::now(),
        }
    }

    fn conn() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        Registry::with_defaults().init_all(&conn).unwrap();
        conn
    }

    #[test]
    fn ingests_a_caddy_access_entry() {
        let line = r#"{"level":"info","ts":1696067106.8245707,"logger":"http.log.access.arm","msg":"handled request","request":{"remote_ip":"134.209.243.63","remote_port":"57526","client_ip":"134.209.243.63","proto":"HTTP/1.1","method":"GET","host":"arm.example.net","uri":"/index.html","headers":{"User-Agent":["curl/8.4.0"],"Referer":["https://example.net/"]}},"bytes_read":0,"user_id":"","duration":0.00328789,"size":32,"status":302}"#;
        let conn = conn();
        assert!(Caddy.ingest(line, &meta(), &conn).unwrap());

        let mut stmt = conn
            .prepare("SELECT remote_host, method, path, protocol, status, bytes, duration_ms, user_agent, referer, host, CAST(ts AS VARCHAR) FROM caddy")
            .unwrap();
        let row = stmt
            .query_row([], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, String>(3)?,
                    r.get::<_, i32>(4)?,
                    r.get::<_, i64>(5)?,
                    r.get::<_, f64>(6)?,
                    r.get::<_, String>(7)?,
                    r.get::<_, String>(8)?,
                    r.get::<_, String>(9)?,
                    r.get::<_, String>(10)?,
                ))
            })
            .unwrap();
        assert_eq!(row.0, "134.209.243.63");
        assert_eq!(row.1, "GET");
        assert_eq!(row.2, "/index.html");
        assert_eq!(row.3, "HTTP/1.1");
        assert_eq!(row.4, 302);
        assert_eq!(row.5, 32);
        // 0.00328789 s → ms
        assert!((row.6 - 3.28789).abs() < 0.0001, "duration was {}", row.6);
        assert_eq!(row.7, "curl/8.4.0");
        assert_eq!(row.8, "https://example.net/");
        assert_eq!(row.9, "arm.example.net");
        assert!(row.10.starts_with("2023-09-30"), "epoch ts became {}", row.10);
    }

    #[test]
    fn falls_back_to_remote_addr_on_older_caddy() {
        // Caddy < 2.5 has no remote_ip/client_ip, just "ip:port".
        let line = r#"{"level":"info","ts":1696067106.5,"msg":"handled request","request":{"remote_addr":"203.0.113.9:41342","proto":"HTTP/2.0","method":"POST","host":"h","uri":"/api"},"duration":0.5,"size":10,"status":201}"#;
        let conn = conn();
        assert!(Caddy.ingest(line, &meta(), &conn).unwrap());
        let host: String = conn
            .prepare("SELECT remote_host FROM caddy")
            .unwrap()
            .query_row([], |r| r.get(0))
            .unwrap();
        assert_eq!(host, "203.0.113.9");
    }

    #[test]
    fn parses_an_ipv6_remote_addr_and_rfc3339_timestamp() {
        let line = r#"{"level":"info","ts":"2026-08-16T10:11:12Z","msg":"handled request","request":{"remote_addr":"[2606:4700::1111]:443","method":"GET","uri":"/"},"status":200,"size":5}"#;
        let conn = conn();
        assert!(Caddy.ingest(line, &meta(), &conn).unwrap());
        let (host, ts): (String, String) = conn
            .prepare("SELECT remote_host, CAST(ts AS VARCHAR) FROM caddy")
            .unwrap()
            .query_row([], |r| Ok((r.get(0)?, r.get(1)?)))
            .unwrap();
        assert_eq!(host, "2606:4700::1111");
        assert!(ts.starts_with("2026-08-16 10:11:12"), "ts was {ts}");
    }

    #[test]
    fn rejects_non_access_entries() {
        let conn = conn();
        // Caddy's own lifecycle messages share the log stream.
        let startup = r#"{"level":"info","ts":1696067106.0,"logger":"tls","msg":"finished cleaning storage units"}"#;
        assert!(!Caddy.ingest(startup, &meta(), &conn).unwrap());
        // A non-access message that happens to carry a request object.
        let other = r#"{"level":"error","ts":1696067106.0,"msg":"dial backend","request":{"remote_ip":"1.2.3.4"}}"#;
        assert!(!Caddy.ingest(other, &meta(), &conn).unwrap());
        assert!(!Caddy.ingest("not json at all", &meta(), &conn).unwrap());
        // Traefik's JSON must not be swallowed by the Caddy parser.
        let traefik = r#"{"ClientHost":"203.0.113.9","RequestMethod":"GET","DownstreamStatus":200}"#;
        assert!(!Caddy.ingest(traefik, &meta(), &conn).unwrap());
    }
}
