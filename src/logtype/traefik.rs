// =============================================================================
// logtype/traefik.rs — Traefik JSON access-log parser + DuckDB storage
//
// Second EasyLog log type. Parses Traefik's JSON access-log format (one JSON
// object per syslog MSG) and inserts a typed row into the `traefik` table.
// Column names mirror the apache table where they overlap (remote_host, path,
// status, bytes, ts, …) plus Traefik specifics: router, service, duration_ms.
// Enable in Traefik with:  accessLog: { format: json }
// =============================================================================

use anyhow::Result;
use chrono::NaiveDateTime;
use duckdb::{Connection, params};
use serde::Deserialize;

use super::{LogType, Meta};

/// Traefik JSON-access-log handler (zero-sized).
pub struct Traefik;

// Subset of Traefik's JSON access-log fields that we store. All optional, since
// Traefik omits some depending on the request/config.
#[derive(Debug, Deserialize)]
struct TraefikJson {
    #[serde(rename = "ClientHost")]
    client_host: Option<String>,
    #[serde(rename = "RequestMethod")]
    method: Option<String>,
    #[serde(rename = "RequestPath")]
    path: Option<String>,
    #[serde(rename = "RequestProtocol")]
    protocol: Option<String>,
    #[serde(rename = "RequestHost")]
    host: Option<String>,
    #[serde(rename = "DownstreamStatus")]
    status: Option<i64>,
    #[serde(rename = "DownstreamContentSize")]
    bytes: Option<i64>,
    #[serde(rename = "RouterName")]
    router: Option<String>,
    #[serde(rename = "ServiceName")]
    service: Option<String>,
    #[serde(rename = "Duration")]
    duration_ns: Option<i64>,
    #[serde(rename = "StartUTC")]
    start_utc: Option<String>,
    #[serde(rename = "request_User-Agent")]
    user_agent: Option<String>,
}

impl LogType for Traefik {
    fn name(&self) -> &'static str {
        "traefik"
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Traefik::init_schema(conn)
    // Creates the `traefik` table if absent.
    // ─────────────────────────────────────────────────────────────────────────
    fn init_schema(&self, conn: &Connection) -> Result<()> {
        conn.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS traefik (
                source_ip   VARCHAR,
                remote_host VARCHAR,
                ts          TIMESTAMP,
                method      VARCHAR,
                path        VARCHAR,
                protocol    VARCHAR,
                status      INTEGER,
                bytes       BIGINT,
                router      VARCHAR,
                service     VARCHAR,
                duration_ms DOUBLE,
                user_agent  VARCHAR,
                host        VARCHAR,
                received_at TIMESTAMP,
                raw         VARCHAR
            );
            "#,
        )?;
        Ok(())
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Traefik::ingest(raw, meta, conn)
    // Parses one JSON access-log line and inserts it. Returns Ok(false) when the
    // line is not parseable JSON or clearly not a Traefik access record.
    // ─────────────────────────────────────────────────────────────────────────
    fn ingest(&self, raw: &str, meta: &Meta, conn: &Connection) -> Result<bool> {
        let Ok(j) = serde_json::from_str::<TraefikJson>(raw.trim()) else {
            return Ok(false);
        };
        // Guard against arbitrary JSON that isn't an access record.
        if j.method.is_none() && j.path.is_none() && j.status.is_none() {
            return Ok(false);
        }

        // Traefik StartUTC is RFC3339; store as a UTC-naive timestamp.
        let ts: Option<NaiveDateTime> = j
            .start_utc
            .as_deref()
            .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
            .map(|dt| dt.naive_utc());
        // Duration is nanoseconds → milliseconds.
        let duration_ms = j.duration_ns.map(|ns| ns as f64 / 1_000_000.0);
        let status = j.status.map(|s| s as i32);

        conn.execute(
            r#"INSERT INTO traefik
               (source_ip, remote_host, ts, method, path, protocol, status, bytes,
                router, service, duration_ms, user_agent, host, received_at, raw)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)"#,
            params![
                meta.source_ip,
                j.client_host.unwrap_or_default(),
                ts,
                j.method.unwrap_or_default(),
                j.path.unwrap_or_default(),
                j.protocol.unwrap_or_default(),
                status,
                j.bytes,
                j.router.unwrap_or_default(),
                j.service.unwrap_or_default(),
                duration_ms,
                j.user_agent.unwrap_or_default(),
                j.host.unwrap_or_default(),
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

    #[test]
    fn ingests_traefik_json_line() {
        let registry = Registry::with_defaults();
        let conn = duckdb::Connection::open_in_memory().unwrap();
        registry.init_all(&conn).unwrap();
        let traefik = Traefik;

        let line = r#"{"ClientHost":"203.0.113.9","RequestMethod":"GET","RequestPath":"/api/users","RequestProtocol":"HTTP/1.1","DownstreamStatus":200,"DownstreamContentSize":1234,"RouterName":"api@docker","ServiceName":"api-svc@docker","Duration":15000000,"StartUTC":"2026-06-13T10:00:00Z","request_User-Agent":"curl/8.0"}"#;
        let meta = Meta {
            source_ip: "192.168.1.9".into(),
            hostname: None,
            received_at: Utc::now(),
        };
        assert!(traefik.ingest(line, &meta, &conn).unwrap());

        let mut stmt = conn
            .prepare("SELECT remote_host, method, path, status, bytes, router, service, duration_ms FROM traefik")
            .unwrap();
        let row = stmt
            .query_map([], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, i32>(3)?,
                    r.get::<_, i64>(4)?,
                    r.get::<_, String>(5)?,
                    r.get::<_, String>(6)?,
                    r.get::<_, f64>(7)?,
                ))
            })
            .unwrap()
            .next()
            .unwrap()
            .unwrap();
        assert_eq!(row.0, "203.0.113.9");
        assert_eq!(row.1, "GET");
        assert_eq!(row.2, "/api/users");
        assert_eq!(row.3, 200);
        assert_eq!(row.4, 1234);
        assert_eq!(row.5, "api@docker");
        assert_eq!(row.6, "api-svc@docker");
        assert_eq!(row.7, 15.0); // 15_000_000 ns → 15 ms
    }

    #[test]
    fn rejects_non_json() {
        let conn = duckdb::Connection::open_in_memory().unwrap();
        Traefik.init_schema(&conn).unwrap();
        let meta = Meta { source_ip: "x".into(), hostname: None, received_at: Utc::now() };
        assert!(!Traefik.ingest("not json", &meta, &conn).unwrap());
    }
}
