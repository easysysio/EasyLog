// =============================================================================
// logtype/nginx.rs — nginx access-log parser + DuckDB storage
//
// nginx's default `combined` access-log format is identical to Apache's Combined
// Log Format, so this type reuses the Apache parser (apache::parse_line) and
// stores rows in an `nginx` table with the same schema. Routing keeps nginx and
// Apache traffic separate (different source IPs → different tables/dashboards).
// =============================================================================

use anyhow::Result;
use duckdb::{Connection, params};

use super::apache::parse_line;
use super::{LogType, Meta};

/// nginx access-log handler (zero-sized).
pub struct Nginx;

impl LogType for Nginx {
    fn name(&self) -> &'static str {
        "nginx"
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Nginx::init_schema(conn)
    // Creates the `nginx` table (same shape as the apache table) if absent.
    // ─────────────────────────────────────────────────────────────────────────
    fn init_schema(&self, conn: &Connection) -> Result<()> {
        conn.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS nginx (
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
    // Nginx::ingest(raw, meta, conn)
    // Parses one access-log line (Common/Combined, via the Apache parser) and
    // inserts it into the `nginx` table. Ok(false) when the line cannot be parsed.
    // ─────────────────────────────────────────────────────────────────────────
    fn ingest(&self, raw: &str, meta: &Meta, conn: &Connection) -> Result<bool> {
        let Some(e) = parse_line(raw) else {
            return Ok(false);
        };
        conn.execute(
            r#"INSERT INTO nginx
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
