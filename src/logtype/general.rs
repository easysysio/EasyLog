// =============================================================================
// logtype/general.rs — general logs: the line, unparsed
//
// Every other log type understands its format and refuses what it doesn't. This
// one accepts anything: it stores the message exactly as received, alongside
// what the syslog envelope already told us — the sending address, the hostname
// the sender claimed, and its tag (APP-NAME).
//
// That makes it the type to point a device at when EasyLog has no parser for it,
// or when you just want to see what a host is actually sending before deciding
// what to do with it. Nothing is dropped: a line that no parser could read is
// still a line worth keeping.
//
// The dashboard over this table is deliberately thin (see web/general.rs): how
// much is arriving, from whom, and the lines themselves — there are no parsed
// fields to chart.
// =============================================================================

use anyhow::Result;
use duckdb::{Connection, params};

use super::{Category, LogType, Meta};

/// Unparsed-syslog handler (zero-sized).
pub struct General;

impl LogType for General {
    fn name(&self) -> &'static str {
        "syslog"
    }

    fn category(&self) -> Category {
        Category::General
    }

    fn label(&self) -> &'static str {
        "General logs"
    }

    fn icon(&self) -> &'static str {
        "bi-journal-text"
    }

    // ─────────────────────────────────────────────────────────────────────────
    // General::init_schema(conn)
    // Creates the `syslog` table if absent. `ts` is the arrival time: with no
    // parser there is no event timestamp to trust, and retention needs a column
    // to age rows by.
    // ─────────────────────────────────────────────────────────────────────────
    // No client address is parsed out of an arbitrary line, so there is nothing
    // to geolocate and the table has no country columns.
    fn has_geo(&self) -> bool {
        false
    }

    fn init_schema(&self, conn: &Connection) -> Result<()> {
        conn.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS syslog (
                source_ip   VARCHAR,
                ts          TIMESTAMP,
                hostname    VARCHAR,
                tag         VARCHAR,
                received_at TIMESTAMP,
                raw         VARCHAR
            );
            "#,
        )?;
        Ok(())
    }

    // ─────────────────────────────────────────────────────────────────────────
    // General::ingest(raw, meta, conn)
    // Stores the line as-is. The only thing rejected is an empty message, which
    // would just be noise; everything else is kept, since keeping what we can't
    // parse is the entire point of this type.
    // ─────────────────────────────────────────────────────────────────────────
    fn ingest(&self, raw: &str, meta: &Meta, conn: &Connection) -> Result<bool> {
        // meta.body is the line with its tag restored; raw has been through the
        // syslog parser, which may have taken the first word for a tag.
        let line = if meta.body.trim().is_empty() { raw } else { meta.body.as_str() };
        if line.trim().is_empty() {
            return Ok(false);
        }
        let received = meta.received_at.naive_utc();
        conn.execute(
            r#"INSERT INTO syslog (source_ip, ts, hostname, tag, received_at, raw)
               VALUES (?,?,?,?,?,?)"#,
            params![
                meta.source_ip,
                received,
                meta.hostname.clone().unwrap_or_default(),
                meta.tag.clone().unwrap_or_default(),
                received,
                line,
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
            source_ip: "192.168.1.50".into(),
            hostname: Some("router1".into()),
            tag: Some("kernel".into()),
            body: String::new(),
            received_at: Utc::now(),
        }
    }

    #[test]
    fn stores_any_line_verbatim() {
        let conn = Connection::open_in_memory().unwrap();
        Registry::with_defaults().init_all(&conn).unwrap();
        // Something no other parser would touch.
        let line = "kernel: [12345.678] wlan0: deauthenticating from aa:bb:cc:dd:ee:ff by local choice";
        assert!(General.ingest(line, &meta(), &conn).unwrap());

        let (src, host, tag, raw): (String, String, String, String) = conn
            .prepare("SELECT source_ip, hostname, tag, raw FROM syslog")
            .unwrap()
            .query_row([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))
            .unwrap();
        assert_eq!(src, "192.168.1.50");
        assert_eq!(host, "router1");
        assert_eq!(tag, "kernel");
        assert_eq!(raw, line, "the line must be stored exactly as received");
    }

    #[test]
    fn accepts_what_every_other_parser_rejects() {
        let conn = Connection::open_in_memory().unwrap();
        Registry::with_defaults().init_all(&conn).unwrap();
        for line in [
            "not a log line at all",
            "<<<>>> ???",
            r#"{"partial":"json"#,
            "2026-08-17 something happened",
        ] {
            assert!(General.ingest(line, &meta(), &conn).unwrap(), "should keep {line:?}");
        }
        let n: i64 = conn
            .prepare("SELECT count(*) FROM syslog")
            .unwrap()
            .query_row([], |r| r.get(0))
            .unwrap();
        assert_eq!(n, 4);
    }

    #[test]
    fn stores_the_line_with_its_tag_restored() {
        // syslog_loose takes the first token as the APP-NAME, so a line with no
        // real tag arrives stripped of its first word. meta.body carries the
        // original, and that is what gets stored.
        let conn = Connection::open_in_memory().unwrap();
        Registry::with_defaults().init_all(&conn).unwrap();
        let meta = Meta {
            source_ip: "192.168.1.50".into(),
            hostname: Some("router1".into()),
            tag: Some("a".into()),
            body: "a bare line with no tag whatsoever".into(),
            received_at: Utc::now(),
        };
        assert!(General.ingest("bare line with no tag whatsoever", &meta, &conn).unwrap());
        let raw: String = conn
            .prepare("SELECT raw FROM syslog")
            .unwrap()
            .query_row([], |r| r.get(0))
            .unwrap();
        assert_eq!(raw, "a bare line with no tag whatsoever");
    }

    #[test]
    fn skips_an_empty_message() {
        let conn = Connection::open_in_memory().unwrap();
        Registry::with_defaults().init_all(&conn).unwrap();
        assert!(!General.ingest("   ", &meta(), &conn).unwrap());
    }
}
