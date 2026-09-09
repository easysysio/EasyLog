// =============================================================================
// logtype/easywaf.rs — EasyWAF event-log parser (logfmt over syslog)
//
// EasyWAF (0.9.0 onwards) sends one UDP datagram per proxied request: RFC 3164
// framing, then a logfmt payload —
//
//   ts=2026-09-09T10:14:22Z site=cloud host=cloud.example client=203.0.113.9 \
//   country=DE method=GET path=/index.php status=403 ms=4 verdict=blocked \
//   score=15 rules=942100,932001 reason="WAF score 15 ≥ block threshold 10"
//
// What makes this its own type rather than an access log is `verdict`, `score`
// and `rules`: a WAF's log says *why* a request was refused, and — just as
// importantly — which requests were served that an enforcing policy would have
// refused (`would_block`, `would_challenge`) or that scored below the threshold
// (`scored`). Flattening those into allow/deny, as the shared firewall shape in
// logtype/firewall.rs would, throws away the reason the logs exist.
//
// Parsing rules, per the EasyWAF specification:
//   * split on whitespace *outside* double quotes, honouring \\ and \" — `path`
//     and `reason` are attacker-influenced and are usually the quoted ones, so a
//     naive split on spaces can be made to forge fields;
//   * split each token on the FIRST '=' only, since values contain '=';
//   * ignore unknown keys rather than reject the line — new fields are expected
//     in both directions;
//   * a missing optional key is absent, not zero: `score` absent (no rule
//     matched at all) and `score=0` are different facts, so score is NULL-able;
//   * a line without ts, verdict or client is malformed — dropped whole rather
//     than stored as a partial row.
//
// Delivery is fire-and-forget: EasyWAF drops lines rather than blocking its
// request path, so a count here is a sample of traffic, never a complete tally.
// =============================================================================

use anyhow::Result;
use chrono::{DateTime, NaiveDateTime};
use duckdb::{Connection, params};

use super::{Category, LogType, Meta};

/// EasyWAF event-log handler (zero-sized).
pub struct EasyWaf;

/// One parsed EasyWAF event. Optional fields stay `None` when the key was
/// absent — the specification is explicit that absent and zero differ.
#[derive(Debug, Clone, PartialEq)]
pub struct WafEvent {
    pub ts: NaiveDateTime,
    pub site: String,
    pub host: String,
    pub client: String,
    /// ISO 3166-1 alpha-2 as EasyWAF resolved it; absent for private ranges.
    pub country: String,
    pub method: String,
    pub path: String,
    pub status: Option<i32>,
    pub ms: Option<i32>,
    pub verdict: String,
    pub score: Option<i32>,
    /// Catalogue rule numbers, comma-separated, as received.
    pub rules: String,
    pub reason: String,
}

/// The verdicts EasyWAF emits. Kept as a list rather than an enum: an unknown
/// verdict from a newer EasyWAF is stored and shown as itself instead of being
/// dropped, which is the same forward-compatibility bargain as unknown keys.
pub const VERDICTS: [&str; 6] =
    ["passed", "scored", "challenged", "blocked", "would_block", "would_challenge"];

// ─────────────────────────────────────────────────────────────────────────────
// pairs(input)
// Tokenizes a logfmt payload into key/value pairs: whitespace separates tokens
// only outside double quotes, `\\` and `\"` are unescaped inside them, and each
// token splits on its first '=' so a value may contain more.
//
// The first occurrence of a key wins. Quoting already prevents an
// attacker-influenced value from opening a second `verdict=`, and preferring the
// earliest occurrence means a later one could not override it even if it did.
// ─────────────────────────────────────────────────────────────────────────────
fn pairs(input: &str) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = Vec::new();
    let mut token = String::new();
    let mut in_quotes = false;
    let mut chars = input.chars();

    let flush = |token: &mut String, out: &mut Vec<(String, String)>| {
        // A token is only a field if it carried a '='; `""` alone is not one.
        if let Some((key, value)) = token.split_once('=') {
            let key = key.trim();
            if !key.is_empty() && !out.iter().any(|(k, _)| k == key) {
                out.push((key.to_string(), value.to_string()));
            }
        }
        token.clear();
    };

    while let Some(c) = chars.next() {
        match c {
            // Inside quotes a backslash escapes the next character verbatim.
            '\\' if in_quotes => {
                if let Some(next) = chars.next() {
                    token.push(next);
                }
            }
            '"' => in_quotes = !in_quotes,
            c if c.is_whitespace() && !in_quotes => flush(&mut token, &mut out),
            c => token.push(c),
        }
    }
    flush(&mut token, &mut out);
    out
}

// ─────────────────────────────────────────────────────────────────────────────
// payload(raw, meta)
// Finds where the logfmt starts. Parsing begins after the syslog tag
// ("easywaf: "), but syslog_loose reads the first token after the hostname as
// APP-NAME and strips it — so on a line sent without a tag it would eat
// `ts=…` itself. Reading the rebuilt body and dropping a leading tag handles
// both shapes.
// ─────────────────────────────────────────────────────────────────────────────
fn payload<'a>(raw: &'a str, meta: &'a Meta) -> &'a str {
    let body = if meta.body.trim().is_empty() { raw } else { meta.body.as_str() };
    let body = body.trim();
    // A tag is the leading "word:" before the first key=value pair.
    match body.split_once(' ') {
        Some((first, rest)) if first.ends_with(':') && !first.contains('=') => rest.trim_start(),
        _ => body,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// parse_line(line)
// Parses one logfmt payload into a WafEvent, or None when a required key (ts,
// verdict, client) is missing or unusable — the caller counts that as a drop.
// ─────────────────────────────────────────────────────────────────────────────
pub fn parse_line(line: &str) -> Option<WafEvent> {
    let fields = pairs(line);
    let get = |key: &str| fields.iter().find(|(k, _)| k == key).map(|(_, v)| v.as_str());
    let text = |key: &str| get(key).unwrap_or("").trim().to_string();
    let number = |key: &str| get(key).and_then(|v| v.trim().parse::<i32>().ok());

    // Required. RFC 3339 in UTC, but an offset is accepted and normalized.
    let ts = DateTime::parse_from_rfc3339(get("ts")?.trim())
        .ok()?
        .naive_utc();
    let verdict = text("verdict");
    let client = text("client");
    if verdict.is_empty() || client.is_empty() {
        return None;
    }

    Some(WafEvent {
        ts,
        site: text("site"),
        host: text("host"),
        client,
        country: text("country").to_uppercase(),
        method: text("method"),
        path: get("path").unwrap_or("").to_string(),
        status: number("status"),
        ms: number("ms"),
        verdict,
        score: number("score"),
        rules: text("rules"),
        reason: get("reason").unwrap_or("").to_string(),
    })
}

impl LogType for EasyWaf {
    fn name(&self) -> &'static str {
        "easywaf"
    }

    fn category(&self) -> Category {
        Category::Waf
    }

    fn label(&self) -> &'static str {
        "EasyWAF"
    }

    fn icon(&self) -> &'static str {
        "bi-shield-shaded"
    }

    // ─────────────────────────────────────────────────────────────────────────
    // EasyWaf::init_schema(conn)
    // Creates the `easywaf` table if absent: the wire fields, the syslog
    // envelope (source_ip — which appliance sent it — and received_at), the
    // resolved country, and the original line.
    // ─────────────────────────────────────────────────────────────────────────
    fn init_schema(&self, conn: &Connection) -> Result<()> {
        conn.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS easywaf (
                source_ip    VARCHAR,
                ts           TIMESTAMP,
                site         VARCHAR,
                host         VARCHAR,
                client       VARCHAR,
                method       VARCHAR,
                path         VARCHAR,
                status       INTEGER,
                ms           INTEGER,
                verdict      VARCHAR,
                score        INTEGER,
                rules        VARCHAR,
                reason       VARCHAR,
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
    // EasyWaf::ingest(raw, meta, conn)
    // Parses one event and stores it. The client address is resolved with
    // EasyLog's own database so the world map and Top-countries panel agree with
    // every other dashboard; EasyWAF's own `country=` is the fallback when the
    // local database has nothing for the address.
    // ─────────────────────────────────────────────────────────────────────────
    fn ingest(&self, raw: &str, meta: &Meta, conn: &Connection) -> Result<bool> {
        let line = payload(raw, meta);
        let Some(e) = parse_line(line) else {
            return Ok(false);
        };
        let (mut country_code, mut country) = crate::geo::lookup(&e.client);
        if country_code.is_empty() && !e.country.is_empty() {
            country_code = e.country.clone();
            country = e.country.clone();
        }
        conn.execute(
            r#"INSERT INTO easywaf
               (source_ip, ts, site, host, client, method, path, status, ms, verdict,
                score, rules, reason, country, country_code, received_at, raw)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)"#,
            params![
                meta.source_ip,
                e.ts,
                e.site,
                e.host,
                e.client,
                e.method,
                e.path,
                e.status,
                e.ms,
                e.verdict,
                e.score,
                e.rules,
                e.reason,
                country,
                country_code,
                meta.received_at.naive_utc(),
                line,
            ],
        )?;
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    fn meta() -> Meta {
        Meta {
            source_ip: "192.0.2.10".to_string(),
            hostname: Some("easywaf".to_string()),
            tag: Some("easywaf:".to_string()),
            body: String::new(),
            received_at: Utc::now(),
        }
    }

    // The five lines the specification says a conforming parser must handle.
    const CORPUS: [&str; 5] = [
        r#"ts=2026-09-09T10:14:22Z site=cloud host=cloud.hakim.family client=203.0.113.9 country=DE method=GET path=/index.php status=200 ms=4 verdict=passed"#,
        r#"ts=2026-09-09T10:14:23Z site=cloud host=cloud.hakim.family client=203.0.113.9 country=DE method=GET path=/admin status=200 ms=6 verdict=scored score=4 rules=913015"#,
        r#"ts=2026-09-09T10:14:24Z site=api host=api.example client=198.51.100.7 method=POST path="/search?q=a b" status=403 ms=2 verdict=blocked score=15 rules=942100,932001 reason="WAF score 15 ≥ block threshold 10""#,
        r#"ts=2026-09-09T10:14:25Z site=api host=api.example client=198.51.100.7 method=GET path="/x=1&y=\"2\"" status=200 ms=3 verdict=would_block score=12 rules=930011 reason="WAF score 12 ≥ block threshold 10""#,
        r#"ts=2026-09-09T10:14:26Z site=web host=web.example client=2001:db8::1 method=GET path=/ status=200 ms=1 verdict=passed"#,
    ];

    #[test]
    fn parses_the_specification_corpus() {
        let events: Vec<WafEvent> = CORPUS.iter().map(|l| parse_line(l).expect("should parse")).collect();

        // A quoted path containing a space must survive whole, and the '=' inside
        // reason must not be mistaken for a field separator.
        assert_eq!(events[2].path, "/search?q=a b");
        assert_eq!(events[2].reason, "WAF score 15 ≥ block threshold 10");
        assert_eq!(events[2].rules, "942100,932001");
        assert_eq!(events[2].verdict, "blocked");

        // Escaped quotes inside a quoted value come back as themselves.
        assert_eq!(events[3].path, r#"/x=1&y="2""#);
        assert_eq!(events[3].verdict, "would_block");

        // IPv6 client, and no country because the address resolves to none.
        assert_eq!(events[4].client, "2001:db8::1");
        assert_eq!(events[4].country, "");

        assert_eq!(events[0].site, "cloud");
        assert_eq!(events[0].host, "cloud.hakim.family");
        assert_eq!(events[0].status, Some(200));
        assert_eq!(events[0].ms, Some(4));
        assert_eq!(events[1].score, Some(4));
        assert_eq!(events[1].rules, "913015");
    }

    // "No rule matched at all" and "matched, scoring zero" are different facts,
    // and the row has to keep them apart.
    #[test]
    fn an_absent_score_is_not_a_zero_score() {
        let passed = parse_line(CORPUS[0]).unwrap();
        assert_eq!(passed.score, None);

        let zero = parse_line("ts=2026-09-09T10:14:22Z client=203.0.113.9 verdict=scored score=0").unwrap();
        assert_eq!(zero.score, Some(0));
    }

    // New fields are expected; a parser that rejected them would break on the
    // next EasyWAF release.
    #[test]
    fn unknown_keys_are_ignored_not_rejected() {
        let line = r#"ts=2026-09-09T10:14:22Z client=203.0.113.9 verdict=passed engine=v2 tags="a b" ratio=0.5"#;
        let e = parse_line(line).expect("should parse despite unknown keys");
        assert_eq!(e.verdict, "passed");
    }

    // A line missing any of the three required keys is a drop, not a partial row.
    #[test]
    fn rejects_lines_missing_a_required_key() {
        for line in [
            "site=cloud client=203.0.113.9 verdict=passed",                       // no ts
            "ts=2026-09-09T10:14:22Z client=203.0.113.9",                         // no verdict
            "ts=2026-09-09T10:14:22Z verdict=passed",                             // no client
            "ts=not-a-timestamp client=203.0.113.9 verdict=passed",               // unusable ts
            "",
        ] {
            assert!(parse_line(line).is_none(), "should reject {line:?}");
        }
    }

    // A quoted value cannot open a second field: the forged verdict stays part
    // of the path, and the real one still decides.
    #[test]
    fn a_quoted_value_cannot_forge_a_field() {
        let line = r#"ts=2026-09-09T10:14:22Z client=203.0.113.9 path="/x verdict=passed" verdict=blocked"#;
        let e = parse_line(line).expect("should parse");
        assert_eq!(e.path, "/x verdict=passed");
        assert_eq!(e.verdict, "blocked");
    }

    #[test]
    fn ingests_into_the_easywaf_table() {
        let conn = Connection::open_in_memory().unwrap();
        EasyWaf.init_schema(&conn).unwrap();
        for line in CORPUS {
            assert!(EasyWaf.ingest(line, &meta(), &conn).unwrap(), "should store {line:?}");
        }

        let (rows, blocked, would): (i64, i64, i64) = conn
            .query_row(
                "SELECT count(*), count(*) FILTER (WHERE verdict = 'blocked'), \
                 count(*) FILTER (WHERE verdict LIKE 'would\\_%' ESCAPE '\\') FROM easywaf",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .unwrap();
        assert_eq!((rows, blocked, would), (5, 1, 1));

        // The appliance that sent the event is kept: a fleet asks "which one
        // refused this" immediately.
        let source: String = conn
            .query_row("SELECT source_ip FROM easywaf LIMIT 1", [], |r| r.get(0))
            .unwrap();
        assert_eq!(source, "192.0.2.10");

        // Absent score stays NULL rather than becoming 0.
        let nulls: i64 = conn
            .query_row("SELECT count(*) FROM easywaf WHERE score IS NULL", [], |r| r.get(0))
            .unwrap();
        assert_eq!(nulls, 2);
    }

    // Whether the syslog layer strips the tag or eats the first field, the same
    // event has to come out.
    #[test]
    fn finds_the_payload_with_or_without_a_tag() {
        let conn = Connection::open_in_memory().unwrap();
        EasyWaf.init_schema(&conn).unwrap();

        // syslog_loose stripped "easywaf:" into the tag, leaving raw intact.
        let tagged = Meta { body: format!("easywaf: {}", CORPUS[0]), ..meta() };
        assert!(EasyWaf.ingest(CORPUS[0], &tagged, &conn).unwrap());

        // No tag on the wire: "ts=…" was taken as the APP-NAME and stripped from
        // raw, so only the rebuilt body still has it.
        let untagged = Meta {
            tag: Some("ts=2026-09-09T10:14:26Z".to_string()),
            body: CORPUS[4].to_string(),
            ..meta()
        };
        let stripped = CORPUS[4].split_once(' ').unwrap().1;
        assert!(EasyWaf.ingest(stripped, &untagged, &conn).unwrap());

        let stored: i64 = conn
            .query_row("SELECT count(*) FROM easywaf WHERE ts IS NOT NULL", [], |r| r.get(0))
            .unwrap();
        assert_eq!(stored, 2);
    }
}
