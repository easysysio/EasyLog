# Changelog

All notable changes to EasyLog are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **Syslog ingestion:** UDP + TCP listeners (RFC3164/RFC5424 via `syslog_loose`)
  on a configurable port (default 514).
- **Pluggable log types:** `LogType` trait + `Registry`; each type owns its
  DuckDB schema and parse/ingest logic.
- **Apache log type:** Combined Log Format parser (method/path/protocol, status,
  bytes, referer, user-agent, UTC-normalized timestamp) with unit tests.
- **DuckDB storage:** embedded columnar store; per-type schema init at startup.
- **Log source management UI** (`/sources`): add and remove log sources
  (name + IP address + log type) from the browser, backed by DuckDB; sources
  load into an in-memory routing map at startup and reload on every change, so
  edits take effect without a restart. Input is validated (valid IP, known log
  type, non-empty name).
- **Apache dashboard** (`GET /apache`): live DuckDB aggregations over the parsed
  rows — KPI cards (requests, unique client IPs, bytes served, error rate),
  a per-hour requests timeline (last 24h), an HTTP status-class breakdown, and
  top-10 URLs and client IPs. Dependency-free, server-rendered CSS bar charts;
  empty-state when no logs have arrived.
- Tera templating (`templates/base.html`, `index.html`, `sources.html`,
  `apache.html`) and a home page at `/`.
- Temporary `GET /apache/recent` JSON endpoint for verifying ingestion.
- `config/easylog.toml` (syslog/web ports, db path); overridable via
  `EASYLOG_CONFIG`.

### Changed
- Syslog routing resolves the log type from the DB-backed source map (by source
  IP), configured via the web UI rather than a static config table.
- **Decoupled syslog ingestion:** the UDP/TCP receive loops no longer write to
  DuckDB inline. They parse the envelope, resolve the log type, and push a work
  item onto a bounded `tokio::sync::mpsc` channel; a dedicated background writer
  task drains the channel and inserts rows in batched transactions (up to 1024
  items per `BEGIN/COMMIT`), amortizing the DB lock and per-statement commit
  cost. The UDP socket is built via `socket2` with an enlarged receive buffer
  (best-effort `SO_RCVBUF`, requested 8 MiB) as a secondary burst mitigation.

### Fixed
- **UDP packet loss under bursts:** each datagram used to be inserted
  synchronously while the single UDP recv loop held the DuckDB mutex, so a
  no-delay burst stalled the loop and the kernel dropped incoming datagrams
  (a ~29-packet burst could land 0 rows, while spacing sends 10 ms apart landed
  all of them). With receiving now decoupled from writing, the recv loop drains
  the socket fast: a 500-packet no-delay burst lands all 500. Bursts beyond the
  OS UDP socket-buffer ceiling are still subject to kernel-level drops (inherent
  to UDP), but no longer to writer back-pressure.

## [0.1.0] — 2026-06-12

### Added
- Initial Axum web service scaffold (`src/main.rs`).
- `GET /` landing route returning a service banner.
- `GET /health` liveness probe returning `ok`.
- Tracing/logging via `tracing` + `tracing-subscriber` (`RUST_LOG`-controlled).
