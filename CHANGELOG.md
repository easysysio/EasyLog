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
- Tera templating (`templates/base.html`, `index.html`, `sources.html`) and a
  home page at `/`.
- Temporary `GET /apache/recent` JSON endpoint for verifying ingestion.
- `config/easylog.toml` (syslog/web ports, db path); overridable via
  `EASYLOG_CONFIG`.

### Changed
- Syslog routing resolves the log type from the DB-backed source map (by source
  IP), configured via the web UI rather than a static config table.

## [0.1.0] — 2026-06-12

### Added
- Initial Axum web service scaffold (`src/main.rs`).
- `GET /` landing route returning a service banner.
- `GET /health` liveness probe returning `ok`.
- Tracing/logging via `tracing` + `tracing-subscriber` (`RUST_LOG`-controlled).
