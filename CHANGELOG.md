# Changelog

All notable changes to EasyLog are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.3.0] — 2026-06-12

### Added
- **Log source management UI** (`/sources`): add and remove log sources
  (name + IP address + log type) from the browser, backed by DuckDB.
- `sources` table in DuckDB; sources load into an in-memory routing map at
  startup and reload on every change, so edits take effect without a restart.
- Tera templating (`templates/base.html`, `index.html`, `sources.html`) and a
  home page at `/`.
- Input validation on add (valid IP address, known log type, non-empty name).

### Changed
- Syslog routing now resolves the log type from the DB-backed source map
  (by source IP) instead of the static config `[hosts]` table.
- Removed the `[hosts]` section from `config/easylog.toml`; sources are now
  managed via the web UI.

## [0.2.0] — 2026-06-12

### Added
- **Syslog ingestion (Stage 1):** UDP + TCP listeners (RFC3164/RFC5424 via
  `syslog_loose`) on a configurable port (default 514).
- **Pluggable log types:** `LogType` trait + `Registry`; each type owns its
  DuckDB schema and parse/ingest logic.
- **Apache log type:** Combined Log Format parser (method/path/protocol, status,
  bytes, referer, user-agent, UTC-normalized timestamp) with unit tests.
- **DuckDB storage:** embedded columnar store; per-type schema init at startup.
- **Source-host routing:** TOML `[hosts]` map dispatches a sending IP/hostname to
  its log type.
- **Config:** `config/easylog.toml` (syslog/web ports, db path, host map);
  overridable via `EASYLOG_CONFIG`.
- Temporary `GET /apache/recent` JSON endpoint for verifying ingestion.

## [0.1.0] — 2026-06-12

### Added
- Initial Axum web service scaffold (`src/main.rs`).
- `GET /` landing route returning a service banner.
- `GET /health` liveness probe returning `ok`.
- Tracing/logging via `tracing` + `tracing-subscriber` (`RUST_LOG`-controlled).
