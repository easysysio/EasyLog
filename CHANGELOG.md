# Changelog

All notable changes to EasyLog are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
