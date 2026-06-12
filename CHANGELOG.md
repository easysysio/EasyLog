# Changelog

All notable changes to EasyLog are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] — 2026-06-12

### Added
- Initial Axum web service scaffold (`src/main.rs`).
- `GET /` landing route returning a service banner.
- `GET /health` liveness probe returning `ok`.
- Tracing/logging via `tracing` + `tracing-subscriber` (`RUST_LOG`-controlled).
