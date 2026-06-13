# Changelog

All notable changes to EasyLog are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **Dashboard time-range selector** (`?range=`): bound the whole Apache dashboard
  to the last **hour / 24h (default) / week / month / year**. The window is
  applied to every aggregation (requests, KPIs, status, top-N), the timeline
  re-buckets to suit the range (5-min → hour → day → month), and the range is
  preserved across drill-down filters.
- Browser **favicon** matching the navbar mark (the `bi-stack` glyph in the brand
  blue, an embedded SVG), served at `/static/favicon.svg` and `/favicon.ico`.

### Changed
- **Single self-contained binary:** the web templates and static assets
  (Bootstrap + icons) are now compiled into the binary (`include_str!` /
  `include_bytes!`) and served from memory, so EasyLog no longer needs
  `templates/` or `static/` on disk. The deb/rpm ship only the binary, config,
  and systemd unit (which drops its `WorkingDirectory`); the `tower-http`
  dependency was removed.

## [0.1.1] — 2026-06-13

### Fixed
- **systemd unit failed to start (`status=217/USER`) in LXC/containers:** the unit
  used `DynamicUser=yes` and mount-namespace sandboxing, which are unreliable in
  LXC. It now runs as root (normal for a syslog collector binding :514) with only
  `StateDirectory` + `NoNewPrivileges`, so it starts portably across hosts and
  containers.

### Added
- **Dashboard drill-down filters:** clicking a client IP, URL, or status code on
  the Apache dashboard filters the entire dashboard to matching requests
  (`/apache?ip=…&path=…&status=…`). Filters stack across dimensions, show as
  removable chips with a "Clear all", and a "no requests match" state keeps the
  filter bar reachable. Filter values are bound as SQL parameters.
- `examples/rsyslog/apache-access.conf` — ready-to-edit rsyslog config for
  forwarding Apache access logs to EasyLog (also shipped in the deb/rpm under
  `/usr/share/doc/easylog/examples/`).

### Changed
- Rewrote `README.md` with a professional structure: features, architecture
  diagram, package/source installation, configuration, usage (including Apache
  log-forwarding via `logger`/`rsyslog`), an endpoints table, and a roadmap.

## [0.1.0] — 2026-06-12

### Added
- Axum web service with tracing/logging (`tracing` + `tracing-subscriber`,
  `RUST_LOG`-controlled); `GET /` landing page and `GET /health` liveness probe.
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
- **Packaging:** `.deb` and `.rpm` for x86_64 and arm64, with a systemd unit and
  a default config, built and published on tag via GitHub Actions.

### Changed
- **Professional Bootstrap 5.3 UI** (dark theme): rebuilt all pages on Bootstrap
  components — responsive navbar, cards, tables, forms, badges, and progress-bar
  charts. Bootstrap CSS/JS and Bootstrap Icons are vendored under `static/` and
  served locally (`/static`, via `tower-http`), so the UI works fully offline.
- Syslog routing resolves the log type from the DB-backed source map (by source
  IP), configured via the web UI rather than a static config table.
- **Decoupled syslog ingestion:** the UDP/TCP receive loops no longer write to
  DuckDB inline. They parse the envelope, resolve the log type, and push a work
  item onto a bounded `tokio::sync::mpsc` channel; a dedicated background writer
  task drains the channel and inserts rows in batched transactions (up to 1024
  items per `BEGIN/COMMIT`), amortizing the DB lock and per-statement commit
  cost. As a secondary burst mitigation, the UDP socket is built via `socket2`
  with an enlarged receive buffer: on Linux it uses `SO_RCVBUFFORCE` (bypasses
  the `net.core.rmem_max` clamp; the privileged :514 listener has the required
  capability) and falls back to portable `SO_RCVBUF`; the kernel-granted size is
  logged at startup so an unprivileged deploy can see whether `rmem_max` must be
  raised.

### Fixed
- **UDP packet loss under bursts:** each datagram used to be inserted
  synchronously while the single UDP recv loop held the DuckDB mutex, so a
  no-delay burst stalled the loop and the kernel dropped incoming datagrams
  (a ~29-packet burst could land 0 rows, while spacing sends 10 ms apart landed
  all of them). With receiving now decoupled from writing, the recv loop drains
  the socket fast: a 500-packet no-delay burst lands all 500. Bursts large
  enough to overflow the kernel UDP socket buffer are still subject to
  kernel-level drops (inherent to UDP), but no longer to writer back-pressure.
