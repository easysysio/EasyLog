<div align="center">

# EasyLog

**A multi-log analyzer with a dedicated dashboard for every log type.**

EasyLog ingests logs over **syslog**, parses each source by type, stores the
parsed events in an embedded **DuckDB** column store, and serves a live
**dashboard per log type** — all from a single, dependency-free binary.

[![Release](https://github.com/yarivha/EasyLog/actions/workflows/release.yml/badge.svg)](https://github.com/yarivha/EasyLog/actions/workflows/release.yml)
[![Latest release](https://img.shields.io/github/v/release/yarivha/EasyLog?sort=semver)](https://github.com/yarivha/EasyLog/releases)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/Rust-1.95%2B-orange.svg)](https://www.rust-lang.org)
[![Platform](https://img.shields.io/badge/Linux-x86__64%20%7C%20arm64-informational.svg)](#installation)

</div>

---

## Features

- 🌐 **Syslog ingestion** over both **UDP and TCP** (RFC 3164 & RFC 5424).
- 🧩 **Pluggable log types** — each type owns its parser, storage schema, and
  dashboard. Adding a new type is a self-contained module.
- 🦆 **DuckDB storage** — parsed events are stored as rows (the source of truth);
  dashboards run live analytical SQL over them, so new charts never need a
  re-ingest, and you can always drill down to the underlying log lines.
- 📊 **Dashboard per log type** — KPI cards, request timelines, status-code
  breakdowns, and top-N tables, rendered server-side. **Click any client IP,
  URL, or status code to drill down** — filters stack and are shareable by URL.
- 🎛️ **Web-managed sources** — map a sending host to a log type from the UI; no
  config edits or restarts required.
- 🔒 **Authentication** — admin account created on first run; the web UI is
  login-protected (bcrypt, signed-cookie sessions). Syslog ingestion stays open.
- 🪶 **Single self-contained binary** — the web templates and static assets
  (Bootstrap + icons) are compiled into the binary, so there's nothing to install
  alongside it and it runs from any directory. Fully offline, no CDN.
- 📦 **First-class packaging** — `.deb` and `.rpm` for **x86_64 and arm64**, with
  a systemd unit, built and published automatically on each tag.

The first supported log type is **Apache** (Combined Log Format).

## How it works

```
                         ┌──────────────────────────────────────────┐
  syslog (UDP/TCP)  ──►  │  envelope parse  ─►  route by source IP   │
                         └───────────────────────────┬──────────────┘
                                                      ▼
                         ┌──────────────────────────────────────────┐
                         │  LogType parser  (apache, …)              │
                         └───────────────────────────┬──────────────┘
                                                      ▼
                         ┌──────────────┐      ┌──────────────────────┐
                         │   DuckDB     │ ◄──► │  dashboard per type   │
                         │ parsed rows  │ SQL  │  (live aggregations)  │
                         └──────────────┘      └──────────────────────┘
```

Each log type implements a `LogType` trait that declares how its lines are
parsed and stored. Incoming syslog messages are routed to a type by the
**sending host's IP**, configured in the web UI (`/sources`) and persisted in
DuckDB.

## Installation

### From packages (recommended)

Download the `.deb` or `.rpm` for your architecture from the
[latest release](https://github.com/yarivha/EasyLog/releases):

```sh
# Debian / Ubuntu
sudo dpkg -i easylog_*_amd64.deb        # or _arm64.deb

# Fedora / RHEL / openSUSE
sudo rpm -i easylog-*.x86_64.rpm        # or .aarch64.rpm

# Start it (and enable on boot)
sudo systemctl enable --now easylog
```

The package installs:

| Path | Contents |
|------|----------|
| `/usr/bin/easylog` | the binary (web UI + assets embedded) |
| `/etc/easylog/easylog.toml` | default configuration |
| `/usr/lib/systemd/system/easylog.service` | systemd unit |
| `/var/lib/easylog/` | DuckDB database (created at runtime) |

The service runs as root (standard for a syslog collector binding port 514), with
a private `StateDirectory` for the database and `NoNewPrivileges` set. Then open
`http://<host>:3000/` — on first run you'll be prompted to **create the admin
account**, after which the UI requires login.

### From source

Requires a Rust toolchain (1.95+) and a C/C++ compiler (for the bundled DuckDB).

```sh
git clone https://github.com/yarivha/EasyLog.git
cd EasyLog
cargo build --release
./target/release/easylog
```

The binary is self-contained — templates and web assets are compiled in, so you
can copy `target/release/easylog` anywhere and run it without any other files.

## Configuration

EasyLog reads `config/easylog.toml` by default (override the path with the
`EASYLOG_CONFIG` environment variable):

```toml
syslog_bind = "0.0.0.0"   # address the UDP+TCP listeners bind to
syslog_port = 514         # standard syslog; use 5514 to run without privileges
web_port    = 3000        # web UI / dashboards
db_path     = "easylog.duckdb"
```

Log sources are **not** configured here — they're managed in the database via the
web UI (see below).

## Usage

### 1. Add a log source

Open `http://<host>:3000/sources` and add a source with a **name**, the sending
host's **IP address**, and a **log type** (e.g. `apache`). EasyLog immediately
starts routing syslog traffic from that IP to the chosen parser.

### 2. Forward logs to EasyLog

Point your log source at EasyLog's syslog port. For an Apache server, either pipe
the access log through `logger`:

```apache
# In the Apache vhost / httpd.conf — forwards the combined access log via syslog
CustomLog "|/usr/bin/logger -n EASYLOG_HOST -P 514 -d -t apache --rfc3164" combined
```

…or have `rsyslog` tail the access log and forward it. A ready-to-edit config is
provided at [`examples/rsyslog/apache-access.conf`](examples/rsyslog/apache-access.conf)
(also installed by the package under `/usr/share/doc/easylog/examples/`):

```sh
sudo cp examples/rsyslog/apache-access.conf /etc/rsyslog.d/60-easylog.conf
# edit EASYLOG_IP + the File= path inside, then:
sudo rsyslogd -N1 && sudo systemctl restart rsyslog
```

Whichever method you use, then register the sending host's IP as an `apache`
source at `http://<host>:3000/sources` — EasyLog routes incoming logs by source IP.

### 3. View the dashboard

Open `http://<host>:3000/apache` for live metrics: requests over time,
status-code breakdown, and top URLs / client IPs.

### Endpoints

| Route | Description |
|-------|-------------|
| `GET /` | Home / overview |
| `GET /apache` | Apache dashboard |
| `GET /sources` | Manage log sources |
| `GET /health` | Liveness probe (`ok`) |
| `GET /apache/recent` | Recent parsed Apache rows (JSON) |

## Development

```sh
cargo build            # debug build
cargo test             # run unit tests (e.g. the Apache parser)
RUST_LOG=debug cargo run   # run with verbose logging
```

For local testing without root, set `syslog_port = 5514` in your config and send
a sample line:

```sh
logger -n 127.0.0.1 -P 5514 -d -t apache --rfc3164 \
  '127.0.0.1 - - [12/Jun/2026:09:00:00 +0000] "GET /test HTTP/1.1" 200 42 "-" "curl/8.0"'
```

Releases are produced by tagging: pushing a `v*` tag triggers
[`.github/workflows/release.yml`](.github/workflows/release.yml), which builds the
packages on native x86_64 and arm64 runners and publishes a GitHub Release from
the matching `CHANGELOG.md` section.

## Roadmap

- Additional log types (each with its own dashboard).
- Configurable log retention / pruning.
- Long-term rollups for high-volume deployments.

See [CHANGELOG.md](CHANGELOG.md) for released and in-progress changes.

## License

Released under the [MIT License](LICENSE).
