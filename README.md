<div align="center">

# EasyLog

**A multi-log analyzer with a dedicated dashboard for every log type.**

EasyLog ingests logs over **syslog**, parses each source by type, stores the
parsed events in an embedded **DuckDB** column store, and serves a live
**dashboard per log type** — all from a single, dependency-free binary.

[![Release](https://github.com/easysysio/EasyLog/actions/workflows/release.yml/badge.svg)](https://github.com/easysysio/EasyLog/actions/workflows/release.yml)
[![Latest release](https://img.shields.io/github/v/release/easysysio/EasyLog?sort=semver)](https://github.com/easysysio/EasyLog/releases)
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
  URL, status code, or country to drill down** — filters stack and are shareable
  by URL.
- 📄 **Raw view** — one button swaps any dashboard for the log lines behind it,
  newest first, under the same range, filters and search; another swaps back.
  Page through with **Load more**, or download every matching line as a file.
- 🔎 **Search on every dashboard** — one box that matches across that type's
  fields (URL, client IP, agent, host; or source, destination, port, rule,
  application). It narrows everything on the page, composes with the active
  filters, and lives in the URL.
- 🌍 **IP geolocation, fully offline** — every client IP is resolved to a country
  at ingest, powering a Countries KPI, Top-countries panels, a country breakdown
  on the overview, and a **shaded world map** on every dashboard that you can
  click to filter. The **DB-IP Lite country database is bundled** in the binary
  (nothing to install); point `geo_db_path` at a MaxMind `.mmdb` to override.
- 🎛️ **Web-managed sources** — map a sending host to a log type from the UI; no
  config edits or restarts required.
- 🧹 **Retention & compaction** — optionally delete events older than
  `retention_days` and reclaim the freed disk by rewriting the database at
  startup, so a long-running collector stays within bounds.
- 🔒 **Authentication** — admin account created on first run; the web UI is
  login-protected (bcrypt, signed-cookie sessions). Syslog ingestion stays open.
- 🪶 **Single self-contained binary** — the web templates and static assets
  (Bootstrap + icons) are compiled into the binary, so there's nothing to install
  alongside it and it runs from any directory. Fully offline, no CDN.
- 📦 **First-class packaging** — `.deb` and `.rpm` for **x86_64 and arm64**, with
  a systemd unit, built and published automatically on each tag.

Supported log types:

* **Web** — **Apache** (Common/Combined Log Format), **nginx** (combined access
  logs), **Caddy** (JSON access logs), **HAProxy** (`option httplog`) and
  **Traefik** (JSON access logs).
* **Firewalls** — **Cisco ASA** (syslog message IDs) and **Palo Alto / PAN-OS**
  (TRAFFIC logs), on a dashboard built around the allow/deny split.

Each type has its own dashboard, grouped by category in the navigation.

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

### From the package repository (recommended)

Installing from the EasySYS repository means upgrades come through your package
manager. Packages are published for **x86_64** and **arm64**; your package
manager picks the right one.

```sh
# Debian / Ubuntu
curl -fsSL https://repo.easysys.io/easylog/stable/debian/key.gpg \
  | sudo gpg --dearmor -o /usr/share/keyrings/easysys.gpg
echo "deb [signed-by=/usr/share/keyrings/easysys.gpg] https://repo.easysys.io/easylog/stable/debian ./" \
  | sudo tee /etc/apt/sources.list.d/easylog.list
sudo apt update && sudo apt install easylog
sudo systemctl enable --now easylog
```

```sh
# Fedora / RHEL
sudo tee /etc/yum.repos.d/easylog.repo >/dev/null <<'EOF'
[easylog]
name=EasyLog
baseurl=https://repo.easysys.io/easylog/stable/redhat
enabled=1
gpgcheck=1
gpgkey=https://repo.easysys.io/easylog/stable/redhat/key.gpg
EOF
sudo dnf install easylog
sudo systemctl enable --now easylog

# openSUSE / SLES — same repository
sudo zypper addrepo -fg https://repo.easysys.io/easylog/stable/redhat easylog
sudo zypper install easylog
sudo systemctl enable --now easylog
```

### From a downloaded package

For hosts without access to the repository, grab the `.deb` or `.rpm` for your
architecture from the [latest release](https://github.com/easysysio/EasyLog/releases):

```sh
sudo dpkg -i easylog_*_amd64.deb        # Debian / Ubuntu (or _arm64.deb)
sudo rpm -i easylog-*.x86_64.rpm        # Fedora / RHEL / openSUSE (or .aarch64.rpm)
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
git clone https://github.com/easysysio/EasyLog.git
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
geo_db_path = ""          # external MaxMind .mmdb; empty = bundled DB-IP Lite

retention_days = 0        # delete events older than N days; 0 = keep everything
auto_compact   = true     # rewrite the database at startup to reclaim disk

log_dir        = "/var/log/easylog"   # EasyLog's own logs; "" = stdout only
log_level      = "info"               # RUST_LOG overrides this
log_keep_days  = 14                   # daily rotation, files kept
```

### EasyLog's own logs

Alongside stdout (so `journalctl -u easylog` keeps working), EasyLog writes two
files under `log_dir`:

| File | Contents |
|------|----------|
| `easylog.log` | Startup and config, geolocation database in use, retention prunes and compactions, and a per-minute ingest summary: received, stored, unparsed, unknown source, queue-full drops |
| `audit.log` | Actions through the UI — sign-ins and failed attempts, sign-outs, first-run admin creation, sources added and removed — each with the account and client address |

Both roll daily and keep `log_keep_days` files, so logrotate isn't needed. The
systemd unit creates `/var/log/easylog` itself (`LogsDirectory`). If the
directory can't be written, EasyLog warns and logs to stdout only rather than
refusing to start.

Log sources are **not** configured here — they're managed in the database via the
web UI (see below).

### Retention

By default EasyLog keeps everything. Set `retention_days` to bound the database:
events older than the window are deleted at startup and hourly thereafter,
across every log type. Rows are aged by their event timestamp, falling back to
when EasyLog received them, so a line whose timestamp couldn't be parsed is
still subject to retention.

Pruning alone bounds growth without returning disk to the OS — DuckDB reuses the
space freed by deleted rows but never shrinks the file. `auto_compact` (on by
default) closes that gap: at startup, if a large share of the file is dead
space, EasyLog rewrites the database into a fresh file and swaps it in. It only
runs before ingestion starts, and the original is kept until the new file is in
place, so an interrupted compaction leaves the database untouched. The
**Storage** card on the overview shows the current size and the active window.

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

Open `http://<host>:3000/web/apache` for live metrics: requests over time,
status-code breakdown, and top URLs / client IPs.

Dashboards are grouped by category in the navigation: the first row selects a
category (Web, and Firewalls / 3rd parties as those types arrive), the second
lists that category's dashboards. Both rows are built from the log-type
registry, so adding a type adds its entry automatically.

### Endpoints

| Route | Description |
|-------|-------------|
| `GET /` | Home / overview |
| `GET /web/apache` | Apache dashboard |
| `GET /web/nginx` | Nginx dashboard |
| `GET /web/caddy` | Caddy dashboard |
| `GET /web/haproxy` | HAProxy dashboard |
| `GET /web/traefik` | Traefik dashboard |
| `GET /firewall/cisco_asa` | Cisco ASA dashboard |
| `GET /firewall/panos` | Palo Alto dashboard |
| `GET /sources` | Manage log sources |
| `GET /health` | Liveness probe (`ok`) |
| `GET /web/apache/recent` | Recent parsed Apache rows (JSON) |

The pre-0.4.2 flat paths (`/apache`, `/nginx`, `/traefik`) permanently redirect
to their category-scoped equivalents, query string included, so bookmarked and
shared filter links keep working.

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

### Bundled data

- IP geolocation by [DB-IP](https://db-ip.com) — DB-IP Lite country database,
  licensed [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/). Released
  binaries embed the edition current at build time (the release workflow fetches
  it); set `geo_db_path` to use your own `.mmdb` between releases.
- Country boundaries from [Natural Earth](https://www.naturalearthdata.com/)
  (public domain), simplified into `assets/geo/world.svg` by
  [`tools/build-world-svg.py`](tools/build-world-svg.py).
