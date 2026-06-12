# EasyLog
A multi-log analyzer. EasyLog ingests logs over **syslog** (UDP + TCP), parses
them per log type, stores rows in **DuckDB**, and (Stage 2) renders a dedicated
dashboard per type. The first supported type is **Apache** (Combined Log Format).

## Architecture

```
syslog (UDP/TCP) → envelope parse → route by source host → LogType parser → DuckDB → dashboard
```

Each log type is a pluggable `LogType` implementation that owns its parser,
DuckDB schema, and dashboard. Sources (which sending IP maps to which log type)
are managed in the database via the web UI at `/sources`.

## Install

Download the `.deb` or `.rpm` for your architecture (x86_64 / arm64) from the
[latest release](https://github.com/yarivha/EasyLog/releases), then:

```sh
sudo dpkg -i easylog_*_amd64.deb       # Debian/Ubuntu
sudo rpm -i  easylog-*.x86_64.rpm      # Fedora/RHEL

sudo systemctl enable --now easylog    # start on boot
```

The package installs the binary to `/usr/bin/easylog`, web assets to
`/usr/share/easylog`, a default config to `/etc/easylog/easylog.toml`, and a
systemd unit. The database lives in `/var/lib/easylog`. Then open
`http://<host>:3000/`.

## Configure

EasyLog loads `config/easylog.toml` (override with `EASYLOG_CONFIG`):

```toml
syslog_port = 514          # standard syslog; use 5514 to run without root
web_port    = 3000
db_path     = "easylog.duckdb"
```

**Log sources** (which sending IP maps to which log type) are managed in the
database via the web UI at `/sources` — add a source with a name, IP address,
and log type, and EasyLog routes matching syslog traffic to that type's parser.

## Run

```sh
cargo run
```

Binding port 514 needs privileges; for local testing set `syslog_port = 5514`.
The web server listens on `http://0.0.0.0:<web_port>`:

Then open `http://localhost:3000/sources` to add a log source, or check:

```sh
curl localhost:3000/health          # -> ok
curl localhost:3000/apache/recent   # -> recent parsed Apache rows (JSON)
```

Set `RUST_LOG=debug` for verbose logging.

## Status

Syslog ingestion (Apache → DuckDB), the source-management UI, and the Apache
dashboard (`/apache`) are complete. Dashboards run live SQL over the stored rows.
Next up: more log types (each with its own dashboard) and log retention.
See [CHANGELOG.md](CHANGELOG.md).
