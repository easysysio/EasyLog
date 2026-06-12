# EasyLog
A multi-log analyzer. EasyLog ingests logs over **syslog** (UDP + TCP), parses
them per log type, stores rows in **DuckDB**, and (Stage 2) renders a dedicated
dashboard per type. The first supported type is **Apache** (Combined Log Format).

## Architecture

```
syslog (UDP/TCP) → envelope parse → route by source host → LogType parser → DuckDB → dashboard
```

Each log type is a pluggable `LogType` implementation that owns its parser,
DuckDB schema, and (later) dashboard. Sources are mapped to a log type by their
IP/hostname in the config's `[hosts]` table.

## Configure

EasyLog loads `config/easylog.toml` (override with `EASYLOG_CONFIG`):

```toml
syslog_port = 514          # standard syslog; use 5514 to run without root
web_port    = 3000
db_path     = "easylog.duckdb"

[hosts]
"127.0.0.1" = "apache"     # map a sending host/IP to a log type
```

## Run

```sh
cargo run
```

Binding port 514 needs privileges; for local testing set `syslog_port = 5514`.
The web server listens on `http://0.0.0.0:<web_port>`:

```sh
curl localhost:3000/health          # -> ok
curl localhost:3000/apache/recent   # -> recent parsed Apache rows (JSON)
```

Set `RUST_LOG=debug` for verbose logging.

## Status

Stage 1 (syslog ingestion → Apache parser → DuckDB) is complete. Stage 2 adds the
Tera-based per-type dashboards. See [CHANGELOG.md](CHANGELOG.md).
