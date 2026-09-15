# Configuration

EasyLog reads `/etc/easylog/easylog.toml` (override the path with the `EASYLOG_CONFIG` environment variable):

```toml
syslog_bind = "0.0.0.0"   # address the UDP + TCP listeners bind to
syslog_port = 514         # standard syslog; use 5514 to run without privileges
web_port    = 3000        # web UI / dashboards
db_path     = "/var/lib/easylog/easylog.duckdb"
geo_db_path = ""          # external MaxMind .mmdb; empty = bundled DB-IP Lite

retention_days = 0        # delete events older than N days; 0 = keep everything
auto_compact   = true     # rewrite the database at startup to reclaim disk

log_dir        = "/var/log/easylog"   # EasyLog's own logs; "" = stdout only
log_level      = "info"               # RUST_LOG overrides this
log_keep_days  = 14                   # daily rotation, files kept
```

## EasyLog's own logs

Besides stdout (so `journalctl -u easylog` works as before), EasyLog writes two files under **`log_dir`**, created by the systemd unit:

* **`easylog.log`** — operations: startup and configuration, which geolocation database is in use, retention prunes and compactions, and a per-minute ingest summary counting messages *received*, *stored*, *unparsed*, from an *unknown source*, and dropped because the write queue was full. That summary is the quickest way to tell whether a device is really sending, and whether its lines are being understood.
* **`audit.log`** — who did what: sign-ins and failed attempts, sign-outs, first-run administrator creation, and sources added or removed, each with the account and the client address.

Both roll daily and keep `log_keep_days` files (default 14), so there's nothing to configure in logrotate. If the directory can't be written — a source build running unprivileged, say — EasyLog logs a warning and continues on stdout instead of failing to start.

## Keeping the database bounded

EasyLog keeps every event by default, which is fine until a busy source fills the
disk. Set **`retention_days`** and anything older is deleted — at startup and
hourly after that, across all log types. Events are aged by their own timestamp,
falling back to when EasyLog received them, so a line whose timestamp couldn't be
parsed is pruned too rather than living forever.

Deleting rows bounds the database but doesn't hand disk back: DuckDB reuses freed
space internally and never shrinks the file, so it stays at its high-water mark.
**`auto_compact`** (on by default) closes that gap by rewriting the database into
a fresh file at startup whenever a large share of it is dead space. It runs before
ingestion begins and keeps the original until the new file is safely in place, so
an interrupted compaction leaves your data untouched.

!!! tip "Where to see it"
    The **Storage** card on the overview shows the database size on disk and the
    active retention window. To reclaim disk right after shortening the window,
    restart the service — that's when compaction runs.

!!! note
    Log **sources** are not configured here — they're managed in the web UI (next section), so you never have to edit and reload a file to add a host.
