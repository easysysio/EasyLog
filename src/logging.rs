// =============================================================================
// logging.rs — EasyLog's own logs: operational and audit
//
// Everything EasyLog says about itself goes to stdout (so `journalctl -u easylog`
// works) and, when a log directory is configured, to files under it:
//
//   easylog.log   operational: startup and config, geolocation database load,
//                 ingest counters (received / parsed / dropped and why), batch
//                 writes, retention prunes and compactions
//   audit.log     who did what: sign-ins and failures with the client address,
//                 sign-outs, first-run admin creation, sources added and removed
//
// The two are separated by tracing target: audit events are emitted with
// `target: "audit"` (see the `audit` module below), the audit file layer keeps
// only those, and the operational file keeps everything else. Both roll daily
// and keep `log_keep_days` files, so no logrotate is required — EasyLog behaves
// the same installed from a package, run from source, or in a container.
//
// A failure to open the log directory is never fatal: it is reported on stdout
// and EasyLog carries on logging there, because losing the log file is not a
// reason to stop collecting logs.
// =============================================================================

use tracing_appender::non_blocking::WorkerGuard;
use tracing_appender::rolling::{RollingFileAppender, Rotation};
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{EnvFilter, Layer, filter::filter_fn, fmt};

use crate::config::Config;

/// Keeps the background writer threads alive; dropping this stops file logging,
/// so `main` holds it for the life of the process.
pub struct Guards(#[allow(dead_code)] Vec<WorkerGuard>);

// ─────────────────────────────────────────────────────────────────────────────
// init(config)
// Installs the global subscriber: stdout always, plus easylog.log and audit.log
// when `log_dir` is set and writable. Returns the writer guards to hold onto.
// ─────────────────────────────────────────────────────────────────────────────
pub fn init(config: &Config) -> Guards {
    // RUST_LOG still wins, so an operator can turn up detail without editing
    // the config file.
    let filter = || {
        EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| EnvFilter::new(config.log_level.trim()))
    };

    let mut guards = Vec::new();
    let stdout_layer = fmt::layer().with_filter(filter());

    let dir = config.log_dir.trim();
    if dir.is_empty() {
        tracing_subscriber::registry().with(stdout_layer).init();
        return Guards(guards);
    }

    match open_dir(dir, config.log_keep_days) {
        Ok((app_writer, audit_writer)) => {
            let (app_nb, app_guard) = tracing_appender::non_blocking(app_writer);
            let (audit_nb, audit_guard) = tracing_appender::non_blocking(audit_writer);
            guards.push(app_guard);
            guards.push(audit_guard);

            // Files get no ANSI colouring — they are read with a pager, not a
            // terminal — and each layer takes only its own half of the events.
            let app_layer = fmt::layer()
                .with_ansi(false)
                .with_writer(app_nb)
                .with_filter(filter())
                .with_filter(filter_fn(|meta| meta.target() != audit::TARGET));
            let audit_layer = fmt::layer()
                .with_ansi(false)
                .with_target(false)
                .with_writer(audit_nb)
                .with_filter(filter_fn(|meta| meta.target() == audit::TARGET));

            tracing_subscriber::registry()
                .with(stdout_layer)
                .with(app_layer)
                .with(audit_layer)
                .init();
            tracing::info!("logging to {dir} (rolling daily, keeping {} files)", config.log_keep_days);
        }
        Err(e) => {
            tracing_subscriber::registry().with(stdout_layer).init();
            tracing::warn!("could not open log directory {dir} ({e}); logging to stdout only");
        }
    }
    Guards(guards)
}

// Creates the directory if needed and builds both rolling appenders.
fn open_dir(dir: &str, keep: u16) -> std::io::Result<(RollingFileAppender, RollingFileAppender)> {
    std::fs::create_dir_all(dir)?;
    // Fail here rather than inside the logging thread if the directory exists
    // but isn't writable (a packaged install running as the wrong user).
    let probe = std::path::Path::new(dir).join(".easylog-write-test");
    std::fs::write(&probe, b"")?;
    let _ = std::fs::remove_file(&probe);

    let build = |prefix: &str| {
        RollingFileAppender::builder()
            .rotation(Rotation::DAILY)
            .filename_prefix(prefix)
            .filename_suffix("log")
            .max_log_files(keep.max(1) as usize)
            .build(dir)
            .map_err(std::io::Error::other)
    };
    Ok((build("easylog")?, build("audit")?))
}

// ─────────────────────────────────────────────────────────────────────────────
// audit — records of actions taken through the web UI
//
// Every entry names the action, the account behind it and the client address, so
// the file answers "who changed this, and from where" without cross-referencing
// anything else. Events are ordinary tracing events on a dedicated target, which
// is what routes them to audit.log.
// ─────────────────────────────────────────────────────────────────────────────
pub mod audit {
    pub const TARGET: &str = "audit";

    /// Who performed an action, and from where. `actor` is "-" when nobody is
    /// signed in yet (a failed sign-in, or first-run setup).
    pub struct Actor {
        pub name: String,
        pub ip: String,
    }

    impl Actor {
        pub fn new(name: impl Into<String>, ip: impl Into<String>) -> Actor {
            let name = name.into();
            Actor {
                name: if name.is_empty() { "-".to_string() } else { name },
                ip: ip.into(),
            }
        }
    }

    /// Records one audited action. `detail` carries the specifics — which source
    /// was added, which account failed to sign in.
    pub fn record(action: &str, actor: &Actor, detail: &str) {
        tracing::info!(
            target: TARGET,
            action = action,
            actor = %actor.name,
            client = %actor.ip,
            detail = detail,
        );
    }
}
