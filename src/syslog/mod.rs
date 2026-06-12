// =============================================================================
// syslog/mod.rs — UDP + TCP syslog listeners and message dispatch
//
// Binds both UDP and TCP on the configured syslog port, decodes each incoming
// message's RFC3164/RFC5424 envelope (via syslog_loose), routes it to a log type
// by source IP / hostname (per config), and hands the MSG body to that type's
// ingest(). Unroutable or unparseable messages are logged and dropped.
// =============================================================================

use std::net::IpAddr;
use std::sync::Arc;

use anyhow::Result;
use chrono::Utc;
use syslog_loose::{Variant, parse_message};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::net::{TcpListener, UdpSocket};

use crate::logtype::Meta;
use crate::state::AppState;

// ─────────────────────────────────────────────────────────────────────────────
// serve(state)
// Spawns the UDP and TCP listeners on the configured bind address/port and
// runs them until one returns an error.
// ─────────────────────────────────────────────────────────────────────────────
pub async fn serve(state: Arc<AppState>) -> Result<()> {
    let addr = (state.config.syslog_bind.clone(), state.config.syslog_port);

    let udp = tokio::spawn(serve_udp(state.clone(), addr.clone()));
    let tcp = tokio::spawn(serve_tcp(state.clone(), addr));

    // If either listener fails, surface the error.
    tokio::select! {
        r = udp => r??,
        r = tcp => r??,
    }
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// serve_udp(state, addr)
// Receives datagrams in a loop; each datagram is one syslog message.
// ─────────────────────────────────────────────────────────────────────────────
async fn serve_udp(state: Arc<AppState>, addr: (String, u16)) -> Result<()> {
    let sock = UdpSocket::bind(&addr).await?;
    tracing::info!("syslog UDP listening on {}:{}", addr.0, addr.1);
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let (n, peer) = sock.recv_from(&mut buf).await?;
        let line = String::from_utf8_lossy(&buf[..n]).into_owned();
        dispatch(&state, peer.ip(), &line);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// serve_tcp(state, addr)
// Accepts TCP connections; reads newline-delimited syslog messages per conn.
// ─────────────────────────────────────────────────────────────────────────────
async fn serve_tcp(state: Arc<AppState>, addr: (String, u16)) -> Result<()> {
    let listener = TcpListener::bind(&addr).await?;
    tracing::info!("syslog TCP listening on {}:{}", addr.0, addr.1);
    loop {
        let (stream, peer) = listener.accept().await?;
        let state = state.clone();
        tokio::spawn(async move {
            let ip = peer.ip();
            let mut lines = BufReader::new(stream).lines();
            loop {
                match lines.next_line().await {
                    Ok(Some(line)) => dispatch(&state, ip, &line),
                    Ok(None) => break,
                    Err(e) => {
                        tracing::debug!("tcp read error from {ip}: {e}");
                        break;
                    }
                }
            }
        });
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// dispatch(state, ip, line)
// Parses the syslog envelope, resolves the log type by source IP/hostname, and
// ingests the MSG body. Locks the DB only for the synchronous insert.
// ─────────────────────────────────────────────────────────────────────────────
fn dispatch(state: &Arc<AppState>, ip: IpAddr, line: &str) {
    let msg = parse_message(line, Variant::Either);
    let ip_str = ip.to_string();
    let hostname = msg.hostname.map(|h| h.to_string());

    let Some(type_name) = state
        .config
        .log_type_for(&ip_str, hostname.as_deref())
        .map(|s| s.to_string())
    else {
        tracing::debug!("no log type mapped for source {ip_str}; dropping");
        return;
    };

    let Some(log_type) = state.registry.get(&type_name) else {
        tracing::warn!("source {ip_str} maps to unknown log type '{type_name}'");
        return;
    };

    let meta = Meta {
        source_ip: ip_str,
        hostname,
        received_at: Utc::now(),
    };

    let conn = state.db.lock().expect("db mutex poisoned");
    match log_type.ingest(msg.msg, &meta, &conn) {
        Ok(true) => {}
        Ok(false) => tracing::debug!("{} line did not parse: {}", type_name, msg.msg),
        Err(e) => tracing::error!("{} ingest failed: {e:#}", type_name),
    }
}
