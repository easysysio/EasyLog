// =============================================================================
// syslog/mod.rs — UDP + TCP syslog listeners and async ingestion pipeline
//
// Binds both UDP and TCP on the configured syslog port, decodes each incoming
// message's RFC3164/RFC5424 envelope (via syslog_loose), and routes it to a log
// type by source IP (per the in-memory source map). To keep the UDP recv loop
// from stalling under bursts, receiving is decoupled from writing: the hot path
// only parses + enqueues a small work item onto a bounded channel (no DB lock),
// and a dedicated background writer task drains the channel and inserts rows in
// batches under a single transaction. Unroutable/unparseable messages are
// logged and dropped; channel overflow drops with a throttled warning.
// =============================================================================

use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::{Context, Result};
use chrono::Utc;
use socket2::{Domain, Protocol, Socket, Type};
use syslog_loose::{Variant, parse_message};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::mpsc;

use crate::logtype::Meta;
use crate::state::AppState;

// Capacity of the receive→write channel. Large enough to absorb a burst while
// the writer catches up; bounded so a runaway sender cannot exhaust memory.
const CHANNEL_CAPACITY: usize = 100_000;

// Maximum number of work items folded into a single write transaction.
const BATCH_MAX: usize = 1024;

// Target size for the UDP socket receive buffer (SO_RCVBUF). A bigger kernel
// buffer gives the recv loop more slack to drain a burst before drops occur.
// BSD/macOS charge a full mbuf cluster per datagram, so for small syslog packets
// the survivable burst scales with this buffer. Requested best-effort; the OS
// clamps it to its own ceiling (e.g. kern.ipc.maxsockbuf / net.core.rmem_max).
const UDP_RECV_BUFFER_BYTES: usize = 8 * 1024 * 1024;

// Count of work items dropped because the channel was full. Used to emit a
// throttled warning rather than one log line per dropped packet.
static DROPPED: AtomicU64 = AtomicU64::new(0);

// A unit of work handed from a receive loop to the writer task: which log type
// to route to, the raw MSG body, and the syslog envelope metadata. Owns its
// data so it can cross the channel without borrowing from the recv buffer.
struct WorkItem {
    type_name: String,
    raw: String,
    meta: Meta,
}

// ─────────────────────────────────────────────────────────────────────────────
// serve(state)
// Spawns the background writer task and the UDP and TCP listeners, wiring them
// together with a bounded mpsc channel, and runs until one of them errors.
// ─────────────────────────────────────────────────────────────────────────────
pub async fn serve(state: Arc<AppState>) -> Result<()> {
    let addr = (state.config.syslog_bind.clone(), state.config.syslog_port);

    // Receive loops are producers; the writer task is the sole consumer.
    let (tx, rx) = mpsc::channel::<WorkItem>(CHANNEL_CAPACITY);

    let writer = tokio::spawn(writer_task(state.clone(), rx));
    let udp = tokio::spawn(serve_udp(state.clone(), addr.clone(), tx.clone()));
    let tcp = tokio::spawn(serve_tcp(state.clone(), addr, tx));

    // If any of the three tasks finishes (always an error in steady state),
    // surface it and shut down.
    tokio::select! {
        r = udp => r??,
        r = tcp => r??,
        r = writer => r??,
    }
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// serve_udp(state, addr, tx)
// Receives datagrams in a loop; each datagram is one syslog message. The socket
// is built via socket2 so its receive buffer can be enlarged before binding.
// The loop only parses + enqueues — it never touches the DB — so it can drain
// the socket as fast as the kernel delivers packets.
// ─────────────────────────────────────────────────────────────────────────────
async fn serve_udp(state: Arc<AppState>, addr: (String, u16), tx: mpsc::Sender<WorkItem>) -> Result<()> {
    let sock = bind_udp(&addr).await?;
    tracing::info!("syslog UDP listening on {}:{}", addr.0, addr.1);
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let (n, peer) = sock.recv_from(&mut buf).await?;
        let line = String::from_utf8_lossy(&buf[..n]).into_owned();
        enqueue(&state, &tx, peer.ip(), &line);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// bind_udp(addr)
// Builds a UDP socket with an enlarged SO_RCVBUF and binds it, returning it as a
// tokio UdpSocket. Resolving and binding via socket2 lets us set the receive
// buffer (a burst-drop mitigation) that tokio's UdpSocket::bind does not expose.
// ─────────────────────────────────────────────────────────────────────────────
async fn bind_udp(addr: &(String, u16)) -> Result<UdpSocket> {
    let sock_addr: SocketAddr = (addr.0.as_str(), addr.1)
        .to_socket_addrs()
        .with_context(|| format!("resolving syslog bind {}:{}", addr.0, addr.1))?
        .next()
        .with_context(|| format!("no address for syslog bind {}:{}", addr.0, addr.1))?;

    let sock = Socket::new(Domain::for_address(sock_addr), Type::DGRAM, Some(Protocol::UDP))?;
    // Best-effort: the OS may clamp the request; log if it differs from asked.
    if let Err(e) = sock.set_recv_buffer_size(UDP_RECV_BUFFER_BYTES) {
        tracing::warn!("could not set UDP recv buffer to {UDP_RECV_BUFFER_BYTES}: {e}");
    }
    sock.set_nonblocking(true)?;
    sock.bind(&sock_addr.into())?;
    Ok(UdpSocket::from_std(sock.into())?)
}

// ─────────────────────────────────────────────────────────────────────────────
// serve_tcp(state, addr, tx)
// Accepts TCP connections; reads newline-delimited syslog messages per conn and
// enqueues each onto the writer channel (no DB lock on this path either).
// ─────────────────────────────────────────────────────────────────────────────
async fn serve_tcp(state: Arc<AppState>, addr: (String, u16), tx: mpsc::Sender<WorkItem>) -> Result<()> {
    let listener = TcpListener::bind(&addr).await?;
    tracing::info!("syslog TCP listening on {}:{}", addr.0, addr.1);
    loop {
        let (stream, peer) = listener.accept().await?;
        let state = state.clone();
        let tx = tx.clone();
        tokio::spawn(async move {
            let ip = peer.ip();
            let mut lines = BufReader::new(stream).lines();
            loop {
                match lines.next_line().await {
                    Ok(Some(line)) => enqueue(&state, &tx, ip, &line),
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
// enqueue(state, tx, ip, line)
// Parses the syslog envelope, resolves the log type by source IP (via the
// in-memory source map, under a short read lock), and pushes a WorkItem onto the
// writer channel. Never locks the DB. If the channel is full, the item is
// dropped and a throttled warning is emitted (back-pressure without stalling the
// recv loop). received_at is stamped here, at receive time.
// ─────────────────────────────────────────────────────────────────────────────
fn enqueue(state: &Arc<AppState>, tx: &mpsc::Sender<WorkItem>, ip: IpAddr, line: &str) {
    let msg = parse_message(line, Variant::Either);
    let ip_str = ip.to_string();
    let hostname = msg.hostname.map(|h| h.to_string());

    let type_name = {
        let map = state.sources.read().expect("sources lock poisoned");
        map.get(&ip_str).map(|s| s.log_type.clone())
    };
    let Some(type_name) = type_name else {
        tracing::debug!("no source configured for {ip_str}; dropping");
        return;
    };

    let meta = Meta {
        source_ip: ip_str,
        hostname,
        received_at: Utc::now(),
    };

    let item = WorkItem {
        type_name,
        raw: msg.msg.to_string(),
        meta,
    };

    if tx.try_send(item).is_err() {
        // Full channel (or closed): count the drop and warn occasionally so a
        // sustained overload does not produce one log line per packet.
        let n = DROPPED.fetch_add(1, Ordering::Relaxed) + 1;
        if n % 1000 == 1 {
            tracing::warn!("syslog write channel full; dropped {n} message(s) so far");
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// writer_task(state, rx)
// The sole DB writer. Blocks for the next work item, then greedily drains up to
// BATCH_MAX items already waiting in the channel and flushes them in a single
// transaction — amortizing the DB lock and DuckDB's per-statement commit cost
// across the whole batch. Runs until the channel is closed (all senders gone).
// ─────────────────────────────────────────────────────────────────────────────
async fn writer_task(state: Arc<AppState>, mut rx: mpsc::Receiver<WorkItem>) -> Result<()> {
    let mut batch: Vec<WorkItem> = Vec::with_capacity(BATCH_MAX);
    loop {
        // Wait for at least one item; None means every sender has dropped.
        let Some(first) = rx.recv().await else {
            tracing::info!("syslog write channel closed; writer task exiting");
            return Ok(());
        };
        batch.push(first);

        // Fold in whatever else is already queued, up to the batch ceiling.
        while batch.len() < BATCH_MAX {
            match rx.try_recv() {
                Ok(item) => batch.push(item),
                Err(_) => break,
            }
        }

        flush_batch(&state, &mut batch);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// flush_batch(state, batch)
// Inserts every item in `batch` into its log type's storage under a single DB
// lock, wrapped in one transaction so the cost of acquiring the lock and
// committing is paid once for the whole batch. Clears `batch` when done. A
// failed transaction is logged and the batch dropped (best-effort ingestion).
// ─────────────────────────────────────────────────────────────────────────────
fn flush_batch(state: &Arc<AppState>, batch: &mut Vec<WorkItem>) {
    if batch.is_empty() {
        return;
    }

    let conn = state.db.lock().expect("db mutex poisoned");
    if let Err(e) = conn.execute_batch("BEGIN TRANSACTION") {
        tracing::error!("failed to begin write transaction: {e:#}");
        batch.clear();
        return;
    }

    for item in batch.iter() {
        let Some(log_type) = state.registry.get(&item.type_name) else {
            tracing::warn!("source maps to unknown log type '{}'", item.type_name);
            continue;
        };
        match log_type.ingest(&item.raw, &item.meta, &conn) {
            Ok(true) => {}
            Ok(false) => tracing::debug!("{} line did not parse: {}", item.type_name, item.raw),
            Err(e) => tracing::error!("{} ingest failed: {e:#}", item.type_name),
        }
    }

    if let Err(e) = conn.execute_batch("COMMIT") {
        tracing::error!("failed to commit write transaction: {e:#}");
        // Try to roll back so the connection is not left mid-transaction.
        let _ = conn.execute_batch("ROLLBACK");
    }

    batch.clear();
}
