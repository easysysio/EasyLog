// =============================================================================
// web/haproxy.rs — HAProxy dashboard (GET /web/haproxy)
//
// HAProxy's httplog carries the total session time, so the dashboard is the
// shared one in web/proxy.rs. Its routing dimensions are the backend and the
// server that handled the request — the two things you reach for when a site
// slows down or starts erroring.
// =============================================================================

use std::sync::Arc;

use axum::{
    extract::{Query, State},
    response::Html,
};

use super::AppError;
use super::proxy::{ExtraDim, Filter, Spec};
use crate::state::AppState;

const SPEC: Spec = Spec {
    table: "haproxy",
    base: "/web/haproxy",
    category: "web",
    label: "HAProxy",
    icon: "bi-shuffle",
    badge: "HTTP log",
    hint: "set `option httplog` and forward its syslog output",
    extra: &[
        ExtraDim { key: "backend", title: "Top backends", icon: "bi-hdd-stack", chip: "Backend" },
        ExtraDim { key: "server", title: "Top servers", icon: "bi-server", chip: "Server" },
    ],
};

// ─────────────────────────────────────────────────────────────────────────────
// GET /web/haproxy  (?range= plus ?ip= ?path= ?status= ?backend= ?server=
// ?country= drill-down filters)
// ─────────────────────────────────────────────────────────────────────────────
pub async fn dashboard(
    State(state): State<Arc<AppState>>,
    Query(filter): Query<Filter>,
) -> Result<Html<String>, AppError> {
    super::proxy::render(&state, filter, &SPEC)
}
