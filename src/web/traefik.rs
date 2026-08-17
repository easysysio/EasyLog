// =============================================================================
// web/traefik.rs — Traefik dashboard (GET /web/traefik)
//
// Traefik logs requests with a duration, so the dashboard is the shared one in
// web/proxy.rs; this module only describes what makes Traefik different: its
// table, route, labelling, and the two routing dimensions it can be filtered by
// (router and service).
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
    table: "traefik",
    base: "/web/traefik",
    category: "web",
    label: "Traefik",
    icon: "bi-diagram-3",
    badge: "JSON access log",
    hint: "forward its JSON access log over syslog",
    search: &["remote_host", "path", "user_agent", "host", "country", "router", "service"],
    extra: &[
        ExtraDim { key: "router", title: "Top routers", icon: "bi-signpost-2", chip: "Router" },
        ExtraDim { key: "service", title: "Top services", icon: "bi-hdd-stack", chip: "Service" },
    ],
};

// ─────────────────────────────────────────────────────────────────────────────
// GET /web/traefik  (?range= plus ?ip= ?path= ?status= ?router= ?service=
// ?country= drill-down filters)
// ─────────────────────────────────────────────────────────────────────────────
pub async fn dashboard(
    State(state): State<Arc<AppState>>,
    Query(filter): Query<Filter>,
) -> Result<Html<String>, AppError> {
    super::proxy::render(&state, filter, &SPEC)
}
