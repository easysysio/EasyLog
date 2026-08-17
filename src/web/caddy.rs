// =============================================================================
// web/caddy.rs — Caddy dashboard (GET /web/caddy)
//
// Caddy's JSON access log carries a request duration, so it shares the renderer
// in web/proxy.rs with Traefik. Caddy has no routing dimensions of its own —
// requests are keyed by host and path — so the spec declares no extra panels
// and the dashboard is KPIs, timeline, status codes, top URLs / IPs / countries
// and the world map.
// =============================================================================

use std::sync::Arc;

use axum::{
    extract::{Query, State},
    response::Html,
};

use super::AppError;
use super::proxy::{Filter, Spec};
use crate::state::AppState;

const SPEC: Spec = Spec {
    table: "caddy",
    base: "/web/caddy",
    category: "web",
    label: "Caddy",
    icon: "bi-shield-check",
    badge: "JSON access log",
    hint: "enable `log { format json }` and forward its access log over syslog",
    search: &["remote_host", "path", "user_agent", "referer", "host", "country"],
    extra: &[],
};

// ─────────────────────────────────────────────────────────────────────────────
// GET /web/caddy  (?range= plus ?ip= ?path= ?status= ?country= filters)
// ─────────────────────────────────────────────────────────────────────────────
pub async fn dashboard(
    State(state): State<Arc<AppState>>,
    Query(filter): Query<Filter>,
) -> Result<Html<String>, AppError> {
    super::proxy::render(&state, filter, &SPEC)
}
