// =============================================================================
// web/unifi.rs — UniFi gateway dashboard (GET /firewall/unifi)
//
// UniFi firewall events normalize into the shared firewall shape, so this module
// only describes what's UniFi-specific: its table, route and labelling, plus the
// two dimensions it identifies — the firewall rule that matched, and the chain
// it sits in (WAN_IN for traffic passing through the gateway, WAN_LOCAL for
// traffic aimed at the gateway itself, and so on).
// =============================================================================

use std::sync::Arc;

use axum::{
    extract::{Query, State},
    response::Response,
};

use super::AppError;
use super::firewall::{ExtraDim, Filter, Spec};
use crate::state::AppState;

const SPEC: Spec = Spec {
    table: "unifi",
    base: "/firewall/unifi",
    category: "firewall",
    label: "UniFi Gateway",
    icon: "bi-router",
    badge: "UniFi firewall log",
    hint: "point the gateway's remote syslog at EasyLog and turn on syslog logging for the firewall rules to watch",
    extra: &[
        ExtraDim { key: "rule", title: "Top firewall rules", icon: "bi-list-check", chip: "Rule" },
        ExtraDim { key: "event_type", title: "Top chains", icon: "bi-diagram-3", chip: "Chain" },
    ],
};

// ─────────────────────────────────────────────────────────────────────────────
// GET /firewall/unifi  (?range= plus ?src= ?dst= ?port= ?action= ?protocol=
// ?rule= ?event_type= ?country= drill-down filters)
// ─────────────────────────────────────────────────────────────────────────────
pub async fn dashboard(
    State(state): State<Arc<AppState>>,
    Query(filter): Query<Filter>,
) -> Result<Response, AppError> {
    super::firewall::render(&state, filter, &SPEC)
}
