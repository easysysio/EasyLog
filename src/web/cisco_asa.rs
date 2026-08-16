// =============================================================================
// web/cisco_asa.rs — Cisco ASA dashboard (GET /firewall/cisco_asa)
//
// The ASA's events normalize into the shared firewall shape, so this module only
// describes what's ASA-specific: its table, route, labelling, and the fact that
// its decisions are attributed to an access-list, which gets its own panel.
// =============================================================================

use std::sync::Arc;

use axum::{
    extract::{Query, State},
    response::Html,
};

use super::AppError;
use super::firewall::{ExtraDim, Filter, Spec};
use crate::state::AppState;

const SPEC: Spec = Spec {
    table: "cisco_asa",
    base: "/firewall/cisco_asa",
    category: "firewall",
    label: "Cisco ASA",
    icon: "bi-bricks",
    badge: "ASA syslog",
    hint: "point `logging host` at EasyLog",
    extra: &[ExtraDim {
        key: "rule",
        title: "Top access-lists",
        icon: "bi-list-check",
        chip: "Access-list",
    }],
};

// ─────────────────────────────────────────────────────────────────────────────
// GET /firewall/cisco_asa  (?range= plus ?src= ?dst= ?port= ?action=
// ?protocol= ?rule= ?country= drill-down filters)
// ─────────────────────────────────────────────────────────────────────────────
pub async fn dashboard(
    State(state): State<Arc<AppState>>,
    Query(filter): Query<Filter>,
) -> Result<Html<String>, AppError> {
    super::firewall::render(&state, filter, &SPEC)
}
