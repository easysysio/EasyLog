// =============================================================================
// web/panos.rs — Palo Alto dashboard (GET /firewall/panos)
//
// PAN-OS events normalize into the shared firewall shape, so this module only
// describes what's Palo-Alto-specific: its table, route and labelling, plus the
// two dimensions it uniquely identifies — the security policy that decided, and
// the App-ID of the traffic itself.
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
    table: "panos",
    base: "/firewall/panos",
    category: "firewall",
    label: "Palo Alto",
    icon: "bi-fire",
    badge: "PAN-OS traffic log",
    hint: "add a syslog server profile and a log-forwarding profile for traffic logs",
    extra: &[
        ExtraDim { key: "application", title: "Top applications", icon: "bi-app-indicator", chip: "Application" },
        ExtraDim { key: "rule", title: "Top security rules", icon: "bi-list-check", chip: "Rule" },
    ],
};

// ─────────────────────────────────────────────────────────────────────────────
// GET /firewall/panos  (?range= plus ?src= ?dst= ?port= ?action= ?protocol=
// ?application= ?rule= ?country= drill-down filters)
// ─────────────────────────────────────────────────────────────────────────────
pub async fn dashboard(
    State(state): State<Arc<AppState>>,
    Query(filter): Query<Filter>,
) -> Result<Response, AppError> {
    super::firewall::render(&state, filter, &SPEC)
}
