// =============================================================================
// web/unifi.rs — UniFi gateway dashboard (GET /firewall/unifi)
//
// UniFi firewall events normalize into the shared firewall shape, so this module
// only describes what's UniFi-specific: its table, route and labelling, plus the
// dimensions it identifies — the firewall rule or IPS signature that matched,
// the application (from CEF events), and the chain the rule sits in (WAN_IN for
// traffic passing through the gateway, WAN_LOCAL for traffic aimed at the
// gateway itself, …) or, for a CEF event, its name ("Threat Detected").
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
    badge: "UniFi firewall + IDS/IPS",
    hint: "point the gateway's remote syslog at EasyLog and turn on syslog logging for the firewall rules to watch",
    extra: &[
        ExtraDim { key: "rule", title: "Top rules & signatures", icon: "bi-list-check", chip: "Rule" },
        ExtraDim { key: "event_type", title: "Top chains & detections", icon: "bi-diagram-3", chip: "Chain" },
        ExtraDim { key: "application", title: "Top applications", icon: "bi-app-indicator", chip: "Application" },
    ],
};

// ─────────────────────────────────────────────────────────────────────────────
// GET /firewall/unifi  (?range= plus ?src= ?dst= ?port= ?action= ?protocol=
// ?rule= ?event_type= ?application= ?country= drill-down filters)
// ─────────────────────────────────────────────────────────────────────────────
pub async fn dashboard(
    State(state): State<Arc<AppState>>,
    Query(filter): Query<Filter>,
) -> Result<Response, AppError> {
    super::firewall::render(&state, filter, &SPEC)
}
