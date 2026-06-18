// =============================================================================
// web/nginx.rs — nginx dashboard (GET /nginx)
//
// nginx access logs share Apache's combined-format schema, so this reuses the
// shared dashboard renderer (web::apache::render) against the `nginx` table and
// the same template, with drill-down links rooted at /nginx.
// =============================================================================

use std::sync::Arc;

use axum::{
    extract::{Query, State},
    response::Html,
};

use super::AppError;
use super::apache::{Filter, render};
use crate::state::AppState;

// ─────────────────────────────────────────────────────────────────────────────
// GET /nginx  (same ?range= / ?ip= / ?path= / ?status= filters as Apache)
// ─────────────────────────────────────────────────────────────────────────────
pub async fn dashboard(
    State(state): State<Arc<AppState>>,
    Query(filter): Query<Filter>,
) -> Result<Html<String>, AppError> {
    render(&state, filter, "nginx", "/nginx", "Nginx", "apache.html")
}
