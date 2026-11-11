//! Tenant controllers.

use axum::extract::State;
use axum::Json;

use crate::controller::map_engagement;
use crate::error::ApiError;
use crate::extractor::tenant::TenantScope;
use crate::port::TenantSummaryView;
use crate::state::AppState;
use crate::view::envelope::ApiResponse;

/// `GET /v1/tenants/me`
pub async fn me(
    State(state): State<AppState>,
    scope: TenantScope,
) -> Result<Json<ApiResponse<TenantSummaryView>>, ApiError> {
    let t = state
        .tenants
        .get(&scope.tenant_id)
        .await
        .map_err(map_engagement)?;
    Ok(Json(ApiResponse::ok(t)))
}
