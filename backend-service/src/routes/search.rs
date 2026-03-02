use axum::{
    Json,
    extract::{Query, State},
};
use serde::Deserialize;

use crate::error::AppError;
use crate::search;
use crate::state::AppState;

#[derive(Deserialize)]
pub struct SearchQuery {
    pub q: String,
    #[serde(default = "default_limit")]
    pub limit: usize,
}

fn default_limit() -> usize {
    5
}

pub async fn unified_search(
    State(state): State<AppState>,
    Query(params): Query<SearchQuery>,
) -> Result<Json<search::CombinedSearchResult>, AppError> {
    let q = params.q.trim();
    if q.is_empty() {
        return Err(AppError::BadRequest("Search query 'q' is required".into()));
    }

    let limit = params.limit.clamp(1, 20);
    let results = search::search_combined(&state.meili, q, limit).await?;
    Ok(Json(results))
}
