use axum::Json;
use axum::extract::{Query, State};
use axum::http::StatusCode;
use serde::Deserialize;

use crate::error::AppError;
use crate::models::{AuditRun, CreateAuditRequest, PaginatedResponse, PaginationParams};
use crate::state::AppState;

// ---------------------------------------------------------------------------
// POST /api/admin/audit
// ---------------------------------------------------------------------------

pub async fn trigger_audit(
    State(state): State<AppState>,
    Json(req): Json<CreateAuditRequest>,
) -> Result<(StatusCode, Json<AuditRun>), AppError> {
    let item_type = req.item_type.trim().to_ascii_lowercase();
    let item_dedup_key = req.item_dedup_key.trim();

    if item_dedup_key.is_empty() {
        return Err(AppError::BadRequest(
            "item_dedup_key must not be empty".to_string(),
        ));
    }
    if item_dedup_key.len() > 500 {
        return Err(AppError::BadRequest(
            "item_dedup_key is too long (max 500 chars)".to_string(),
        ));
    }

    // Validate item_type and verify the item exists
    let exists: bool = match item_type.as_str() {
        "server" => {
            sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM merged_servers WHERE dedup_key = $1)")
                .bind(item_dedup_key)
                .fetch_one(&state.db)
                .await?
        }
        "skill" => {
            sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM merged_skills WHERE dedup_key = $1)")
                .bind(item_dedup_key)
                .fetch_one(&state.db)
                .await?
        }
        _ => {
            return Err(AppError::BadRequest(
                "item_type must be 'server' or 'skill'".to_string(),
            ));
        }
    };
    if !exists {
        return Err(AppError::NotFound);
    }

    let run = sqlx::query_as::<_, AuditRun>(
        r#"
        INSERT INTO audit_runs (item_type, item_dedup_key, status, requested_by)
        VALUES ($1, $2, 'pending', 'admin')
        ON CONFLICT (item_type, item_dedup_key)
        WHERE status IN ('pending', 'running')
        DO UPDATE
        SET requested_by = audit_runs.requested_by
        RETURNING id, item_type, item_dedup_key, status, result, score, grade,
                  requested_by, created_at, completed_at
        "#,
    )
    .bind(&item_type)
    .bind(item_dedup_key)
    .fetch_one(&state.db)
    .await?;

    Ok((StatusCode::OK, Json(run)))
}

// ---------------------------------------------------------------------------
// GET /api/admin/audits
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct AuditListQuery {
    pub status: Option<String>,
    pub page: Option<u32>,
    pub per_page: Option<u32>,
}

pub async fn list_audit_runs(
    State(state): State<AppState>,
    Query(params): Query<AuditListQuery>,
) -> Result<Json<PaginatedResponse<AuditRun>>, AppError> {
    let pagination = PaginationParams {
        page: params.page.unwrap_or(1),
        per_page: params.per_page.unwrap_or(12),
    }
    .validated();

    let offset = pagination.offset();

    // ----- COUNT + DATA -----
    let (total, items): (i64, Vec<AuditRun>) = if let Some(ref status) = params.status {
        let total =
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM audit_runs WHERE status = $1")
                .bind(status)
                .fetch_one(&state.db)
                .await?;

        let items = sqlx::query_as::<_, AuditRun>(
            r#"
            SELECT id, item_type, item_dedup_key, status, result, score, grade,
                   requested_by, created_at, completed_at
            FROM audit_runs
            WHERE status = $1
            ORDER BY created_at DESC
            LIMIT $2 OFFSET $3
            "#,
        )
        .bind(status)
        .bind(pagination.per_page as i64)
        .bind(offset as i64)
        .fetch_all(&state.db)
        .await?;

        (total, items)
    } else {
        let total = sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM audit_runs")
            .fetch_one(&state.db)
            .await?;

        let items = sqlx::query_as::<_, AuditRun>(
            r#"
            SELECT id, item_type, item_dedup_key, status, result, score, grade,
                   requested_by, created_at, completed_at
            FROM audit_runs
            ORDER BY created_at DESC
            LIMIT $1 OFFSET $2
            "#,
        )
        .bind(pagination.per_page as i64)
        .bind(offset as i64)
        .fetch_all(&state.db)
        .await?;

        (total, items)
    };

    Ok(Json(PaginatedResponse::new(
        items,
        total,
        pagination.page,
        pagination.per_page,
    )))
}

// ---------------------------------------------------------------------------
// POST /api/admin/sync-search
// ---------------------------------------------------------------------------

pub async fn trigger_search_sync(
    State(state): State<AppState>,
) -> Result<(StatusCode, Json<serde_json::Value>), AppError> {
    let permit = match state.search_sync_permit.clone().try_acquire_owned() {
        Ok(permit) => permit,
        Err(_) => {
            return Ok((
                StatusCode::CONFLICT,
                Json(serde_json::json!({ "status": "sync_already_running" })),
            ));
        }
    };

    let pool = state.db.clone();
    let meili = state.meili.clone();
    tokio::spawn(async move {
        let _permit = permit;
        if let Err(e) = crate::jobs::search_sync::run_search_sync_with_retries(&pool, &meili).await
        {
            tracing::error!("Manual search sync failed: {e}");
        }
    });
    Ok((
        StatusCode::ACCEPTED,
        Json(serde_json::json!({ "status": "sync_started" })),
    ))
}
