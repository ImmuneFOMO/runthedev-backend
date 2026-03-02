use axum::Json;
use axum::extract::State;
use serde::Serialize;

use crate::error::AppError;
use crate::state::{AppState, CachedStats};

const STATS_CACHE_TTL_SECS: i64 = 60;

#[derive(Serialize)]
pub struct StatsResponse {
    pub servers_count: i64,
    pub skills_count: i64,
    pub audited_servers: i64,
    pub audited_skills: i64,
}

/// GET /api/stats — Landing page aggregate counts
pub async fn get_stats(State(state): State<AppState>) -> Result<Json<StatsResponse>, AppError> {
    {
        let cache = state.stats_cache.read().await;
        if let Some(cached) = &*cache {
            let age = chrono::Utc::now() - cached.cached_at;
            if age.num_seconds() < STATS_CACHE_TTL_SECS {
                return Ok(Json(StatsResponse {
                    servers_count: cached.servers_count,
                    skills_count: cached.skills_count,
                    audited_servers: cached.audited_servers,
                    audited_skills: cached.audited_skills,
                }));
            }
        }
    }

    let _refresh_guard = state.stats_refresh_lock.lock().await;

    {
        let cache = state.stats_cache.read().await;
        if let Some(cached) = &*cache {
            let age = chrono::Utc::now() - cached.cached_at;
            if age.num_seconds() < STATS_CACHE_TTL_SECS {
                return Ok(Json(StatsResponse {
                    servers_count: cached.servers_count,
                    skills_count: cached.skills_count,
                    audited_servers: cached.audited_servers,
                    audited_skills: cached.audited_skills,
                }));
            }
        }
    }

    let row = sqlx::query_as::<_, (i64, i64, i64, i64)>(
        r#"
        SELECT
            (SELECT COUNT(*) FROM merged_servers) AS servers_count,
            (SELECT COUNT(*) FROM merged_skills) AS skills_count,
            (SELECT COUNT(DISTINCT item_dedup_key) FROM audit_runs WHERE item_type = 'server' AND status = 'completed') AS audited_servers,
            (SELECT COUNT(DISTINCT item_dedup_key) FROM audit_runs WHERE item_type = 'skill' AND status = 'completed') AS audited_skills
        "#,
    )
    .fetch_one(&state.db)
    .await?;

    {
        let mut cache = state.stats_cache.write().await;
        *cache = Some(CachedStats {
            servers_count: row.0,
            skills_count: row.1,
            audited_servers: row.2,
            audited_skills: row.3,
            cached_at: chrono::Utc::now(),
        });
    }

    Ok(Json(StatsResponse {
        servers_count: row.0,
        skills_count: row.1,
        audited_servers: row.2,
        audited_skills: row.3,
    }))
}
