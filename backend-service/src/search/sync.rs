use std::time::Duration;

use meilisearch_sdk::client::{Client as MeiliClient, SwapIndexes};
use meilisearch_sdk::settings::PaginationSetting;
use meilisearch_sdk::task_info::TaskInfo;
use meilisearch_sdk::tasks::Task;
use serde::Serialize;
use sqlx::PgPool;

use crate::error::AppError;

const TASK_POLL_INTERVAL: Duration = Duration::from_millis(200);
const TASK_TIMEOUT: Duration = Duration::from_secs(600);

async fn wait_for_task(meili: &MeiliClient, task: TaskInfo, context: &str) -> Result<(), AppError> {
    let status = task
        .wait_for_completion(meili, Some(TASK_POLL_INTERVAL), Some(TASK_TIMEOUT))
        .await
        .map_err(|e| AppError::Search(format!("{context}: {e}")))?;

    match status {
        Task::Succeeded { .. } => Ok(()),
        Task::Failed { .. } => Err(AppError::Search(format!(
            "{context}: task failed ({status:?})"
        ))),
        Task::Enqueued { .. } | Task::Processing { .. } => Err(AppError::Search(format!(
            "{context}: task did not complete"
        ))),
    }
}

async fn ensure_index(meili: &MeiliClient, uid: &str, primary_key: &str) -> Result<(), AppError> {
    match meili.create_index(uid, Some(primary_key)).await {
        Ok(task) => wait_for_task(meili, task, &format!("create {uid} index")).await,
        Err(e) => {
            let msg = e.to_string();
            if msg.contains("index_already_exists") || msg.contains("already exists") {
                Ok(())
            } else {
                Err(AppError::Search(msg))
            }
        }
    }
}

async fn delete_index_if_exists(meili: &MeiliClient, uid: &str) -> Result<(), AppError> {
    match meili.delete_index(uid).await {
        Ok(task) => wait_for_task(meili, task, &format!("delete {uid} index")).await,
        Err(e) => {
            let msg = e.to_string();
            if msg.contains("index_not_found") {
                Ok(())
            } else {
                Err(AppError::Search(msg))
            }
        }
    }
}

/// Document shape for the "servers" Meilisearch index.
/// Only lightweight fields — NO tools, resources, prompts, connections, etc.
#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct ServerSearchDoc {
    pub id: i32,
    pub dedup_key: String,
    pub name: String,
    pub description: String,
    pub categories: Option<serde_json::Value>,
    pub language: Option<String>,
    pub security_grade: Option<String>,
    pub quality_grade: Option<String>,
    pub license_grade: Option<String>,
    pub stars: i32,
    pub weekly_downloads: Option<i32>,
    pub source_count: i32,
    pub github_url: Option<String>,
    pub github_owner: Option<String>,
    pub github_repo: Option<String>,
}

/// Document shape for the "skills" Meilisearch index.
#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct SkillSearchDoc {
    pub id: i32,
    pub dedup_key: String,
    pub name: String,
    pub skill_name: String,
    pub description: String,
    pub categories: Option<serde_json::Value>,
    pub quality_score: Option<f64>,
    pub stars: i32,
    pub installs: i32,
    pub weekly_installs: i32,
    pub source_count: i32,
    pub github_url: Option<String>,
    pub github_owner: Option<String>,
    pub github_repo: Option<String>,
    pub audit_summary: Option<serde_json::Value>,
}

/// Full sync: syncs all servers and skills from PG to Meilisearch.
/// Called on startup and by the daily cron job.
pub async fn full_sync(pool: &PgPool, meili: &MeiliClient) -> Result<(), AppError> {
    tracing::info!("Starting full Meilisearch sync...");
    sync_servers(pool, meili).await?;
    sync_skills(pool, meili).await?;
    tracing::info!("Meilisearch sync complete");
    Ok(())
}

/// Sync all servers from PG to Meilisearch.
async fn sync_servers(pool: &PgPool, meili: &MeiliClient) -> Result<(), AppError> {
    const LIVE_INDEX: &str = "servers";
    const STAGING_INDEX: &str = "servers_staging";

    ensure_index(meili, LIVE_INDEX, "id").await?;
    delete_index_if_exists(meili, STAGING_INDEX).await?;
    ensure_index(meili, STAGING_INDEX, "id").await?;

    let index = meili.index(STAGING_INDEX);

    // Configure index settings.
    let task = index
        .set_searchable_attributes([
            "name",
            "description",
            "categories",
            "language",
            "github_url",
            "github_owner",
            "github_repo",
        ])
        .await
        .map_err(|e| AppError::Search(e.to_string()))?;
    wait_for_task(meili, task, "set servers searchable attributes").await?;

    let task = index
        .set_filterable_attributes([
            "categories",
            "language",
            "security_grade",
            "quality_grade",
            "license_grade",
            "stars",
            "weekly_downloads",
            "source_count",
        ])
        .await
        .map_err(|e| AppError::Search(e.to_string()))?;
    wait_for_task(meili, task, "set servers filterable attributes").await?;

    let task = index
        .set_sortable_attributes(["stars", "weekly_downloads", "name"])
        .await
        .map_err(|e| AppError::Search(e.to_string()))?;
    wait_for_task(meili, task, "set servers sortable attributes").await?;

    let task = index
        .set_pagination(PaginationSetting {
            max_total_hits: 100_000,
        })
        .await
        .map_err(|e| AppError::Search(e.to_string()))?;
    wait_for_task(meili, task, "set servers pagination").await?;

    // Paginate through merged_servers to avoid loading all rows into memory at once.
    // We use `id` as the Meilisearch primary key because `dedup_key` contains `/`
    // (e.g. "owner/repo") which Meilisearch does not allow in primary keys.
    let mut last_id = 0i32;
    let batch_size = 5000i64;
    let mut total = 0usize;
    loop {
        let rows = sqlx::query_as::<_, ServerSearchDoc>(
            r#"
            SELECT
                id,
                dedup_key,
                name,
                description,
                categories,
                language,
                security_grade,
                quality_grade,
                license_grade,
                stars,
                weekly_downloads,
                source_count,
                github_url,
                github_owner,
                github_repo
            FROM merged_servers
            WHERE id > $1
            ORDER BY id
            LIMIT $2
            "#,
        )
        .bind(last_id)
        .bind(batch_size)
        .fetch_all(pool)
        .await?;

        if rows.is_empty() {
            break;
        }

        let count = rows.len();
        total += count;

        let task = index
            .add_documents(&rows, Some("id"))
            .await
            .map_err(|e| AppError::Search(e.to_string()))?;
        wait_for_task(meili, task, "index servers batch").await?;

        if let Some(last) = rows.last() {
            last_id = last.id;
        }

        if count < batch_size as usize {
            break;
        }
    }

    let task = meili
        .swap_indexes([&SwapIndexes {
            indexes: (LIVE_INDEX.to_string(), STAGING_INDEX.to_string()),
        }])
        .await
        .map_err(|e| AppError::Search(e.to_string()))?;
    wait_for_task(meili, task, "swap servers indexes").await?;

    if let Err(e) = delete_index_if_exists(meili, STAGING_INDEX).await {
        tracing::warn!("Failed to cleanup old servers index after swap: {e}");
    }

    tracing::info!("Synced {} servers to Meilisearch", total);
    Ok(())
}

/// Sync all skills from PG to Meilisearch.
async fn sync_skills(pool: &PgPool, meili: &MeiliClient) -> Result<(), AppError> {
    const LIVE_INDEX: &str = "skills";
    const STAGING_INDEX: &str = "skills_staging";

    ensure_index(meili, LIVE_INDEX, "id").await?;
    delete_index_if_exists(meili, STAGING_INDEX).await?;
    ensure_index(meili, STAGING_INDEX, "id").await?;

    let index = meili.index(STAGING_INDEX);

    // Configure index settings
    let task = index
        .set_searchable_attributes([
            "name",
            "skill_name",
            "description",
            "categories",
            "github_url",
            "github_owner",
        ])
        .await
        .map_err(|e| AppError::Search(e.to_string()))?;
    wait_for_task(meili, task, "set skills searchable attributes").await?;

    let task = index
        .set_filterable_attributes([
            "categories",
            "quality_score",
            "stars",
            "installs",
            "source_count",
        ])
        .await
        .map_err(|e| AppError::Search(e.to_string()))?;
    wait_for_task(meili, task, "set skills filterable attributes").await?;

    let task = index
        .set_sortable_attributes(["stars", "installs", "weekly_installs", "name"])
        .await
        .map_err(|e| AppError::Search(e.to_string()))?;
    wait_for_task(meili, task, "set skills sortable attributes").await?;

    let task = index
        .set_pagination(PaginationSetting {
            max_total_hits: 100_000,
        })
        .await
        .map_err(|e| AppError::Search(e.to_string()))?;
    wait_for_task(meili, task, "set skills pagination").await?;

    // Paginate through merged_skills to avoid loading all 270k+ rows into memory at once.
    // We use `id` as the Meilisearch primary key because `dedup_key` contains `/`
    // (e.g. "owner/repo") which Meilisearch does not allow in primary keys.
    let mut last_id = 0i32;
    let batch_size = 5000i64;
    let mut total = 0usize;
    loop {
        let rows = sqlx::query_as::<_, SkillSearchDoc>(
            r#"
            SELECT
                id,
                dedup_key,
                name,
                skill_name,
                description,
                categories,
                quality_score,
                stars,
                installs,
                weekly_installs,
                source_count,
                github_url,
                github_owner,
                github_repo,
                audit_summary
            FROM merged_skills
            WHERE id > $1
            ORDER BY id
            LIMIT $2
            "#,
        )
        .bind(last_id)
        .bind(batch_size)
        .fetch_all(pool)
        .await?;

        if rows.is_empty() {
            break;
        }

        let count = rows.len();
        total += count;

        let task = index
            .add_documents(&rows, Some("id"))
            .await
            .map_err(|e| AppError::Search(e.to_string()))?;
        wait_for_task(meili, task, "index skills batch").await?;

        if let Some(last) = rows.last() {
            last_id = last.id;
        }

        if count < batch_size as usize {
            break;
        }
    }

    let task = meili
        .swap_indexes([&SwapIndexes {
            indexes: (LIVE_INDEX.to_string(), STAGING_INDEX.to_string()),
        }])
        .await
        .map_err(|e| AppError::Search(e.to_string()))?;
    wait_for_task(meili, task, "swap skills indexes").await?;

    if let Err(e) = delete_index_if_exists(meili, STAGING_INDEX).await {
        tracing::warn!("Failed to cleanup old skills index after swap: {e}");
    }

    tracing::info!("Synced {} skills to Meilisearch", total);
    Ok(())
}
