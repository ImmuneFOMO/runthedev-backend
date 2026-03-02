use axum::Json;
use axum::extract::{Path, Query, State};
use serde::Deserialize;
use sqlx::Row;

use crate::error::AppError;
use crate::models::{
    AuditBrief, PaginatedResponse, PaginationParams, RelatedServer, ServerDetail, ServerListItem,
};
use crate::search;
use crate::state::{AppState, CachedCategoryList, CategoryCount};

// ---------------------------------------------------------------------------
// Query params
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct ServerListQuery {
    pub q: Option<String>,
    pub sort: Option<String>,
    pub categories: Option<String>,
    pub page: Option<u32>,
    pub per_page: Option<u32>,
}

// ---------------------------------------------------------------------------
// GET /api/servers
// ---------------------------------------------------------------------------

pub async fn list_servers(
    State(state): State<AppState>,
    Query(params): Query<ServerListQuery>,
) -> Result<Json<PaginatedResponse<ServerListItem>>, AppError> {
    let pagination = PaginationParams {
        page: params.page.unwrap_or(1),
        per_page: params.per_page.unwrap_or(12),
    }
    .validated();

    let offset = pagination.offset();

    // Parse categories filter
    let categories: Vec<String> = params
        .categories
        .as_deref()
        .unwrap_or("")
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();

    let query_text = params.q.as_deref().unwrap_or("").trim();

    let (items, total) = if !query_text.is_empty() {
        search_servers_path(&state, query_text, &categories, &pagination, offset).await?
    } else {
        browse_servers_path(&state, &categories, &params.sort, &pagination, offset).await?
    };

    Ok(Json(PaginatedResponse::new(
        items,
        total,
        pagination.page,
        pagination.per_page,
    )))
}

/// Search-driven listing: Meilisearch returns dedup_keys, then we fetch from PG.
async fn search_servers_path(
    state: &AppState,
    query_text: &str,
    categories: &[String],
    _pagination: &PaginationParams,
    offset: u32,
) -> Result<(Vec<ServerListItem>, i64), AppError> {
    let cats = if categories.is_empty() {
        None
    } else {
        Some(categories)
    };

    let result = search::search_servers(
        &state.meili,
        query_text,
        cats,
        offset as usize,
        _pagination.per_page as usize,
    )
    .await?;

    if result.dedup_keys.is_empty() {
        return Ok((vec![], result.total_hits));
    }

    // Build a parameterised IN clause preserving Meilisearch ordering
    let placeholders: Vec<String> = (1..=result.dedup_keys.len())
        .map(|i| format!("${}", i))
        .collect();

    let pos_idx = result.dedup_keys.len() + 1;
    let sql = format!(
        r#"
        SELECT
            s.id, s.dedup_key, s.name, s.description, s.github_url,
            s.categories, s.language, s.security_grade,
            s.quality_grade, s.license_grade,
            s.stars, s.weekly_downloads, s.source_count,
            a.grade AS audit_grade, a.score AS audit_score
        FROM merged_servers s
        LEFT JOIN LATERAL (
            SELECT grade, score FROM audit_runs
            WHERE item_type = 'server' AND item_dedup_key = s.dedup_key AND status = 'completed'
            ORDER BY completed_at DESC LIMIT 1
        ) a ON true
        WHERE s.dedup_key IN ({keys})
        ORDER BY array_position(${pos_idx}::text[], s.dedup_key)
        "#,
        keys = placeholders.join(", "),
        pos_idx = pos_idx,
    );

    let mut q = sqlx::query(&sql);
    for key in &result.dedup_keys {
        q = q.bind(key);
    }
    q = q.bind(&result.dedup_keys);

    let rows = q.fetch_all(&state.db).await?;

    let items = rows
        .iter()
        .map(|row| {
            let audit_grade: Option<String> = row.get("audit_grade");
            let audit_score: Option<f64> = row.get("audit_score");
            let audit = if audit_grade.is_some() || audit_score.is_some() {
                Some(AuditBrief {
                    grade: audit_grade,
                    score: audit_score,
                    status: None,
                    message: None,
                })
            } else {
                None
            };
            ServerListItem {
                id: row.get("id"),
                dedup_key: row.get("dedup_key"),
                name: row.get("name"),
                description: row.get("description"),
                github_url: row.get("github_url"),
                categories: row.get("categories"),
                language: row.get("language"),
                security_grade: row.get("security_grade"),
                quality_grade: row.get("quality_grade"),
                license_grade: row.get("license_grade"),
                stars: row.get("stars"),
                weekly_downloads: row.get("weekly_downloads"),
                source_count: row.get("source_count"),
                audit,
            }
        })
        .collect();

    Ok((items, result.total_hits))
}

/// Browse listing (no search query): fully PG-driven with dynamic filters & sort.
async fn browse_servers_path(
    state: &AppState,
    categories: &[String],
    sort: &Option<String>,
    pagination: &PaginationParams,
    offset: u32,
) -> Result<(Vec<ServerListItem>, i64), AppError> {
    let sort_clause = match sort.as_deref().unwrap_or("featured") {
        "stars" => "s.stars DESC",
        "downloads" => "s.weekly_downloads DESC NULLS LAST",
        "name" => "s.name ASC",
        _ => "CASE WHEN s.security_grade IS NOT NULL THEN 0 ELSE 1 END, s.stars DESC NULLS LAST",
    };

    let has_cats = !categories.is_empty();

    // ----- COUNT query -----
    let count_sql = if has_cats {
        r#"
            SELECT COUNT(*) AS cnt
            FROM merged_servers s
            WHERE s.categories IS NOT NULL
              AND jsonb_typeof(s.categories) = 'array'
              AND s.categories ?| $1::text[]
            "#
        .to_string()
    } else {
        "SELECT COUNT(*) AS cnt FROM merged_servers s".to_string()
    };

    let total: i64 = if has_cats {
        sqlx::query_scalar::<_, i64>(&count_sql)
            .bind(categories)
            .fetch_one(&state.db)
            .await?
    } else {
        sqlx::query_scalar::<_, i64>(&count_sql)
            .fetch_one(&state.db)
            .await?
    };

    // ----- DATA query -----
    let data_sql = if has_cats {
        format!(
            r#"
            SELECT
                s.id, s.dedup_key, s.name, s.description, s.github_url,
                s.categories, s.language, s.security_grade,
                s.quality_grade, s.license_grade,
                s.stars, s.weekly_downloads, s.source_count,
                a.grade AS audit_grade, a.score AS audit_score
            FROM merged_servers s
            LEFT JOIN LATERAL (
                SELECT grade, score FROM audit_runs
                WHERE item_type = 'server' AND item_dedup_key = s.dedup_key AND status = 'completed'
                ORDER BY completed_at DESC LIMIT 1
            ) a ON true
            WHERE s.categories IS NOT NULL
              AND jsonb_typeof(s.categories) = 'array'
              AND s.categories ?| $1::text[]
            ORDER BY {sort_clause}
            LIMIT $2 OFFSET $3
            "#,
            sort_clause = sort_clause,
        )
    } else {
        format!(
            r#"
            SELECT
                s.id, s.dedup_key, s.name, s.description, s.github_url,
                s.categories, s.language, s.security_grade,
                s.quality_grade, s.license_grade,
                s.stars, s.weekly_downloads, s.source_count,
                a.grade AS audit_grade, a.score AS audit_score
            FROM merged_servers s
            LEFT JOIN LATERAL (
                SELECT grade, score FROM audit_runs
                WHERE item_type = 'server' AND item_dedup_key = s.dedup_key AND status = 'completed'
                ORDER BY completed_at DESC LIMIT 1
            ) a ON true
            ORDER BY {sort_clause}
            LIMIT $1 OFFSET $2
            "#,
            sort_clause = sort_clause,
        )
    };

    let rows = if has_cats {
        sqlx::query(&data_sql)
            .bind(categories)
            .bind(pagination.per_page as i64)
            .bind(offset as i64)
            .fetch_all(&state.db)
            .await?
    } else {
        sqlx::query(&data_sql)
            .bind(pagination.per_page as i64)
            .bind(offset as i64)
            .fetch_all(&state.db)
            .await?
    };

    let items = rows
        .iter()
        .map(|row| {
            let audit_grade: Option<String> = row.get("audit_grade");
            let audit_score: Option<f64> = row.get("audit_score");
            let audit = if audit_grade.is_some() || audit_score.is_some() {
                Some(AuditBrief {
                    grade: audit_grade,
                    score: audit_score,
                    status: None,
                    message: None,
                })
            } else {
                None
            };
            ServerListItem {
                id: row.get("id"),
                dedup_key: row.get("dedup_key"),
                name: row.get("name"),
                description: row.get("description"),
                github_url: row.get("github_url"),
                categories: row.get("categories"),
                language: row.get("language"),
                security_grade: row.get("security_grade"),
                quality_grade: row.get("quality_grade"),
                license_grade: row.get("license_grade"),
                stars: row.get("stars"),
                weekly_downloads: row.get("weekly_downloads"),
                source_count: row.get("source_count"),
                audit,
            }
        })
        .collect();

    Ok((items, total))
}

// ---------------------------------------------------------------------------
// GET /api/servers/:dedup_key
// ---------------------------------------------------------------------------

pub async fn get_server_detail(
    State(state): State<AppState>,
    Path(dedup_key): Path<String>,
) -> Result<Json<ServerDetail>, AppError> {
    // Fetch the main server row with audit and tools_count
    let row = sqlx::query(
        r#"
        SELECT
            s.id, s.dedup_key, s.name, s.description,
            s.github_owner, s.github_repo, s.github_url,
            s.categories, s.language, s.license,
            s.security_grade, s.quality_grade, s.license_grade,
            s.stars, s.forks, s.weekly_downloads,
            s.tools, s.resources, s.prompts, s.connections,
            jsonb_array_length(COALESCE(s.tools, '[]'::jsonb))::BIGINT AS tools_count,
            s.source_count,
            s.created_at, s.updated_at,
            a.grade AS audit_grade, a.score AS audit_score
        FROM merged_servers s
        LEFT JOIN LATERAL (
            SELECT grade, score FROM audit_runs
            WHERE item_type = 'server' AND item_dedup_key = s.dedup_key AND status = 'completed'
            ORDER BY completed_at DESC LIMIT 1
        ) a ON true
        WHERE s.dedup_key = $1
        "#,
    )
    .bind(&dedup_key)
    .fetch_optional(&state.db)
    .await?
    .ok_or(AppError::NotFound)?;

    let audit_grade: Option<String> = row.get("audit_grade");
    let audit_score: Option<f64> = row.get("audit_score");
    let audit = if audit_grade.is_some() || audit_score.is_some() {
        Some(AuditBrief {
            grade: audit_grade,
            score: audit_score,
            status: None,
            message: None,
        })
    } else {
        None
    };

    let related_categories: Vec<String> = row
        .get::<Option<serde_json::Value>, _>("categories")
        .and_then(|value| {
            value.as_array().map(|items| {
                items
                    .iter()
                    .filter_map(|item| item.as_str().map(str::to_string))
                    .collect()
            })
        })
        .unwrap_or_default();

    // Fetch related servers (up to 3 sharing at least one category)
    let related_rows = if related_categories.is_empty() {
        vec![]
    } else {
        sqlx::query(
            r#"
            SELECT s2.id, s2.dedup_key, s2.name, s2.description, s2.github_url,
                   s2.categories, s2.language, s2.security_grade, s2.stars,
                   s2.weekly_downloads, s2.source_count
            FROM merged_servers s2
            WHERE s2.dedup_key != $1
              AND s2.categories IS NOT NULL
              AND jsonb_typeof(s2.categories) = 'array'
              AND s2.categories ?| $2::text[]
            ORDER BY s2.stars DESC
            LIMIT 3
            "#,
        )
        .bind(&dedup_key)
        .bind(&related_categories)
        .fetch_all(&state.db)
        .await?
    };

    let related: Vec<RelatedServer> = related_rows
        .iter()
        .map(|r| RelatedServer {
            id: r.get("id"),
            dedup_key: r.get("dedup_key"),
            name: r.get("name"),
            description: r.get("description"),
            github_url: r.get("github_url"),
            categories: r.get("categories"),
            language: r.get("language"),
            security_grade: r.get("security_grade"),
            stars: r.get("stars"),
            weekly_downloads: r.get("weekly_downloads"),
            source_count: r.get("source_count"),
        })
        .collect();

    let detail = ServerDetail {
        id: row.get("id"),
        dedup_key: row.get("dedup_key"),
        name: row.get("name"),
        description: row.get("description"),
        github_owner: row.get("github_owner"),
        github_repo: row.get("github_repo"),
        github_url: row.get("github_url"),
        categories: row.get("categories"),
        language: row.get("language"),
        license: row.get("license"),
        security_grade: row.get("security_grade"),
        quality_grade: row.get("quality_grade"),
        license_grade: row.get("license_grade"),
        stars: row.get("stars"),
        forks: row.get("forks"),
        weekly_downloads: row.get("weekly_downloads"),
        tools: row.get("tools"),
        tools_count: row.get("tools_count"),
        resources: row.get("resources"),
        prompts: row.get("prompts"),
        connections: row.get("connections"),
        source_count: row.get("source_count"),
        created_at: row.get("created_at"),
        updated_at: row.get("updated_at"),
        audit,
        related,
    };

    Ok(Json(detail))
}

// ---------------------------------------------------------------------------
// GET /api/servers/categories
// ---------------------------------------------------------------------------

pub async fn get_server_categories(
    State(state): State<AppState>,
) -> Result<Json<Vec<CategoryCount>>, AppError> {
    // Check cache first
    {
        let cache = state.category_cache.read().await;
        if let Some(cached) = &cache.servers {
            let age = chrono::Utc::now() - cached.cached_at;
            if age.num_seconds() < 300 {
                return Ok(Json(cached.items.clone()));
            }
        }
    }

    let _refresh_guard = state.server_category_refresh_lock.lock().await;

    // Check again after acquiring refresh lock to avoid cache stampede
    {
        let cache = state.category_cache.read().await;
        if let Some(cached) = &cache.servers {
            let age = chrono::Utc::now() - cached.cached_at;
            if age.num_seconds() < 300 {
                return Ok(Json(cached.items.clone()));
            }
        }
    }

    let rows = sqlx::query(
        r#"
        SELECT cat, COUNT(*) AS count
        FROM merged_servers s,
             jsonb_array_elements_text(
                 CASE
                     WHEN jsonb_typeof(s.categories) = 'array' THEN s.categories
                     ELSE '[]'::jsonb
                 END
             ) AS cat
        WHERE s.categories IS NOT NULL AND s.categories != 'null'::jsonb
        GROUP BY cat
        HAVING LENGTH(cat) > 1 AND LENGTH(cat) < 100
           AND LOWER(TRIM(cat)) NOT IN ('null', 'none', 'undefined', 'n/a', 'string', '')
        ORDER BY count DESC
        "#,
    )
    .fetch_all(&state.db)
    .await?;

    let cats: Vec<CategoryCount> = rows
        .iter()
        .map(|r| CategoryCount {
            name: r.get("cat"),
            count: r.get("count"),
        })
        .collect();

    // Update cache
    {
        let mut cache = state.category_cache.write().await;
        cache.servers = Some(CachedCategoryList {
            items: cats.clone(),
            cached_at: chrono::Utc::now(),
        });
    }

    Ok(Json(cats))
}
