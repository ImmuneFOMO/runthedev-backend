use axum::Json;
use axum::extract::{Path, Query, State};
use serde::Deserialize;
use sqlx::Row;

use crate::error::AppError;
use crate::models::{
    AuditBrief, PaginatedResponse, PaginationParams, RelatedSkill, SkillDetail, SkillListItem,
};
use crate::search;
use crate::state::{AppState, CachedCategoryList, CategoryCount};

// ---------------------------------------------------------------------------
// Query params
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct SkillListQuery {
    pub q: Option<String>,
    pub sort: Option<String>,
    pub categories: Option<String>,
    pub page: Option<u32>,
    pub per_page: Option<u32>,
}

// ---------------------------------------------------------------------------
// GET /api/skills
// ---------------------------------------------------------------------------

pub async fn list_skills(
    State(state): State<AppState>,
    Query(params): Query<SkillListQuery>,
) -> Result<Json<PaginatedResponse<SkillListItem>>, AppError> {
    let pagination = PaginationParams {
        page: params.page.unwrap_or(1),
        per_page: params.per_page.unwrap_or(12),
    }
    .validated();

    let offset = pagination.offset();

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
        search_skills_path(&state, query_text, &categories, &pagination, offset).await?
    } else {
        browse_skills_path(&state, &categories, &params.sort, &pagination, offset).await?
    };

    Ok(Json(PaginatedResponse::new(
        items,
        total,
        pagination.page,
        pagination.per_page,
    )))
}

/// Search-driven listing via Meilisearch.
async fn search_skills_path(
    state: &AppState,
    query_text: &str,
    categories: &[String],
    _pagination: &PaginationParams,
    offset: u32,
) -> Result<(Vec<SkillListItem>, i64), AppError> {
    let cats = if categories.is_empty() {
        None
    } else {
        Some(categories)
    };

    let result = search::search_skills(
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

    let placeholders: Vec<String> = (1..=result.dedup_keys.len())
        .map(|i| format!("${}", i))
        .collect();

    let pos_idx = result.dedup_keys.len() + 1;
    let sql = format!(
        r#"
        SELECT
            s.id, s.dedup_key, s.skill_name, s.name, s.description, s.github_url,
            s.categories, s.quality_score, s.audit_summary,
            s.stars, s.installs, s.source_count,
            a.grade AS audit_grade, a.score AS audit_score
        FROM merged_skills s
        LEFT JOIN LATERAL (
            SELECT grade, score FROM audit_runs
            WHERE item_type = 'skill' AND item_dedup_key = s.dedup_key AND status = 'completed'
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
                })
            } else {
                None
            };
            SkillListItem {
                id: row.get("id"),
                dedup_key: row.get("dedup_key"),
                skill_name: row.get("skill_name"),
                name: row.get("name"),
                description: row.get("description"),
                github_url: row.get("github_url"),
                categories: row.get("categories"),
                quality_score: row.get("quality_score"),
                audit_summary: row.get("audit_summary"),
                stars: row.get("stars"),
                installs: row.get("installs"),
                source_count: row.get("source_count"),
                audit,
            }
        })
        .collect();

    Ok((items, result.total_hits))
}

/// Browse listing (no search query): PG-driven with filters & sort.
async fn browse_skills_path(
    state: &AppState,
    categories: &[String],
    sort: &Option<String>,
    pagination: &PaginationParams,
    offset: u32,
) -> Result<(Vec<SkillListItem>, i64), AppError> {
    let sort_clause = match sort.as_deref().unwrap_or("featured") {
        "stars" => "s.stars DESC",
        "installs" => "s.installs DESC",
        "name" => "s.name ASC",
        _ => "CASE WHEN s.quality_score IS NOT NULL THEN 0 ELSE 1 END, s.stars DESC NULLS LAST",
    };

    let has_cats = !categories.is_empty();

    // ----- COUNT -----
    let count_sql = if has_cats {
        "SELECT COUNT(*) AS cnt FROM merged_skills s
         WHERE s.categories IS NOT NULL
           AND jsonb_typeof(s.categories) = 'array'
           AND s.categories ?| $1::text[]"
            .to_string()
    } else {
        "SELECT COUNT(*) AS cnt FROM merged_skills s".to_string()
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

    // ----- DATA -----
    let data_sql = if has_cats {
        format!(
            r#"
            SELECT
                s.id, s.dedup_key, s.skill_name, s.name, s.description, s.github_url,
                s.categories, s.quality_score, s.audit_summary,
                s.stars, s.installs, s.source_count,
                a.grade AS audit_grade, a.score AS audit_score
            FROM merged_skills s
            LEFT JOIN LATERAL (
                SELECT grade, score FROM audit_runs
                WHERE item_type = 'skill' AND item_dedup_key = s.dedup_key AND status = 'completed'
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
                s.id, s.dedup_key, s.skill_name, s.name, s.description, s.github_url,
                s.categories, s.quality_score, s.audit_summary,
                s.stars, s.installs, s.source_count,
                a.grade AS audit_grade, a.score AS audit_score
            FROM merged_skills s
            LEFT JOIN LATERAL (
                SELECT grade, score FROM audit_runs
                WHERE item_type = 'skill' AND item_dedup_key = s.dedup_key AND status = 'completed'
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
                })
            } else {
                None
            };
            SkillListItem {
                id: row.get("id"),
                dedup_key: row.get("dedup_key"),
                skill_name: row.get("skill_name"),
                name: row.get("name"),
                description: row.get("description"),
                github_url: row.get("github_url"),
                categories: row.get("categories"),
                quality_score: row.get("quality_score"),
                audit_summary: row.get("audit_summary"),
                stars: row.get("stars"),
                installs: row.get("installs"),
                source_count: row.get("source_count"),
                audit,
            }
        })
        .collect();

    Ok((items, total))
}

// ---------------------------------------------------------------------------
// GET /api/skills/:dedup_key
// ---------------------------------------------------------------------------

pub async fn get_skill_detail(
    State(state): State<AppState>,
    Path(dedup_key): Path<String>,
) -> Result<Json<SkillDetail>, AppError> {
    let row = sqlx::query(
        r#"
        SELECT
            s.id, s.dedup_key, s.skill_name, s.name, s.description,
            s.github_owner, s.github_repo, s.github_url,
            s.categories, s.quality_score, s.audit_summary,
            s.skill_md_content, s.security_audits,
            s.stars, s.forks, s.installs, s.weekly_installs,
            s.activations, s.unique_users, s.upvotes, s.downvotes,
            s.source_count,
            s.created_at, s.updated_at,
            a.grade AS audit_grade, a.score AS audit_score
        FROM merged_skills s
        LEFT JOIN LATERAL (
            SELECT grade, score FROM audit_runs
            WHERE item_type = 'skill' AND item_dedup_key = s.dedup_key AND status = 'completed'
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

    // Related skills: up to 3 sharing at least one category
    let related_rows = if related_categories.is_empty() {
        vec![]
    } else {
        sqlx::query(
            r#"
            SELECT s2.id, s2.dedup_key, s2.skill_name, s2.name, s2.description, s2.github_url,
                   s2.categories, s2.quality_score, s2.stars, s2.installs, s2.source_count
            FROM merged_skills s2
            WHERE s2.dedup_key != $1
              AND s2.categories IS NOT NULL
              AND jsonb_typeof(s2.categories) = 'array'
              AND s2.categories ?| $2::text[]
            ORDER BY s2.installs DESC
            LIMIT 3
            "#,
        )
        .bind(&dedup_key)
        .bind(&related_categories)
        .fetch_all(&state.db)
        .await?
    };

    let related: Vec<RelatedSkill> = related_rows
        .iter()
        .map(|r| RelatedSkill {
            id: r.get("id"),
            dedup_key: r.get("dedup_key"),
            skill_name: r.get("skill_name"),
            name: r.get("name"),
            description: r.get("description"),
            github_url: r.get("github_url"),
            categories: r.get("categories"),
            quality_score: r.get("quality_score"),
            stars: r.get("stars"),
            installs: r.get("installs"),
            source_count: r.get("source_count"),
        })
        .collect();

    let github_owner: Option<String> = row.get("github_owner");

    let detail = SkillDetail {
        id: row.get("id"),
        dedup_key: row.get("dedup_key"),
        skill_name: row.get("skill_name"),
        name: row.get("name"),
        description: row.get("description"),
        github_owner,
        github_repo: row.get("github_repo"),
        github_url: row.get("github_url"),
        categories: row.get("categories"),
        quality_score: row.get("quality_score"),
        audit_summary: row.get("audit_summary"),
        skill_md_content: row.get("skill_md_content"),
        security_audits: row.get("security_audits"),
        stars: row.get("stars"),
        forks: row.get("forks"),
        installs: row.get("installs"),
        weekly_installs: row.get("weekly_installs"),
        activations: row.get("activations"),
        unique_users: row.get("unique_users"),
        upvotes: row.get("upvotes"),
        downvotes: row.get("downvotes"),
        source_count: row.get("source_count"),
        created_at: row.get("created_at"),
        updated_at: row.get("updated_at"),
        audit,
        related,
    };

    Ok(Json(detail))
}

// ---------------------------------------------------------------------------
// GET /api/skills/categories
// ---------------------------------------------------------------------------

pub async fn get_skill_categories(
    State(state): State<AppState>,
) -> Result<Json<Vec<CategoryCount>>, AppError> {
    // Check cache
    {
        let cache = state.category_cache.read().await;
        if let Some(cached) = &cache.skills {
            let age = chrono::Utc::now() - cached.cached_at;
            if age.num_seconds() < 300 {
                return Ok(Json(cached.items.clone()));
            }
        }
    }

    let _refresh_guard = state.skill_category_refresh_lock.lock().await;

    // Check again after acquiring refresh lock to avoid cache stampede
    {
        let cache = state.category_cache.read().await;
        if let Some(cached) = &cache.skills {
            let age = chrono::Utc::now() - cached.cached_at;
            if age.num_seconds() < 300 {
                return Ok(Json(cached.items.clone()));
            }
        }
    }

    let rows = sqlx::query(
        r#"
        SELECT cat, COUNT(*) AS count
        FROM merged_skills s,
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
        cache.skills = Some(CachedCategoryList {
            items: cats.clone(),
            cached_at: chrono::Utc::now(),
        });
    }

    Ok(Json(cats))
}
