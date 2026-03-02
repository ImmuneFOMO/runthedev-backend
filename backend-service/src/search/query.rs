use std::time::Duration;

use meilisearch_sdk::client::Client as MeiliClient;
use serde::{Deserialize, Serialize};

use crate::error::AppError;

const MEILI_REQUEST_TIMEOUT: Duration = Duration::from_secs(3);

/// Result from a Meilisearch search.
pub struct SearchResult {
    pub dedup_keys: Vec<String>,
    pub total_hits: i64,
}

/// Minimal document shape for deserializing search hits.
/// We only need the `dedup_key` to look up full records from PG.
#[derive(Debug, Deserialize)]
struct HitDoc {
    dedup_key: String,
}

/// Search servers in Meilisearch, returns matching `dedup_keys` in relevance order.
pub async fn search_servers(
    meili: &MeiliClient,
    query: &str,
    categories: Option<&[String]>,
    offset: usize,
    limit: usize,
) -> Result<SearchResult, AppError> {
    search_index(meili, "servers", query, categories, offset, limit).await
}

/// Search skills in Meilisearch, returns matching `dedup_keys` in relevance order.
pub async fn search_skills(
    meili: &MeiliClient,
    query: &str,
    categories: Option<&[String]>,
    offset: usize,
    limit: usize,
) -> Result<SearchResult, AppError> {
    search_index(meili, "skills", query, categories, offset, limit).await
}

/// Shared implementation for searching any Meilisearch index.
async fn search_index(
    meili: &MeiliClient,
    index_name: &str,
    query: &str,
    categories: Option<&[String]>,
    offset: usize,
    limit: usize,
) -> Result<SearchResult, AppError> {
    let index = meili.index(index_name);

    // Build the filter string for categories if provided.
    // Meilisearch filter syntax: `categories IN ["search", "databases"]`
    let filter_string = categories.and_then(|cats| {
        if cats.is_empty() {
            return None;
        }
        let quoted: Vec<String> = cats
            .iter()
            .map(|c| format!("\"{}\"", c.replace(['"', '\\'], "")))
            .collect();
        Some(format!("categories IN [{}]", quoted.join(", ")))
    });

    let mut search = index.search();
    search
        .with_query(query)
        .with_offset(offset)
        .with_limit(limit);

    if let Some(ref filter) = filter_string {
        search.with_filter(filter);
    }

    let results = tokio::time::timeout(MEILI_REQUEST_TIMEOUT, search.execute::<HitDoc>())
        .await
        .map_err(|_| AppError::Search("Search request timed out".to_string()))?
        .map_err(|e| AppError::Search(e.to_string()))?;

    let dedup_keys = results
        .hits
        .into_iter()
        .map(|hit| hit.result.dedup_key)
        .collect();

    let total_hits = results
        .estimated_total_hits
        .or(results.total_hits)
        .unwrap_or(0) as i64;

    Ok(SearchResult {
        dedup_keys,
        total_hits,
    })
}

// ---------------------------------------------------------------------------
// Combined (unified) search — returns lightweight hits from both indexes
// ---------------------------------------------------------------------------

/// Combined search result spanning both servers and skills.
#[derive(Debug, Serialize)]
pub struct CombinedSearchResult {
    pub servers: Vec<ServerSearchHit>,
    pub skills: Vec<SkillSearchHit>,
    pub servers_total: i64,
    pub skills_total: i64,
}

/// Lightweight server hit returned directly from Meilisearch (no PG round-trip).
#[derive(Debug, Serialize, Deserialize)]
pub struct ServerSearchHit {
    pub dedup_key: String,
    pub name: String,
    pub description: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub github_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub categories: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub language: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub security_grade: Option<String>,
    pub stars: i32,
    /// Always "server" — injected after deserialization.
    #[serde(rename = "type", default)]
    pub item_type: String,
}

/// Lightweight skill hit returned directly from Meilisearch (no PG round-trip).
#[derive(Debug, Serialize, Deserialize)]
pub struct SkillSearchHit {
    pub dedup_key: String,
    pub name: String,
    pub skill_name: String,
    pub description: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub github_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub categories: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub quality_score: Option<f64>,
    pub stars: i32,
    pub installs: i32,
    /// Always "skill" — injected after deserialization.
    #[serde(rename = "type", default)]
    pub item_type: String,
}

/// Search both servers and skills simultaneously and return lightweight hits.
pub async fn search_combined(
    meili: &MeiliClient,
    query: &str,
    limit: usize,
) -> Result<CombinedSearchResult, AppError> {
    let (server_result, skill_result) = tokio::join!(
        search_index_raw::<ServerSearchHit>(meili, "servers", query, limit),
        search_index_raw::<SkillSearchHit>(meili, "skills", query, limit),
    );

    let (mut server_hits, servers_total) = server_result?;
    let (mut skill_hits, skills_total) = skill_result?;

    // Stamp the type discriminator on each hit.
    for h in &mut server_hits {
        h.item_type = "server".to_string();
    }
    for h in &mut skill_hits {
        h.item_type = "skill".to_string();
    }

    Ok(CombinedSearchResult {
        servers: server_hits,
        skills: skill_hits,
        servers_total,
        skills_total,
    })
}

/// Raw search helper that deserializes full documents from Meilisearch.
async fn search_index_raw<T: serde::de::DeserializeOwned + Send + Sync + 'static>(
    meili: &MeiliClient,
    index_name: &str,
    query: &str,
    limit: usize,
) -> Result<(Vec<T>, i64), AppError> {
    let index = meili.index(index_name);

    let results = tokio::time::timeout(
        MEILI_REQUEST_TIMEOUT,
        index
            .search()
            .with_query(query)
            .with_limit(limit)
            .execute::<T>(),
    )
    .await
    .map_err(|_| AppError::Search("Search request timed out".to_string()))?
    .map_err(|e| AppError::Search(e.to_string()))?;

    let total = results
        .estimated_total_hits
        .or(results.total_hits)
        .unwrap_or(0) as i64;

    let hits: Vec<T> = results.hits.into_iter().map(|h| h.result).collect();

    Ok((hits, total))
}
