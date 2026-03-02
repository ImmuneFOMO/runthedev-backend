use super::audit::AuditBrief;
use chrono::{DateTime, Utc};
use serde::Serialize;

/// Lightweight item for list responses - NO heavy fields
#[derive(Debug, Serialize)]
pub struct ServerListItem {
    pub id: i32,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub quality_grade: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub license_grade: Option<String>,
    pub stars: i32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub weekly_downloads: Option<i32>,
    pub source_count: i32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub audit: Option<AuditBrief>,
}

/// Full detail response
#[derive(Debug, Serialize)]
pub struct ServerDetail {
    pub id: i32,
    pub dedup_key: String,
    pub name: String,
    pub description: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub github_owner: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub github_repo: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub github_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub categories: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub language: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub license: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub security_grade: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub quality_grade: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub license_grade: Option<String>,
    pub stars: i32,
    pub forks: i32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub weekly_downloads: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tools: Option<serde_json::Value>,
    pub tools_count: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resources: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prompts: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub connections: Option<serde_json::Value>,
    pub source_count: i32,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub audit: Option<AuditBrief>,
    pub related: Vec<RelatedServer>,
}

/// Related server for detail response
#[derive(Debug, Serialize)]
pub struct RelatedServer {
    pub id: i32,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub weekly_downloads: Option<i32>,
    pub source_count: i32,
}
