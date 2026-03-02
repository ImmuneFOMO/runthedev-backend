use super::audit::AuditBrief;
use chrono::{DateTime, Utc};
use serde::Serialize;

/// Lightweight list item
#[derive(Debug, Serialize)]
pub struct SkillListItem {
    pub id: i32,
    pub dedup_key: String,
    pub skill_name: String,
    pub name: String,
    pub description: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub github_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub categories: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub quality_score: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub audit_summary: Option<serde_json::Value>,
    pub stars: i32,
    pub installs: i32,
    pub source_count: i32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub audit: Option<AuditBrief>,
}

/// Full detail response
#[derive(Debug, Serialize)]
pub struct SkillDetail {
    pub id: i32,
    pub dedup_key: String,
    pub skill_name: String,
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
    pub quality_score: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub audit_summary: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub skill_md_content: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub security_audits: Option<serde_json::Value>,
    pub stars: i32,
    pub forks: i32,
    pub installs: i32,
    pub weekly_installs: i32,
    pub activations: i32,
    pub unique_users: i32,
    pub upvotes: i32,
    pub downvotes: i32,
    pub source_count: i32,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub audit: Option<AuditBrief>,
    pub related: Vec<RelatedSkill>,
}

/// Related skill for detail response
#[derive(Debug, Serialize)]
pub struct RelatedSkill {
    pub id: i32,
    pub dedup_key: String,
    pub skill_name: String,
    pub name: String,
    pub description: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub github_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub categories: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub quality_score: Option<f64>,
    pub stars: i32,
    pub installs: i32,
    pub source_count: i32,
}
