use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;

/// Full audit_runs row
#[derive(Debug, FromRow, Serialize)]
pub struct AuditRun {
    pub id: i32,
    pub item_type: String,
    pub item_dedup_key: String,
    pub status: String,
    pub result: Option<serde_json::Value>,
    pub score: Option<f64>,
    pub grade: Option<String>,
    pub requested_by: String,
    pub created_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
}

/// Lightweight audit info for list responses
#[derive(Debug, Clone, Serialize)]
pub struct AuditBrief {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub grade: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub score: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

/// Request body for POST /api/admin/audit
#[derive(Debug, Deserialize)]
pub struct CreateAuditRequest {
    pub item_type: String,
    pub item_dedup_key: String,
}
