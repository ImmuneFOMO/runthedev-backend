use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize)]
pub struct CliCheckQuery {
    pub slug: String,
    #[serde(rename = "type")]
    pub item_type: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CliRequestAuditRequest {
    pub slug: String,
    #[serde(rename = "type")]
    pub item_type: String,
    pub cli_version: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CliRequestAuditResponse {
    pub request_count: i64,
    pub auto_audit_triggered: bool,
    pub message: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct CliCheckResponse {
    pub found: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub item_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub item: Option<CliCheckItem>,
    pub audits: Vec<CliAuditEntry>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub connections: Option<Vec<CliConnectionPayload>>,
    pub audit_request_count: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct CliCheckItem {
    pub dedup_key: String,
    pub name: String,
    pub description: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub github_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stars: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub language: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CliAuditEntry {
    pub provider: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider_label: Option<String>,
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub grade: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub score: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub security_grade: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub quality_grade: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub license_grade: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub findings: Vec<CliAuditFinding>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub messages: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CliAuditFinding {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub severity: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
    pub message: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct CliConnectionPayload {
    #[serde(rename = "type")]
    pub connection_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub runtime: Option<String>,
    #[serde(rename = "deploymentUrl", skip_serializing_if = "Option::is_none")]
    pub deployment_url: Option<String>,
    #[serde(rename = "bundleUrl", skip_serializing_if = "Option::is_none")]
    pub bundle_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub command: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub args: Option<Vec<String>>,
}
