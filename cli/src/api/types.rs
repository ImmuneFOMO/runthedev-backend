use clap::ValueEnum;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ValueEnum)]
#[serde(rename_all = "lowercase")]
pub enum ItemType {
    Server,
    Skill,
}

impl ItemType {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Server => "server",
            Self::Skill => "skill",
        }
    }
}

impl std::fmt::Display for ItemType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct CheckResponse {
    pub found: bool,
    pub item_type: Option<ItemType>,
    pub item: Option<CheckItem>,
    pub audits: Vec<AuditProvider>,
    pub connections: Option<Vec<ConnectionPayload>>,
    pub audit_request_count: i64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CheckItem {
    pub dedup_key: String,
    pub name: String,
    pub description: String,
    pub github_url: Option<String>,
    pub stars: Option<i64>,
    pub language: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AuditProvider {
    pub provider: String,
    pub provider_label: Option<String>,
    pub status: String,
    pub grade: Option<String>,
    pub score: Option<f64>,
    pub security_grade: Option<String>,
    pub quality_grade: Option<String>,
    pub license_grade: Option<String>,
    pub url: Option<String>,
    pub updated_at: Option<String>,
    #[serde(default)]
    pub findings: Vec<AuditFinding>,
    #[serde(default)]
    pub messages: Vec<String>,
    pub metadata: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AuditFinding {
    pub severity: Option<String>,
    pub code: Option<String>,
    pub message: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SkillDetailResponse {
    pub dedup_key: String,
    pub skill_name: String,
    pub name: String,
    pub description: String,
    pub github_url: Option<String>,
    pub skill_md_content: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ConnectionPayload {
    #[serde(rename = "type")]
    pub connection_type: String,
    pub runtime: Option<String>,
    #[serde(rename = "deploymentUrl")]
    pub deployment_url: Option<String>,
    #[serde(rename = "bundleUrl")]
    pub bundle_url: Option<String>,
    pub command: Option<String>,
    pub args: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize)]
pub struct RequestAuditRequest {
    pub slug: String,
    #[serde(rename = "type")]
    pub item_type: ItemType,
    pub cli_version: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RequestAuditResponse {
    pub request_count: i64,
    pub auto_audit_triggered: bool,
    pub message: String,
}
