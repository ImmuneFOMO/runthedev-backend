use reqwest::StatusCode;

use crate::api::types::{
    CheckResponse, ItemType, RequestAuditRequest, RequestAuditResponse, SkillDetailResponse,
};
use crate::{CliError, CliResult};

#[derive(Debug, Clone)]
pub struct ApiClient {
    base_url: String,
    http: reqwest::Client,
}

impl ApiClient {
    pub fn new_from_env() -> Self {
        let base_url = std::env::var("RTD_API_URL")
            .ok()
            .filter(|value| !value.trim().is_empty())
            .unwrap_or_else(|| "http://localhost:4000".to_string());

        Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            http: reqwest::Client::new(),
        }
    }

    pub async fn get_check(&self, slug: &str, item_type: ItemType) -> CliResult<CheckResponse> {
        let url = format!("{}/api/cli/check", self.base_url);
        let res = self
            .http
            .get(url)
            .query(&[("slug", slug), ("type", item_type.as_str())])
            .send()
            .await
            .map_err(|err| CliError::Api(format!("failed to call check endpoint: {err}")))?;

        if res.status().is_success() {
            return res
                .json::<CheckResponse>()
                .await
                .map_err(|err| CliError::Api(format!("invalid check response payload: {err}")));
        }

        let status = res.status();
        let body = res
            .json::<serde_json::Value>()
            .await
            .unwrap_or_else(|_| serde_json::json!({}));
        let message = body
            .get("error")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("backend error");

        if status == StatusCode::BAD_REQUEST {
            return Err(CliError::Input(message.to_string()));
        }

        Err(CliError::Api(format!(
            "check request failed ({status}): {message}"
        )))
    }

    pub async fn post_request_audit(
        &self,
        slug: &str,
        item_type: ItemType,
        cli_version: &str,
    ) -> CliResult<RequestAuditResponse> {
        let payload = RequestAuditRequest {
            slug: slug.to_string(),
            item_type,
            cli_version: cli_version.to_string(),
        };

        let url = format!("{}/api/cli/request-audit", self.base_url);
        let res = self
            .http
            .post(url)
            .json(&payload)
            .send()
            .await
            .map_err(|err| {
                CliError::Api(format!("failed to call request-audit endpoint: {err}"))
            })?;

        if res.status().is_success() {
            return res.json::<RequestAuditResponse>().await.map_err(|err| {
                CliError::Api(format!("invalid request-audit response payload: {err}"))
            });
        }

        let status = res.status();
        let body = res
            .json::<serde_json::Value>()
            .await
            .unwrap_or_else(|_| serde_json::json!({}));
        let message = body
            .get("error")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("backend error");

        if status == StatusCode::BAD_REQUEST {
            return Err(CliError::Input(message.to_string()));
        }

        if status == StatusCode::NOT_FOUND {
            return Err(CliError::Input("item not found".to_string()));
        }

        Err(CliError::Api(format!(
            "request-audit failed ({status}): {message}"
        )))
    }

    pub async fn get_skill_detail(&self, slug: &str) -> CliResult<SkillDetailResponse> {
        let mut url = url::Url::parse(&format!("{}/api/skills", self.base_url)).map_err(|err| {
            CliError::Operational(format!(
                "invalid API base URL for skill detail request: {err}"
            ))
        })?;
        {
            let mut segments = url.path_segments_mut().map_err(|_| {
                CliError::Operational(
                    "failed to build skill detail URL from API base URL".to_string(),
                )
            })?;
            segments.push(slug);
        }

        let res =
            self.http.get(url).send().await.map_err(|err| {
                CliError::Api(format!("failed to call skill detail endpoint: {err}"))
            })?;

        if res.status().is_success() {
            return res.json::<SkillDetailResponse>().await.map_err(|err| {
                CliError::Api(format!("invalid skill detail response payload: {err}"))
            });
        }

        let status = res.status();
        let body = res
            .json::<serde_json::Value>()
            .await
            .unwrap_or_else(|_| serde_json::json!({}));
        let message = body
            .get("error")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("backend error");

        if status == StatusCode::BAD_REQUEST {
            return Err(CliError::Input(message.to_string()));
        }

        if status == StatusCode::NOT_FOUND {
            return Err(CliError::Input("skill not found".to_string()));
        }

        Err(CliError::Api(format!(
            "skill detail request failed ({status}): {message}"
        )))
    }
}
