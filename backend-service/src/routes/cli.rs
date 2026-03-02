use axum::Json;
use axum::extract::{Query, State};
use axum::http::StatusCode;
use sqlx::Row;

use crate::error::AppError;
use crate::models::{
    CliAuditEntry, CliAuditFinding, CliCheckItem, CliCheckQuery, CliCheckResponse,
    CliConnectionPayload, CliRequestAuditRequest, CliRequestAuditResponse,
};
use crate::state::AppState;

pub async fn check_item(
    State(state): State<AppState>,
    Query(params): Query<CliCheckQuery>,
) -> Result<Json<CliCheckResponse>, AppError> {
    let slug = validate_slug(&params.slug)?;
    let item_type = validate_item_type(&params.item_type)?;

    let request_count = request_count(&state, item_type, &slug).await?;
    let runthedev_audit = runthedev_audit_entry(&state, item_type, &slug, request_count).await?;

    if item_type == "server" {
        let row = sqlx::query(
            r#"
            SELECT dedup_key, name, description, github_url, stars, language,
                   security_grade, quality_grade, license_grade, connections
            FROM merged_servers
            WHERE dedup_key = $1
            "#,
        )
        .bind(&slug)
        .fetch_optional(&state.db)
        .await?;

        let Some(row) = row else {
            return Ok(Json(CliCheckResponse {
                found: false,
                item_type: Some(item_type.to_string()),
                item: None,
                audits: Vec::new(),
                connections: None,
                audit_request_count: request_count,
            }));
        };

        let connections = parse_connections(row.get::<Option<serde_json::Value>, _>("connections"));
        let security_grade: Option<String> = row.get("security_grade");
        let quality_grade: Option<String> = row.get("quality_grade");
        let license_grade: Option<String> = row.get("license_grade");
        let audits = vec![
            source_grades_audit_entry(
                security_grade.clone(),
                quality_grade.clone(),
                license_grade.clone(),
            ),
            runthedev_audit,
        ];

        return Ok(Json(CliCheckResponse {
            found: true,
            item_type: Some(item_type.to_string()),
            item: Some(CliCheckItem {
                dedup_key: row.get("dedup_key"),
                name: row.get("name"),
                description: row.get("description"),
                github_url: row.get("github_url"),
                stars: row.get::<Option<i32>, _>("stars").map(i64::from),
                language: row.get("language"),
            }),
            audits,
            connections,
            audit_request_count: request_count,
        }));
    }

    let row = sqlx::query(
        r#"
        SELECT dedup_key, COALESCE(name, skill_name, dedup_key) AS name,
               description, github_url, stars, audit_summary, security_audits
        FROM merged_skills
        WHERE dedup_key = $1
        "#,
    )
    .bind(&slug)
    .fetch_optional(&state.db)
    .await?;

    let Some(row) = row else {
        return Ok(Json(CliCheckResponse {
            found: false,
            item_type: Some(item_type.to_string()),
            item: None,
            audits: Vec::new(),
            connections: None,
            audit_request_count: request_count,
        }));
    };

    let mut audits = Vec::new();
    audits.extend(parse_skill_audit_summary(
        row.get::<Option<serde_json::Value>, _>("audit_summary"),
    ));
    audits.extend(parse_skill_security_audits(
        row.get::<Option<serde_json::Value>, _>("security_audits"),
    ));
    audits.push(runthedev_audit);

    Ok(Json(CliCheckResponse {
        found: true,
        item_type: Some(item_type.to_string()),
        item: Some(CliCheckItem {
            dedup_key: row.get("dedup_key"),
            name: row.get("name"),
            description: row.get("description"),
            github_url: row.get("github_url"),
            stars: row.get::<Option<i32>, _>("stars").map(i64::from),
            language: None,
        }),
        audits,
        connections: None,
        audit_request_count: request_count,
    }))
}

pub async fn request_audit(
    State(state): State<AppState>,
    Json(req): Json<CliRequestAuditRequest>,
) -> Result<(StatusCode, Json<CliRequestAuditResponse>), AppError> {
    let slug = validate_slug(&req.slug)?;
    let item_type = validate_item_type(&req.item_type)?;
    let cli_version = validate_cli_version(req.cli_version.as_deref())?;

    let exists: bool = match item_type {
        "server" => {
            sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM merged_servers WHERE dedup_key = $1)")
                .bind(&slug)
                .fetch_one(&state.db)
                .await?
        }
        "skill" => {
            sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM merged_skills WHERE dedup_key = $1)")
                .bind(&slug)
                .fetch_one(&state.db)
                .await?
        }
        _ => false,
    };

    if !exists {
        return Err(AppError::NotFound);
    }

    sqlx::query(
        r#"
        INSERT INTO audit_requests (item_type, item_dedup_key, source, cli_version)
        VALUES ($1, $2, 'cli', $3)
        "#,
    )
    .bind(item_type)
    .bind(&slug)
    .bind(cli_version.as_deref())
    .execute(&state.db)
    .await?;

    let count = request_count(&state, item_type, &slug).await?;
    let auto_audit_triggered = count >= 10;

    Ok((
        StatusCode::OK,
        Json(CliRequestAuditResponse {
            request_count: count,
            auto_audit_triggered,
            message: format!("Request recorded. {count}/10 before auto-audit."),
        }),
    ))
}

fn validate_slug(raw: &str) -> Result<String, AppError> {
    if raw.is_empty() {
        return Err(AppError::BadRequest("slug must not be empty".to_string()));
    }

    if raw != raw.trim() {
        return Err(AppError::BadRequest(
            "slug must be canonical owner/repo".to_string(),
        ));
    }

    let parts: Vec<&str> = raw.split('/').collect();
    if parts.len() != 2 {
        return Err(AppError::BadRequest(
            "slug must be canonical owner/repo".to_string(),
        ));
    }

    let owner = parts[0];
    let repo = parts[1];

    if !is_valid_owner(owner) || !is_valid_repo(repo) || repo.ends_with(".git") {
        return Err(AppError::BadRequest(
            "slug must be canonical owner/repo".to_string(),
        ));
    }

    let canonical = format!(
        "{}/{}",
        owner.to_ascii_lowercase(),
        repo.to_ascii_lowercase()
    );
    if raw != canonical {
        return Err(AppError::BadRequest(
            "slug must be canonical owner/repo".to_string(),
        ));
    }

    Ok(raw.to_string())
}

fn is_valid_owner(owner: &str) -> bool {
    if owner.is_empty() || owner.len() > 39 {
        return false;
    }

    let bytes = owner.as_bytes();
    if !bytes[0].is_ascii_alphanumeric() || !bytes[bytes.len() - 1].is_ascii_alphanumeric() {
        return false;
    }

    bytes
        .iter()
        .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'-')
}

fn is_valid_repo(repo: &str) -> bool {
    if repo.is_empty() || repo.len() > 100 {
        return false;
    }

    if repo.starts_with('.') || repo.ends_with('.') {
        return false;
    }

    repo.bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_' || byte == b'.')
}

fn validate_item_type(raw: &str) -> Result<&str, AppError> {
    let item_type = raw.trim().to_ascii_lowercase();
    match item_type.as_str() {
        "server" => Ok("server"),
        "skill" => Ok("skill"),
        _ => Err(AppError::BadRequest(
            "type must be 'server' or 'skill'".to_string(),
        )),
    }
}

fn validate_cli_version(raw: Option<&str>) -> Result<Option<String>, AppError> {
    let Some(raw) = raw else {
        return Ok(None);
    };

    let version = raw.trim();
    if version.is_empty() {
        return Err(AppError::BadRequest(
            "cli_version must not be empty when provided".to_string(),
        ));
    }
    if version.len() > 20 {
        return Err(AppError::BadRequest(
            "cli_version is too long (max 20 chars)".to_string(),
        ));
    }
    if !version.bytes().all(|byte| {
        byte.is_ascii_alphanumeric() || byte == b'.' || byte == b'-' || byte == b'+' || byte == b'_'
    }) {
        return Err(AppError::BadRequest(
            "cli_version has invalid characters".to_string(),
        ));
    }

    Ok(Some(version.to_string()))
}

async fn request_count(state: &AppState, item_type: &str, slug: &str) -> Result<i64, AppError> {
    let count = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM audit_requests WHERE item_type = $1 AND item_dedup_key = $2",
    )
    .bind(item_type)
    .bind(slug)
    .fetch_one(&state.db)
    .await?;

    Ok(count)
}

async fn runthedev_audit_entry(
    state: &AppState,
    item_type: &str,
    slug: &str,
    request_count: i64,
) -> Result<CliAuditEntry, AppError> {
    let row = sqlx::query(
        r#"
        SELECT status, grade, score, result, completed_at, created_at
        FROM audit_runs
        WHERE item_type = $1 AND item_dedup_key = $2
        ORDER BY created_at DESC
        LIMIT 1
        "#,
    )
    .bind(item_type)
    .bind(slug)
    .fetch_optional(&state.db)
    .await?;

    Ok(match row {
        Some(audit) => {
            let db_status: String = audit.get("status");
            let result = audit.get::<Option<serde_json::Value>, _>("result");
            let grade = audit.get::<Option<String>, _>("grade");
            let score = audit.get::<Option<f64>, _>("score");
            let mut findings = extract_findings(result.as_ref());
            let mut messages = Vec::new();
            let normalized_status = if db_status == "completed" {
                completed_status_from_outcome(grade.as_deref(), score, &findings)
            } else {
                normalize_provider_status(Some(db_status.as_str()))
            };

            if db_status == "failed" && findings.is_empty() {
                findings.push(CliAuditFinding {
                    severity: Some("high".to_string()),
                    code: Some("audit-run-failed".to_string()),
                    message: "RunTheDev audit run failed before producing a report.".to_string(),
                });
            }

            if normalized_status == "pending" {
                messages.push("RunTheDev audit is queued or in progress.".to_string());
            }

            CliAuditEntry {
                provider: "runthedev".to_string(),
                provider_label: Some("RunTheDev".to_string()),
                status: normalized_status,
                grade,
                score,
                security_grade: None,
                quality_grade: None,
                license_grade: None,
                url: None,
                updated_at: audit
                    .get::<Option<chrono::DateTime<chrono::Utc>>, _>("completed_at")
                    .or_else(|| audit.get::<Option<chrono::DateTime<chrono::Utc>>, _>("created_at"))
                    .map(|ts| ts.to_rfc3339()),
                findings,
                messages,
                metadata: result,
            }
        }
        None => CliAuditEntry {
            provider: "runthedev".to_string(),
            provider_label: Some("RunTheDev".to_string()),
            status: if request_count > 0 {
                "pending".to_string()
            } else {
                "none".to_string()
            },
            grade: None,
            score: None,
            security_grade: None,
            quality_grade: None,
            license_grade: None,
            url: None,
            updated_at: None,
            findings: Vec::new(),
            messages: vec![if request_count > 0 {
                "Audit requested and waiting to run.".to_string()
            } else {
                "Not available yet.".to_string()
            }],
            metadata: None,
        },
    })
}

fn source_grades_audit_entry(
    security_grade: Option<String>,
    quality_grade: Option<String>,
    license_grade: Option<String>,
) -> CliAuditEntry {
    let mut findings = Vec::new();

    if is_bad_grade(security_grade.as_deref()) {
        findings.push(CliAuditFinding {
            severity: Some("high".to_string()),
            code: Some("security-grade".to_string()),
            message: format!(
                "Security rating is {}.",
                security_grade
                    .clone()
                    .unwrap_or_else(|| "unknown".to_string())
            ),
        });
    }

    if is_bad_grade(quality_grade.as_deref()) {
        findings.push(CliAuditFinding {
            severity: Some("medium".to_string()),
            code: Some("quality-grade".to_string()),
            message: format!(
                "Quality rating is {}.",
                quality_grade
                    .clone()
                    .unwrap_or_else(|| "unknown".to_string())
            ),
        });
    }

    if is_bad_grade(license_grade.as_deref()) {
        findings.push(CliAuditFinding {
            severity: Some("low".to_string()),
            code: Some("license-grade".to_string()),
            message: format!(
                "License rating is {}.",
                license_grade
                    .clone()
                    .unwrap_or_else(|| "unknown".to_string())
            ),
        });
    }

    let status = if security_grade.is_none() && quality_grade.is_none() && license_grade.is_none() {
        "none".to_string()
    } else if is_bad_grade(security_grade.as_deref()) || is_bad_grade(quality_grade.as_deref()) {
        "fail".to_string()
    } else if is_bad_grade(license_grade.as_deref()) {
        "warn".to_string()
    } else {
        "pass".to_string()
    };

    CliAuditEntry {
        provider: "source".to_string(),
        provider_label: Some("Source ratings".to_string()),
        status,
        grade: None,
        score: None,
        security_grade,
        quality_grade,
        license_grade,
        url: None,
        updated_at: None,
        findings,
        messages: Vec::new(),
        metadata: None,
    }
}

fn parse_skill_audit_summary(value: Option<serde_json::Value>) -> Vec<CliAuditEntry> {
    let Some(value) = value else {
        return Vec::new();
    };

    let mut audits = Vec::new();
    if let Some(object) = value.as_object() {
        let has_provider_mapping = object
            .keys()
            .any(|key| !is_reserved_skill_audit_summary_key(key));

        if has_provider_mapping {
            for (provider, item) in object {
                if is_reserved_skill_audit_summary_key(provider) {
                    continue;
                }

                let status = item
                    .as_str()
                    .map(|s| normalize_provider_status(Some(s)))
                    .or_else(|| {
                        item.get("status")
                            .and_then(serde_json::Value::as_str)
                            .map(|s| normalize_provider_status(Some(s)))
                    })
                    .unwrap_or_else(|| "unknown".to_string());

                audits.push(CliAuditEntry {
                    provider: normalize_provider_key(provider),
                    provider_label: Some(provider.to_string()),
                    status,
                    grade: item
                        .get("grade")
                        .and_then(serde_json::Value::as_str)
                        .map(str::to_string),
                    score: item.get("score").and_then(serde_json::Value::as_f64),
                    security_grade: None,
                    quality_grade: None,
                    license_grade: None,
                    url: item
                        .get("url")
                        .and_then(serde_json::Value::as_str)
                        .map(str::to_string),
                    updated_at: item
                        .get("updated_at")
                        .and_then(serde_json::Value::as_str)
                        .map(str::to_string),
                    findings: extract_findings(Some(item)),
                    messages: extract_messages(Some(item)),
                    metadata: Some(item.clone()),
                });
            }
        }
    }

    if audits.is_empty() {
        audits.push(CliAuditEntry {
            provider: "skill-audit-summary".to_string(),
            provider_label: Some("Skill audit summary".to_string()),
            status: normalize_provider_status(
                value
                    .get("risk_level")
                    .and_then(serde_json::Value::as_str)
                    .or_else(|| value.get("status").and_then(serde_json::Value::as_str)),
            ),
            grade: value
                .get("grade")
                .and_then(serde_json::Value::as_str)
                .map(str::to_string),
            score: value.get("score").and_then(serde_json::Value::as_f64),
            security_grade: None,
            quality_grade: None,
            license_grade: None,
            url: value
                .get("url")
                .and_then(serde_json::Value::as_str)
                .map(str::to_string),
            updated_at: value
                .get("updated_at")
                .and_then(serde_json::Value::as_str)
                .map(str::to_string),
            findings: extract_findings(Some(&value)),
            messages: extract_messages(Some(&value)),
            metadata: Some(value),
        });
    }

    audits
}

fn parse_skill_security_audits(value: Option<serde_json::Value>) -> Vec<CliAuditEntry> {
    let Some(value) = value else {
        return Vec::new();
    };

    let Some(items) = value.as_array() else {
        return vec![CliAuditEntry {
            provider: "security-audit".to_string(),
            provider_label: Some("Security audits".to_string()),
            status: normalize_provider_status(
                value
                    .get("status")
                    .and_then(serde_json::Value::as_str)
                    .or_else(|| value.get("result").and_then(serde_json::Value::as_str)),
            ),
            grade: value
                .get("grade")
                .and_then(serde_json::Value::as_str)
                .map(str::to_string),
            score: value.get("score").and_then(serde_json::Value::as_f64),
            security_grade: None,
            quality_grade: None,
            license_grade: None,
            url: None,
            updated_at: None,
            findings: extract_findings(Some(&value)),
            messages: extract_messages(Some(&value)),
            metadata: Some(value),
        }];
    };

    let mut findings = Vec::new();
    let mut has_failure = false;
    for item in items {
        if item
            .get("pass")
            .and_then(serde_json::Value::as_bool)
            .is_some_and(|pass| !pass)
        {
            has_failure = true;
            findings.push(CliAuditFinding {
                severity: item
                    .get("severity")
                    .and_then(serde_json::Value::as_str)
                    .map(str::to_ascii_lowercase)
                    .or(Some("medium".to_string())),
                code: item
                    .get("rule")
                    .or_else(|| item.get("id"))
                    .and_then(serde_json::Value::as_str)
                    .map(str::to_string),
                message: item
                    .get("message")
                    .or_else(|| item.get("summary"))
                    .or_else(|| item.get("rule"))
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("Security check failed")
                    .to_string(),
            });
        }
    }

    vec![CliAuditEntry {
        provider: "security-audit".to_string(),
        provider_label: Some("Security audits".to_string()),
        status: if items.is_empty() {
            "none".to_string()
        } else if has_failure {
            "fail".to_string()
        } else {
            "pass".to_string()
        },
        grade: None,
        score: None,
        security_grade: None,
        quality_grade: None,
        license_grade: None,
        url: None,
        updated_at: None,
        findings,
        messages: Vec::new(),
        metadata: Some(value),
    }]
}

fn extract_findings(value: Option<&serde_json::Value>) -> Vec<CliAuditFinding> {
    let Some(value) = value else {
        return Vec::new();
    };

    let Some(items) = value.get("findings").and_then(serde_json::Value::as_array) else {
        return Vec::new();
    };

    let mut findings = Vec::new();
    for finding in items {
        findings.push(CliAuditFinding {
            severity: finding
                .get("severity")
                .and_then(serde_json::Value::as_str)
                .map(str::to_ascii_lowercase),
            code: finding
                .get("code")
                .or_else(|| finding.get("rule"))
                .and_then(serde_json::Value::as_str)
                .map(str::to_string),
            message: finding
                .get("message")
                .or_else(|| finding.get("summary"))
                .or_else(|| finding.get("title"))
                .and_then(serde_json::Value::as_str)
                .unwrap_or("No details provided")
                .to_string(),
        });
    }

    findings
}

fn extract_messages(value: Option<&serde_json::Value>) -> Vec<String> {
    let Some(value) = value else {
        return Vec::new();
    };

    if let Some(items) = value.get("messages").and_then(serde_json::Value::as_array) {
        return items
            .iter()
            .filter_map(serde_json::Value::as_str)
            .map(str::to_string)
            .collect();
    }

    if let Some(message) = value.get("message").and_then(serde_json::Value::as_str) {
        return vec![message.to_string()];
    }

    Vec::new()
}

fn normalize_provider_key(raw: &str) -> String {
    let mut key = String::new();
    let mut last_dash = false;
    for ch in raw.chars() {
        if ch.is_ascii_alphanumeric() {
            key.push(ch.to_ascii_lowercase());
            last_dash = false;
        } else if !last_dash {
            key.push('-');
            last_dash = true;
        }
    }

    let cleaned = key.trim_matches('-').to_string();
    if cleaned.is_empty() {
        "provider".to_string()
    } else {
        cleaned
    }
}

fn normalize_provider_status(raw: Option<&str>) -> String {
    let normalized = raw
        .map(str::trim)
        .map(str::to_ascii_lowercase)
        .unwrap_or_else(|| "unknown".to_string());

    match normalized.as_str() {
        "pass" | "passed" | "ok" | "safe" | "success" | "a" | "b" => "pass".to_string(),
        "warn" | "warning" | "c" | "medium" => "warn".to_string(),
        "fail" | "failed" | "unsafe" | "high" | "critical" | "d" | "f" => "fail".to_string(),
        "pending" | "queued" | "running" | "in_progress" => "pending".to_string(),
        "none" | "not_available" | "n/a" => "none".to_string(),
        "unknown" => "unknown".to_string(),
        _ => "unknown".to_string(),
    }
}

fn completed_status_from_outcome(
    grade: Option<&str>,
    score: Option<f64>,
    findings: &[CliAuditFinding],
) -> String {
    if is_bad_grade(grade) || score.is_some_and(|value| value < 60.0) {
        return "fail".to_string();
    }

    if findings.iter().any(|finding| {
        finding
            .severity
            .as_deref()
            .map(|severity| {
                let value = severity.to_ascii_lowercase();
                value == "critical" || value == "high"
            })
            .unwrap_or(false)
    }) {
        return "fail".to_string();
    }

    if findings.iter().any(|finding| {
        finding
            .severity
            .as_deref()
            .map(|severity| severity.eq_ignore_ascii_case("medium"))
            .unwrap_or(false)
    }) {
        return "warn".to_string();
    }

    if !findings.is_empty() {
        return "warn".to_string();
    }

    if let Some(grade) = grade {
        let status = normalize_provider_status(Some(grade));
        if status == "pass" || status == "warn" {
            return status;
        }
    }

    if score.is_some() {
        return "pass".to_string();
    }

    "unknown".to_string()
}

fn is_reserved_skill_audit_summary_key(key: &str) -> bool {
    matches!(
        key,
        "risk_level"
            | "flags"
            | "status"
            | "score"
            | "grade"
            | "findings"
            | "messages"
            | "message"
            | "url"
            | "updated_at"
    )
}

fn is_bad_grade(grade: Option<&str>) -> bool {
    grade
        .map(str::trim)
        .map(str::to_ascii_uppercase)
        .map(|value| value.starts_with('D') || value.starts_with('F'))
        .unwrap_or(false)
}

fn parse_connections(value: Option<serde_json::Value>) -> Option<Vec<CliConnectionPayload>> {
    let raw = value?;
    let array = raw.as_array()?;
    let mut parsed = Vec::new();

    for item in array {
        let Some(connection_type) = item.get("type").and_then(serde_json::Value::as_str) else {
            continue;
        };

        let runtime = item
            .get("runtime")
            .and_then(serde_json::Value::as_str)
            .map(str::to_string);
        let deployment_url = item
            .get("deploymentUrl")
            .and_then(serde_json::Value::as_str)
            .map(str::to_string);
        let bundle_url = item
            .get("bundleUrl")
            .and_then(serde_json::Value::as_str)
            .map(str::to_string);
        let command = item
            .get("command")
            .and_then(serde_json::Value::as_str)
            .map(str::to_string);
        let args = item
            .get("args")
            .and_then(serde_json::Value::as_array)
            .map(|values| {
                values
                    .iter()
                    .filter_map(serde_json::Value::as_str)
                    .map(str::to_string)
                    .collect::<Vec<_>>()
            });

        parsed.push(CliConnectionPayload {
            connection_type: connection_type.to_string(),
            runtime,
            deployment_url,
            bundle_url,
            command,
            args,
        });
    }

    Some(parsed)
}
