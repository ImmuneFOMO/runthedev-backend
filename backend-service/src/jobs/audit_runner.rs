use std::time::Duration;

use reqwest::Client;
use serde_json::{Value, json};
use sqlx::{PgPool, Row};

const SKILL_AUDIT_ENDPOINT: &str = "/audit/skill/summary";
const SERVER_AUDIT_ENDPOINT: &str = "/audit/code/summary";

pub fn spawn_audit_runner(
    pool: PgPool,
    http_client: Client,
    audit_service_url: String,
    poll_interval_seconds: u64,
) {
    let poll_interval = Duration::from_secs(poll_interval_seconds.max(1));

    tokio::spawn(async move {
        tracing::info!(
            "Audit runner started: service_url={} poll_interval={}s",
            audit_service_url,
            poll_interval.as_secs()
        );

        loop {
            match process_next_run(&pool, &http_client, &audit_service_url).await {
                Ok(true) => continue,
                Ok(false) => tokio::time::sleep(poll_interval).await,
                Err(err) => {
                    tracing::error!("Audit runner iteration failed: {err}");
                    tokio::time::sleep(poll_interval).await;
                }
            }
        }
    });
}

struct PendingAuditRun {
    id: i32,
    item_type: String,
    item_dedup_key: String,
}

enum AuditExecution {
    Completed {
        result: Value,
        grade: Option<String>,
        score: Option<f64>,
    },
    Failed {
        result: Value,
    },
}

async fn process_next_run(
    pool: &PgPool,
    http_client: &Client,
    audit_service_url: &str,
) -> Result<bool, String> {
    let Some(run) = claim_next_pending_run(pool)
        .await
        .map_err(|err| format!("failed to claim pending audit run: {err}"))?
    else {
        return Ok(false);
    };

    tracing::info!(
        "Processing audit run id={} type={} slug={}",
        run.id,
        run.item_type,
        run.item_dedup_key
    );

    match execute_run(pool, http_client, audit_service_url, &run).await {
        AuditExecution::Completed {
            result,
            grade,
            score,
        } => {
            mark_completed(pool, run.id, result, grade, score)
                .await
                .map_err(|err| format!("failed to mark run {} completed: {err}", run.id))?;
            tracing::info!("Audit run {} completed", run.id);
        }
        AuditExecution::Failed { result } => {
            mark_failed(pool, run.id, result)
                .await
                .map_err(|err| format!("failed to mark run {} failed: {err}", run.id))?;
            tracing::warn!("Audit run {} failed", run.id);
        }
    }

    Ok(true)
}

async fn claim_next_pending_run(pool: &PgPool) -> Result<Option<PendingAuditRun>, sqlx::Error> {
    let mut tx = pool.begin().await?;

    let row = sqlx::query(
        r#"
        SELECT id, item_type, item_dedup_key
        FROM audit_runs
        WHERE status = 'pending'
        ORDER BY
            CASE requested_by
                WHEN 'admin' THEN 0
                WHEN 'cli' THEN 1
                ELSE 2
            END,
            created_at ASC
        FOR UPDATE SKIP LOCKED
        LIMIT 1
        "#,
    )
    .fetch_optional(&mut *tx)
    .await?;

    let Some(row) = row else {
        tx.commit().await?;
        return Ok(None);
    };

    let run = PendingAuditRun {
        id: row.get("id"),
        item_type: row.get("item_type"),
        item_dedup_key: row.get("item_dedup_key"),
    };

    sqlx::query("UPDATE audit_runs SET status = 'running' WHERE id = $1")
        .bind(run.id)
        .execute(&mut *tx)
        .await?;

    tx.commit().await?;
    Ok(Some(run))
}

async fn execute_run(
    pool: &PgPool,
    http_client: &Client,
    audit_service_url: &str,
    run: &PendingAuditRun,
) -> AuditExecution {
    let target_url = match resolve_target_url(pool, &run.item_type, &run.item_dedup_key).await {
        Ok(url) => url,
        Err(err) => {
            return AuditExecution::Failed {
                result: json!({
                    "error": err,
                    "provider": "runthedev-audit-service"
                }),
            };
        }
    };

    let response = match call_audit_service(
        http_client,
        audit_service_url,
        &run.item_type,
        &target_url,
    )
    .await
    {
        Ok(response) => response,
        Err(err) => {
            if run.item_type == "server" && err.contains("429 Too Many Requests") {
                tracing::warn!(
                    "Code-summary audit rate limited for run {} ({}); retrying with skill-summary fallback",
                    run.id,
                    run.item_dedup_key
                );

                match call_server_skill_fallback(http_client, audit_service_url, &target_url).await
                {
                    Ok(mut fallback_response) => {
                        if let Some(object) = fallback_response.as_object_mut() {
                            object.insert(
                                "_runner_note".to_string(),
                                Value::String(
                                    "code-summary rate limited; used skill-summary fallback"
                                        .to_string(),
                                ),
                            );
                        }

                        let (grade, score) =
                            derive_grade_and_score(&run.item_type, &fallback_response);
                        return AuditExecution::Completed {
                            result: fallback_response,
                            grade,
                            score,
                        };
                    }
                    Err(fallback_err) => {
                        return AuditExecution::Failed {
                            result: json!({
                                "error": format!("{err}; fallback failed: {fallback_err}"),
                                "target_url": target_url,
                                "provider": "runthedev-audit-service"
                            }),
                        };
                    }
                }
            }

            return AuditExecution::Failed {
                result: json!({
                    "error": err,
                    "target_url": target_url,
                    "provider": "runthedev-audit-service"
                }),
            };
        }
    };

    let (grade, score) = derive_grade_and_score(&run.item_type, &response);
    AuditExecution::Completed {
        result: response,
        grade,
        score,
    }
}

async fn resolve_target_url(pool: &PgPool, item_type: &str, slug: &str) -> Result<String, String> {
    match item_type {
        "server" => {
            let exists: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM merged_servers WHERE dedup_key = $1)",
            )
            .bind(slug)
            .fetch_one(pool)
            .await
            .map_err(|err| format!("failed to lookup item URL: {err}"))?;

            if !exists {
                return Err(format!("item '{slug}' no longer exists in source table"));
            }

            Ok(format!("https://github.com/{slug}"))
        }
        "skill" => {
            let row = sqlx::query(
                r#"
                SELECT github_owner, github_repo, skill_name
                FROM merged_skills
                WHERE dedup_key = $1
                "#,
            )
            .bind(slug)
            .fetch_optional(pool)
            .await
            .map_err(|err| format!("failed to lookup item URL: {err}"))?;

            let Some(row) = row else {
                return Err(format!("item '{slug}' no longer exists in source table"));
            };

            let slug_parts: Vec<&str> = slug.split('/').collect();
            if slug_parts.len() != 2 {
                return Err(format!("invalid skill dedup key '{slug}'"));
            }

            let owner = row
                .get::<Option<String>, _>("github_owner")
                .filter(|value| !value.trim().is_empty())
                .unwrap_or_else(|| slug_parts[0].to_string());
            let repo = row
                .get::<Option<String>, _>("github_repo")
                .filter(|value| !value.trim().is_empty())
                .unwrap_or_else(|| slug_parts[1].to_string());
            let skill_name = row
                .get::<Option<String>, _>("skill_name")
                .filter(|value| !value.trim().is_empty())
                .unwrap_or_else(|| slug_parts[1].to_string());

            Ok(format!(
                "https://github.com/{owner}/{repo}/tree/main/skills/{skill_name}"
            ))
        }
        _ => Err(format!("unsupported item_type '{item_type}'")),
    }
}

async fn call_audit_service(
    http_client: &Client,
    audit_service_url: &str,
    item_type: &str,
    target_url: &str,
) -> Result<Value, String> {
    let endpoint = endpoint_for_item_type(item_type)
        .ok_or_else(|| format!("unsupported item_type '{item_type}'"))?;
    let request_body = request_body_for_item_type(item_type, target_url);

    call_audit_endpoint(http_client, audit_service_url, endpoint, request_body).await
}

async fn call_server_skill_fallback(
    http_client: &Client,
    audit_service_url: &str,
    target_url: &str,
) -> Result<Value, String> {
    let doc_url = format!("{}/tree/main", target_url.trim_end_matches('/'));
    let request_body = json!({
        "url": doc_url,
        "max_depth": 2,
        "max_docs": 30,
        "max_total_chars": 500000,
        "ai_explain": true
    });

    call_audit_endpoint(
        http_client,
        audit_service_url,
        SKILL_AUDIT_ENDPOINT,
        request_body,
    )
    .await
}

async fn call_audit_endpoint(
    http_client: &Client,
    audit_service_url: &str,
    endpoint: &str,
    request_body: Value,
) -> Result<Value, String> {
    let url = format!("{}{}", audit_service_url.trim_end_matches('/'), endpoint);

    let response = http_client
        .post(&url)
        .json(&request_body)
        .send()
        .await
        .map_err(|err| format!("failed to call audit-service endpoint '{url}': {err}"))?;

    let status = response.status();
    if !status.is_success() {
        let body = response
            .text()
            .await
            .unwrap_or_else(|_| "<failed to read response body>".to_string());
        return Err(format!("audit-service responded with {status}: {body}"));
    }

    response
        .json::<Value>()
        .await
        .map_err(|err| format!("invalid JSON from audit-service: {err}"))
}

fn endpoint_for_item_type(item_type: &str) -> Option<&'static str> {
    match item_type {
        "skill" => Some(SKILL_AUDIT_ENDPOINT),
        "server" => Some(SERVER_AUDIT_ENDPOINT),
        _ => None,
    }
}

fn request_body_for_item_type(item_type: &str, target_url: &str) -> Value {
    match item_type {
        "skill" => json!({
            "url": target_url,
            "max_depth": 2,
            "max_docs": 30,
            "max_total_chars": 500000,
            "ai_explain": true
        }),
        "server" => json!({
            "url": target_url,
            "max_files": 40,
            "max_total_chars": 400000,
            "ai_classify": true
        }),
        _ => json!({ "url": target_url }),
    }
}

fn derive_grade_and_score(item_type: &str, payload: &Value) -> (Option<String>, Option<f64>) {
    match item_type {
        "skill" => derive_skill_grade_and_score(payload),
        "server" => derive_server_grade_and_score(payload),
        _ => (None, None),
    }
}

fn derive_skill_grade_and_score(payload: &Value) -> (Option<String>, Option<f64>) {
    if let Some(risk_level) = payload.get("risk_level").and_then(Value::as_str) {
        let (grade, score) = map_risk_level_to_grade_score(risk_level);
        if grade.is_some() || score.is_some() {
            return (grade, score);
        }
    }

    let status = payload
        .get("status")
        .and_then(Value::as_str)
        .unwrap_or_default();
    map_status_to_grade_score(status)
}

fn derive_server_grade_and_score(payload: &Value) -> (Option<String>, Option<f64>) {
    let grade = payload
        .get("risk_level")
        .and_then(Value::as_str)
        .and_then(|risk_level| map_risk_level_to_grade_score(risk_level).0);

    let score = payload
        .get("security_score")
        .and_then(value_to_f64)
        .or_else(|| {
            payload
                .get("risk_level")
                .and_then(Value::as_str)
                .and_then(|risk_level| map_risk_level_to_grade_score(risk_level).1)
        });

    (grade, score)
}

fn value_to_f64(value: &Value) -> Option<f64> {
    value
        .as_f64()
        .or_else(|| value.as_i64().map(|int| int as f64))
}

fn map_risk_level_to_grade_score(risk_level: &str) -> (Option<String>, Option<f64>) {
    match risk_level.trim().to_ascii_uppercase().as_str() {
        "SAFE" => (Some("A".to_string()), Some(95.0)),
        "CAUTION" => (Some("C".to_string()), Some(75.0)),
        "HIGH" => (Some("D".to_string()), Some(45.0)),
        "CRITICAL" => (Some("F".to_string()), Some(20.0)),
        _ => (None, None),
    }
}

fn map_status_to_grade_score(status: &str) -> (Option<String>, Option<f64>) {
    match status.trim().to_ascii_uppercase().as_str() {
        "PASS" => (Some("A".to_string()), Some(95.0)),
        "WARN" => (Some("C".to_string()), Some(75.0)),
        "FAIL" => (Some("F".to_string()), Some(20.0)),
        _ => (None, None),
    }
}

async fn mark_completed(
    pool: &PgPool,
    run_id: i32,
    result: Value,
    grade: Option<String>,
    score: Option<f64>,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"
        UPDATE audit_runs
        SET status = 'completed',
            result = $2,
            score = $3,
            grade = $4,
            completed_at = NOW()
        WHERE id = $1
        "#,
    )
    .bind(run_id)
    .bind(result)
    .bind(score)
    .bind(grade)
    .execute(pool)
    .await?;

    Ok(())
}

async fn mark_failed(pool: &PgPool, run_id: i32, result: Value) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"
        UPDATE audit_runs
        SET status = 'failed',
            result = $2,
            score = NULL,
            grade = NULL,
            completed_at = NOW()
        WHERE id = $1
        "#,
    )
    .bind(run_id)
    .bind(result)
    .execute(pool)
    .await?;

    Ok(())
}
