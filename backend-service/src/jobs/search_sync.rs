use meilisearch_sdk::client::Client as MeiliClient;
use sqlx::PgPool;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Semaphore;

use crate::search;

const SYNC_RETRY_ATTEMPTS: u32 = 5;
const SYNC_RETRY_START_DELAY: Duration = Duration::from_secs(30);
const SYNC_RETRY_MAX_DELAY: Duration = Duration::from_secs(15 * 60);
const SYNC_ATTEMPT_TIMEOUT: Duration = Duration::from_secs(30 * 60);

pub async fn run_search_sync_with_retries(
    pool: &PgPool,
    meili: &MeiliClient,
) -> Result<(), crate::error::AppError> {
    let mut delay = SYNC_RETRY_START_DELAY;

    for attempt in 1..=SYNC_RETRY_ATTEMPTS {
        let attempt_result =
            tokio::time::timeout(SYNC_ATTEMPT_TIMEOUT, search::full_sync(pool, meili)).await;

        match attempt_result {
            Ok(Ok(())) => return Ok(()),
            Ok(Err(err)) if attempt == SYNC_RETRY_ATTEMPTS => return Err(err),
            Err(_) if attempt == SYNC_RETRY_ATTEMPTS => {
                return Err(crate::error::AppError::Search(
                    "Meilisearch sync attempt timed out".to_string(),
                ));
            }
            Ok(Err(err)) => {
                tracing::warn!(
                    "Meilisearch sync attempt {attempt}/{SYNC_RETRY_ATTEMPTS} failed: {err}; retrying in {}s",
                    delay.as_secs()
                );
                tokio::time::sleep(delay).await;
                delay = std::cmp::min(delay.saturating_mul(2), SYNC_RETRY_MAX_DELAY);
            }
            Err(_) => {
                tracing::warn!(
                    "Meilisearch sync attempt {attempt}/{SYNC_RETRY_ATTEMPTS} timed out after {}s; retrying in {}s",
                    SYNC_ATTEMPT_TIMEOUT.as_secs(),
                    delay.as_secs()
                );
                tokio::time::sleep(delay).await;
                delay = std::cmp::min(delay.saturating_mul(2), SYNC_RETRY_MAX_DELAY);
            }
        }
    }

    Ok(())
}

/// Spawns a background task that runs Meilisearch full sync daily at 03:00 UTC.
pub fn spawn_search_sync(pool: PgPool, meili: MeiliClient, sync_permit: Arc<Semaphore>) {
    tokio::spawn(async move {
        loop {
            let sleep_duration = duration_until_next_hour(3);
            tracing::info!("Next Meilisearch sync in {}s", sleep_duration.as_secs());

            tokio::time::sleep(sleep_duration).await;

            let _permit = match sync_permit.clone().acquire_owned().await {
                Ok(permit) => permit,
                Err(e) => {
                    tracing::error!("Scheduled Meilisearch sync skipped: permit unavailable: {e}");
                    continue;
                }
            };

            tracing::info!("Starting scheduled Meilisearch sync...");
            match run_search_sync_with_retries(&pool, &meili).await {
                Ok(()) => tracing::info!("Scheduled Meilisearch sync completed successfully"),
                Err(e) => tracing::error!("Scheduled Meilisearch sync failed: {e}"),
            }
        }
    });
}

/// Returns the `std::time::Duration` from now until the next occurrence of
/// `hour`:00 UTC. If the target hour has already passed today, the next
/// occurrence is tomorrow.
fn duration_until_next_hour(hour: u32) -> std::time::Duration {
    let now = chrono::Utc::now();
    let target_today = now.date_naive().and_hms_opt(hour, 0, 0).expect("valid HMS");
    let target_today =
        chrono::DateTime::<chrono::Utc>::from_naive_utc_and_offset(target_today, chrono::Utc);

    let next_run = if now < target_today {
        target_today
    } else {
        target_today + chrono::TimeDelta::days(1)
    };

    (next_run - now)
        .to_std()
        .unwrap_or(std::time::Duration::from_secs(3600))
}
