use sqlx::PgPool;

/// Spawns a background task that queues top items for audit daily at 04:00 UTC.
///
/// Selects the top 100 servers (by stars) and top 100 skills (by installs)
/// that either have never been audited or were last audited more than 7 days
/// ago, then inserts them as `pending` into `audit_runs`.
pub fn spawn_audit_queue(pool: PgPool) {
    tokio::spawn(async move {
        loop {
            let sleep_duration = duration_until_next_hour(4);
            tracing::info!("Next audit queue run in {}s", sleep_duration.as_secs());

            tokio::time::sleep(sleep_duration).await;

            tracing::info!("Running audit queue job...");
            match queue_top_items(&pool).await {
                Ok(count) => tracing::info!("Queued {count} items for audit"),
                Err(e) => tracing::error!("Audit queue job failed: {e}"),
            }
        }
    });
}

/// Inserts pending audit runs for the top servers and skills that need
/// (re-)auditing and returns the total number of rows inserted.
async fn queue_top_items(pool: &PgPool) -> Result<usize, sqlx::Error> {
    let mut tx = pool.begin().await?;

    // Queue top 100 servers by stars that need auditing
    let servers = sqlx::query(
        r#"
        INSERT INTO audit_runs (item_type, item_dedup_key, status, requested_by)
        SELECT 'server', s.dedup_key, 'pending', 'cron'
        FROM merged_servers s
        WHERE NOT EXISTS (
            SELECT 1 FROM audit_runs a
            WHERE a.item_type = 'server'
              AND a.item_dedup_key = s.dedup_key
              AND a.status IN ('pending', 'running')
        )
        AND NOT EXISTS (
            SELECT 1 FROM audit_runs a
            WHERE a.item_type = 'server'
              AND a.item_dedup_key = s.dedup_key
              AND a.status = 'completed'
              AND a.completed_at > NOW() - INTERVAL '7 days'
        )
        ORDER BY s.stars DESC
        LIMIT 100
        ON CONFLICT (item_type, item_dedup_key)
        WHERE status IN ('pending', 'running')
        DO NOTHING
        "#,
    )
    .execute(&mut *tx)
    .await?;

    // Queue top 100 skills by installs that need auditing
    let skills = sqlx::query(
        r#"
        INSERT INTO audit_runs (item_type, item_dedup_key, status, requested_by)
        SELECT 'skill', s.dedup_key, 'pending', 'cron'
        FROM merged_skills s
        WHERE NOT EXISTS (
            SELECT 1 FROM audit_runs a
            WHERE a.item_type = 'skill'
              AND a.item_dedup_key = s.dedup_key
              AND a.status IN ('pending', 'running')
        )
        AND NOT EXISTS (
            SELECT 1 FROM audit_runs a
            WHERE a.item_type = 'skill'
              AND a.item_dedup_key = s.dedup_key
              AND a.status = 'completed'
              AND a.completed_at > NOW() - INTERVAL '7 days'
        )
        ORDER BY s.installs DESC
        LIMIT 100
        ON CONFLICT (item_type, item_dedup_key)
        WHERE status IN ('pending', 'running')
        DO NOTHING
        "#,
    )
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;

    Ok(servers.rows_affected() as usize + skills.rows_affected() as usize)
}

/// Returns the `std::time::Duration` from now until the next occurrence of
/// `hour`:00 UTC.
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
