mod config;
mod error;
mod jobs;
mod middleware;
mod models;
mod routes;
mod search;
mod state;

use std::{sync::Arc, time::Duration};

use axum::{
    Router,
    extract::State,
    http::HeaderValue,
    http::StatusCode,
    middleware as axum_mw,
    routing::{get, post},
};
use meilisearch_sdk::client::Client as MeiliClient;
use tokio::sync::{Mutex, RwLock, Semaphore};
use tower_governor::GovernorError;
use tower_governor::GovernorLayer;
use tower_http::compression::CompressionLayer;
use tower_http::cors::{AllowOrigin, CorsLayer};
use tower_http::set_header::SetResponseHeaderLayer;
use tower_http::trace::TraceLayer;

use crate::config::Config;
use crate::state::{AppState, CachedCategories};

/// Simple health check for load balancers and Docker healthchecks.
async fn health() -> &'static str {
    "OK"
}

fn governor_error_response(error: GovernorError) -> axum::http::Response<axum::body::Body> {
    let (status, message, headers) = match error {
        GovernorError::TooManyRequests { headers, .. } => (
            StatusCode::TOO_MANY_REQUESTS,
            "Too many requests".to_string(),
            headers,
        ),
        GovernorError::UnableToExtractKey => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Internal server error".to_string(),
            None,
        ),
        GovernorError::Other { code, msg, headers } => (
            code,
            msg.unwrap_or_else(|| "Internal server error".to_string()),
            headers,
        ),
    };

    let body = serde_json::json!({ "error": message }).to_string();
    let mut response = axum::http::Response::builder()
        .status(status)
        .header(axum::http::header::CONTENT_TYPE, "application/json")
        .body(axum::body::Body::from(body))
        .expect("valid governor error response");

    if let Some(headers) = headers {
        response.headers_mut().extend(headers);
    }

    response
}

/// Readiness check that verifies external dependencies.
async fn ready(State(state): State<AppState>) -> Result<&'static str, StatusCode> {
    sqlx::query_scalar::<_, i32>("SELECT 1")
        .fetch_one(&state.db)
        .await
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;

    if !state.meili.is_healthy().await {
        return Err(StatusCode::SERVICE_UNAVAILABLE);
    }

    Ok("OK")
}

async fn shutdown_signal() {
    let ctrl_c = async {
        if let Err(err) = tokio::signal::ctrl_c().await {
            tracing::error!("Failed to install Ctrl+C signal handler: {err}");
        }
    };

    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut signal) => {
                signal.recv().await;
            }
            Err(err) => {
                tracing::error!("Failed to install SIGTERM handler: {err}");
            }
        }
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }

    tracing::info!("Shutdown signal received");
}

#[tokio::main]
async fn main() {
    // 0. Load .env before anything else (so RUST_LOG is available for tracing)
    dotenvy::dotenv().ok();

    // 1. Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    tracing::info!("RunTheDev API starting...");

    // 2. Load config from environment
    let config = Config::from_env();

    // Save bind address before moving config into Arc
    let addr = format!("{}:{}", config.host, config.port);

    // 3. Connect to PostgreSQL
    let pool = sqlx::PgPool::connect(&config.database_url)
        .await
        .expect("Failed to connect to PostgreSQL");

    tracing::info!("Connected to PostgreSQL");

    // 4. Run migrations
    sqlx::migrate!("./migrations")
        .run(&pool)
        .await
        .expect("Failed to run database migrations");

    tracing::info!("Database migrations complete");

    // 5. Create Meilisearch client
    let meili = MeiliClient::new(&config.meili_url, Some(&config.meili_master_key))
        .expect("Failed to create Meilisearch client");

    // 6. Create AppState
    let state = AppState {
        db: pool,
        meili,
        config: Arc::new(config),
        category_cache: Arc::new(RwLock::new(CachedCategories::default())),
        server_category_refresh_lock: Arc::new(Mutex::new(())),
        skill_category_refresh_lock: Arc::new(Mutex::new(())),
        stats_cache: Arc::new(RwLock::new(None)),
        stats_refresh_lock: Arc::new(Mutex::new(())),
        search_sync_permit: Arc::new(Semaphore::new(1)),
    };

    // 7. Run initial Meilisearch sync (fire-and-forget in background)
    let sync_pool = state.db.clone();
    let sync_meili = state.meili.clone();
    let sync_permit = state.search_sync_permit.clone();
    tokio::spawn(async move {
        let _permit = match sync_permit.acquire_owned().await {
            Ok(permit) => permit,
            Err(e) => {
                tracing::warn!("Initial Meilisearch sync skipped: permit unavailable: {e}");
                return;
            }
        };

        match jobs::search_sync::run_search_sync_with_retries(&sync_pool, &sync_meili).await {
            Ok(()) => tracing::info!("Initial Meilisearch sync complete"),
            Err(e) => tracing::warn!("Initial Meilisearch sync failed (non-fatal): {e}"),
        }
    });

    // 8. Spawn background jobs
    jobs::spawn_search_sync(
        state.db.clone(),
        state.meili.clone(),
        state.search_sync_permit.clone(),
    );
    jobs::spawn_audit_queue(state.db.clone());
    let audit_client = reqwest::Client::builder()
        .timeout(Duration::from_secs(state.config.audit_http_timeout_seconds))
        .build()
        .expect("Failed to create audit-service HTTP client");
    jobs::spawn_audit_runner(
        state.db.clone(),
        audit_client,
        state.config.audit_service_url.clone(),
        state.config.audit_poll_interval_seconds,
    );

    // 9. Build the router with three route groups + different rate limiters

    // Health check (no rate limit, no auth)
    let health_routes = Router::new()
        .route("/health", get(health))
        .route("/ready", get(ready));

    // List routes: 30 req/min (search + browse)
    let list_routes = Router::new()
        .route("/api/servers", get(routes::servers::list_servers))
        .route("/api/skills", get(routes::skills::list_skills))
        .route("/api/search", get(routes::search::unified_search))
        .layer(
            GovernorLayer::new(middleware::rate_limit::search_rate_limiter())
                .error_handler(governor_error_response),
        );

    // Public routes: 60 req/min (stats, categories, detail)
    let public_routes = Router::new()
        .route("/api/stats", get(routes::stats::get_stats))
        .route("/api/cli/check", get(routes::cli::check_item))
        .route("/api/cli/request-audit", post(routes::cli::request_audit))
        .route(
            "/api/servers/categories",
            get(routes::servers::get_server_categories),
        )
        .route(
            "/api/skills/categories",
            get(routes::skills::get_skill_categories),
        )
        .route(
            "/api/servers/{dedup_key}",
            get(routes::servers::get_server_detail),
        )
        .route(
            "/api/skills/{dedup_key}",
            get(routes::skills::get_skill_detail),
        )
        .layer(
            GovernorLayer::new(middleware::rate_limit::public_rate_limiter())
                .error_handler(governor_error_response),
        );

    // Admin routes: 120 req/min + auth
    let admin_routes = Router::new()
        .route("/api/admin/audit", post(routes::admin::trigger_audit))
        .route("/api/admin/audits", get(routes::admin::list_audit_runs))
        .route(
            "/api/admin/sync-search",
            post(routes::admin::trigger_search_sync),
        )
        .layer(axum_mw::from_fn_with_state(
            state.clone(),
            middleware::auth::require_admin,
        ))
        .layer(
            GovernorLayer::new(middleware::rate_limit::admin_rate_limiter())
                .error_handler(governor_error_response),
        );

    let cors_extra_origins = state.config.cors_extra_origins.clone();

    // Merge all routes
    let app = Router::new()
        .merge(health_routes)
        .merge(list_routes)
        .merge(public_routes)
        .merge(admin_routes)
        .with_state(state);

    // 10. Add CORS layer
    let cors = CorsLayer::new()
        .allow_origin(AllowOrigin::predicate(
            move |origin: &axum::http::HeaderValue, _request_parts: &axum::http::request::Parts| {
                let origin_str = origin.to_str().unwrap_or("");
                // Allow localhost with any port
                if origin_str == "http://localhost" || origin_str.starts_with("http://localhost:") {
                    return true;
                }
                // Allow additional configured origins (exact match)
                if cors_extra_origins
                    .iter()
                    .any(|allowed| allowed == origin_str)
                {
                    return true;
                }
                // Allow exact runthe.dev
                if origin_str == "https://runthe.dev" {
                    return true;
                }
                // Allow subdomains of runthe.dev
                if origin_str.starts_with("https://") && origin_str.ends_with(".runthe.dev") {
                    // Verify single level subdomain (no dots between https:// and .runthe.dev)
                    let subdomain = &origin_str[8..origin_str.len() - 11]; // strip "https://" and ".runthe.dev"
                    return !subdomain.contains('.') && !subdomain.is_empty();
                }
                false
            },
        ))
        .allow_methods([
            axum::http::Method::GET,
            axum::http::Method::POST,
            axum::http::Method::OPTIONS,
        ])
        .allow_headers([
            axum::http::HeaderName::from_static("content-type"),
            axum::http::HeaderName::from_static("authorization"),
        ]);

    let app = app.layer(cors);

    // 11. Add security headers
    let app = app
        .layer(SetResponseHeaderLayer::overriding(
            axum::http::header::X_CONTENT_TYPE_OPTIONS,
            HeaderValue::from_static("nosniff"),
        ))
        .layer(SetResponseHeaderLayer::overriding(
            axum::http::header::X_FRAME_OPTIONS,
            HeaderValue::from_static("DENY"),
        ));

    // 12. Add compression and tracing
    let app = app
        .layer(CompressionLayer::new())
        .layer(TraceLayer::new_for_http());

    // 13. Bind and serve
    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .expect("Failed to bind");
    tracing::info!("Server running on {addr}");
    let app = app.into_make_service_with_connect_info::<std::net::SocketAddr>();
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .expect("Server error");
}
