use std::sync::Arc;
use std::time::Duration;

use governor::clock::QuantaInstant;
use governor::middleware::NoOpMiddleware;
use tower_governor::governor::{GovernorConfig, GovernorConfigBuilder};
use tower_governor::key_extractor::PeerIpKeyExtractor;

/// Concrete governor config type: rate-limit by peer IP with no extra headers.
///
/// Use with `GovernorLayer::new(config)` to create a rate-limiting layer
/// for axum route groups.
pub type GovernorCfg = GovernorConfig<PeerIpKeyExtractor, NoOpMiddleware<QuantaInstant>>;

/// Returns a `GovernorConfig` for public endpoints: 60 req/min per IP.
///
/// Replenishes 1 token per second with a burst capacity of 60,
/// giving a sustained rate of 60 requests per minute.
pub fn public_rate_limiter() -> Arc<GovernorCfg> {
    Arc::new(
        GovernorConfigBuilder::default()
            .period(Duration::from_secs(1))
            .burst_size(60)
            .finish()
            .expect("Failed to create public rate limiter"),
    )
}

/// Returns a `GovernorConfig` for list/search endpoints: 30 req/min per IP.
///
/// Replenishes 1 token every 2 seconds with a burst capacity of 30,
/// giving a sustained rate of 30 requests per minute.
pub fn search_rate_limiter() -> Arc<GovernorCfg> {
    Arc::new(
        GovernorConfigBuilder::default()
            .period(Duration::from_secs(2))
            .burst_size(30)
            .finish()
            .expect("Failed to create search rate limiter"),
    )
}

/// Returns a `GovernorConfig` for admin endpoints: 120 req/min per IP.
///
/// Replenishes 1 token every 500ms with a burst capacity of 120,
/// giving a sustained rate of 120 requests per minute.
pub fn admin_rate_limiter() -> Arc<GovernorCfg> {
    Arc::new(
        GovernorConfigBuilder::default()
            .period(Duration::from_millis(500))
            .burst_size(120)
            .finish()
            .expect("Failed to create admin rate limiter"),
    )
}
