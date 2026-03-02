use std::sync::Arc;

use meilisearch_sdk::client::Client as MeiliClient;
use sqlx::PgPool;
use tokio::sync::{Mutex, RwLock, Semaphore};

use crate::config::Config;

/// Category cache type — shared across handlers via `AppState`.
pub type CategoryCache = Arc<RwLock<CachedCategories>>;
pub type StatsCache = Arc<RwLock<Option<CachedStats>>>;

pub struct CachedCategoryList {
    pub items: Vec<CategoryCount>,
    pub cached_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Default)]
pub struct CachedCategories {
    pub servers: Option<CachedCategoryList>,
    pub skills: Option<CachedCategoryList>,
}

#[derive(Clone, serde::Serialize)]
pub struct CategoryCount {
    pub name: String,
    pub count: i64,
}

pub struct CachedStats {
    pub servers_count: i64,
    pub skills_count: i64,
    pub audited_servers: i64,
    pub audited_skills: i64,
    pub cached_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Clone)]
pub struct AppState {
    pub db: PgPool,
    pub meili: MeiliClient,
    pub config: Arc<Config>,
    pub category_cache: CategoryCache,
    pub server_category_refresh_lock: Arc<Mutex<()>>,
    pub skill_category_refresh_lock: Arc<Mutex<()>>,
    pub stats_cache: StatsCache,
    pub stats_refresh_lock: Arc<Mutex<()>>,
    pub search_sync_permit: Arc<Semaphore>,
}
