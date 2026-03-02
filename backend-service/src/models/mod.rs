pub mod audit;
pub mod server;
pub mod skill;

// Re-exports
pub use audit::{AuditBrief, AuditRun, CreateAuditRequest};
pub use server::{RelatedServer, ServerDetail, ServerListItem};
pub use skill::{RelatedSkill, SkillDetail, SkillListItem};

/// Pagination query params
#[derive(Debug, serde::Deserialize)]
pub struct PaginationParams {
    #[serde(default = "default_page")]
    pub page: u32,
    #[serde(default = "default_per_page")]
    pub per_page: u32,
}

impl PaginationParams {
    pub fn offset(&self) -> u32 {
        (self.page.saturating_sub(1)) * self.per_page
    }

    pub fn validated(self) -> Self {
        Self {
            page: self.page.max(1),
            per_page: self.per_page.clamp(1, 50),
        }
    }
}

fn default_page() -> u32 {
    1
}
fn default_per_page() -> u32 {
    12
}

/// Generic paginated response
#[derive(Debug, serde::Serialize)]
pub struct PaginatedResponse<T: serde::Serialize> {
    pub items: Vec<T>,
    pub total: i64,
    pub page: u32,
    pub per_page: u32,
    pub total_pages: u32,
}

impl<T: serde::Serialize> PaginatedResponse<T> {
    pub fn new(items: Vec<T>, total: i64, page: u32, per_page: u32) -> Self {
        let total_pages = if per_page == 0 {
            0
        } else {
            ((total as f64) / (per_page as f64)).ceil() as u32
        };
        Self {
            items,
            total,
            page,
            per_page,
            total_pages,
        }
    }
}
