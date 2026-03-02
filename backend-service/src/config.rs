use std::env;

fn validate_secret(name: &str, value: &str) {
    let lower = value.to_ascii_lowercase();
    let looks_weak = value.len() < 16
        || lower.contains("change-me")
        || lower.contains("example")
        || lower.contains("dev-key")
        || lower.contains("default");

    assert!(
        !looks_weak,
        "{name} appears weak; use a strong secret value"
    );
}

pub struct Config {
    pub database_url: String,
    pub meili_url: String,
    pub meili_master_key: String,
    pub admin_api_key: String,
    pub audit_service_url: String,
    pub audit_poll_interval_seconds: u64,
    pub audit_http_timeout_seconds: u64,
    pub cors_extra_origins: Vec<String>,
    pub host: String,
    pub port: u16,
}

impl Config {
    pub fn from_env() -> Self {
        let meili_master_key = env::var("MEILI_MASTER_KEY").expect("MEILI_MASTER_KEY must be set");
        let admin_api_key = env::var("ADMIN_API_KEY").expect("ADMIN_API_KEY must be set");

        validate_secret("MEILI_MASTER_KEY", &meili_master_key);
        validate_secret("ADMIN_API_KEY", &admin_api_key);

        let cors_extra_origins = env::var("CORS_EXTRA_ORIGINS")
            .unwrap_or_default()
            .split(',')
            .map(str::trim)
            .filter(|origin| !origin.is_empty())
            .map(str::to_string)
            .collect();

        Self {
            database_url: env::var("DATABASE_URL").expect("DATABASE_URL must be set"),
            meili_url: env::var("MEILI_URL").expect("MEILI_URL must be set"),
            meili_master_key,
            admin_api_key,
            audit_service_url: env::var("AUDIT_SERVICE_URL")
                .unwrap_or_else(|_| "http://127.0.0.1:8000".to_string()),
            audit_poll_interval_seconds: env::var("AUDIT_POLL_INTERVAL_SECONDS")
                .unwrap_or_else(|_| "10".to_string())
                .parse()
                .expect("AUDIT_POLL_INTERVAL_SECONDS must be a valid u64"),
            audit_http_timeout_seconds: env::var("AUDIT_HTTP_TIMEOUT_SECONDS")
                .unwrap_or_else(|_| "120".to_string())
                .parse()
                .expect("AUDIT_HTTP_TIMEOUT_SECONDS must be a valid u64"),
            cors_extra_origins,
            host: env::var("HOST").unwrap_or_else(|_| "0.0.0.0".to_string()),
            port: env::var("PORT")
                .unwrap_or_else(|_| "4000".to_string())
                .parse()
                .expect("PORT must be a valid u16"),
        }
    }
}
