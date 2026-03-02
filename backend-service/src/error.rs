use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};

#[derive(Debug, thiserror::Error)]
pub enum AppError {
    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),

    #[error("Not found")]
    NotFound,

    #[error("Bad request: {0}")]
    BadRequest(String),

    #[error("Unauthorized")]
    Unauthorized,

    #[error("Search error: {0}")]
    Search(String),

    #[allow(dead_code)]
    #[error("Internal error: {0}")]
    Internal(String),
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, message) = match &self {
            AppError::Database(_) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Internal server error".to_string(),
            ),
            AppError::NotFound => (StatusCode::NOT_FOUND, "Not found".to_string()),
            AppError::BadRequest(msg) => (StatusCode::BAD_REQUEST, msg.clone()),
            AppError::Unauthorized => (StatusCode::UNAUTHORIZED, "Unauthorized".to_string()),
            AppError::Search(_) => (
                StatusCode::BAD_GATEWAY,
                "Search service temporarily unavailable".to_string(),
            ),
            AppError::Internal(_) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Internal server error".to_string(),
            ),
        };

        // Log the actual error for debugging
        match &self {
            AppError::Database(_) | AppError::Search(_) | AppError::Internal(_) => {
                tracing::error!("AppError: {self}");
            }
            _ => {
                tracing::warn!("AppError: {self}");
            }
        }

        let body = serde_json::json!({ "error": message });
        (status, axum::Json(body)).into_response()
    }
}
