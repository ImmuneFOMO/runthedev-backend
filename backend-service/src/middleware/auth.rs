use axum::{
    body::Body,
    extract::State,
    http::{Request, header::AUTHORIZATION},
    middleware::Next,
    response::Response,
};
use subtle::ConstantTimeEq;

use crate::error::AppError;
use crate::state::AppState;

/// Constant-time string comparison to prevent timing attacks.
///
/// Both branches (equal and unequal length) iterate the same number of bytes
/// to avoid leaking the secret's length via timing.
fn constant_time_eq(a: &str, b: &str) -> bool {
    bool::from(a.as_bytes().ct_eq(b.as_bytes()))
}

/// Middleware that validates admin API key from `Authorization: Bearer <token>`.
///
/// Use with `axum::middleware::from_fn_with_state` on admin route groups.
pub async fn require_admin(
    State(state): State<AppState>,
    request: Request<Body>,
    next: Next,
) -> Result<Response, AppError> {
    let auth_header = request
        .headers()
        .get(AUTHORIZATION)
        .and_then(|v| v.to_str().ok());

    match auth_header {
        Some(header) if header.starts_with("Bearer ") => {
            let token = header[7..].trim();
            if constant_time_eq(token, &state.config.admin_api_key) {
                Ok(next.run(request).await)
            } else {
                Err(AppError::Unauthorized)
            }
        }
        _ => Err(AppError::Unauthorized),
    }
}
