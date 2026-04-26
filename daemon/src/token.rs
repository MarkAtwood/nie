use anyhow::{Context, Result};
use axum::{
    extract::{Request, State},
    http::StatusCode,
    middleware::Next,
    response::IntoResponse,
};
use rand::Rng;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use subtle::ConstantTimeEq;

use crate::state::DaemonState;

/// The raw bearer token extracted from the `?token=` query parameter.
///
/// Set by the `redact_token_query_param` middleware in `main.rs` as a request
/// extension before the URI is redacted.  Downstream handlers read the token
/// from here rather than from the `Query` extractor, which would see
/// `[redacted]` after URI mutation.
#[derive(Clone)]
pub struct QueryToken(pub String);

/// Load token from `data_dir/daemon.token`, or generate and save one.
pub fn load_or_create_token(data_dir: &Path) -> Result<String> {
    let token_path = data_dir.join("daemon.token");
    if token_path.exists() {
        let raw = std::fs::read_to_string(&token_path)
            .with_context(|| format!("failed to read token file: {}", token_path.display()))?;
        let token = raw.trim().to_string();
        anyhow::ensure!(!token.is_empty(), "daemon.token is empty");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&token_path)?.permissions().mode();
            anyhow::ensure!(
                mode & 0o077 == 0,
                "daemon.token permissions too permissive: {:o} (must be 0o600 or stricter)",
                mode & 0o777
            );
        }
        return Ok(token);
    }
    let bytes: [u8; 32] = rand::thread_rng().gen();
    use base64::Engine;
    let token = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes);
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&token_path)
        .with_context(|| format!("failed to create token file: {}", token_path.display()))?;
    writeln!(file, "{}", token)?;
    tracing::info!("generated new daemon token at {}", token_path.display());
    Ok(token)
}

/// Middleware that extracts `?token=` from the request URI, stores it as a
/// [`QueryToken`] extension, and then replaces the token value in the URI with
/// `[redacted]`.  Any downstream logging (including an axum `TraceLayer`) sees
/// only the redacted URI; the actual token value is available to handlers via
/// `Extension<QueryToken>`.
///
/// Redaction is case-insensitive (`token=`, `TOKEN=`, `Token=`, etc.) and also
/// matches the URL-encoded form `%74oken=` (lowercase 't' percent-encoded as
/// `%74`).  A parameter is a token parameter if its name, when lowercased and
/// with `%74` replaced by `t`, is `"token"`.
pub async fn redact_token_query_param(req: Request, next: Next) -> axum::response::Response {
    use axum::http::Uri;

    let (mut parts, body) = req.into_parts();
    let uri = &parts.uri;

    if let Some(query) = uri.query() {
        let lower = query.to_ascii_lowercase();
        let normalized = lower.replace("%74oken", "token");
        if normalized.contains("token=") {
            let mut raw_token: Option<String> = None;
            let redacted_query: String = query
                .split('&')
                .map(|param| {
                    let name = param.split('=').next().unwrap_or(param);
                    let name_lower = name.to_ascii_lowercase();
                    let name_norm = name_lower.replace("%74oken", "token");
                    if name_norm == "token" {
                        if raw_token.is_none() {
                            raw_token = param.find('=').map(|i| param[i + 1..].to_string());
                        }
                        "token=[redacted]"
                    } else {
                        param
                    }
                })
                .collect::<Vec<_>>()
                .join("&");

            if let Some(tok) = raw_token {
                parts.extensions.insert(QueryToken(tok));
            }

            let mut builder = Uri::builder();
            if let Some(scheme) = uri.scheme() {
                builder = builder.scheme(scheme.clone());
            }
            if let Some(authority) = uri.authority() {
                builder = builder.authority(authority.clone());
            }
            let path_and_query = format!("{}?{}", uri.path(), redacted_query);
            if let Ok(new_uri) = builder.path_and_query(path_and_query).build() {
                parts.uri = new_uri;
            }
        }
    }

    let req = Request::from_parts(parts, body);
    next.run(req).await
}

/// axum middleware that enforces Bearer token auth on HTTP routes.
/// Checks the `Authorization: Bearer <token>` header.
/// Returns 401 on missing or wrong token.
pub async fn require_token(
    State(state): State<DaemonState>,
    req: Request,
    next: Next,
) -> impl IntoResponse {
    let auth_ok = req
        .headers()
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .map(|h| validate_token_header(h, state.token()))
        .unwrap_or(false);

    if auth_ok {
        next.run(req).await.into_response()
    } else {
        StatusCode::UNAUTHORIZED.into_response()
    }
}

/// Validate a `Bearer <token>` header value using constant-time comparison.
/// Returns false on any format error — no details are leaked.
pub fn validate_token_header(header_value: &str, expected: &str) -> bool {
    let Some(token) = header_value.strip_prefix("Bearer ") else {
        return false;
    };
    bool::from(token.as_bytes().ct_eq(expected.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_token_missing_bearer() {
        assert!(!validate_token_header("", "secret"));
        assert!(!validate_token_header("secret", "secret"));
        assert!(!validate_token_header("bearer secret", "secret")); // case sensitive
    }

    #[test]
    fn test_validate_token_wrong() {
        assert!(!validate_token_header("Bearer wrong", "correct"));
    }

    #[test]
    fn test_validate_token_ok() {
        assert!(validate_token_header("Bearer correct", "correct"));
    }

    #[test]
    fn test_validate_token_empty_expected() {
        assert!(!validate_token_header("Bearer notempty", ""));
    }
}
