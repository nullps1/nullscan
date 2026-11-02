use axum::{
    extract::{Request, State},
    http::{header, HeaderMap, StatusCode},
    middleware::Next,
    response::{Html, IntoResponse, Redirect, Response},
    Json,
};
use serde::Deserialize;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use uuid::Uuid;

use crate::web::state::AppState;
use crate::web::types::ApiResponse;

pub const MIN_TOKEN_LEN: usize = 16;

/// Resolve the dashboard bearer token.
///
/// Returns `(token, generated)`. A missing token is generated for this process.
/// Supplied tokens come from `--web-token` or `NULLSCAN_WEB_TOKEN`.
pub fn resolve_token(supplied: Option<String>) -> anyhow::Result<(String, bool)> {
    match supplied {
        Some(raw) => {
            let token = raw.trim().to_string();
            validate_token(&token)?;
            Ok((token, false))
        }
        None => Ok((generate_token(), true)),
    }
}

pub fn validate_token(token: &str) -> anyhow::Result<()> {
    if token.len() < MIN_TOKEN_LEN || token.len() > 256 {
        anyhow::bail!(
            "dashboard token must be {MIN_TOKEN_LEN}-256 characters (got {})",
            token.len()
        );
    }
    if !token
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        anyhow::bail!("dashboard token may contain only ASCII letters, digits, '-' and '_'");
    }
    Ok(())
}

pub fn generate_token() -> String {
    let mut token = String::with_capacity(64);
    token.push_str(&hex_encode(Uuid::new_v4().as_bytes()));
    token.push_str(&hex_encode(Uuid::new_v4().as_bytes()));
    token
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

/// True when the dashboard bind address is loopback (the default).
pub fn is_loopback_bind(bind_addr: &str) -> bool {
    parse_bind_ip(bind_addr)
        .map(|ip| ip.is_loopback())
        .unwrap_or(false)
}

pub fn bind_socket(bind_addr: &str, port: u16) -> anyhow::Result<SocketAddr> {
    let ip = parse_bind_ip(bind_addr).map_err(|_| {
        anyhow::anyhow!(
            "invalid --web-bind address '{bind_addr}' (use an IP such as 127.0.0.1 or ::1)"
        )
    })?;
    Ok(SocketAddr::new(ip, port))
}

fn parse_bind_ip(bind_addr: &str) -> Result<IpAddr, ()> {
    let trimmed = bind_addr.trim();
    if trimmed.eq_ignore_ascii_case("localhost") {
        return Ok(IpAddr::V4(Ipv4Addr::LOCALHOST));
    }
    let bare = trimmed.trim_matches(|c| c == '[' || c == ']');
    bare.parse().map_err(|_| ())
}

pub fn tokens_equal(expected: &str, provided: &str) -> bool {
    let expected = expected.as_bytes();
    let provided = provided.as_bytes();
    let mut diff = expected.len() ^ provided.len();
    for (index, expected_byte) in expected.iter().enumerate() {
        let provided_byte = provided.get(index).copied().unwrap_or(0);
        diff |= (*expected_byte ^ provided_byte) as usize;
    }
    diff == 0
}

pub fn request_is_authorized(state: &AppState, headers: &HeaderMap) -> bool {
    if let Some(token) = bearer_token(headers) {
        if tokens_equal(&state.auth_token, token) {
            return true;
        }
    }
    if let Some(token) = cookie_token(headers) {
        if tokens_equal(&state.auth_token, token) {
            return true;
        }
    }
    false
}

fn bearer_token(headers: &HeaderMap) -> Option<&str> {
    let value = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    let token = value
        .strip_prefix("Bearer ")
        .or_else(|| value.strip_prefix("bearer "))?
        .trim();
    if token.is_empty() {
        None
    } else {
        Some(token)
    }
}

fn cookie_token(headers: &HeaderMap) -> Option<&str> {
    let raw = headers.get(header::COOKIE)?.to_str().ok()?;
    for part in raw.split(';') {
        let part = part.trim();
        if let Some(value) = part.strip_prefix("nullscan_token=") {
            if !value.is_empty() {
                return Some(value);
            }
        }
    }
    None
}

pub async fn require_auth(
    State(state): State<Arc<AppState>>,
    request: Request,
    next: Next,
) -> Response {
    if request_is_authorized(&state, request.headers()) {
        return next.run(request).await;
    }

    if request.uri().path().starts_with("/api/") {
        unauthorized_response()
    } else {
        Redirect::to("/login").into_response()
    }
}

fn unauthorized_response() -> Response {
    (
        StatusCode::UNAUTHORIZED,
        [(header::WWW_AUTHENTICATE, "Bearer")],
        Json(ApiResponse::<()>::error(
            "missing or invalid dashboard token".to_string(),
        )),
    )
        .into_response()
}

#[derive(Debug, Deserialize)]
pub struct SessionRequest {
    pub token: String,
}

pub async fn create_session(
    State(state): State<Arc<AppState>>,
    Json(body): Json<SessionRequest>,
) -> Response {
    if !tokens_equal(&state.auth_token, body.token.trim()) {
        return unauthorized_response();
    }

    let cookie = format!(
        "nullscan_token={}; HttpOnly; SameSite=Strict; Path=/; Max-Age=43200",
        state.auth_token
    );
    (
        StatusCode::OK,
        [(header::SET_COOKIE, cookie)],
        Json(ApiResponse::success("authenticated".to_string())),
    )
        .into_response()
}

pub async fn login_page() -> Html<&'static str> {
    Html(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>NullScan — Sign in</title>
    <style>
        body {
            margin: 0;
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
            color: #f5f5f5;
        }
        form {
            width: min(420px, calc(100% - 2rem));
            background: rgba(255, 255, 255, 0.05);
            border: 1px solid rgba(233, 69, 96, 0.35);
            border-radius: 12px;
            padding: 2rem;
        }
        h1 { margin: 0 0 0.5rem; color: #e94560; }
        p { color: #f39c12; line-height: 1.4; }
        label { display: block; margin: 1rem 0 0.4rem; }
        input {
            width: 100%;
            padding: 0.75rem;
            border-radius: 8px;
            border: 1px solid rgba(233, 69, 96, 0.4);
            background: rgba(0, 0, 0, 0.25);
            color: #fff;
            box-sizing: border-box;
        }
        button {
            margin-top: 1rem;
            width: 100%;
            padding: 0.8rem;
            border: 0;
            border-radius: 8px;
            background: linear-gradient(45deg, #e94560, #f39c12);
            color: white;
            font-weight: 700;
            cursor: pointer;
        }
        .error { color: #e74c3c; min-height: 1.2rem; }
        .fine { color: rgba(255,255,255,0.65); font-size: 0.9rem; }
    </style>
</head>
<body>
    <form id="login">
        <h1>NullScan</h1>
        <p>Paste the dashboard token printed when the server started.</p>
        <label for="token">Bearer token</label>
        <input id="token" name="token" autocomplete="off" spellcheck="false" required>
        <div class="error" id="error"></div>
        <button type="submit">Unlock dashboard</button>
        <p class="fine">Authorized use only. The token is stored in an HttpOnly cookie for this browser. API clients should send <code>Authorization: Bearer &lt;token&gt;</code>.</p>
    </form>
    <script>
        document.getElementById('login').addEventListener('submit', async (event) => {
            event.preventDefault();
            const error = document.getElementById('error');
            error.textContent = '';
            const token = document.getElementById('token').value.trim();
            try {
                const response = await fetch('/api/session', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ token })
                });
                if (!response.ok) {
                    error.textContent = 'That token was rejected.';
                    return;
                }
                window.location.href = '/dashboard';
            } catch (err) {
                error.textContent = 'Could not reach the dashboard.';
            }
        });
    </script>
</body>
</html>"#,
    )
}

pub fn warn_if_not_loopback(bind_addr: &str, socket: SocketAddr) {
    if is_loopback_bind(bind_addr) {
        return;
    }
    eprintln!();
    eprintln!("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
    eprintln!("WARNING: NullScan web dashboard is NOT bound to loopback.");
    eprintln!("Bind address: {socket}");
    eprintln!("The default is 127.0.0.1. This exposes the dashboard on the network.");
    eprintln!("Anyone who can reach this address and obtain the token can start scans.");
    eprintln!("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
    eprintln!();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_token_meets_policy() {
        let token = generate_token();
        assert!(validate_token(&token).is_ok());
        assert_eq!(token.len(), 64);
    }

    #[test]
    fn rejects_short_and_punctuated_tokens() {
        assert!(validate_token("short").is_err());
        assert!(validate_token("has space in token").is_err());
        assert!(validate_token("semicolon;not-allowed-here").is_err());
        assert!(validate_token("perfectly-fine_token1").is_ok());
    }

    #[test]
    fn loopback_detection() {
        assert!(is_loopback_bind("127.0.0.1"));
        assert!(is_loopback_bind("localhost"));
        assert!(is_loopback_bind("::1"));
        assert!(is_loopback_bind("[::1]"));
        assert!(!is_loopback_bind("0.0.0.0"));
        assert!(!is_loopback_bind("192.168.1.10"));
        assert!(!is_loopback_bind("not-an-ip"));
    }

    #[test]
    fn token_compare_rejects_mismatch() {
        assert!(tokens_equal("test-token-value-ok", "test-token-value-ok"));
        assert!(!tokens_equal("test-token-value-ok", "test-token-value-no"));
        assert!(!tokens_equal(
            "test-token-value-ok",
            "test-token-value-ok-extra"
        ));
        assert!(!tokens_equal("test-token-value-ok", ""));
    }
}
