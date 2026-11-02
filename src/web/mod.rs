use std::sync::Arc;

use axum::{
    middleware,
    routing::{get, post},
    Router,
};
use tower_http::services::ServeDir;

mod auth;
mod dashboard;
mod handlers;
mod state;
mod types;

pub use auth::resolve_token;
pub use state::AppState;

use auth::{bind_socket, create_session, login_page, require_auth, warn_if_not_loopback};
use dashboard::{dashboard_index, dashboard_scan_detail};
use handlers::{
    export_scan, get_scan, get_scan_results, health_check, list_scans, start_scan, stop_scan,
};

#[derive(Clone)]
pub struct WebServer {
    pub state: Arc<AppState>,
}

impl WebServer {
    pub fn new(token: String) -> Self {
        Self {
            state: Arc::new(AppState::new(token)),
        }
    }

    pub fn router(state: Arc<AppState>) -> Router {
        let protected = Router::new()
            .route("/api/scan", post(start_scan))
            .route("/api/scans", get(list_scans))
            .route("/api/scan/{id}", get(get_scan))
            .route("/api/scan/{id}/results", get(get_scan_results))
            .route("/api/scan/{id}/stop", post(stop_scan))
            .route("/api/scan/{id}/export", get(export_scan))
            .route("/api/health", get(health_check))
            .route("/", get(dashboard_index))
            .route("/dashboard", get(dashboard_index))
            .route("/scan/{id}", get(dashboard_scan_detail))
            .route_layer(middleware::from_fn_with_state(state.clone(), require_auth));

        Router::new()
            .route("/login", get(login_page))
            .route("/api/session", post(create_session))
            .merge(protected)
            .nest_service("/static", ServeDir::new("src/web/static"))
            .with_state(state)
    }

    pub async fn start(&self, bind_addr: &str, port: u16, generated: bool) -> anyhow::Result<()> {
        let socket_addr = bind_socket(bind_addr, port)?;
        warn_if_not_loopback(bind_addr, socket_addr);

        eprintln!("NullScan web dashboard");
        eprintln!("  URL:   http://{socket_addr}/dashboard");
        if generated {
            eprintln!("  Token: {}", self.state.auth_token);
            eprintln!("  Generated for this process only. It is not written to disk.");
        } else {
            eprintln!("  Token: using --web-token / NULLSCAN_WEB_TOKEN (not reprinted).");
        }
        eprintln!("  API:   Authorization: Bearer <token>");
        eprintln!("  UI:    open the URL and paste the token. It is stored as an HttpOnly cookie.");
        eprintln!("  There is no default port; this process is listening on {socket_addr}.");

        let listener = tokio::net::TcpListener::bind(socket_addr).await?;
        axum::serve(listener, Self::router(self.state.clone())).await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt;

    const TOKEN: &str = "test-token-value-ok";

    fn test_app() -> Router {
        WebServer::router(Arc::new(AppState::new(TOKEN.to_string())))
    }

    async fn status_of(app: Router, builder: axum::http::request::Builder) -> StatusCode {
        let response = app
            .oneshot(builder.body(Body::empty()).unwrap())
            .await
            .unwrap();
        response.status()
    }

    #[tokio::test]
    async fn api_rejects_missing_token() {
        let status = status_of(test_app(), Request::builder().uri("/api/health")).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn api_rejects_wrong_bearer() {
        let status = status_of(
            test_app(),
            Request::builder()
                .uri("/api/health")
                .header("authorization", "Bearer not-the-token-value"),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn api_accepts_bearer_and_cookie() {
        let app = test_app();
        let bearer = status_of(
            app.clone(),
            Request::builder()
                .uri("/api/health")
                .header("authorization", format!("Bearer {TOKEN}")),
        )
        .await;
        assert_eq!(bearer, StatusCode::OK);

        let cookie = status_of(
            app,
            Request::builder()
                .uri("/api/scans")
                .header("cookie", format!("nullscan_token={TOKEN}")),
        )
        .await;
        assert_eq!(cookie, StatusCode::OK);
    }

    #[tokio::test]
    async fn dashboard_redirects_until_login() {
        let app = test_app();
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/dashboard")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        assert_eq!(response.headers().get("location").unwrap(), "/login");

        let login = app
            .oneshot(
                Request::builder()
                    .uri("/login")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(login.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn session_sets_cookie_for_valid_token() {
        let app = test_app();
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/session")
                    .header("content-type", "application/json")
                    .body(Body::from(format!(r#"{{"token":"{TOKEN}"}}"#)))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let cookie = response
            .headers()
            .get("set-cookie")
            .unwrap()
            .to_str()
            .unwrap();
        assert!(cookie.contains(&format!("nullscan_token={TOKEN}")));
        assert!(cookie.contains("HttpOnly"));
        assert!(cookie.contains("SameSite=Strict"));
    }

    #[tokio::test]
    async fn session_rejects_invalid_token() {
        let response = test_app()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/session")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"token":"wrong-token-value"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn authenticated_dashboard_renders() {
        let response = test_app()
            .oneshot(
                Request::builder()
                    .uri("/dashboard")
                    .header("cookie", format!("nullscan_token={TOKEN}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }
}
