use std::time::Duration;

use axum::middleware as axum_middleware;
use axum::routing::{get, post};
use axum::Router;
use tokio::net::TcpListener;

use crate::handlers;
use crate::middleware::{require_auth, validate_host};
use crate::state::AppState;

/// Build the axum router with all routes. `port` is the port the server is
/// bound to; it is used to validate the Host header on every request.
pub fn build_router(state: AppState, port: u16) -> Router {
    // Public routes (no auth required)
    let public = Router::new()
        .route("/", get(crate::frontend::serve_index))
        .route("/health", get(|| async { "ok" }))
        .route("/api/auth/login", post(handlers::auth::login))
        .route("/api/identities", get(handlers::identity::list_identities));

    // Protected routes (session required)
    let protected = Router::new()
        .route("/api/auth/status", get(handlers::auth::status))
        .route("/api/auth/logout", post(handlers::auth::logout))
        .route("/api/vaults", get(handlers::vault::list_vaults))
        .route("/api/vaults/{name}", get(handlers::vault::get_vault))
        .route(
            "/api/vaults/{vault}/envs/{env}/secrets",
            get(handlers::secret::list_secrets).post(handlers::secret::set_secret),
        )
        .route(
            "/api/vaults/{vault}/envs/{env}/secrets/{key}",
            get(handlers::secret::get_secret).delete(handlers::secret::delete_secret),
        )
        .route("/api/vaults/{vault}/audit", get(handlers::audit::get_audit))
        .layer(axum_middleware::from_fn_with_state(
            state.clone(),
            require_auth,
        ));

    // Host-header validation applies to ALL routes (public and protected) to
    // block DNS-rebinding attacks against the local server.
    public
        .merge(protected)
        .layer(axum_middleware::from_fn(move |req, next| {
            validate_host(req, next, port)
        }))
        .with_state(state)
}

/// Start the web server on 127.0.0.1:port.
pub async fn run(state: AppState, port: u16) -> anyhow::Result<()> {
    let app = build_router(state.clone(), port);

    let addr = format!("127.0.0.1:{}", port);
    let listener = TcpListener::bind(&addr).await?;

    // Spawn background session sweeper
    let sessions = state.sessions.clone();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(60)).await;
            sessions.sweep_expired();
        }
    });

    eprintln!("sigyn web GUI listening on http://{}", addr);
    axum::serve(listener, app).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt;

    use super::build_router;
    use crate::state::AppState;

    const TEST_PORT: u16 = 4567;

    fn test_router() -> axum::Router {
        let state = AppState::new(std::env::temp_dir(), Duration::from_secs(60));
        build_router(state, TEST_PORT)
    }

    fn request(host: Option<&str>) -> Request<Body> {
        let builder = Request::builder().uri("/health");
        let builder = match host {
            Some(h) => builder.header("host", h),
            None => builder,
        };
        builder.body(Body::empty()).unwrap()
    }

    #[tokio::test]
    async fn test_host_evil_rejected() {
        let res = test_router()
            .oneshot(request(Some("evil.com")))
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn test_host_rebound_with_port_rejected() {
        let res = test_router()
            .oneshot(request(Some(&format!("evil.com:{}", TEST_PORT))))
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn test_host_missing_rejected() {
        let res = test_router().oneshot(request(None)).await.unwrap();
        assert_eq!(res.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn test_host_wrong_port_rejected() {
        let res = test_router()
            .oneshot(request(Some("127.0.0.1:9999")))
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn test_host_loopback_with_port_allowed() {
        let res = test_router()
            .oneshot(request(Some(&format!("127.0.0.1:{}", TEST_PORT))))
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_host_localhost_allowed() {
        let res = test_router()
            .oneshot(request(Some(&format!("localhost:{}", TEST_PORT))))
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);

        let res = test_router()
            .oneshot(request(Some("localhost")))
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_host_guard_covers_protected_routes() {
        // Even authenticated-route requests must pass the host guard first.
        let req = Request::builder()
            .uri("/api/vaults")
            .header("host", "evil.com")
            .body(Body::empty())
            .unwrap();
        let res = test_router().oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::FORBIDDEN);
    }
}
