use std::time::Duration;

use axum::middleware as axum_middleware;
use axum::routing::{get, post};
use axum::Router;
use tokio::net::TcpListener;

use crate::handlers;
use crate::middleware::require_auth;
use crate::state::AppState;

/// Build the axum router with all routes.
pub fn build_router(state: AppState) -> Router {
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

    public.merge(protected).with_state(state)
}

/// Start the web server on 127.0.0.1:port.
pub async fn run(state: AppState, port: u16) -> anyhow::Result<()> {
    let app = build_router(state.clone());

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
