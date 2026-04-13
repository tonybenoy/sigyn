mod error;
mod frontend;
pub mod handlers;
mod middleware;
mod server;
mod session;
mod state;

use std::path::PathBuf;
use std::time::Duration;

use state::AppState;

/// Configuration for the web server.
pub struct ServerConfig {
    pub port: u16,
    pub sigyn_home: PathBuf,
    pub session_timeout_secs: u64,
}

/// Start the local web GUI server. Blocks until the server is shut down.
pub async fn start_server(config: ServerConfig) -> anyhow::Result<()> {
    let state = AppState::new(
        config.sigyn_home,
        Duration::from_secs(config.session_timeout_secs),
    );
    server::run(state, config.port).await
}
