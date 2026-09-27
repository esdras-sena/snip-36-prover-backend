use std::net::SocketAddr;
use std::sync::Arc;

use axum::routing::post;
use axum::Router;
use snip36_core::config::Config;
use snip36_server::routes::prove_and_submit::prove_and_submit;
use snip36_server::routes::veil::veil_prove_and_settle;
use snip36_server::AppState;
use tower_http::cors::{Any, CorsLayer};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();

    let config = Config::from_env(None)?;
    let state = Arc::new(AppState::new(config));

    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    let app = Router::new()
        .route("/api/prove-and-submit", post(prove_and_submit))
        .route("/api/veil/prove-and-settle", post(veil_prove_and_settle))
        .with_state(state)
        .layer(cors);

    let port: u16 = std::env::var("PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(8080);
    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!("snip36 prover server listening on http://{addr}");

    axum::serve(listener, app).await?;
    Ok(())
}
