//! blapki server entry point.

use blapki::{app, config::Settings, http};
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();
    init_tracing();

    let config_path = std::env::var("BLAPKI_CONFIG").unwrap_or_else(|_| "config.toml".to_string());
    let settings = Settings::load(&config_path)?;

    let listen = settings.server.listen.clone();
    let state = app::build_state(&settings).await?;
    let app = http::router(state);

    let listener = tokio::net::TcpListener::bind(&listen).await?;
    tracing::info!(%listen, "blapki listening");
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;
    Ok(())
}

fn init_tracing() {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info,blapki=debug,tower_http=info"));
    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(filter)
        .init();
}

async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
    tracing::info!("shutting down");
}
