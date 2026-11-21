//! blapki server entry point.

use blapki::{admin, app, config::Settings, http};
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();
    init_tracing();

    let config_path = std::env::var("BLAPKI_CONFIG").unwrap_or_else(|_| "config.toml".to_string());
    let args: Vec<String> = std::env::args().skip(1).collect();
    let args: Vec<&str> = args.iter().map(String::as_str).collect();

    match args.as_slice() {
        [] | ["serve"] => serve(&config_path).await,
        ["revoke", ca, serial] => revoke(&config_path, ca, serial, None).await,
        ["revoke", ca, serial, reason] => revoke(&config_path, ca, serial, Some(reason)).await,
        ["help"] | ["-h"] | ["--help"] => {
            println!("{}", admin::USAGE);
            Ok(())
        }
        _ => {
            eprintln!("{}", admin::USAGE);
            std::process::exit(2);
        }
    }
}

async fn serve(config_path: &str) -> anyhow::Result<()> {
    let settings = Settings::load(config_path)?;

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

async fn revoke(
    config_path: &str,
    ca: &str,
    serial: &str,
    reason: Option<&str>,
) -> anyhow::Result<()> {
    let settings = Settings::load(config_path)?;
    if admin::revoke(&settings, ca, serial, reason).await? {
        println!("revoked certificate {serial} of ca '{ca}'");
        Ok(())
    } else {
        eprintln!("no valid certificate {serial} for ca '{ca}' (unknown or already revoked)");
        std::process::exit(1);
    }
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
