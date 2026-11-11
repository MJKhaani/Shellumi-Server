//! Shellumi Server - Headless, self-hostable synchronization backend.

use clap::Parser;
use shellumi_server::config::{CliArgs, ServerConfig};
use shellumi_server::server;
use std::process::ExitCode;
use tracing::{error, info};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

#[tokio::main]
async fn main() -> ExitCode {
    let cli = CliArgs::parse();

    let config = match ServerConfig::load(&cli) {
        Ok(cfg) => cfg,
        Err(err) => {
            eprintln!("Configuration error: {err}");
            return ExitCode::FAILURE;
        }
    };

    // Initialize structured logging
    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(&config.log_level));

    if config.log_format == "pretty" {
        tracing_subscriber::registry()
            .with(filter)
            .with(tracing_subscriber::fmt::layer().pretty())
            .init();
    } else {
        tracing_subscriber::registry()
            .with(filter)
            .with(tracing_subscriber::fmt::layer().json())
            .init();
    }

    info!(
        version = env!("CARGO_PKG_VERSION"),
        listen = %config.listen_addr,
        public_url = %config.public_url,
        registration = %config.registration,
        "Starting Shellumi Server"
    );

    if let Err(err) = server::run(config).await {
        error!(error = %err, "Server terminated with error");
        return ExitCode::FAILURE;
    }

    ExitCode::SUCCESS
}
