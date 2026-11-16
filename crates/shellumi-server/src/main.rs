//! Shellumi Server - Headless, self-hostable synchronization backend.

use clap::Parser;
use shellumi_server::cli::{admin, backup, doctor, migrate, BackupAction, Commands, MigrateAction};
use shellumi_server::config::{CliArgs, ServerConfig};
use shellumi_server::server;
use shellumi_server_store::{AnyStore, PgStore};
use std::process::ExitCode;
use std::sync::Arc;
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

    // Subcommand dispatch
    match &cli.command {
        Some(Commands::Doctor) => {
            let report = doctor::run_diagnostics(&config).await;
            doctor::print_doctor_report(&report);
            if report.all_passed {
                return ExitCode::SUCCESS;
            } else {
                return ExitCode::FAILURE;
            }
        }
        Some(Commands::Backup(backup_args)) => {
            let BackupAction::Verify { file } = &backup_args.action;
            match backup::verify_backup_file(file) {
                Ok(report) => {
                    backup::print_backup_report(&report);
                    if report.verified {
                        return ExitCode::SUCCESS;
                    } else {
                        return ExitCode::FAILURE;
                    }
                }
                Err(err) => {
                    eprintln!("Error opening backup file: {err}");
                    return ExitCode::FAILURE;
                }
            }
        }
        Some(Commands::Migrate(migrate_args)) => match &migrate_args.action {
            MigrateAction::Status => {
                let report = migrate::get_migration_status(&config);
                migrate::print_migration_status(&report);
                return ExitCode::SUCCESS;
            }
            MigrateAction::Run => {
                let report = migrate::get_migration_status(&config);
                migrate::print_migration_status(&report);
                match migrate::run_database_migrations(&config).await {
                    Ok(_) => return ExitCode::SUCCESS,
                    Err(err) => {
                        eprintln!("\n[ FAIL ] Migration failed: {err}");
                        return ExitCode::FAILURE;
                    }
                }
            }
        },
        Some(Commands::Admin(admin_args)) => {
            let store = if let Some(ref db_url) = config.database_url {
                match PgStore::connect(db_url).await {
                    Ok(pg) => Arc::new(AnyStore::postgres(pg)),
                    Err(e) => {
                        eprintln!("Failed to connect to database: {e}");
                        return ExitCode::FAILURE;
                    }
                }
            } else {
                Arc::new(AnyStore::memory())
            };
            match admin::run_admin_command(store, admin_args).await {
                Ok(_) => return ExitCode::SUCCESS,
                Err(err) => {
                    eprintln!("Admin error: {err}");
                    return ExitCode::FAILURE;
                }
            }
        }
        None | Some(Commands::Serve) => {
            // Run server daemon below
        }
    }

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
        metrics = config.metrics_enabled,
        rate_limit_per_min = config.rate_limit_per_minute,
        "Starting Shellumi Server"
    );

    if let Err(err) = server::run(config).await {
        error!(error = %err, "Server terminated with error");
        return ExitCode::FAILURE;
    }

    ExitCode::SUCCESS
}
