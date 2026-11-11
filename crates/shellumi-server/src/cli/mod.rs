//! Command-line interface definitions and subcommand dispatchers.

pub mod admin;
pub mod backup;
pub mod doctor;
pub mod migrate;

use clap::{Args, Subcommand};
use std::path::PathBuf;

/// Subcommands available in the `shellumi-server` CLI.
#[derive(Debug, Subcommand, Clone)]
pub enum Commands {
    /// Run the HTTP/WSS API server daemon (default if omitted)
    Serve,
    /// Run system diagnostics and configuration health checks
    Doctor,
    /// Administrative direct management utilities (offline/interactive)
    Admin(admin::AdminArgs),
    /// Database schema migration inspection and runner
    Migrate(MigrateArgs),
    /// Database backup inspection and cryptographic verification
    Backup(BackupArgs),
}

#[derive(Debug, Args, Clone)]
pub struct MigrateArgs {
    #[command(subcommand)]
    pub action: MigrateAction,
}

#[derive(Debug, Subcommand, Clone)]
pub enum MigrateAction {
    /// Inspect available forward migrations and connection status
    Status,
    /// Run pending database migrations
    Run,
}

#[derive(Debug, Args, Clone)]
pub struct BackupArgs {
    #[command(subcommand)]
    pub action: BackupAction,
}

#[derive(Debug, Subcommand, Clone)]
pub enum BackupAction {
    /// Cryptographically inspect and verify a database backup file
    Verify {
        /// Path to the database dump file (e.g. backup.dump or backup.sql)
        file: PathBuf,
    },
}
