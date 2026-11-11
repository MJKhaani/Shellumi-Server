//! Database schema migration utilities (`shellumi-server migrate status` and `run`).

use crate::config::ServerConfig;
use std::fs;
use std::path::PathBuf;

/// Migration status summary.
#[derive(Debug, Clone)]
pub struct MigrationStatusReport {
    pub migrations_dir: PathBuf,
    pub available_migrations: Vec<String>,
    pub database_configured: bool,
    pub database_url_redacted: Option<String>,
}

/// Finds and lists available forward-only SQL migration files.
pub fn get_migration_status(config: &ServerConfig) -> MigrationStatusReport {
    // Look for migrations in relative paths or working directory
    let search_paths = [
        PathBuf::from("migrations"),
        PathBuf::from("../../migrations"),
        PathBuf::from("../migrations"),
    ];

    let migrations_dir = search_paths
        .into_iter()
        .find(|p| p.is_dir())
        .unwrap_or_else(|| PathBuf::from("migrations"));

    let mut available_migrations = Vec::new();

    if let Ok(entries) = fs::read_dir(&migrations_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) == Some("sql") {
                if let Some(file_name) = path.file_name().and_then(|s| s.to_str()) {
                    available_migrations.push(file_name.to_string());
                }
            }
        }
    }

    available_migrations.sort();

    let database_configured = config.database_url.is_some();
    let database_url_redacted = config.database_url.as_ref().map(|url| {
        // Redact password in URI if present
        if let Some(at_idx) = url.find('@') {
            if let Some(colon_idx) = url[..at_idx].rfind(':') {
                return format!("{}://***@{}", &url[..colon_idx], &url[at_idx + 1..]);
            }
        }
        url.clone()
    });

    MigrationStatusReport {
        migrations_dir,
        available_migrations,
        database_configured,
        database_url_redacted,
    }
}

/// Displays the migration status report to stdout.
pub fn print_migration_status(report: &MigrationStatusReport) {
    println!("\n=== Shellumi Server Database Migrations ===\n");
    println!("Migrations directory: {}", report.migrations_dir.display());
    println!(
        "Available migrations: {}",
        report.available_migrations.len()
    );
    for migration in &report.available_migrations {
        println!("  - {migration}");
    }
    println!();
    if report.database_configured {
        println!(
            "Target Database: {}",
            report
                .database_url_redacted
                .as_deref()
                .unwrap_or("configured")
        );
        println!("Status: Ready to execute forward migrations.");
    } else {
        println!("Target Database: Ephemeral In-Memory Storage");
        println!("Status: In-memory store automatically initializes runtime schemas.");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_migration_status_reports_migrations() {
        let config = ServerConfig::default();
        let report = get_migration_status(&config);
        assert!(!report.database_configured);
        // Migrations should find the repo migrations dir
        assert!(!report.available_migrations.is_empty());
        assert!(report
            .available_migrations
            .iter()
            .any(|m| m.contains("initial_schema")));
    }
}
