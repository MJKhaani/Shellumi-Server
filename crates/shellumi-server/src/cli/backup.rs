//! Database backup inspection and cryptographic verification utility (`shellumi-server backup verify`).

use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{self, Read};
use std::path::{Path, PathBuf};

/// Summary report of database backup verification.
#[derive(Debug, Clone)]
pub struct BackupVerificationReport {
    pub file_path: PathBuf,
    pub file_size_bytes: u64,
    pub sha256_checksum: String,
    pub format: &'static str,
    pub detected_tables: Vec<String>,
    pub missing_tables: Vec<String>,
    pub zero_plaintext_keys_verified: bool,
    pub verified: bool,
    pub error_message: Option<String>,
}

/// Core required tables in a Shellumi Server database backup.
pub const REQUIRED_BACKUP_TABLES: &[&str] = &[
    "server_settings",
    "users",
    "organizations",
    "devices",
    "sessions",
    "vaults",
    "vault_members",
    "records",
    "change_log",
    "vault_key_envelopes",
    "audit_events",
];

/// Verifies a database backup file against schema signatures and cryptographic invariants.
pub fn verify_backup_file(path: &Path) -> io::Result<BackupVerificationReport> {
    let mut file = File::open(path)?;
    let metadata = file.metadata()?;
    let file_size_bytes = metadata.len();

    if file_size_bytes == 0 {
        return Ok(BackupVerificationReport {
            file_path: path.to_path_buf(),
            file_size_bytes: 0,
            sha256_checksum: String::new(),
            format: "empty",
            detected_tables: Vec::new(),
            missing_tables: REQUIRED_BACKUP_TABLES
                .iter()
                .map(|&s| s.to_string())
                .collect(),
            zero_plaintext_keys_verified: false,
            verified: false,
            error_message: Some("Backup file is empty (0 bytes)".to_string()),
        });
    }

    // Read header and content for hashing and table signature detection
    let mut hasher = Sha256::new();
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)?;
    hasher.update(&buffer);
    let sha256_checksum = hex::encode(hasher.finalize());

    // Format detection
    let is_pg_custom = buffer.starts_with(b"PGDMP");
    let is_sql_text = buffer.starts_with(b"--")
        || buffer.starts_with(b"/*")
        || buffer
            .windows(12)
            .any(|w| w == b"CREATE TABLE" || w == b"create table");

    let format = if is_pg_custom {
        "PostgreSQL Custom Archive (pg_dump -Fc)"
    } else if is_sql_text {
        "PostgreSQL Plaintext SQL (pg_dump)"
    } else {
        "Unknown binary/archive"
    };

    // Table signature scan
    let content_lossy = String::from_utf8_lossy(&buffer);
    let mut detected_tables = Vec::new();
    let mut missing_tables = Vec::new();

    for &table in REQUIRED_BACKUP_TABLES {
        let needle = table.as_bytes();
        let found = buffer
            .windows(needle.len())
            .any(|window| window.eq_ignore_ascii_case(needle));
        if found {
            detected_tables.push(table.to_string());
        } else {
            missing_tables.push(table.to_string());
        }
    }

    // Zero-knowledge security check: ensure no raw OpenSSH or RSA private keys were accidentally dumped
    let private_key_needles = [
        "BEGIN OPENSSH PRIVATE KEY",
        "BEGIN RSA PRIVATE KEY",
        "BEGIN EC PRIVATE KEY",
        "BEGIN PRIVATE KEY",
    ];

    let has_plaintext_private_key = private_key_needles
        .iter()
        .any(|&needle| content_lossy.contains(needle));

    let zero_plaintext_keys_verified = !has_plaintext_private_key;

    let verified =
        (is_pg_custom || is_sql_text) && missing_tables.is_empty() && zero_plaintext_keys_verified;

    let error_message = if !zero_plaintext_keys_verified {
        Some("CRITICAL SECURITY VIOLATION: Plaintext private key material detected in database dump!".to_string())
    } else if !is_pg_custom && !is_sql_text {
        Some(
            "Unrecognized backup file format; expected PostgreSQL custom archive or SQL dump"
                .to_string(),
        )
    } else if !missing_tables.is_empty() {
        Some(format!(
            "Missing required table definitions: {}",
            missing_tables.join(", ")
        ))
    } else {
        None
    };

    Ok(BackupVerificationReport {
        file_path: path.to_path_buf(),
        file_size_bytes,
        sha256_checksum,
        format,
        detected_tables,
        missing_tables,
        zero_plaintext_keys_verified,
        verified,
        error_message,
    })
}

/// Displays the backup verification report to stdout.
pub fn print_backup_report(report: &BackupVerificationReport) {
    println!("\n=== Shellumi Server Backup Verification ===\n");
    println!("File:       {}", report.file_path.display());
    println!("Size:       {} bytes", report.file_size_bytes);
    println!("SHA-256:    {}", report.sha256_checksum);
    println!("Format:     {}", report.format);
    println!(
        "Tables:     {}/{} detected",
        report.detected_tables.len(),
        REQUIRED_BACKUP_TABLES.len()
    );
    println!(
        "Zero-E2EE:  {}",
        if report.zero_plaintext_keys_verified {
            "[OK] No plaintext private keys found"
        } else {
            "[FAIL] Plaintext private key leaked!"
        }
    );

    if let Some(err) = &report.error_message {
        println!("\n[FAIL] Verification Failed: {err}");
    } else {
        println!("\n[ OK ] Backup integrity VERIFIED successfully.");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use uuid::Uuid;

    #[test]
    fn test_verify_valid_sql_backup() {
        let temp_path =
            std::env::temp_dir().join(format!("test_valid_backup_{}.sql", Uuid::now_v7()));
        {
            let mut file = File::create(&temp_path).unwrap();
            writeln!(file, "-- PostgreSQL database dump for Shellumi Server").unwrap();
            for table in REQUIRED_BACKUP_TABLES {
                writeln!(file, "CREATE TABLE public.{table} (id uuid primary key);").unwrap();
            }
        }

        let report = verify_backup_file(&temp_path).unwrap();
        let _ = std::fs::remove_file(&temp_path);

        assert!(report.verified);
        assert_eq!(report.missing_tables.len(), 0);
        assert!(report.zero_plaintext_keys_verified);
        assert_eq!(report.format, "PostgreSQL Plaintext SQL (pg_dump)");
    }

    #[test]
    fn test_verify_detects_corrupt_or_leaked_key_material() {
        let temp_path =
            std::env::temp_dir().join(format!("test_leaked_backup_{}.sql", Uuid::now_v7()));
        {
            let mut file = File::create(&temp_path).unwrap();
            writeln!(file, "-- PostgreSQL database dump").unwrap();
            for table in REQUIRED_BACKUP_TABLES {
                writeln!(file, "CREATE TABLE public.{table} (id uuid primary key);").unwrap();
            }
            // Inject prohibited raw private key
            writeln!(file, "-----BEGIN OPENSSH PRIVATE KEY-----").unwrap();
        }

        let report = verify_backup_file(&temp_path).unwrap();
        let _ = std::fs::remove_file(&temp_path);

        assert!(!report.verified);
        assert!(!report.zero_plaintext_keys_verified);
        assert!(report
            .error_message
            .unwrap()
            .contains("CRITICAL SECURITY VIOLATION"));
    }
}
