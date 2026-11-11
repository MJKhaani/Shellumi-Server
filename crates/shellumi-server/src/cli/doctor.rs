//! System diagnostics and self-check utility (`shellumi-server doctor`).

use crate::config::ServerConfig;
use std::fs;
use std::path::Path;

/// Result of diagnostic check execution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiagnosticCheck {
    pub name: &'static str,
    pub passed: bool,
    pub message: String,
    pub is_warning: bool,
}

/// Report summarizing all diagnostic checks.
#[derive(Debug, Clone)]
pub struct DoctorReport {
    pub checks: Vec<DiagnosticCheck>,
    pub all_passed: bool,
}

/// Executes all system diagnostic checks against the provided configuration.
pub fn run_diagnostics(config: &ServerConfig) -> DoctorReport {
    let mut checks = Vec::new();

    // 1. Configuration Validation
    match config.validate() {
        Ok(_) => checks.push(DiagnosticCheck {
            name: "Configuration Validation",
            passed: true,
            message: "Server configuration passed all invariant checks".to_string(),
            is_warning: false,
        }),
        Err(err) => checks.push(DiagnosticCheck {
            name: "Configuration Validation",
            passed: false,
            message: format!("Configuration validation failed: {err}"),
            is_warning: false,
        }),
    }

    // 2. Network & Public URL Security
    if config.listen_addr.ip().is_loopback() {
        checks.push(DiagnosticCheck {
            name: "Network Listener Security",
            passed: true,
            message: format!("Listening on loopback address ({})", config.listen_addr),
            is_warning: false,
        });
    } else if config.public_url.starts_with("https://") {
        checks.push(DiagnosticCheck {
            name: "Network Listener Security",
            passed: true,
            message: format!(
                "Listening on {} with canonical HTTPS public URL ({})",
                config.listen_addr, config.public_url
            ),
            is_warning: false,
        });
    } else if !config.trusted_proxies.is_empty() {
        checks.push(DiagnosticCheck {
            name: "Network Listener Security",
            passed: true,
            message: format!(
                "Listening on {} behind {} trusted proxies",
                config.listen_addr,
                config.trusted_proxies.len()
            ),
            is_warning: false,
        });
    } else {
        checks.push(DiagnosticCheck {
            name: "Network Listener Security",
            passed: false,
            message: format!(
                "Non-loopback address ({}) exposed without HTTPS or trusted proxies",
                config.listen_addr
            ),
            is_warning: false,
        });
    }

    // 3. Storage & Database URL
    if let Some(db_url) = &config.database_url {
        if db_url.starts_with("postgres://") || db_url.starts_with("postgresql://") {
            checks.push(DiagnosticCheck {
                name: "Database Configuration",
                passed: true,
                message: "Valid PostgreSQL connection string configured".to_string(),
                is_warning: false,
            });
        } else {
            checks.push(DiagnosticCheck {
                name: "Database Configuration",
                passed: false,
                message: "Database URL is not a recognized postgresql:// connection scheme"
                    .to_string(),
                is_warning: false,
            });
        }
    } else {
        checks.push(DiagnosticCheck {
            name: "Database Configuration",
            passed: true,
            message: "Defaulting to ephemeral in-memory storage (suitable for tests and single-node development)".to_string(),
            is_warning: true,
        });
    }

    // 4. Token TTL Ratios
    if config.access_token_ttl_secs > 0
        && config.refresh_token_ttl_secs >= config.access_token_ttl_secs
    {
        checks.push(DiagnosticCheck {
            name: "Token Lifetimes",
            passed: true,
            message: format!(
                "Access token TTL ({}s) and refresh token TTL ({}s) valid",
                config.access_token_ttl_secs, config.refresh_token_ttl_secs
            ),
            is_warning: false,
        });
    } else {
        checks.push(DiagnosticCheck {
            name: "Token Lifetimes",
            passed: false,
            message: "Invalid token lifetimes configured".to_string(),
            is_warning: false,
        });
    }

    // 5. Payload Limits
    if config.max_request_bytes >= config.max_record_bytes && config.max_record_bytes > 0 {
        checks.push(DiagnosticCheck {
            name: "Payload Boundaries",
            passed: true,
            message: format!(
                "Max request ({} bytes) >= max record ({} bytes)",
                config.max_request_bytes, config.max_record_bytes
            ),
            is_warning: false,
        });
    } else {
        checks.push(DiagnosticCheck {
            name: "Payload Boundaries",
            passed: false,
            message: "Max record size exceeds max request body limit".to_string(),
            is_warning: false,
        });
    }

    // 6. Working Directory & Filesystem Access
    let test_path = Path::new(".shellumi-doctor-probe");
    match fs::write(test_path, b"probe") {
        Ok(_) => {
            let _ = fs::remove_file(test_path);
            checks.push(DiagnosticCheck {
                name: "Filesystem Permissions",
                passed: true,
                message: "Working directory is writable".to_string(),
                is_warning: false,
            });
        }
        Err(err) => {
            checks.push(DiagnosticCheck {
                name: "Filesystem Permissions",
                passed: false,
                message: format!("Working directory write probe failed: {err}"),
                is_warning: false,
            });
        }
    }

    let all_passed = checks.iter().all(|c| c.passed);

    DoctorReport { checks, all_passed }
}

/// Formats and displays the diagnostic report to stdout.
pub fn print_doctor_report(report: &DoctorReport) {
    println!("\n=== Shellumi Server Diagnostic Doctor ===\n");
    for check in &report.checks {
        let tag = if !check.passed {
            "[FAIL]"
        } else if check.is_warning {
            "[WARN]"
        } else {
            "[ OK ]"
        };
        println!("{tag} {}: {}", check.name, check.message);
    }
    println!();
    if report.all_passed {
        println!("All system diagnostic checks PASSED.");
    } else {
        println!("One or more diagnostic checks FAILED. Please review configuration.");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_diagnostics_on_default_config_passes() {
        let config = ServerConfig::default();
        let report = run_diagnostics(&config);
        assert!(report.all_passed);
        assert_eq!(report.checks.len(), 6);
    }
}
