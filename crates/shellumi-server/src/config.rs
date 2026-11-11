//! Configuration management for Shellumi Server.
//!
//! Follows strict precedence:
//! 1. CLI flags
//! 2. Environment variables (`SHELLUMI_SERVER_*`)
//! 3. Configuration file (`config.toml`)
//! 4. Secure defaults

use clap::{Parser, ValueEnum};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::fs;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::str::FromStr;

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("Failed to read configuration file at '{path}': {source}")]
    Io {
        path: PathBuf,
        source: std::io::Error,
    },

    #[error("Failed to parse TOML configuration from '{path}': {source}")]
    Toml {
        path: PathBuf,
        source: toml::de::Error,
    },

    #[error("Validation error: {0}")]
    Validation(String),
}

/// Registration mode for the server.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ValueEnum)]
#[serde(rename_all = "snake_case")]
pub enum RegistrationMode {
    InviteOnly,
    Closed,
}

impl fmt::Display for RegistrationMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InviteOnly => write!(f, "invite_only"),
            Self::Closed => write!(f, "closed"),
        }
    }
}

impl FromStr for RegistrationMode {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "invite_only" => Ok(Self::InviteOnly),
            "closed" => Ok(Self::Closed),
            other => Err(format!(
                "invalid registration mode '{other}'; supported: invite_only, closed"
            )),
        }
    }
}

/// Fully resolved and validated server runtime configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServerConfig {
    pub listen_addr: SocketAddr,
    pub public_url: String,
    pub database_url: Option<String>,
    pub log_level: String,
    pub log_format: String,
    pub registration: RegistrationMode,
    pub access_token_ttl_secs: u64,
    pub refresh_token_ttl_secs: u64,
    pub max_request_bytes: usize,
    pub max_record_bytes: usize,
    pub collab_enabled: bool,
    pub metrics_enabled: bool,
    pub trusted_proxies: Vec<IpAddr>,
    pub allowed_origins: Vec<String>,
    pub dev_mode: bool,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            listen_addr: SocketAddr::from(([127, 0, 0, 1], 8080)),
            public_url: "http://127.0.0.1:8080".to_string(),
            database_url: None,
            log_level: "info".to_string(),
            log_format: "json".to_string(),
            registration: RegistrationMode::InviteOnly,
            access_token_ttl_secs: 900,          // 15 minutes
            refresh_token_ttl_secs: 2_592_000,   // 30 days
            max_request_bytes: 10 * 1024 * 1024, // 10 MiB
            max_record_bytes: 1024 * 1024,       // 1 MiB
            collab_enabled: false,
            metrics_enabled: false,
            trusted_proxies: Vec::new(),
            allowed_origins: Vec::new(),
            dev_mode: false,
        }
    }
}

impl ServerConfig {
    /// Validates the resolved configuration against security invariants.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.listen_addr.port() == 0 {
            return Err(ConfigError::Validation(
                "Listen port must be greater than 0".to_string(),
            ));
        }

        // Security check: non-loopback listener requires HTTPS or trusted proxies unless in dev mode
        if !self.listen_addr.ip().is_loopback()
            && !self.dev_mode
            && self.trusted_proxies.is_empty()
            && !self.public_url.starts_with("https://")
        {
            return Err(ConfigError::Validation(
                "Binding to a non-loopback address requires an HTTPS public URL or explicit trusted proxies"
                    .to_string(),
            ));
        }

        if self.access_token_ttl_secs == 0 {
            return Err(ConfigError::Validation(
                "access_token_ttl_secs must be greater than 0".to_string(),
            ));
        }

        if self.refresh_token_ttl_secs < self.access_token_ttl_secs {
            return Err(ConfigError::Validation(
                "refresh_token_ttl_secs must be greater than or equal to access_token_ttl_secs"
                    .to_string(),
            ));
        }

        if self.max_record_bytes == 0 {
            return Err(ConfigError::Validation(
                "max_record_bytes must be greater than 0".to_string(),
            ));
        }

        if self.max_request_bytes < self.max_record_bytes {
            return Err(ConfigError::Validation(
                "max_request_bytes must be greater than or equal to max_record_bytes".to_string(),
            ));
        }

        Ok(())
    }
}

/// Optional file configuration schema.
#[derive(Debug, Default, Deserialize)]
pub struct ConfigFile {
    pub listen_addr: Option<SocketAddr>,
    pub public_url: Option<String>,
    pub database_url: Option<String>,
    pub log_level: Option<String>,
    pub log_format: Option<String>,
    pub registration: Option<RegistrationMode>,
    pub access_token_ttl_secs: Option<u64>,
    pub refresh_token_ttl_secs: Option<u64>,
    pub max_request_bytes: Option<usize>,
    pub max_record_bytes: Option<usize>,
    pub collab_enabled: Option<bool>,
    pub metrics_enabled: Option<bool>,
    pub trusted_proxies: Option<Vec<IpAddr>>,
    pub allowed_origins: Option<Vec<String>>,
    pub dev_mode: Option<bool>,
}

impl ConfigFile {
    pub fn load_from_file(path: &Path) -> Result<Self, ConfigError> {
        let content = fs::read_to_string(path).map_err(|e| ConfigError::Io {
            path: path.to_path_buf(),
            source: e,
        })?;
        toml::from_str(&content).map_err(|e| ConfigError::Toml {
            path: path.to_path_buf(),
            source: e,
        })
    }
}

/// Command-line arguments.
#[derive(Debug, Parser)]
#[command(
    name = "shellumi-server",
    about = "Self-hosted, encrypted synchronization server for Shellumi",
    version
)]
pub struct CliArgs {
    /// Path to TOML configuration file
    #[arg(short, long, env = "SHELLUMI_SERVER_CONFIG")]
    pub config: Option<PathBuf>,

    /// Listening address and port (e.g. 127.0.0.1:8080)
    #[arg(long, env = "SHELLUMI_SERVER_LISTEN_ADDR")]
    pub listen_addr: Option<SocketAddr>,

    /// Canonical public URL (e.g. https://shellumi.example.com)
    #[arg(long, env = "SHELLUMI_SERVER_PUBLIC_URL")]
    pub public_url: Option<String>,

    /// PostgreSQL database connection URL
    #[arg(long, env = "SHELLUMI_SERVER_DATABASE_URL")]
    pub database_url: Option<String>,

    /// Path to file containing the database connection URL
    #[arg(long, env = "SHELLUMI_SERVER_DATABASE_URL_FILE")]
    pub database_url_file: Option<PathBuf>,

    /// Log level (trace, debug, info, warn, error)
    #[arg(long, env = "SHELLUMI_SERVER_LOG_LEVEL")]
    pub log_level: Option<String>,

    /// Log output format (json, pretty)
    #[arg(long, env = "SHELLUMI_SERVER_LOG_FORMAT")]
    pub log_format: Option<String>,

    /// Registration policy (invite_only, closed)
    #[arg(long, env = "SHELLUMI_SERVER_REGISTRATION")]
    pub registration: Option<RegistrationMode>,

    /// Bearer access token lifetime in seconds
    #[arg(long, env = "SHELLUMI_SERVER_ACCESS_TOKEN_TTL")]
    pub access_token_ttl: Option<u64>,

    /// Refresh token lifetime in seconds
    #[arg(long, env = "SHELLUMI_SERVER_REFRESH_TOKEN_TTL")]
    pub refresh_token_ttl: Option<u64>,

    /// Maximum request body size in bytes
    #[arg(long, env = "SHELLUMI_SERVER_MAX_REQUEST_BYTES")]
    pub max_request_bytes: Option<usize>,

    /// Maximum record size in bytes
    #[arg(long, env = "SHELLUMI_SERVER_MAX_RECORD_BYTES")]
    pub max_record_bytes: Option<usize>,

    /// Enable optional real-time terminal collaboration WSS relay
    #[arg(long, env = "SHELLUMI_SERVER_COLLAB_ENABLED")]
    pub collab_enabled: Option<bool>,

    /// Enable metrics endpoint
    #[arg(long, env = "SHELLUMI_SERVER_METRICS_ENABLED")]
    pub metrics_enabled: Option<bool>,

    /// Developer mode bypasses certain non-loopback security checks (for tests only)
    #[arg(long, env = "SHELLUMI_SERVER_DEV_MODE")]
    pub dev_mode: Option<bool>,
}

impl ServerConfig {
    /// Loads configuration by combining CLI arguments, environment, config file, and defaults.
    pub fn load(cli: &CliArgs) -> Result<Self, ConfigError> {
        let file_cfg = if let Some(path) = &cli.config {
            ConfigFile::load_from_file(path)?
        } else {
            ConfigFile::default()
        };

        let defaults = ServerConfig::default();

        let database_url = cli
            .database_url
            .clone()
            .or_else(|| {
                cli.database_url_file
                    .as_ref()
                    .and_then(|p| fs::read_to_string(p).map(|s| s.trim().to_string()).ok())
            })
            .or(file_cfg.database_url);

        let config = ServerConfig {
            listen_addr: cli
                .listen_addr
                .or(file_cfg.listen_addr)
                .unwrap_or(defaults.listen_addr),
            public_url: cli
                .public_url
                .clone()
                .or(file_cfg.public_url)
                .unwrap_or(defaults.public_url),
            database_url,
            log_level: cli
                .log_level
                .clone()
                .or(file_cfg.log_level)
                .unwrap_or(defaults.log_level),
            log_format: cli
                .log_format
                .clone()
                .or(file_cfg.log_format)
                .unwrap_or(defaults.log_format),
            registration: cli
                .registration
                .or(file_cfg.registration)
                .unwrap_or(defaults.registration),
            access_token_ttl_secs: cli
                .access_token_ttl
                .or(file_cfg.access_token_ttl_secs)
                .unwrap_or(defaults.access_token_ttl_secs),
            refresh_token_ttl_secs: cli
                .refresh_token_ttl
                .or(file_cfg.refresh_token_ttl_secs)
                .unwrap_or(defaults.refresh_token_ttl_secs),
            max_request_bytes: cli
                .max_request_bytes
                .or(file_cfg.max_request_bytes)
                .unwrap_or(defaults.max_request_bytes),
            max_record_bytes: cli
                .max_record_bytes
                .or(file_cfg.max_record_bytes)
                .unwrap_or(defaults.max_record_bytes),
            collab_enabled: cli
                .collab_enabled
                .or(file_cfg.collab_enabled)
                .unwrap_or(defaults.collab_enabled),
            metrics_enabled: cli
                .metrics_enabled
                .or(file_cfg.metrics_enabled)
                .unwrap_or(defaults.metrics_enabled),
            trusted_proxies: file_cfg.trusted_proxies.unwrap_or(defaults.trusted_proxies),
            allowed_origins: file_cfg.allowed_origins.unwrap_or(defaults.allowed_origins),
            dev_mode: cli
                .dev_mode
                .or(file_cfg.dev_mode)
                .unwrap_or(defaults.dev_mode),
        };

        config.validate()?;
        Ok(config)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config_validates_successfully() {
        let config = ServerConfig::default();
        assert!(config.validate().is_ok());
        assert_eq!(config.listen_addr.to_string(), "127.0.0.1:8080");
        assert_eq!(config.registration, RegistrationMode::InviteOnly);
        assert_eq!(config.max_request_bytes, 10 * 1024 * 1024);
        assert_eq!(config.max_record_bytes, 1024 * 1024);
    }

    #[test]
    fn test_rejects_unsafe_non_loopback_without_https() {
        let config = ServerConfig {
            listen_addr: "0.0.0.0:8080".parse().unwrap(),
            public_url: "http://0.0.0.0:8080".to_string(),
            dev_mode: false,
            trusted_proxies: vec![],
            ..Default::default()
        };

        let err = config.validate().unwrap_err();
        match err {
            ConfigError::Validation(msg) => {
                assert!(msg.contains("non-loopback"));
            }
            _ => panic!("unexpected error type"),
        }
    }

    #[test]
    fn test_allows_non_loopback_with_https() {
        let config = ServerConfig {
            listen_addr: "0.0.0.0:8443".parse().unwrap(),
            public_url: "https://shellumi.example.com".to_string(),
            ..Default::default()
        };
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_allows_non_loopback_with_trusted_proxies() {
        let config = ServerConfig {
            listen_addr: "0.0.0.0:8080".parse().unwrap(),
            public_url: "http://internal-service:8080".to_string(),
            trusted_proxies: vec!["10.0.0.1".parse().unwrap()],
            ..Default::default()
        };
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_rejects_invalid_token_ttls() {
        let config = ServerConfig {
            access_token_ttl_secs: 0,
            ..Default::default()
        };
        assert!(config.validate().is_err());

        let config_inverted = ServerConfig {
            access_token_ttl_secs: 1000,
            refresh_token_ttl_secs: 500,
            ..Default::default()
        };
        assert!(config_inverted.validate().is_err());
    }

    #[test]
    fn test_rejects_record_size_greater_than_request_size() {
        let config = ServerConfig {
            max_request_bytes: 100,
            max_record_bytes: 200,
            ..Default::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_cli_overrides_file_and_defaults() {
        let cli = CliArgs {
            config: None,
            listen_addr: Some("127.0.0.1:9090".parse().unwrap()),
            public_url: Some("http://127.0.0.1:9090".to_string()),
            database_url: None,
            database_url_file: None,
            log_level: Some("debug".to_string()),
            log_format: Some("pretty".to_string()),
            registration: Some(RegistrationMode::Closed),
            access_token_ttl: Some(300),
            refresh_token_ttl: Some(600),
            max_request_bytes: Some(5_000_000),
            max_record_bytes: Some(500_000),
            collab_enabled: Some(true),
            metrics_enabled: Some(true),
            dev_mode: Some(false),
        };

        let config = ServerConfig::load(&cli).unwrap();
        assert_eq!(config.listen_addr.port(), 9090);
        assert_eq!(config.log_level, "debug");
        assert_eq!(config.log_format, "pretty");
        assert_eq!(config.registration, RegistrationMode::Closed);
        assert_eq!(config.access_token_ttl_secs, 300);
        assert_eq!(config.refresh_token_ttl_secs, 600);
        assert!(config.collab_enabled);
        assert!(config.metrics_enabled);
    }
}
