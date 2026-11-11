//! Core domain logic, configuration models, authorization roles, and domain errors.

use serde::{Deserialize, Serialize};
use std::fmt;
use thiserror::Error;
use uuid::Uuid;

#[derive(Debug, Error)]
pub enum DomainError {
    #[error("Configuration error: {0}")]
    Configuration(String),

    #[error("Authentication required")]
    Unauthenticated,

    #[error("Invalid credentials")]
    InvalidCredentials,

    #[error("Invalid token: {0}")]
    InvalidToken(String),

    #[error("Token expired")]
    TokenExpired,

    #[error("Token reuse detected")]
    TokenReuseDetected,

    #[error("Bootstrap has already been consumed")]
    BootstrapAlreadyConsumed,

    #[error("Invalid bootstrap token")]
    InvalidBootstrapToken,

    #[error("Device is revoked")]
    DeviceRevoked,

    #[error("Device not found")]
    DeviceNotFound,

    #[error("Invalid public key: {0}")]
    InvalidPublicKey(String),

    #[error("Permission denied: {0}")]
    PermissionDenied(String),

    #[error("Resource not found")]
    NotFound,

    #[error("Conflict: {0}")]
    Conflict(String),

    #[error("Payload too large: limit {limit} bytes, actual {actual} bytes")]
    PayloadTooLarge { limit: usize, actual: usize },

    #[error("Invalid input: {0}")]
    InvalidInput(String),

    #[error("Internal server error: {0}")]
    Internal(String),
}

/// Organization role for RBAC.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OrgRole {
    Owner,
    Admin,
    Member,
}

impl fmt::Display for OrgRole {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Owner => write!(f, "owner"),
            Self::Admin => write!(f, "admin"),
            Self::Member => write!(f, "member"),
        }
    }
}

/// User domain entity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct User {
    pub id: Uuid,
    pub username: String,
    pub email: String,
    pub password_hash: String,
    pub created_at: i64,
    pub updated_at: i64,
    pub is_active: bool,
}

/// Organization / Tenant domain entity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Organization {
    pub id: Uuid,
    pub name: String,
    pub created_at: i64,
}

/// Organization membership mapping.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OrgMembership {
    pub org_id: Uuid,
    pub user_id: Uuid,
    pub role: OrgRole,
    pub created_at: i64,
}

/// Registered client device.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Device {
    pub id: Uuid,
    pub user_id: Uuid,
    pub device_name: String,
    pub signing_public_key: String,
    pub agreement_public_key: String,
    pub created_at: i64,
    pub last_seen_at: Option<i64>,
    pub revoked_at: Option<i64>,
}

/// User session / refresh token record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Session {
    pub id: Uuid,
    pub user_id: Uuid,
    pub device_id: Option<Uuid>,
    pub refresh_token_hash: String,
    pub expires_at: i64,
    pub created_at: i64,
    pub revoked_at: Option<i64>,
}

/// Server settings and bootstrap state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServerSettings {
    pub id: Uuid,
    pub install_id: Uuid,
    pub schema_version: u32,
    pub bootstrap_consumed: bool,
    pub bootstrap_token_hash: Option<String>,
    pub created_at: i64,
    pub updated_at: i64,
}
