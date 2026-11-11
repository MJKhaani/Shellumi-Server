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

    #[error("Revision conflict for object '{object_id}': expected revision {expected}, current revision {actual}")]
    RevisionConflict {
        object_id: String,
        expected: u64,
        actual: u64,
    },

    #[error(
        "Idempotency conflict for key '{key}': request payload does not match previous commit"
    )]
    IdempotencyConflict { key: String },

    #[error("Invalid signature: {0}")]
    InvalidSignature(String),

    #[error("Vault not found: {0}")]
    VaultNotFound(Uuid),

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

// ---------------------------------------------------------------------------
// Vault & Sync Domain Entities
// ---------------------------------------------------------------------------

/// Role within a vault.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VaultRole {
    Viewer = 0,
    Editor = 1,
    Administrator = 2,
    Owner = 3,
}

impl VaultRole {
    pub fn can_write(&self) -> bool {
        matches!(self, Self::Owner | Self::Administrator | Self::Editor)
    }

    pub fn can_admin(&self) -> bool {
        matches!(self, Self::Owner | Self::Administrator)
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Viewer => "viewer",
            Self::Editor => "editor",
            Self::Administrator => "administrator",
            Self::Owner => "owner",
        }
    }
}

impl fmt::Display for VaultRole {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Vault type: personal or shared team vault.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VaultType {
    Personal,
    Team,
}

impl VaultType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Personal => "personal",
            Self::Team => "team",
        }
    }
}

/// Vault domain entity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Vault {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub owner_id: Uuid,
    pub vault_type: VaultType,
    pub encrypted_name: Option<String>,
    pub active_key_epoch: u32,
    pub server_sequence: u64,
    pub created_at: i64,
    pub updated_at: i64,
    pub deleted_at: Option<i64>,
}

/// Membership of a user in a vault.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultMember {
    pub vault_id: Uuid,
    pub user_id: Uuid,
    pub role: VaultRole,
    pub joined_at: i64,
}

/// Authoritative current state of a synced entity record in a vault.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Record {
    pub vault_id: Uuid,
    pub object_id: String,
    pub entity_type: String,
    pub current_revision: u64,
    pub key_epoch: u32,
    pub author_device_id: Uuid,
    pub deleted: bool,
    pub encrypted_envelope: Option<String>,
    pub ciphertext_digest: String,
    pub last_server_sequence: u64,
    pub updated_at: i64,
}

/// Append-only entry in a vault's monotonic change feed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChangeLogEntry {
    pub vault_id: Uuid,
    pub sequence: u64,
    pub object_id: String,
    pub entity_type: String,
    pub revision: u64,
    pub deleted: bool,
    pub author_device_id: Uuid,
    pub encrypted_envelope: Option<String>,
    pub ciphertext_digest: String,
    pub created_at: i64,
}

/// Mutation idempotency record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MutationIdempotency {
    pub vault_id: Uuid,
    pub idempotency_key: String,
    pub device_id: Uuid,
    pub request_hash: String,
    pub response_payload: String,
    pub created_at: i64,
}
