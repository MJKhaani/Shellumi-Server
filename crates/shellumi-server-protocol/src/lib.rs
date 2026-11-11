//! Protocol definitions, DTOs, versioning, and wire formats for Shellumi Server.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Current wire protocol version.
pub const CURRENT_PROTOCOL_VERSION: u32 = 1;

/// Minimum supported wire protocol version.
pub const MIN_PROTOCOL_VERSION: u32 = 1;

/// Health response payload for `/health/live` and `/health/ready`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HealthResponse {
    pub status: String,
    pub service: String,
    pub version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<String>,
}

/// Server capabilities response payload for `/api/v1/capabilities`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilitiesResponse {
    pub server_version: String,
    pub protocol_version: u32,
    pub min_protocol_version: u32,
    pub supported_features: Vec<String>,
    pub supported_e2ee_suites: Vec<String>,
    pub limits: ServerLimits,
}

/// Bounded limits advertised by the server.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServerLimits {
    pub max_request_bytes: usize,
    pub max_record_bytes: usize,
    pub max_mutations_per_commit: usize,
}

/// Standard machine-readable error response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ErrorResponse {
    pub error_code: String,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
}

// ---------------------------------------------------------------------------
// Authentication & Bootstrap DTOs
// ---------------------------------------------------------------------------

/// Request payload for one-time first-run bootstrap (`POST /api/v1/bootstrap`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BootstrapRequest {
    pub admin_username: String,
    pub admin_email: String,
    pub admin_password: String,
    pub org_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bootstrap_token: Option<String>,
}

/// Response payload for successful bootstrap.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BootstrapResponse {
    pub org_id: Uuid,
    pub user_id: Uuid,
    pub username: String,
    pub email: String,
    pub access_token: String,
    pub refresh_token: String,
    pub expires_in_secs: u64,
}

/// Request payload for user login (`POST /api/v1/auth/login`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LoginRequest {
    pub identifier: String,
    pub password: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_id: Option<Uuid>,
}

/// Response payload for successful login.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LoginResponse {
    pub user_id: Uuid,
    pub username: String,
    pub email: String,
    pub access_token: String,
    pub refresh_token: String,
    pub expires_in_secs: u64,
}

/// Request payload for token refresh (`POST /api/v1/auth/refresh`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RefreshTokenRequest {
    pub refresh_token: String,
}

/// Response payload for refreshed tokens.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RefreshTokenResponse {
    pub access_token: String,
    pub refresh_token: String,
    pub expires_in_secs: u64,
}

/// Request payload for logout (`POST /api/v1/auth/logout`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LogoutRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
}

/// Summary of an organization membership for user info.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UserOrgSummary {
    pub org_id: Uuid,
    pub org_name: String,
    pub role: String,
}

/// Response payload for current authenticated user (`GET /api/v1/me`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MeResponse {
    pub user_id: Uuid,
    pub username: String,
    pub email: String,
    pub organizations: Vec<UserOrgSummary>,
}

// ---------------------------------------------------------------------------
// Device Management DTOs
// ---------------------------------------------------------------------------

/// Request payload for registering a new client device (`POST /api/v1/devices`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegisterDeviceRequest {
    pub device_name: String,
    pub signing_public_key: String,
    pub agreement_public_key: String,
}

/// Device representation returned by device management endpoints.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceResponse {
    pub device_id: Uuid,
    pub user_id: Uuid,
    pub device_name: String,
    pub signing_public_key: String,
    pub agreement_public_key: String,
    pub created_at: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_seen_at: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revoked_at: Option<i64>,
}
