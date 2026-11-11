//! Protocol definitions, DTOs, versioning, and wire formats for Shellumi Server.

use serde::{Deserialize, Serialize};

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
