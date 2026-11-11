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

// ---------------------------------------------------------------------------
// Vault & Synchronization DTOs
// ---------------------------------------------------------------------------

/// Client-sealed authenticated ciphertext envelope.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedEnvelope {
    pub salt: String,
    pub nonce: String,
    pub ciphertext: String,
    pub associated_data: String,
    pub kdf_iterations: u32,
}

fn default_vault_type() -> String {
    "personal".to_string()
}

/// Request payload for creating a new vault (`POST /api/v1/vaults`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CreateVaultRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub encrypted_name: Option<String>,
    #[serde(default = "default_vault_type")]
    pub vault_type: String,
}

/// Request payload for updating vault metadata (`PATCH /api/v1/vaults/{id}`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpdateVaultRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub encrypted_name: Option<String>,
}

/// Representation of a vault returned by API endpoints.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultResponse {
    pub vault_id: Uuid,
    pub tenant_id: Uuid,
    pub owner_id: Uuid,
    pub vault_type: String,
    pub encrypted_name: Option<String>,
    pub active_key_epoch: u32,
    pub server_sequence: u64,
    pub role: String,
    pub created_at: i64,
    pub updated_at: i64,
}

/// List of vaults accessible to the authenticated user (`GET /api/v1/vaults`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultListResponse {
    pub vaults: Vec<VaultResponse>,
}

/// A single mutation item in a commit batch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MutationItem {
    pub object_id: String,
    pub entity_type: String,
    pub expected_revision: u64,
    pub deleted: bool,
    pub key_epoch: u32,
    pub device_counter: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub encrypted_envelope: Option<EncryptedEnvelope>,
    pub device_signature: String,
}

/// Batch commit request (`POST /api/v1/vaults/{id}/commits`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommitBatchRequest {
    pub protocol_version: u32,
    pub vault_id: Uuid,
    pub idempotency_key: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub base_cursor: Option<String>,
    pub mutations: Vec<MutationItem>,
}

/// Acknowledged mutation result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MutationAck {
    pub object_id: String,
    pub assigned_revision: u64,
    pub server_sequence: u64,
    pub deleted: bool,
}

/// Response payload for a committed mutation batch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommitBatchResponse {
    pub vault_id: Uuid,
    pub commit_sequence: u64,
    pub next_cursor: String,
    pub applied: Vec<MutationAck>,
}

/// An entry in a change feed or snapshot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyncChangeItem {
    pub sequence: u64,
    pub object_id: String,
    pub entity_type: String,
    pub revision: u64,
    pub deleted: bool,
    pub author_device_id: Uuid,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub encrypted_envelope: Option<EncryptedEnvelope>,
    pub updated_at: i64,
}

/// Paginated delta feed response (`GET /api/v1/vaults/{id}/changes`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChangeFeedResponse {
    pub vault_id: Uuid,
    pub latest_sequence: u64,
    pub next_cursor: String,
    pub has_more: bool,
    pub records: Vec<SyncChangeItem>,
}

/// Full vault recovery snapshot (`GET /api/v1/vaults/{id}/snapshots/{revision}`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotResponse {
    pub vault_id: Uuid,
    pub server_sequence: u64,
    pub records: Vec<SyncChangeItem>,
}

// ---------------------------------------------------------------------------
// Team Collaboration, Invites, Key Envelopes & Audit DTOs
// ---------------------------------------------------------------------------

/// Representation of a vault member.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultMemberResponse {
    pub vault_id: Uuid,
    pub user_id: Uuid,
    pub username: String,
    pub role: String,
    pub joined_at: i64,
}

/// List of members in a vault (`GET /api/v1/vaults/{id}/members`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultMemberListResponse {
    pub members: Vec<VaultMemberResponse>,
}

/// Request to add or update a member's role (`POST /api/v1/vaults/{id}/members`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AddVaultMemberRequest {
    pub user_id: Uuid,
    pub role: String,
}

/// Request to create a scoped invitation (`POST /api/v1/vaults/{id}/invites`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CreateInviteRequest {
    pub role: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recipient_email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ttl_secs: Option<u64>,
}

/// Representation of an invitation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InviteResponse {
    pub invite_id: Uuid,
    pub vault_id: Uuid,
    pub role: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub invite_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recipient_email: Option<String>,
    pub expires_at: i64,
    pub created_at: i64,
}

/// List of invitations (`GET /api/v1/vaults/{id}/invites`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InviteListResponse {
    pub invites: Vec<InviteResponse>,
}

/// Request to accept an invitation (`POST /api/v1/invites/accept`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AcceptInviteRequest {
    pub invite_token: String,
}

/// Response payload for accepted invitation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AcceptInviteResponse {
    pub vault_id: Uuid,
    pub role: String,
}

/// Item representing a wrapped DEK for a recipient device.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyEnvelopeItem {
    pub recipient_device_id: Uuid,
    pub wrapped_dek: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_agreement_ephemeral_pk: Option<String>,
}

/// Request to publish wrapped key envelopes (`POST /api/v1/vaults/{id}/keys/envelopes`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublishKeyEnvelopesRequest {
    pub epoch: u32,
    pub envelopes: Vec<KeyEnvelopeItem>,
}

/// Representation of a stored key envelope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyEnvelopeResponse {
    pub vault_id: Uuid,
    pub epoch: u32,
    pub recipient_device_id: Uuid,
    pub sender_device_id: Uuid,
    pub wrapped_dek: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_agreement_ephemeral_pk: Option<String>,
    pub created_at: i64,
}

/// List of key envelopes for the calling device (`GET /api/v1/vaults/{id}/keys/envelopes`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyEnvelopeListResponse {
    pub envelopes: Vec<KeyEnvelopeResponse>,
}

/// Request to rotate key epoch (`POST /api/v1/vaults/{id}/keys/epochs`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RotateKeyEpochRequest {
    pub new_epoch: u32,
    pub envelopes: Vec<KeyEnvelopeItem>,
}

/// Response for rotated key epoch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RotateKeyEpochResponse {
    pub vault_id: Uuid,
    pub active_key_epoch: u32,
    pub enrolled_envelopes: usize,
}

/// Representation of an audit event (`GET /api/v1/vaults/{id}/audit`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditEventResponse {
    pub id: i64,
    pub vault_id: Uuid,
    pub actor_user_id: Uuid,
    pub actor_device_id: Option<Uuid>,
    pub action: String,
    pub target_type: String,
    pub target_id: String,
    pub details: Option<String>,
    pub predecessor_hash: String,
    pub event_hash: String,
    pub created_at: i64,
}

/// List of audit events.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditLogResponse {
    pub vault_id: Uuid,
    pub events: Vec<AuditEventResponse>,
}
