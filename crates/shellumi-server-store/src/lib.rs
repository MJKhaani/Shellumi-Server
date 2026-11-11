//! Storage interfaces, traits, and implementations for Shellumi Server.

use async_trait::async_trait;
use shellumi_server_domain::{
    ChangeLogEntry, Device, DomainError, MutationIdempotency, OrgMembership, OrgRole, Organization,
    Record, ServerSettings, Session, User, Vault, VaultMember, VaultRole,
};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;

#[async_trait]
pub trait SettingsRepository: Send + Sync {
    async fn get_settings(&self) -> Result<ServerSettings, DomainError>;
    async fn update_settings(&self, settings: &ServerSettings) -> Result<(), DomainError>;
    async fn mark_bootstrap_consumed(
        &self,
        expected_token_hash: Option<&str>,
    ) -> Result<(), DomainError>;
}

#[async_trait]
pub trait UserRepository: Send + Sync {
    async fn create_user(&self, user: &User) -> Result<(), DomainError>;
    async fn find_user_by_id(&self, id: Uuid) -> Result<Option<User>, DomainError>;
    async fn find_by_identifier(&self, identifier: &str) -> Result<Option<User>, DomainError>;
    async fn list_orgs_for_user(
        &self,
        user_id: Uuid,
    ) -> Result<Vec<(Organization, OrgRole)>, DomainError>;
}

#[async_trait]
pub trait OrgRepository: Send + Sync {
    async fn create_org(&self, org: &Organization, owner_id: Uuid) -> Result<(), DomainError>;
    async fn find_org_by_id(&self, id: Uuid) -> Result<Option<Organization>, DomainError>;
    async fn add_member(
        &self,
        org_id: Uuid,
        user_id: Uuid,
        role: OrgRole,
    ) -> Result<(), DomainError>;
    async fn get_member_role(
        &self,
        org_id: Uuid,
        user_id: Uuid,
    ) -> Result<Option<OrgRole>, DomainError>;
}

#[async_trait]
pub trait DeviceRepository: Send + Sync {
    async fn create_device(&self, device: &Device) -> Result<(), DomainError>;
    async fn find_device_by_id(&self, id: Uuid) -> Result<Option<Device>, DomainError>;
    async fn list_for_user(&self, user_id: Uuid) -> Result<Vec<Device>, DomainError>;
    async fn revoke_device(&self, device_id: Uuid, user_id: Uuid) -> Result<(), DomainError>;
    async fn update_last_seen(&self, device_id: Uuid, timestamp: i64) -> Result<(), DomainError>;
}

#[async_trait]
pub trait SessionRepository: Send + Sync {
    async fn create_session(&self, session: &Session) -> Result<(), DomainError>;
    async fn find_active_by_token_hash(&self, hash: &str) -> Result<Option<Session>, DomainError>;
    async fn rotate_refresh_token(
        &self,
        old_hash: &str,
        new_session: &mut Session,
    ) -> Result<Uuid, DomainError>;
    async fn revoke_session(&self, session_id: Uuid) -> Result<(), DomainError>;
    async fn revoke_all_for_device(&self, device_id: Uuid) -> Result<(), DomainError>;
    async fn revoke_all_for_user(&self, user_id: Uuid) -> Result<(), DomainError>;
}

#[async_trait]
pub trait VaultRepository: Send + Sync {
    async fn create_vault(
        &self,
        vault: &Vault,
        initial_member: &VaultMember,
    ) -> Result<(), DomainError>;
    async fn find_vault_by_id(&self, vault_id: Uuid) -> Result<Option<Vault>, DomainError>;
    async fn list_vaults_for_user(
        &self,
        user_id: Uuid,
    ) -> Result<Vec<(Vault, VaultRole)>, DomainError>;
    async fn update_vault_metadata(
        &self,
        vault_id: Uuid,
        encrypted_name: Option<String>,
    ) -> Result<(), DomainError>;
    async fn delete_vault(&self, vault_id: Uuid) -> Result<(), DomainError>;
    async fn get_vault_member_role(
        &self,
        vault_id: Uuid,
        user_id: Uuid,
    ) -> Result<Option<VaultRole>, DomainError>;
    async fn add_vault_member(&self, member: &VaultMember) -> Result<(), DomainError>;
    async fn list_vault_members(&self, vault_id: Uuid) -> Result<Vec<VaultMember>, DomainError>;
}

#[async_trait]
pub trait SyncRepository: Send + Sync {
    async fn find_record(
        &self,
        vault_id: Uuid,
        object_id: &str,
    ) -> Result<Option<Record>, DomainError>;
    async fn find_idempotency(
        &self,
        vault_id: Uuid,
        idempotency_key: &str,
    ) -> Result<Option<MutationIdempotency>, DomainError>;
    #[allow(clippy::too_many_arguments)]
    async fn apply_commit_batch(
        &self,
        vault_id: Uuid,
        device_id: Uuid,
        idempotency_key: &str,
        request_hash: &str,
        response_payload: &str,
        records_to_upsert: &[Record],
        change_log_entries: &[ChangeLogEntry],
        new_server_sequence: u64,
    ) -> Result<(), DomainError>;
    async fn get_changes(
        &self,
        vault_id: Uuid,
        since_sequence: u64,
        limit: usize,
    ) -> Result<Vec<ChangeLogEntry>, DomainError>;
    async fn get_snapshot_records(&self, vault_id: Uuid) -> Result<Vec<Record>, DomainError>;
}

pub trait Store:
    SettingsRepository
    + UserRepository
    + OrgRepository
    + DeviceRepository
    + SessionRepository
    + VaultRepository
    + SyncRepository
{
}

// ---------------------------------------------------------------------------
// Thread-safe In-Memory Store for Testing and Isolation
// ---------------------------------------------------------------------------

#[derive(Debug, Default)]
struct MemoryState {
    settings: Option<ServerSettings>,
    users: HashMap<Uuid, User>,
    users_by_username: HashMap<String, Uuid>,
    users_by_email: HashMap<String, Uuid>,
    organizations: HashMap<Uuid, Organization>,
    memberships: Vec<OrgMembership>,
    devices: HashMap<Uuid, Device>,
    sessions: HashMap<Uuid, Session>,
    sessions_by_hash: HashMap<String, Uuid>,
    vaults: HashMap<Uuid, Vault>,
    vault_members: Vec<VaultMember>,
    records: HashMap<(Uuid, String), Record>,
    change_log: Vec<ChangeLogEntry>,
    idempotency: HashMap<(Uuid, String), MutationIdempotency>,
}

#[derive(Debug, Clone, Default)]
pub struct InMemoryStore {
    state: Arc<RwLock<MemoryState>>,
}

impl InMemoryStore {
    pub fn new() -> Self {
        Self {
            state: Arc::new(RwLock::new(MemoryState::default())),
        }
    }

    pub fn with_settings(settings: ServerSettings) -> Self {
        let memory = MemoryState {
            settings: Some(settings),
            ..Default::default()
        };
        Self {
            state: Arc::new(RwLock::new(memory)),
        }
    }
}

impl Store for InMemoryStore {}

#[async_trait]
impl SettingsRepository for InMemoryStore {
    async fn get_settings(&self) -> Result<ServerSettings, DomainError> {
        let lock = self.state.read().await;
        if let Some(s) = &lock.settings {
            Ok(s.clone())
        } else {
            // Default initial settings if not explicitly seeded
            let now = chrono::Utc::now().timestamp();
            Ok(ServerSettings {
                id: Uuid::new_v4(),
                install_id: Uuid::new_v4(),
                schema_version: 1,
                bootstrap_consumed: false,
                bootstrap_token_hash: None,
                created_at: now,
                updated_at: now,
            })
        }
    }

    async fn update_settings(&self, settings: &ServerSettings) -> Result<(), DomainError> {
        let mut lock = self.state.write().await;
        lock.settings = Some(settings.clone());
        Ok(())
    }

    async fn mark_bootstrap_consumed(
        &self,
        expected_token_hash: Option<&str>,
    ) -> Result<(), DomainError> {
        let mut lock = self.state.write().await;
        let mut settings = if let Some(s) = lock.settings.clone() {
            s
        } else {
            let now = chrono::Utc::now().timestamp();
            ServerSettings {
                id: Uuid::new_v4(),
                install_id: Uuid::new_v4(),
                schema_version: 1,
                bootstrap_consumed: false,
                bootstrap_token_hash: None,
                created_at: now,
                updated_at: now,
            }
        };

        if settings.bootstrap_consumed {
            return Err(DomainError::BootstrapAlreadyConsumed);
        }

        if let Some(expected_hash) = &settings.bootstrap_token_hash {
            match expected_token_hash {
                Some(provided) if provided == expected_hash => {}
                _ => return Err(DomainError::InvalidBootstrapToken),
            }
        }

        settings.bootstrap_consumed = true;
        settings.updated_at = chrono::Utc::now().timestamp();
        lock.settings = Some(settings);
        Ok(())
    }
}

#[async_trait]
impl UserRepository for InMemoryStore {
    async fn create_user(&self, user: &User) -> Result<(), DomainError> {
        let mut lock = self.state.write().await;
        let lower_username = user.username.to_lowercase();
        let lower_email = user.email.to_lowercase();

        if lock.users_by_username.contains_key(&lower_username) {
            return Err(DomainError::Conflict(format!(
                "Username '{}' is already registered",
                user.username
            )));
        }

        if lock.users_by_email.contains_key(&lower_email) {
            return Err(DomainError::Conflict(format!(
                "Email '{}' is already registered",
                user.email
            )));
        }

        lock.users_by_username.insert(lower_username, user.id);
        lock.users_by_email.insert(lower_email, user.id);
        lock.users.insert(user.id, user.clone());
        Ok(())
    }

    async fn find_user_by_id(&self, id: Uuid) -> Result<Option<User>, DomainError> {
        let lock = self.state.read().await;
        Ok(lock.users.get(&id).cloned())
    }

    async fn find_by_identifier(&self, identifier: &str) -> Result<Option<User>, DomainError> {
        let lock = self.state.read().await;
        let lower = identifier.trim().to_lowercase();

        if let Some(&user_id) = lock.users_by_username.get(&lower) {
            return Ok(lock.users.get(&user_id).cloned());
        }

        if let Some(&user_id) = lock.users_by_email.get(&lower) {
            return Ok(lock.users.get(&user_id).cloned());
        }

        Ok(None)
    }

    async fn list_orgs_for_user(
        &self,
        user_id: Uuid,
    ) -> Result<Vec<(Organization, OrgRole)>, DomainError> {
        let lock = self.state.read().await;
        let mut orgs = Vec::new();

        for m in &lock.memberships {
            if m.user_id == user_id {
                if let Some(org) = lock.organizations.get(&m.org_id) {
                    orgs.push((org.clone(), m.role));
                }
            }
        }

        Ok(orgs)
    }
}

#[async_trait]
impl OrgRepository for InMemoryStore {
    async fn create_org(&self, org: &Organization, owner_id: Uuid) -> Result<(), DomainError> {
        let mut lock = self.state.write().await;
        lock.organizations.insert(org.id, org.clone());
        lock.memberships.push(OrgMembership {
            org_id: org.id,
            user_id: owner_id,
            role: OrgRole::Owner,
            created_at: org.created_at,
        });
        Ok(())
    }

    async fn find_org_by_id(&self, id: Uuid) -> Result<Option<Organization>, DomainError> {
        let lock = self.state.read().await;
        Ok(lock.organizations.get(&id).cloned())
    }

    async fn add_member(
        &self,
        org_id: Uuid,
        user_id: Uuid,
        role: OrgRole,
    ) -> Result<(), DomainError> {
        let mut lock = self.state.write().await;
        if !lock.organizations.contains_key(&org_id) {
            return Err(DomainError::NotFound);
        }

        // Remove existing membership if present
        lock.memberships
            .retain(|m| !(m.org_id == org_id && m.user_id == user_id));
        lock.memberships.push(OrgMembership {
            org_id,
            user_id,
            role,
            created_at: chrono::Utc::now().timestamp(),
        });
        Ok(())
    }

    async fn get_member_role(
        &self,
        org_id: Uuid,
        user_id: Uuid,
    ) -> Result<Option<OrgRole>, DomainError> {
        let lock = self.state.read().await;
        for m in &lock.memberships {
            if m.org_id == org_id && m.user_id == user_id {
                return Ok(Some(m.role));
            }
        }
        Ok(None)
    }
}

#[async_trait]
impl DeviceRepository for InMemoryStore {
    async fn create_device(&self, device: &Device) -> Result<(), DomainError> {
        let mut lock = self.state.write().await;

        // Check if device with same user and signing key exists
        for existing in lock.devices.values() {
            if existing.user_id == device.user_id
                && existing.signing_public_key == device.signing_public_key
                && existing.revoked_at.is_none()
            {
                return Err(DomainError::Conflict(
                    "A device with this signing public key is already registered".to_string(),
                ));
            }
        }

        lock.devices.insert(device.id, device.clone());
        Ok(())
    }

    async fn find_device_by_id(&self, id: Uuid) -> Result<Option<Device>, DomainError> {
        let lock = self.state.read().await;
        Ok(lock.devices.get(&id).cloned())
    }

    async fn list_for_user(&self, user_id: Uuid) -> Result<Vec<Device>, DomainError> {
        let lock = self.state.read().await;
        let devices = lock
            .devices
            .values()
            .filter(|d| d.user_id == user_id)
            .cloned()
            .collect();
        Ok(devices)
    }

    async fn revoke_device(&self, device_id: Uuid, user_id: Uuid) -> Result<(), DomainError> {
        let mut lock = self.state.write().await;
        let now = chrono::Utc::now().timestamp();

        let device = lock
            .devices
            .get_mut(&device_id)
            .ok_or(DomainError::DeviceNotFound)?;

        if device.user_id != user_id {
            return Err(DomainError::PermissionDenied(
                "Cannot revoke device belonging to another user".to_string(),
            ));
        }

        device.revoked_at = Some(now);

        // Also revoke all sessions tied to this device
        for session in lock.sessions.values_mut() {
            if session.device_id == Some(device_id) && session.revoked_at.is_none() {
                session.revoked_at = Some(now);
            }
        }

        Ok(())
    }

    async fn update_last_seen(&self, device_id: Uuid, timestamp: i64) -> Result<(), DomainError> {
        let mut lock = self.state.write().await;
        if let Some(dev) = lock.devices.get_mut(&device_id) {
            dev.last_seen_at = Some(timestamp);
        }
        Ok(())
    }
}

#[async_trait]
impl SessionRepository for InMemoryStore {
    async fn create_session(&self, session: &Session) -> Result<(), DomainError> {
        let mut lock = self.state.write().await;
        lock.sessions_by_hash
            .insert(session.refresh_token_hash.clone(), session.id);
        lock.sessions.insert(session.id, session.clone());
        Ok(())
    }

    async fn find_active_by_token_hash(&self, hash: &str) -> Result<Option<Session>, DomainError> {
        let lock = self.state.read().await;
        let now = chrono::Utc::now().timestamp();

        if let Some(&session_id) = lock.sessions_by_hash.get(hash) {
            if let Some(session) = lock.sessions.get(&session_id) {
                if session.revoked_at.is_none() && session.expires_at > now {
                    return Ok(Some(session.clone()));
                }
            }
        }
        Ok(None)
    }

    async fn rotate_refresh_token(
        &self,
        old_hash: &str,
        new_session: &mut Session,
    ) -> Result<Uuid, DomainError> {
        let mut lock = self.state.write().await;
        let now = chrono::Utc::now().timestamp();

        let old_session_id = lock
            .sessions_by_hash
            .get(old_hash)
            .copied()
            .ok_or(DomainError::Unauthenticated)?;

        let old_session = lock
            .sessions
            .get_mut(&old_session_id)
            .ok_or(DomainError::Unauthenticated)?;

        if old_session.revoked_at.is_some() || old_session.expires_at <= now {
            // Token reuse / expired token rotation detected! Revoke all sessions for this user for security
            let user_id = old_session.user_id;
            for s in lock.sessions.values_mut() {
                if s.user_id == user_id && s.revoked_at.is_none() {
                    s.revoked_at = Some(now);
                }
            }
            return Err(DomainError::TokenReuseDetected);
        }

        let user_id = old_session.user_id;
        let device_id = old_session.device_id;

        // Revoke the old session
        old_session.revoked_at = Some(now);

        // Populate user and device on new session and persist
        new_session.user_id = user_id;
        new_session.device_id = device_id;

        lock.sessions_by_hash
            .insert(new_session.refresh_token_hash.clone(), new_session.id);
        lock.sessions.insert(new_session.id, new_session.clone());

        Ok(user_id)
    }

    async fn revoke_session(&self, session_id: Uuid) -> Result<(), DomainError> {
        let mut lock = self.state.write().await;
        let now = chrono::Utc::now().timestamp();
        if let Some(s) = lock.sessions.get_mut(&session_id) {
            s.revoked_at = Some(now);
        }
        Ok(())
    }

    async fn revoke_all_for_device(&self, device_id: Uuid) -> Result<(), DomainError> {
        let mut lock = self.state.write().await;
        let now = chrono::Utc::now().timestamp();
        for s in lock.sessions.values_mut() {
            if s.device_id == Some(device_id) && s.revoked_at.is_none() {
                s.revoked_at = Some(now);
            }
        }
        Ok(())
    }

    async fn revoke_all_for_user(&self, user_id: Uuid) -> Result<(), DomainError> {
        let mut lock = self.state.write().await;
        let now = chrono::Utc::now().timestamp();
        for s in lock.sessions.values_mut() {
            if s.user_id == user_id && s.revoked_at.is_none() {
                s.revoked_at = Some(now);
            }
        }
        Ok(())
    }
}

#[async_trait]
impl VaultRepository for InMemoryStore {
    async fn create_vault(
        &self,
        vault: &Vault,
        initial_member: &VaultMember,
    ) -> Result<(), DomainError> {
        let mut lock = self.state.write().await;
        if lock.vaults.contains_key(&vault.id) {
            return Err(DomainError::Conflict(format!(
                "Vault with id '{}' already exists",
                vault.id
            )));
        }
        lock.vaults.insert(vault.id, vault.clone());
        lock.vault_members.push(initial_member.clone());
        Ok(())
    }

    async fn find_vault_by_id(&self, vault_id: Uuid) -> Result<Option<Vault>, DomainError> {
        let lock = self.state.read().await;
        Ok(lock.vaults.get(&vault_id).cloned())
    }

    async fn list_vaults_for_user(
        &self,
        user_id: Uuid,
    ) -> Result<Vec<(Vault, VaultRole)>, DomainError> {
        let lock = self.state.read().await;
        let mut results = Vec::new();
        for m in &lock.vault_members {
            if m.user_id == user_id {
                if let Some(vault) = lock.vaults.get(&m.vault_id) {
                    if vault.deleted_at.is_none() {
                        results.push((vault.clone(), m.role));
                    }
                }
            }
        }
        Ok(results)
    }

    async fn update_vault_metadata(
        &self,
        vault_id: Uuid,
        encrypted_name: Option<String>,
    ) -> Result<(), DomainError> {
        let mut lock = self.state.write().await;
        let vault = lock
            .vaults
            .get_mut(&vault_id)
            .ok_or(DomainError::VaultNotFound(vault_id))?;
        vault.encrypted_name = encrypted_name;
        vault.updated_at = chrono::Utc::now().timestamp();
        Ok(())
    }

    async fn delete_vault(&self, vault_id: Uuid) -> Result<(), DomainError> {
        let mut lock = self.state.write().await;
        let vault = lock
            .vaults
            .get_mut(&vault_id)
            .ok_or(DomainError::VaultNotFound(vault_id))?;
        vault.deleted_at = Some(chrono::Utc::now().timestamp());
        Ok(())
    }

    async fn get_vault_member_role(
        &self,
        vault_id: Uuid,
        user_id: Uuid,
    ) -> Result<Option<VaultRole>, DomainError> {
        let lock = self.state.read().await;
        for m in &lock.vault_members {
            if m.vault_id == vault_id && m.user_id == user_id {
                return Ok(Some(m.role));
            }
        }
        Ok(None)
    }

    async fn add_vault_member(&self, member: &VaultMember) -> Result<(), DomainError> {
        let mut lock = self.state.write().await;
        if let Some(existing) = lock
            .vault_members
            .iter_mut()
            .find(|m| m.vault_id == member.vault_id && m.user_id == member.user_id)
        {
            existing.role = member.role;
        } else {
            lock.vault_members.push(member.clone());
        }
        Ok(())
    }

    async fn list_vault_members(&self, vault_id: Uuid) -> Result<Vec<VaultMember>, DomainError> {
        let lock = self.state.read().await;
        let members = lock
            .vault_members
            .iter()
            .filter(|m| m.vault_id == vault_id)
            .cloned()
            .collect();
        Ok(members)
    }
}

#[async_trait]
impl SyncRepository for InMemoryStore {
    async fn find_record(
        &self,
        vault_id: Uuid,
        object_id: &str,
    ) -> Result<Option<Record>, DomainError> {
        let lock = self.state.read().await;
        Ok(lock
            .records
            .get(&(vault_id, object_id.to_string()))
            .cloned())
    }

    async fn find_idempotency(
        &self,
        vault_id: Uuid,
        idempotency_key: &str,
    ) -> Result<Option<MutationIdempotency>, DomainError> {
        let lock = self.state.read().await;
        Ok(lock
            .idempotency
            .get(&(vault_id, idempotency_key.to_string()))
            .cloned())
    }

    #[allow(clippy::too_many_arguments)]
    async fn apply_commit_batch(
        &self,
        vault_id: Uuid,
        device_id: Uuid,
        idempotency_key: &str,
        request_hash: &str,
        response_payload: &str,
        records_to_upsert: &[Record],
        change_log_entries: &[ChangeLogEntry],
        new_server_sequence: u64,
    ) -> Result<(), DomainError> {
        let mut lock = self.state.write().await;
        let now = chrono::Utc::now().timestamp();

        if let Some(vault) = lock.vaults.get_mut(&vault_id) {
            vault.server_sequence = new_server_sequence;
            vault.updated_at = now;
        }

        for record in records_to_upsert {
            lock.records
                .insert((vault_id, record.object_id.clone()), record.clone());
        }

        for entry in change_log_entries {
            lock.change_log.push(entry.clone());
        }

        let idem = MutationIdempotency {
            vault_id,
            idempotency_key: idempotency_key.to_string(),
            device_id,
            request_hash: request_hash.to_string(),
            response_payload: response_payload.to_string(),
            created_at: now,
        };
        lock.idempotency
            .insert((vault_id, idempotency_key.to_string()), idem);

        Ok(())
    }

    async fn get_changes(
        &self,
        vault_id: Uuid,
        since_sequence: u64,
        limit: usize,
    ) -> Result<Vec<ChangeLogEntry>, DomainError> {
        let lock = self.state.read().await;
        let mut matching: Vec<ChangeLogEntry> = lock
            .change_log
            .iter()
            .filter(|e| e.vault_id == vault_id && e.sequence > since_sequence)
            .cloned()
            .collect();

        matching.sort_by_key(|e| e.sequence);
        matching.truncate(limit);
        Ok(matching)
    }

    async fn get_snapshot_records(&self, vault_id: Uuid) -> Result<Vec<Record>, DomainError> {
        let lock = self.state.read().await;
        let records: Vec<Record> = lock
            .records
            .values()
            .filter(|r| r.vault_id == vault_id && !r.deleted)
            .cloned()
            .collect();
        Ok(records)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_in_memory_store_user_and_org_lifecycle() {
        let store = InMemoryStore::new();
        let now = chrono::Utc::now().timestamp();

        let user = User {
            id: Uuid::new_v4(),
            username: "alice".to_string(),
            email: "alice@example.com".to_string(),
            password_hash: "argon2-hash".to_string(),
            created_at: now,
            updated_at: now,
            is_active: true,
        };

        store.create_user(&user).await.unwrap();

        // Duplicate username rejected
        let dup_user = User {
            id: Uuid::new_v4(),
            username: "ALICE".to_string(),
            email: "other@example.com".to_string(),
            password_hash: "hash".to_string(),
            created_at: now,
            updated_at: now,
            is_active: true,
        };
        assert!(store.create_user(&dup_user).await.is_err());

        // Find by username case-insensitively
        let found = store.find_by_identifier("Alice").await.unwrap().unwrap();
        assert_eq!(found.id, user.id);

        // Find by email case-insensitively
        let found_email = store
            .find_by_identifier("alice@EXAMPLE.com")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(found_email.id, user.id);

        // Create organization
        let org = Organization {
            id: Uuid::new_v4(),
            name: "Acme Corp".to_string(),
            created_at: now,
        };
        store.create_org(&org, user.id).await.unwrap();

        let orgs = store.list_orgs_for_user(user.id).await.unwrap();
        assert_eq!(orgs.len(), 1);
        assert_eq!(orgs[0].0.name, "Acme Corp");
        assert_eq!(orgs[0].1, OrgRole::Owner);
    }

    #[tokio::test]
    async fn test_device_lifecycle_and_revocation() {
        let store = InMemoryStore::new();
        let user_id = Uuid::new_v4();
        let now = chrono::Utc::now().timestamp();

        let device = Device {
            id: Uuid::new_v4(),
            user_id,
            device_name: "MacBook Pro".to_string(),
            signing_public_key: "ed25519-key-abc".to_string(),
            agreement_public_key: "x25519-key-xyz".to_string(),
            created_at: now,
            last_seen_at: None,
            revoked_at: None,
        };

        store.create_device(&device).await.unwrap();

        let devices = store.list_for_user(user_id).await.unwrap();
        assert_eq!(devices.len(), 1);
        assert_eq!(devices[0].device_name, "MacBook Pro");

        // Revoke device
        store.revoke_device(device.id, user_id).await.unwrap();
        let revoked = store.find_device_by_id(device.id).await.unwrap().unwrap();
        assert!(revoked.revoked_at.is_some());
    }

    #[tokio::test]
    async fn test_session_rotation_and_theft_detection() {
        let store = InMemoryStore::new();
        let user_id = Uuid::new_v4();
        let now = chrono::Utc::now().timestamp();

        let s1 = Session {
            id: Uuid::new_v4(),
            user_id,
            device_id: None,
            refresh_token_hash: "hash-token-1".to_string(),
            expires_at: now + 3600,
            created_at: now,
            revoked_at: None,
        };

        store.create_session(&s1).await.unwrap();

        let mut s2 = Session {
            id: Uuid::new_v4(),
            user_id,
            device_id: None,
            refresh_token_hash: "hash-token-2".to_string(),
            expires_at: now + 3600,
            created_at: now,
            revoked_at: None,
        };

        // Normal rotation
        store
            .rotate_refresh_token("hash-token-1", &mut s2)
            .await
            .unwrap();

        // Old token cannot be retrieved as active
        assert!(store
            .find_active_by_token_hash("hash-token-1")
            .await
            .unwrap()
            .is_none());

        // Attempting to rotate old token again triggers reuse detection and revokes s2
        let mut s3 = Session {
            id: Uuid::new_v4(),
            user_id,
            device_id: None,
            refresh_token_hash: "hash-token-3".to_string(),
            expires_at: now + 3600,
            created_at: now,
            revoked_at: None,
        };
        let err = store
            .rotate_refresh_token("hash-token-1", &mut s3)
            .await
            .unwrap_err();
        match err {
            DomainError::TokenReuseDetected => {}
            _ => panic!("Expected TokenReuseDetected error"),
        }

        // s2 was automatically revoked upon reuse detection!
        assert!(store
            .find_active_by_token_hash("hash-token-2")
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn test_vault_lifecycle_and_rbac() {
        let store = InMemoryStore::new();
        let tenant_id = Uuid::new_v4();
        let user_id = Uuid::new_v4();
        let vault_id = Uuid::new_v4();
        let now = chrono::Utc::now().timestamp();

        let vault = Vault {
            id: vault_id,
            tenant_id,
            owner_id: user_id,
            vault_type: shellumi_server_domain::VaultType::Personal,
            encrypted_name: Some("My Encrypted Vault".to_string()),
            active_key_epoch: 1,
            server_sequence: 0,
            created_at: now,
            updated_at: now,
            deleted_at: None,
        };

        let member = VaultMember {
            vault_id,
            user_id,
            role: VaultRole::Owner,
            joined_at: now,
        };

        store.create_vault(&vault, &member).await.unwrap();

        let user_vaults = store.list_vaults_for_user(user_id).await.unwrap();
        assert_eq!(user_vaults.len(), 1);
        assert_eq!(user_vaults[0].0.id, vault_id);
        assert_eq!(user_vaults[0].1, VaultRole::Owner);

        // Role check
        let role = store
            .get_vault_member_role(vault_id, user_id)
            .await
            .unwrap();
        assert_eq!(role, Some(VaultRole::Owner));

        // Metadata update
        store
            .update_vault_metadata(vault_id, Some("Updated Name".to_string()))
            .await
            .unwrap();
        let fetched = store.find_vault_by_id(vault_id).await.unwrap().unwrap();
        assert_eq!(fetched.encrypted_name.as_deref(), Some("Updated Name"));

        // Delete vault
        store.delete_vault(vault_id).await.unwrap();
        let active = store.list_vaults_for_user(user_id).await.unwrap();
        assert_eq!(active.len(), 0);
    }

    #[tokio::test]
    async fn test_sync_repository_commit_batch_and_feed() {
        let store = InMemoryStore::new();
        let vault_id = Uuid::new_v4();
        let device_id = Uuid::new_v4();
        let now = chrono::Utc::now().timestamp();

        let record = Record {
            vault_id,
            object_id: "host-1".to_string(),
            entity_type: "host".to_string(),
            current_revision: 1,
            key_epoch: 1,
            author_device_id: device_id,
            deleted: false,
            encrypted_envelope: Some("ciphertext-json".to_string()),
            ciphertext_digest: "digest-1".to_string(),
            last_server_sequence: 1,
            updated_at: now,
        };

        let entry = ChangeLogEntry {
            vault_id,
            sequence: 1,
            object_id: "host-1".to_string(),
            entity_type: "host".to_string(),
            revision: 1,
            deleted: false,
            author_device_id: device_id,
            encrypted_envelope: Some("ciphertext-json".to_string()),
            ciphertext_digest: "digest-1".to_string(),
            created_at: now,
        };

        store
            .apply_commit_batch(
                vault_id,
                device_id,
                "idem-key-1",
                "request-hash-1",
                "{\"applied\":[]}",
                &[record],
                &[entry],
                1,
            )
            .await
            .unwrap();

        // Idempotency lookup
        let idem = store
            .find_idempotency(vault_id, "idem-key-1")
            .await
            .unwrap();
        assert!(idem.is_some());
        assert_eq!(idem.unwrap().request_hash, "request-hash-1");

        // Record lookup
        let r = store.find_record(vault_id, "host-1").await.unwrap();
        assert!(r.is_some());
        assert_eq!(r.unwrap().current_revision, 1);

        // Changes feed
        let changes = store.get_changes(vault_id, 0, 10).await.unwrap();
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].object_id, "host-1");
        assert_eq!(changes[0].sequence, 1);
    }
}
