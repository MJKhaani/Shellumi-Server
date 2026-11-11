//! Storage interfaces, traits, and implementations for Shellumi Server.

use async_trait::async_trait;
use shellumi_server_domain::{
    Device, DomainError, OrgMembership, OrgRole, Organization, ServerSettings, Session, User,
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

pub trait Store:
    SettingsRepository + UserRepository + OrgRepository + DeviceRepository + SessionRepository
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
}
