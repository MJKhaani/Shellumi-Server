//! PostgreSQL storage implementation using SQLx.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use shellumi_server_domain::{
    AuditEvent, ChangeLogEntry, CollabMode, CollabParticipant, CollabRole, CollabSession, Device,
    DomainError, MutationIdempotency, OrgRole, Organization, Record, ServerSettings, Session, User,
    Vault, VaultInvite, VaultKeyEnvelope, VaultMember, VaultRole, VaultType,
};
use shellumi_server_protocol::{CollabFrame, CommitBatchRequest, CommitBatchResponse, MutationAck};
use sqlx::postgres::PgPoolOptions;
use sqlx::{PgPool, Row};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;

use crate::{
    compute_audit_hash, AuditRepository, CollabRepository, DeviceRepository, InMemoryStore,
    InviteRepository, KeyEnvelopeRepository, OrgRepository, SessionRepository, SettingsRepository,
    Store, SyncRepository, UserRepository, VaultRepository, GENESIS_AUDIT_HASH,
    SERVER_SETTINGS_SINGLETON_ID,
};

pub static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("../../migrations");

/// Runs all pending forward-only SQL migrations against the PostgreSQL pool.
pub async fn run_migrations(pool: &PgPool) -> Result<(), DomainError> {
    MIGRATOR
        .run(pool)
        .await
        .map_err(|e| DomainError::Internal(format!("Database migration failed: {e}")))?;
    Ok(())
}

fn map_db_error(e: sqlx::Error) -> DomainError {
    match e {
        sqlx::Error::Database(ref dbe) => {
            if dbe.is_unique_violation() {
                DomainError::Conflict(dbe.message().to_string())
            } else {
                DomainError::Internal(format!("Database error: {dbe}"))
            }
        }
        sqlx::Error::RowNotFound => DomainError::NotFound,
        other => DomainError::Internal(format!("Database error: {other}")),
    }
}

fn to_timestamptz(epoch_secs: i64) -> DateTime<Utc> {
    DateTime::from_timestamp(epoch_secs, 0).unwrap_or_default()
}

fn from_timestamptz(dt: DateTime<Utc>) -> i64 {
    dt.timestamp()
}

#[derive(Clone)]
pub struct PgStore {
    pool: PgPool,
    collab_frames: Arc<RwLock<HashMap<Uuid, Vec<CollabFrame>>>>,
}

impl PgStore {
    pub async fn connect(database_url: &str) -> Result<Self, DomainError> {
        let pool = PgPoolOptions::new()
            .max_connections(20)
            .acquire_timeout(std::time::Duration::from_secs(5))
            .connect(database_url)
            .await
            .map_err(|e| {
                DomainError::Configuration(format!("Failed to connect to PostgreSQL: {e}"))
            })?;

        Ok(Self {
            pool,
            collab_frames: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    pub fn from_pool(pool: PgPool) -> Self {
        Self {
            pool,
            collab_frames: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    pub async fn is_ready(&self) -> bool {
        sqlx::query("SELECT 1").execute(&self.pool).await.is_ok()
    }

    pub async fn run_migrations(&self) -> Result<(), DomainError> {
        run_migrations(&self.pool).await
    }

    pub async fn notify_sync_event(&self, channel: &str, payload: &str) -> Result<(), DomainError> {
        sqlx::query("SELECT pg_notify($1, $2)")
            .bind(channel)
            .bind(payload)
            .execute(&self.pool)
            .await
            .map_err(map_db_error)?;
        Ok(())
    }
}

impl Store for PgStore {}

// ---------------------------------------------------------------------------
// SettingsRepository
// ---------------------------------------------------------------------------

#[async_trait]
impl SettingsRepository for PgStore {
    async fn get_settings(&self) -> Result<ServerSettings, DomainError> {
        let row = sqlx::query(
            "SELECT id, install_id, schema_version, bootstrap_consumed, bootstrap_token_hash, token_signing_key, created_at, updated_at FROM server_settings ORDER BY created_at ASC LIMIT 1"
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_db_error)?;

        if let Some(r) = row {
            Ok(ServerSettings {
                id: r.get("id"),
                install_id: r.get("install_id"),
                schema_version: r.get::<i32, _>("schema_version") as u32,
                bootstrap_consumed: r.get("bootstrap_consumed"),
                bootstrap_token_hash: r.get("bootstrap_token_hash"),
                token_signing_key: r.get("token_signing_key"),
                created_at: r.get("created_at"),
                updated_at: r.get("updated_at"),
            })
        } else {
            let now = Utc::now().timestamp();
            let settings = ServerSettings {
                id: SERVER_SETTINGS_SINGLETON_ID,
                install_id: Uuid::new_v4(),
                schema_version: 1,
                bootstrap_consumed: false,
                bootstrap_token_hash: None,
                token_signing_key: None,
                created_at: now,
                updated_at: now,
            };
            self.update_settings(&settings).await?;
            Ok(settings)
        }
    }

    async fn update_settings(&self, settings: &ServerSettings) -> Result<(), DomainError> {
        sqlx::query(
            r#"
            INSERT INTO server_settings (id, install_id, schema_version, bootstrap_consumed, bootstrap_token_hash, token_signing_key, created_at, updated_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            ON CONFLICT (id) DO UPDATE SET
                install_id = EXCLUDED.install_id,
                schema_version = EXCLUDED.schema_version,
                bootstrap_consumed = EXCLUDED.bootstrap_consumed,
                bootstrap_token_hash = EXCLUDED.bootstrap_token_hash,
                token_signing_key = EXCLUDED.token_signing_key,
                updated_at = EXCLUDED.updated_at
            "#
        )
        .bind(settings.id)
        .bind(settings.install_id)
        .bind(settings.schema_version as i32)
        .bind(settings.bootstrap_consumed)
        .bind(&settings.bootstrap_token_hash)
        .bind(&settings.token_signing_key)
        .bind(settings.created_at)
        .bind(settings.updated_at)
        .execute(&self.pool)
        .await
        .map_err(map_db_error)?;

        Ok(())
    }

    async fn mark_bootstrap_consumed(
        &self,
        expected_token_hash: Option<&str>,
    ) -> Result<(), DomainError> {
        let mut tx = self.pool.begin().await.map_err(map_db_error)?;

        sqlx::query("SELECT pg_advisory_xact_lock(714263)")
            .execute(&mut *tx)
            .await
            .map_err(map_db_error)?;

        let row = sqlx::query(
            "SELECT id, bootstrap_consumed, bootstrap_token_hash FROM server_settings WHERE id = $1 FOR UPDATE"
        )
        .bind(SERVER_SETTINGS_SINGLETON_ID)
        .fetch_optional(&mut *tx)
        .await
        .map_err(map_db_error)?;

        let (id, consumed, stored_token_hash) = if let Some(r) = row {
            (
                r.get::<Uuid, _>("id"),
                r.get::<bool, _>("bootstrap_consumed"),
                r.get::<Option<String>, _>("bootstrap_token_hash"),
            )
        } else {
            let now = Utc::now().timestamp();
            sqlx::query(
                "INSERT INTO server_settings (id, install_id, schema_version, bootstrap_consumed, bootstrap_token_hash, token_signing_key, created_at, updated_at) VALUES ($1, $2, 1, false, NULL, NULL, $3, $3) ON CONFLICT (id) DO NOTHING"
            )
            .bind(SERVER_SETTINGS_SINGLETON_ID)
            .bind(Uuid::new_v4())
            .bind(now)
            .execute(&mut *tx)
            .await
            .map_err(map_db_error)?;
            (SERVER_SETTINGS_SINGLETON_ID, false, None)
        };

        if consumed {
            return Err(DomainError::BootstrapAlreadyConsumed);
        }

        if let Some(required_hash) = stored_token_hash.as_deref() {
            if expected_token_hash != Some(required_hash) {
                return Err(DomainError::InvalidBootstrapToken);
            }
        }

        let now = Utc::now().timestamp();
        sqlx::query(
            "UPDATE server_settings SET bootstrap_consumed = true, updated_at = $1 WHERE id = $2",
        )
        .bind(now)
        .bind(id)
        .execute(&mut *tx)
        .await
        .map_err(map_db_error)?;

        tx.commit().await.map_err(map_db_error)?;
        Ok(())
    }

    async fn complete_bootstrap(
        &self,
        expected_token_hash: Option<&str>,
        user: &User,
        org: &Organization,
        session: &Session,
    ) -> Result<(), DomainError> {
        let mut tx = self.pool.begin().await.map_err(map_db_error)?;

        // Acquire advisory transaction lock for bootstrap singleton guarantee
        sqlx::query("SELECT pg_advisory_xact_lock(714263)")
            .execute(&mut *tx)
            .await
            .map_err(map_db_error)?;

        let row = sqlx::query(
            "SELECT id, bootstrap_consumed, bootstrap_token_hash FROM server_settings WHERE id = $1 FOR UPDATE",
        )
        .bind(SERVER_SETTINGS_SINGLETON_ID)
        .fetch_optional(&mut *tx)
        .await
        .map_err(map_db_error)?;

        let (id, consumed, stored_token_hash) = if let Some(r) = row {
            (
                r.get::<Uuid, _>("id"),
                r.get::<bool, _>("bootstrap_consumed"),
                r.get::<Option<String>, _>("bootstrap_token_hash"),
            )
        } else {
            let now = Utc::now().timestamp();
            sqlx::query(
                "INSERT INTO server_settings (id, install_id, schema_version, bootstrap_consumed, bootstrap_token_hash, token_signing_key, created_at, updated_at) VALUES ($1, $2, 1, false, NULL, NULL, $3, $3) ON CONFLICT (id) DO NOTHING",
            )
            .bind(SERVER_SETTINGS_SINGLETON_ID)
            .bind(Uuid::new_v4())
            .bind(now)
            .execute(&mut *tx)
            .await
            .map_err(map_db_error)?;
            (SERVER_SETTINGS_SINGLETON_ID, false, None)
        };

        if consumed {
            return Err(DomainError::BootstrapAlreadyConsumed);
        }

        if let Some(required_hash) = stored_token_hash.as_deref() {
            if expected_token_hash != Some(required_hash) {
                return Err(DomainError::InvalidBootstrapToken);
            }
        }

        let now = Utc::now().timestamp();
        sqlx::query(
            "UPDATE server_settings SET bootstrap_consumed = true, updated_at = $1 WHERE id = $2",
        )
        .bind(now)
        .bind(id)
        .execute(&mut *tx)
        .await
        .map_err(map_db_error)?;

        // Insert User - bind raw i64 Unix timestamps
        sqlx::query(
            r#"
            INSERT INTO users (id, username, email, password_hash, is_active, created_at, updated_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            "#,
        )
        .bind(user.id)
        .bind(&user.username)
        .bind(&user.email)
        .bind(&user.password_hash)
        .bind(user.is_active)
        .bind(user.created_at)
        .bind(user.updated_at)
        .execute(&mut *tx)
        .await
        .map_err(map_db_error)?;

        // Insert Org - bind raw i64 Unix timestamp
        sqlx::query(
            r#"
            INSERT INTO organizations (id, name, created_at)
            VALUES ($1, $2, $3)
            "#,
        )
        .bind(org.id)
        .bind(&org.name)
        .bind(org.created_at)
        .execute(&mut *tx)
        .await
        .map_err(map_db_error)?;

        // Insert Org Membership - table organization_memberships, column created_at, raw i64
        sqlx::query(
            r#"
            INSERT INTO organization_memberships (org_id, user_id, role, created_at)
            VALUES ($1, $2, 'owner', $3)
            "#,
        )
        .bind(org.id)
        .bind(user.id)
        .bind(user.created_at)
        .execute(&mut *tx)
        .await
        .map_err(map_db_error)?;

        // Insert Session - bind raw i64 Unix timestamps
        sqlx::query(
            r#"
            INSERT INTO sessions (id, user_id, device_id, refresh_token_hash, expires_at, created_at)
            VALUES ($1, $2, $3, $4, $5, $6)
            "#,
        )
        .bind(session.id)
        .bind(session.user_id)
        .bind(session.device_id)
        .bind(&session.refresh_token_hash)
        .bind(session.expires_at)
        .bind(session.created_at)
        .execute(&mut *tx)
        .await
        .map_err(map_db_error)?;

        tx.commit().await.map_err(map_db_error)?;
        Ok(())
    }

    async fn get_or_init_server_keys(&self) -> Result<(Uuid, Vec<u8>), DomainError> {
        let mut tx = self.pool.begin().await.map_err(map_db_error)?;

        sqlx::query("SELECT pg_advisory_xact_lock(714263)")
            .execute(&mut *tx)
            .await
            .map_err(map_db_error)?;

        let row = sqlx::query(
            "SELECT id, install_id, token_signing_key FROM server_settings ORDER BY created_at ASC LIMIT 1 FOR UPDATE",
        )
        .fetch_optional(&mut *tx)
        .await
        .map_err(map_db_error)?;

        if let Some(r) = row {
            let id: Uuid = r.get("id");
            let install_id: Uuid = r.get("install_id");
            let stored_key: Option<String> = r.get("token_signing_key");

            if let Some(key_hex) = stored_key {
                let bytes = hex::decode(&key_hex).map_err(|_| {
                    DomainError::Configuration("Stored signing key is invalid".into())
                })?;
                if bytes.len() != 32 {
                    return Err(DomainError::Configuration(
                        "Stored signing key has invalid length".into(),
                    ));
                }
                tx.commit().await.map_err(map_db_error)?;
                return Ok((install_id, bytes));
            }

            use ring::rand::SecureRandom;
            let rng = ring::rand::SystemRandom::new();
            let mut key = vec![0u8; 32];
            rng.fill(&mut key)
                .map_err(|_| DomainError::Internal("Entropy failure".into()))?;
            let hex_key = hex::encode(&key);
            let now = Utc::now().timestamp();

            sqlx::query(
                "UPDATE server_settings SET token_signing_key = $1, updated_at = $2 WHERE id = $3",
            )
            .bind(&hex_key)
            .bind(now)
            .bind(id)
            .execute(&mut *tx)
            .await
            .map_err(map_db_error)?;

            tx.commit().await.map_err(map_db_error)?;
            Ok((install_id, key))
        } else {
            let install_id = Uuid::new_v4();
            use ring::rand::SecureRandom;
            let rng = ring::rand::SystemRandom::new();
            let mut key = vec![0u8; 32];
            rng.fill(&mut key)
                .map_err(|_| DomainError::Internal("Entropy failure".into()))?;
            let hex_key = hex::encode(&key);
            let now = Utc::now().timestamp();

            sqlx::query(
                r#"
                INSERT INTO server_settings (id, install_id, schema_version, bootstrap_consumed, bootstrap_token_hash, token_signing_key, created_at, updated_at)
                VALUES ($1, $2, 1, false, NULL, $3, $4, $4)
                ON CONFLICT (id) DO UPDATE SET
                    token_signing_key = COALESCE(server_settings.token_signing_key, EXCLUDED.token_signing_key),
                    updated_at = EXCLUDED.updated_at
                "#,
            )
            .bind(SERVER_SETTINGS_SINGLETON_ID)
            .bind(install_id)
            .bind(&hex_key)
            .bind(now)
            .execute(&mut *tx)
            .await
            .map_err(map_db_error)?;

            tx.commit().await.map_err(map_db_error)?;
            Ok((install_id, key))
        }
    }
}

// ---------------------------------------------------------------------------
// UserRepository
// ---------------------------------------------------------------------------

#[async_trait]
impl UserRepository for PgStore {
    async fn create_user(&self, user: &User) -> Result<(), DomainError> {
        sqlx::query(
            "INSERT INTO users (id, username, email, password_hash, created_at, updated_at, is_active) VALUES ($1, $2, $3, $4, $5, $6, $7)"
        )
        .bind(user.id)
        .bind(&user.username)
        .bind(&user.email)
        .bind(&user.password_hash)
        .bind(user.created_at)
        .bind(user.updated_at)
        .bind(user.is_active)
        .execute(&self.pool)
        .await
        .map_err(map_db_error)?;

        Ok(())
    }

    async fn find_user_by_id(&self, id: Uuid) -> Result<Option<User>, DomainError> {
        let row = sqlx::query(
            "SELECT id, username, email, password_hash, created_at, updated_at, is_active FROM users WHERE id = $1"
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await
        .map_err(map_db_error)?;

        Ok(row.map(|r| User {
            id: r.get("id"),
            username: r.get("username"),
            email: r.get("email"),
            password_hash: r.get("password_hash"),
            created_at: r.get("created_at"),
            updated_at: r.get("updated_at"),
            is_active: r.get("is_active"),
        }))
    }

    async fn find_by_identifier(&self, identifier: &str) -> Result<Option<User>, DomainError> {
        let row = sqlx::query(
            "SELECT id, username, email, password_hash, created_at, updated_at, is_active FROM users WHERE username = $1 OR email = $1 LIMIT 1"
        )
        .bind(identifier)
        .fetch_optional(&self.pool)
        .await
        .map_err(map_db_error)?;

        Ok(row.map(|r| User {
            id: r.get("id"),
            username: r.get("username"),
            email: r.get("email"),
            password_hash: r.get("password_hash"),
            created_at: r.get("created_at"),
            updated_at: r.get("updated_at"),
            is_active: r.get("is_active"),
        }))
    }

    async fn list_users(&self) -> Result<Vec<User>, DomainError> {
        let rows = sqlx::query(
            "SELECT id, username, email, password_hash, created_at, updated_at, is_active FROM users ORDER BY created_at ASC"
        )
        .fetch_all(&self.pool)
        .await
        .map_err(map_db_error)?;

        Ok(rows
            .into_iter()
            .map(|r| User {
                id: r.get("id"),
                username: r.get("username"),
                email: r.get("email"),
                password_hash: r.get("password_hash"),
                created_at: r.get("created_at"),
                updated_at: r.get("updated_at"),
                is_active: r.get("is_active"),
            })
            .collect())
    }

    async fn update_user(&self, user: &User) -> Result<(), DomainError> {
        sqlx::query(
            "UPDATE users SET username = $1, email = $2, password_hash = $3, updated_at = $4, is_active = $5 WHERE id = $6"
        )
        .bind(&user.username)
        .bind(&user.email)
        .bind(&user.password_hash)
        .bind(user.updated_at)
        .bind(user.is_active)
        .bind(user.id)
        .execute(&self.pool)
        .await
        .map_err(map_db_error)?;

        Ok(())
    }

    async fn list_orgs_for_user(
        &self,
        user_id: Uuid,
    ) -> Result<Vec<(Organization, OrgRole)>, DomainError> {
        let rows = sqlx::query(
            r#"
            SELECT o.id, o.name, o.created_at, om.role
            FROM organizations o
            JOIN organization_memberships om ON o.id = om.org_id
            WHERE om.user_id = $1
            ORDER BY o.created_at ASC
            "#,
        )
        .bind(user_id)
        .fetch_all(&self.pool)
        .await
        .map_err(map_db_error)?;

        let mut results = Vec::new();
        for r in rows {
            let role_str: String = r.get("role");
            let role = match role_str.as_str() {
                "owner" => OrgRole::Owner,
                "admin" => OrgRole::Admin,
                _ => OrgRole::Member,
            };
            results.push((
                Organization {
                    id: r.get("id"),
                    name: r.get("name"),
                    created_at: r.get("created_at"),
                },
                role,
            ));
        }

        Ok(results)
    }
}

// ---------------------------------------------------------------------------
// OrgRepository
// ---------------------------------------------------------------------------

#[async_trait]
impl OrgRepository for PgStore {
    async fn create_org(&self, org: &Organization, owner_id: Uuid) -> Result<(), DomainError> {
        let mut tx = self.pool.begin().await.map_err(map_db_error)?;

        sqlx::query("INSERT INTO organizations (id, name, created_at) VALUES ($1, $2, $3)")
            .bind(org.id)
            .bind(&org.name)
            .bind(org.created_at)
            .execute(&mut *tx)
            .await
            .map_err(map_db_error)?;

        sqlx::query(
            "INSERT INTO organization_memberships (org_id, user_id, role, created_at) VALUES ($1, $2, 'owner', $3)"
        )
        .bind(org.id)
        .bind(owner_id)
        .bind(org.created_at)
        .execute(&mut *tx)
        .await
        .map_err(map_db_error)?;

        tx.commit().await.map_err(map_db_error)?;
        Ok(())
    }

    async fn find_org_by_id(&self, id: Uuid) -> Result<Option<Organization>, DomainError> {
        let row = sqlx::query("SELECT id, name, created_at FROM organizations WHERE id = $1")
            .bind(id)
            .fetch_optional(&self.pool)
            .await
            .map_err(map_db_error)?;

        Ok(row.map(|r| Organization {
            id: r.get("id"),
            name: r.get("name"),
            created_at: r.get("created_at"),
        }))
    }

    async fn add_member(
        &self,
        org_id: Uuid,
        user_id: Uuid,
        role: OrgRole,
    ) -> Result<(), DomainError> {
        let now = Utc::now().timestamp();
        sqlx::query(
            r#"
            INSERT INTO organization_memberships (org_id, user_id, role, created_at)
            VALUES ($1, $2, $3, $4)
            ON CONFLICT (org_id, user_id) DO UPDATE SET role = EXCLUDED.role
            "#,
        )
        .bind(org_id)
        .bind(user_id)
        .bind(match role {
            OrgRole::Owner => "owner",
            OrgRole::Admin => "admin",
            OrgRole::Member => "member",
        })
        .bind(now)
        .execute(&self.pool)
        .await
        .map_err(map_db_error)?;

        Ok(())
    }

    async fn get_member_role(
        &self,
        org_id: Uuid,
        user_id: Uuid,
    ) -> Result<Option<OrgRole>, DomainError> {
        let row = sqlx::query(
            "SELECT role FROM organization_memberships WHERE org_id = $1 AND user_id = $2",
        )
        .bind(org_id)
        .bind(user_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(map_db_error)?;

        Ok(row.map(|r| {
            let role_str: String = r.get("role");
            match role_str.as_str() {
                "owner" => OrgRole::Owner,
                "admin" => OrgRole::Admin,
                _ => OrgRole::Member,
            }
        }))
    }
}

// ---------------------------------------------------------------------------
// DeviceRepository
// ---------------------------------------------------------------------------

#[async_trait]
impl DeviceRepository for PgStore {
    async fn create_device(&self, device: &Device) -> Result<(), DomainError> {
        sqlx::query(
            r#"
            INSERT INTO devices (id, user_id, device_name, signing_public_key, agreement_public_key, created_at, last_seen_at, revoked_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            "#
        )
        .bind(device.id)
        .bind(device.user_id)
        .bind(&device.device_name)
        .bind(&device.signing_public_key)
        .bind(&device.agreement_public_key)
        .bind(device.created_at)
        .bind(device.last_seen_at)
        .bind(device.revoked_at)
        .execute(&self.pool)
        .await
        .map_err(map_db_error)?;

        Ok(())
    }

    async fn find_device_by_id(&self, id: Uuid) -> Result<Option<Device>, DomainError> {
        let row = sqlx::query(
            "SELECT id, user_id, device_name, signing_public_key, agreement_public_key, created_at, last_seen_at, revoked_at FROM devices WHERE id = $1"
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await
        .map_err(map_db_error)?;

        Ok(row.map(|r| Device {
            id: r.get("id"),
            user_id: r.get("user_id"),
            device_name: r.get("device_name"),
            signing_public_key: r.get("signing_public_key"),
            agreement_public_key: r.get("agreement_public_key"),
            created_at: r.get("created_at"),
            last_seen_at: r.get("last_seen_at"),
            revoked_at: r.get("revoked_at"),
        }))
    }

    async fn list_for_user(&self, user_id: Uuid) -> Result<Vec<Device>, DomainError> {
        let rows = sqlx::query(
            "SELECT id, user_id, device_name, signing_public_key, agreement_public_key, created_at, last_seen_at, revoked_at FROM devices WHERE user_id = $1 ORDER BY created_at ASC"
        )
        .bind(user_id)
        .fetch_all(&self.pool)
        .await
        .map_err(map_db_error)?;

        Ok(rows
            .into_iter()
            .map(|r| Device {
                id: r.get("id"),
                user_id: r.get("user_id"),
                device_name: r.get("device_name"),
                signing_public_key: r.get("signing_public_key"),
                agreement_public_key: r.get("agreement_public_key"),
                created_at: r.get("created_at"),
                last_seen_at: r.get("last_seen_at"),
                revoked_at: r.get("revoked_at"),
            })
            .collect())
    }

    async fn revoke_device(&self, device_id: Uuid, user_id: Uuid) -> Result<(), DomainError> {
        let now = Utc::now().timestamp();
        sqlx::query(
            "UPDATE devices SET revoked_at = $1 WHERE id = $2 AND user_id = $3 AND revoked_at IS NULL"
        )
        .bind(now)
        .bind(device_id)
        .bind(user_id)
        .execute(&self.pool)
        .await
        .map_err(map_db_error)?;

        Ok(())
    }

    async fn update_last_seen(&self, device_id: Uuid, timestamp: i64) -> Result<(), DomainError> {
        sqlx::query("UPDATE devices SET last_seen_at = $1 WHERE id = $2")
            .bind(timestamp)
            .bind(device_id)
            .execute(&self.pool)
            .await
            .map_err(map_db_error)?;

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// SessionRepository
// ---------------------------------------------------------------------------

#[async_trait]
impl SessionRepository for PgStore {
    async fn create_session(&self, session: &Session) -> Result<(), DomainError> {
        sqlx::query(
            "INSERT INTO sessions (id, user_id, device_id, refresh_token_hash, expires_at, created_at, revoked_at) VALUES ($1, $2, $3, $4, $5, $6, $7)"
        )
        .bind(session.id)
        .bind(session.user_id)
        .bind(session.device_id)
        .bind(&session.refresh_token_hash)
        .bind(session.expires_at)
        .bind(session.created_at)
        .bind(session.revoked_at)
        .execute(&self.pool)
        .await
        .map_err(map_db_error)?;

        Ok(())
    }

    async fn find_session_by_id(&self, session_id: Uuid) -> Result<Option<Session>, DomainError> {
        let row = sqlx::query(
            "SELECT id, user_id, device_id, refresh_token_hash, expires_at, created_at, revoked_at FROM sessions WHERE id = $1"
        )
        .bind(session_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(map_db_error)?;

        Ok(row.map(|r| Session {
            id: r.get("id"),
            user_id: r.get("user_id"),
            device_id: r.get("device_id"),
            refresh_token_hash: r.get("refresh_token_hash"),
            expires_at: r.get("expires_at"),
            created_at: r.get("created_at"),
            revoked_at: r.get("revoked_at"),
        }))
    }

    async fn find_active_by_token_hash(&self, hash: &str) -> Result<Option<Session>, DomainError> {
        let now = Utc::now().timestamp();
        let row = sqlx::query(
            "SELECT id, user_id, device_id, refresh_token_hash, expires_at, created_at, revoked_at FROM sessions WHERE refresh_token_hash = $1 AND revoked_at IS NULL AND expires_at > $2"
        )
        .bind(hash)
        .bind(now)
        .fetch_optional(&self.pool)
        .await
        .map_err(map_db_error)?;

        Ok(row.map(|r| Session {
            id: r.get("id"),
            user_id: r.get("user_id"),
            device_id: r.get("device_id"),
            refresh_token_hash: r.get("refresh_token_hash"),
            expires_at: r.get("expires_at"),
            created_at: r.get("created_at"),
            revoked_at: r.get("revoked_at"),
        }))
    }

    async fn rotate_refresh_token(
        &self,
        old_hash: &str,
        new_session: &mut Session,
    ) -> Result<Uuid, DomainError> {
        let mut tx = self.pool.begin().await.map_err(map_db_error)?;
        let now = Utc::now().timestamp();

        let row = sqlx::query(
            "SELECT id, user_id, device_id, refresh_token_hash, expires_at, created_at, revoked_at FROM sessions WHERE refresh_token_hash = $1 FOR UPDATE"
        )
        .bind(old_hash)
        .fetch_optional(&mut *tx)
        .await
        .map_err(map_db_error)?;

        let old_session = match row {
            Some(r) => Session {
                id: r.get("id"),
                user_id: r.get("user_id"),
                device_id: r.get("device_id"),
                refresh_token_hash: r.get("refresh_token_hash"),
                expires_at: r.get("expires_at"),
                created_at: r.get("created_at"),
                revoked_at: r.get("revoked_at"),
            },
            None => return Err(DomainError::InvalidCredentials),
        };

        if old_session.revoked_at.is_some() {
            // Theft detected: revoke all sessions for this user
            sqlx::query(
                "UPDATE sessions SET revoked_at = $1 WHERE user_id = $2 AND revoked_at IS NULL",
            )
            .bind(now)
            .bind(old_session.user_id)
            .execute(&mut *tx)
            .await
            .map_err(map_db_error)?;
            tx.commit().await.map_err(map_db_error)?;
            return Err(DomainError::TokenReuseDetected);
        }

        if old_session.expires_at <= now {
            return Err(DomainError::TokenExpired);
        }

        // Revoke the old session
        sqlx::query("UPDATE sessions SET revoked_at = $1 WHERE id = $2")
            .bind(now)
            .bind(old_session.id)
            .execute(&mut *tx)
            .await
            .map_err(map_db_error)?;

        // Insert new session
        new_session.user_id = old_session.user_id;
        new_session.device_id = old_session.device_id;
        sqlx::query(
            "INSERT INTO sessions (id, user_id, device_id, refresh_token_hash, expires_at, created_at, revoked_at) VALUES ($1, $2, $3, $4, $5, $6, $7)"
        )
        .bind(new_session.id)
        .bind(new_session.user_id)
        .bind(new_session.device_id)
        .bind(&new_session.refresh_token_hash)
        .bind(new_session.expires_at)
        .bind(new_session.created_at)
        .bind(new_session.revoked_at)
        .execute(&mut *tx)
        .await
        .map_err(map_db_error)?;

        tx.commit().await.map_err(map_db_error)?;
        Ok(new_session.id)
    }

    async fn list_sessions_for_user(&self, user_id: Uuid) -> Result<Vec<Session>, DomainError> {
        let rows = sqlx::query(
            "SELECT id, user_id, device_id, refresh_token_hash, expires_at, created_at, revoked_at FROM sessions WHERE user_id = $1 ORDER BY created_at DESC"
        )
        .bind(user_id)
        .fetch_all(&self.pool)
        .await
        .map_err(map_db_error)?;

        Ok(rows
            .into_iter()
            .map(|r| Session {
                id: r.get("id"),
                user_id: r.get("user_id"),
                device_id: r.get("device_id"),
                refresh_token_hash: r.get("refresh_token_hash"),
                expires_at: r.get("expires_at"),
                created_at: r.get("created_at"),
                revoked_at: r.get("revoked_at"),
            })
            .collect())
    }

    async fn revoke_session(&self, session_id: Uuid) -> Result<(), DomainError> {
        let now = Utc::now().timestamp();
        sqlx::query("UPDATE sessions SET revoked_at = $1 WHERE id = $2 AND revoked_at IS NULL")
            .bind(now)
            .bind(session_id)
            .execute(&self.pool)
            .await
            .map_err(map_db_error)?;

        Ok(())
    }

    async fn revoke_all_for_device(&self, device_id: Uuid) -> Result<(), DomainError> {
        let now = Utc::now().timestamp();
        sqlx::query(
            "UPDATE sessions SET revoked_at = $1 WHERE device_id = $2 AND revoked_at IS NULL",
        )
        .bind(now)
        .bind(device_id)
        .execute(&self.pool)
        .await
        .map_err(map_db_error)?;

        Ok(())
    }

    async fn revoke_all_for_user(&self, user_id: Uuid) -> Result<(), DomainError> {
        let now = Utc::now().timestamp();
        sqlx::query(
            "UPDATE sessions SET revoked_at = $1 WHERE user_id = $2 AND revoked_at IS NULL",
        )
        .bind(now)
        .bind(user_id)
        .execute(&self.pool)
        .await
        .map_err(map_db_error)?;

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// VaultRepository
// ---------------------------------------------------------------------------

#[async_trait]
impl VaultRepository for PgStore {
    async fn create_vault(
        &self,
        vault: &Vault,
        initial_member: &VaultMember,
    ) -> Result<(), DomainError> {
        let mut tx = self.pool.begin().await.map_err(map_db_error)?;

        sqlx::query(
            r#"
            INSERT INTO vaults (id, tenant_id, owner_id, vault_type, encrypted_name, active_key_epoch, server_sequence, created_at, updated_at, deleted_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
            "#
        )
        .bind(vault.id)
        .bind(vault.tenant_id)
        .bind(vault.owner_id)
        .bind(match vault.vault_type {
            VaultType::Personal => "personal",
            VaultType::Team => "team",
        })
        .bind(&vault.encrypted_name)
        .bind(vault.active_key_epoch as i32)
        .bind(vault.server_sequence as i64)
        .bind(to_timestamptz(vault.created_at))
        .bind(to_timestamptz(vault.updated_at))
        .bind(vault.deleted_at.map(to_timestamptz))
        .execute(&mut *tx)
        .await
        .map_err(map_db_error)?;

        sqlx::query(
            "INSERT INTO vault_members (vault_id, user_id, role, joined_at) VALUES ($1, $2, $3, $4)"
        )
        .bind(initial_member.vault_id)
        .bind(initial_member.user_id)
        .bind(initial_member.role.as_str())
        .bind(to_timestamptz(initial_member.joined_at))
        .execute(&mut *tx)
        .await
        .map_err(map_db_error)?;

        tx.commit().await.map_err(map_db_error)?;
        Ok(())
    }

    async fn find_vault_by_id(&self, vault_id: Uuid) -> Result<Option<Vault>, DomainError> {
        let row = sqlx::query(
            r#"
            SELECT id, tenant_id, owner_id, vault_type, encrypted_name, active_key_epoch, server_sequence, created_at, updated_at, deleted_at
            FROM vaults WHERE id = $1
            "#
        )
        .bind(vault_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(map_db_error)?;

        Ok(row.map(|r| {
            let vt_str: String = r.get("vault_type");
            let vt = match vt_str.as_str() {
                "team" => VaultType::Team,
                _ => VaultType::Personal,
            };
            Vault {
                id: r.get("id"),
                tenant_id: r.get("tenant_id"),
                owner_id: r.get("owner_id"),
                vault_type: vt,
                encrypted_name: r.get("encrypted_name"),
                active_key_epoch: r.get::<i32, _>("active_key_epoch") as u32,
                server_sequence: r.get::<i64, _>("server_sequence") as u64,
                created_at: from_timestamptz(r.get("created_at")),
                updated_at: from_timestamptz(r.get("updated_at")),
                deleted_at: r
                    .get::<Option<DateTime<Utc>>, _>("deleted_at")
                    .map(from_timestamptz),
            }
        }))
    }

    async fn list_vaults_for_user(
        &self,
        user_id: Uuid,
    ) -> Result<Vec<(Vault, VaultRole)>, DomainError> {
        let rows = sqlx::query(
            r#"
            SELECT v.id, v.tenant_id, v.owner_id, v.vault_type, v.encrypted_name, v.active_key_epoch, v.server_sequence, v.created_at, v.updated_at, v.deleted_at, vm.role
            FROM vaults v
            JOIN vault_members vm ON v.id = vm.vault_id
            WHERE vm.user_id = $1 AND v.deleted_at IS NULL
            ORDER BY v.created_at ASC
            "#
        )
        .bind(user_id)
        .fetch_all(&self.pool)
        .await
        .map_err(map_db_error)?;

        let mut results = Vec::new();
        for r in rows {
            let vt_str: String = r.get("vault_type");
            let vt = match vt_str.as_str() {
                "team" => VaultType::Team,
                _ => VaultType::Personal,
            };
            let role_str: String = r.get("role");
            let role = match role_str.as_str() {
                "owner" => VaultRole::Owner,
                "administrator" => VaultRole::Administrator,
                "editor" => VaultRole::Editor,
                _ => VaultRole::Viewer,
            };
            results.push((
                Vault {
                    id: r.get("id"),
                    tenant_id: r.get("tenant_id"),
                    owner_id: r.get("owner_id"),
                    vault_type: vt,
                    encrypted_name: r.get("encrypted_name"),
                    active_key_epoch: r.get::<i32, _>("active_key_epoch") as u32,
                    server_sequence: r.get::<i64, _>("server_sequence") as u64,
                    created_at: from_timestamptz(r.get("created_at")),
                    updated_at: from_timestamptz(r.get("updated_at")),
                    deleted_at: r
                        .get::<Option<DateTime<Utc>>, _>("deleted_at")
                        .map(from_timestamptz),
                },
                role,
            ));
        }

        Ok(results)
    }

    async fn update_vault_metadata(
        &self,
        vault_id: Uuid,
        encrypted_name: Option<String>,
    ) -> Result<(), DomainError> {
        sqlx::query("UPDATE vaults SET encrypted_name = $1, updated_at = NOW() WHERE id = $2 AND deleted_at IS NULL")
            .bind(encrypted_name)
            .bind(vault_id)
            .execute(&self.pool)
            .await
            .map_err(map_db_error)?;

        Ok(())
    }

    async fn delete_vault(&self, vault_id: Uuid) -> Result<(), DomainError> {
        sqlx::query("UPDATE vaults SET deleted_at = NOW(), updated_at = NOW() WHERE id = $1 AND deleted_at IS NULL")
            .bind(vault_id)
            .execute(&self.pool)
            .await
            .map_err(map_db_error)?;

        Ok(())
    }

    async fn get_vault_member_role(
        &self,
        vault_id: Uuid,
        user_id: Uuid,
    ) -> Result<Option<VaultRole>, DomainError> {
        let row =
            sqlx::query("SELECT role FROM vault_members WHERE vault_id = $1 AND user_id = $2")
                .bind(vault_id)
                .bind(user_id)
                .fetch_optional(&self.pool)
                .await
                .map_err(map_db_error)?;

        Ok(row.map(|r| {
            let role_str: String = r.get("role");
            match role_str.as_str() {
                "owner" => VaultRole::Owner,
                "administrator" => VaultRole::Administrator,
                "editor" => VaultRole::Editor,
                _ => VaultRole::Viewer,
            }
        }))
    }

    async fn add_vault_member(&self, member: &VaultMember) -> Result<(), DomainError> {
        sqlx::query(
            r#"
            INSERT INTO vault_members (vault_id, user_id, role, joined_at)
            VALUES ($1, $2, $3, $4)
            ON CONFLICT (vault_id, user_id) DO UPDATE SET role = EXCLUDED.role
            "#,
        )
        .bind(member.vault_id)
        .bind(member.user_id)
        .bind(member.role.as_str())
        .bind(to_timestamptz(member.joined_at))
        .execute(&self.pool)
        .await
        .map_err(map_db_error)?;

        Ok(())
    }

    async fn list_vault_members(&self, vault_id: Uuid) -> Result<Vec<VaultMember>, DomainError> {
        let rows = sqlx::query(
            "SELECT vault_id, user_id, role, joined_at FROM vault_members WHERE vault_id = $1 ORDER BY joined_at ASC"
        )
        .bind(vault_id)
        .fetch_all(&self.pool)
        .await
        .map_err(map_db_error)?;

        Ok(rows
            .into_iter()
            .map(|r| {
                let role_str: String = r.get("role");
                let role = match role_str.as_str() {
                    "owner" => VaultRole::Owner,
                    "administrator" => VaultRole::Administrator,
                    "editor" => VaultRole::Editor,
                    _ => VaultRole::Viewer,
                };
                VaultMember {
                    vault_id: r.get("vault_id"),
                    user_id: r.get("user_id"),
                    role,
                    joined_at: from_timestamptz(r.get("joined_at")),
                }
            })
            .collect())
    }

    async fn remove_vault_member(&self, vault_id: Uuid, user_id: Uuid) -> Result<(), DomainError> {
        sqlx::query("DELETE FROM vault_members WHERE vault_id = $1 AND user_id = $2")
            .bind(vault_id)
            .bind(user_id)
            .execute(&self.pool)
            .await
            .map_err(map_db_error)?;

        Ok(())
    }

    async fn count_vault_owners(&self, vault_id: Uuid) -> Result<usize, DomainError> {
        let row = sqlx::query(
            "SELECT COUNT(*) as count FROM vault_members WHERE vault_id = $1 AND role = 'owner'",
        )
        .bind(vault_id)
        .fetch_one(&self.pool)
        .await
        .map_err(map_db_error)?;

        let count: i64 = row.get("count");
        Ok(count as usize)
    }

    async fn update_vault_key_epoch(
        &self,
        vault_id: Uuid,
        new_epoch: u32,
    ) -> Result<(), DomainError> {
        sqlx::query("UPDATE vaults SET active_key_epoch = $1, updated_at = NOW() WHERE id = $2")
            .bind(new_epoch as i32)
            .bind(vault_id)
            .execute(&self.pool)
            .await
            .map_err(map_db_error)?;

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// InviteRepository
// ---------------------------------------------------------------------------

#[async_trait]
impl InviteRepository for PgStore {
    async fn create_invite(&self, invite: &VaultInvite) -> Result<(), DomainError> {
        sqlx::query(
            r#"
            INSERT INTO vault_invites (id, vault_id, inviter_user_id, role, invite_token_hash, recipient_email, expires_at, accepted_at, accepted_by_user_id, revoked_at, created_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
            "#
        )
        .bind(invite.id)
        .bind(invite.vault_id)
        .bind(invite.inviter_user_id)
        .bind(invite.role.as_str())
        .bind(&invite.invite_token_hash)
        .bind(&invite.recipient_email)
        .bind(to_timestamptz(invite.expires_at))
        .bind(invite.accepted_at.map(to_timestamptz))
        .bind(invite.accepted_by_user_id)
        .bind(invite.revoked_at.map(to_timestamptz))
        .bind(to_timestamptz(invite.created_at))
        .execute(&self.pool)
        .await
        .map_err(map_db_error)?;

        Ok(())
    }

    async fn find_invite_by_id(&self, invite_id: Uuid) -> Result<Option<VaultInvite>, DomainError> {
        let row = sqlx::query(
            "SELECT id, vault_id, inviter_user_id, role, invite_token_hash, recipient_email, expires_at, accepted_at, accepted_by_user_id, revoked_at, created_at FROM vault_invites WHERE id = $1"
        )
        .bind(invite_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(map_db_error)?;

        Ok(row.map(|r| {
            let role_str: String = r.get("role");
            let role = match role_str.as_str() {
                "administrator" => VaultRole::Administrator,
                "editor" => VaultRole::Editor,
                _ => VaultRole::Viewer,
            };
            VaultInvite {
                id: r.get("id"),
                vault_id: r.get("vault_id"),
                inviter_user_id: r.get("inviter_user_id"),
                role,
                invite_token_hash: r.get("invite_token_hash"),
                recipient_email: r.get("recipient_email"),
                expires_at: from_timestamptz(r.get("expires_at")),
                accepted_at: r
                    .get::<Option<DateTime<Utc>>, _>("accepted_at")
                    .map(from_timestamptz),
                accepted_by_user_id: r.get("accepted_by_user_id"),
                revoked_at: r
                    .get::<Option<DateTime<Utc>>, _>("revoked_at")
                    .map(from_timestamptz),
                created_at: from_timestamptz(r.get("created_at")),
            }
        }))
    }

    async fn find_invite_by_hash(
        &self,
        token_hash: &str,
    ) -> Result<Option<VaultInvite>, DomainError> {
        let row = sqlx::query(
            "SELECT id, vault_id, inviter_user_id, role, invite_token_hash, recipient_email, expires_at, accepted_at, accepted_by_user_id, revoked_at, created_at FROM vault_invites WHERE invite_token_hash = $1"
        )
        .bind(token_hash)
        .fetch_optional(&self.pool)
        .await
        .map_err(map_db_error)?;

        Ok(row.map(|r| {
            let role_str: String = r.get("role");
            let role = match role_str.as_str() {
                "administrator" => VaultRole::Administrator,
                "editor" => VaultRole::Editor,
                _ => VaultRole::Viewer,
            };
            VaultInvite {
                id: r.get("id"),
                vault_id: r.get("vault_id"),
                inviter_user_id: r.get("inviter_user_id"),
                role,
                invite_token_hash: r.get("invite_token_hash"),
                recipient_email: r.get("recipient_email"),
                expires_at: from_timestamptz(r.get("expires_at")),
                accepted_at: r
                    .get::<Option<DateTime<Utc>>, _>("accepted_at")
                    .map(from_timestamptz),
                accepted_by_user_id: r.get("accepted_by_user_id"),
                revoked_at: r
                    .get::<Option<DateTime<Utc>>, _>("revoked_at")
                    .map(from_timestamptz),
                created_at: from_timestamptz(r.get("created_at")),
            }
        }))
    }

    async fn list_active_invites(&self, vault_id: Uuid) -> Result<Vec<VaultInvite>, DomainError> {
        let rows = sqlx::query(
            "SELECT id, vault_id, inviter_user_id, role, invite_token_hash, recipient_email, expires_at, accepted_at, accepted_by_user_id, revoked_at, created_at FROM vault_invites WHERE vault_id = $1 AND accepted_at IS NULL AND revoked_at IS NULL AND expires_at > NOW() ORDER BY created_at DESC"
        )
        .bind(vault_id)
        .fetch_all(&self.pool)
        .await
        .map_err(map_db_error)?;

        Ok(rows
            .into_iter()
            .map(|r| {
                let role_str: String = r.get("role");
                let role = match role_str.as_str() {
                    "administrator" => VaultRole::Administrator,
                    "editor" => VaultRole::Editor,
                    _ => VaultRole::Viewer,
                };
                VaultInvite {
                    id: r.get("id"),
                    vault_id: r.get("vault_id"),
                    inviter_user_id: r.get("inviter_user_id"),
                    role,
                    invite_token_hash: r.get("invite_token_hash"),
                    recipient_email: r.get("recipient_email"),
                    expires_at: from_timestamptz(r.get("expires_at")),
                    accepted_at: r
                        .get::<Option<DateTime<Utc>>, _>("accepted_at")
                        .map(from_timestamptz),
                    accepted_by_user_id: r.get("accepted_by_user_id"),
                    revoked_at: r
                        .get::<Option<DateTime<Utc>>, _>("revoked_at")
                        .map(from_timestamptz),
                    created_at: from_timestamptz(r.get("created_at")),
                }
            })
            .collect())
    }

    async fn revoke_invite(&self, invite_id: Uuid, revoked_at: i64) -> Result<(), DomainError> {
        sqlx::query(
            "UPDATE vault_invites SET revoked_at = $1 WHERE id = $2 AND revoked_at IS NULL AND accepted_at IS NULL"
        )
        .bind(to_timestamptz(revoked_at))
        .bind(invite_id)
        .execute(&self.pool)
        .await
        .map_err(map_db_error)?;

        Ok(())
    }

    async fn accept_invite(
        &self,
        invite_id: Uuid,
        accepted_by_user_id: Uuid,
        accepted_at: i64,
    ) -> Result<(), DomainError> {
        let mut tx = self.pool.begin().await.map_err(map_db_error)?;

        let row = sqlx::query(
            "SELECT vault_id, role, expires_at, accepted_at, revoked_at FROM vault_invites WHERE id = $1 FOR UPDATE"
        )
        .bind(invite_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(map_db_error)?;

        let (vault_id, role_str, expires_at, accepted, revoked) = match row {
            Some(r) => (
                r.get::<Uuid, _>("vault_id"),
                r.get::<String, _>("role"),
                from_timestamptz(r.get("expires_at")),
                r.get::<Option<DateTime<Utc>>, _>("accepted_at").is_some(),
                r.get::<Option<DateTime<Utc>>, _>("revoked_at").is_some(),
            ),
            None => return Err(DomainError::InviteNotFound),
        };

        if accepted {
            return Err(DomainError::InviteAlreadyAccepted);
        }
        if revoked {
            return Err(DomainError::InviteRevoked);
        }
        if expires_at <= accepted_at {
            return Err(DomainError::InviteExpired);
        }

        sqlx::query(
            "UPDATE vault_invites SET accepted_at = $1, accepted_by_user_id = $2 WHERE id = $3",
        )
        .bind(to_timestamptz(accepted_at))
        .bind(accepted_by_user_id)
        .bind(invite_id)
        .execute(&mut *tx)
        .await
        .map_err(map_db_error)?;

        sqlx::query(
            r#"
            INSERT INTO vault_members (vault_id, user_id, role, joined_at)
            VALUES ($1, $2, $3, $4)
            ON CONFLICT (vault_id, user_id) DO UPDATE SET role = EXCLUDED.role
            "#,
        )
        .bind(vault_id)
        .bind(accepted_by_user_id)
        .bind(&role_str)
        .bind(to_timestamptz(accepted_at))
        .execute(&mut *tx)
        .await
        .map_err(map_db_error)?;

        tx.commit().await.map_err(map_db_error)?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// KeyEnvelopeRepository
// ---------------------------------------------------------------------------

#[async_trait]
impl KeyEnvelopeRepository for PgStore {
    async fn save_envelopes(&self, envelopes: &[VaultKeyEnvelope]) -> Result<(), DomainError> {
        let mut tx = self.pool.begin().await.map_err(map_db_error)?;

        for env in envelopes {
            sqlx::query(
                r#"
                INSERT INTO vault_key_envelopes (vault_id, epoch, recipient_device_id, sender_device_id, wrapped_dek, key_agreement_ephemeral_pk, created_at)
                VALUES ($1, $2, $3, $4, $5, $6, $7)
                ON CONFLICT (vault_id, epoch, recipient_device_id) DO UPDATE SET
                    sender_device_id = EXCLUDED.sender_device_id,
                    wrapped_dek = EXCLUDED.wrapped_dek,
                    key_agreement_ephemeral_pk = EXCLUDED.key_agreement_ephemeral_pk
                "#
            )
            .bind(env.vault_id)
            .bind(env.epoch as i32)
            .bind(env.recipient_device_id)
            .bind(env.sender_device_id)
            .bind(&env.wrapped_dek)
            .bind(&env.key_agreement_ephemeral_pk)
            .bind(to_timestamptz(env.created_at))
            .execute(&mut *tx)
            .await
            .map_err(map_db_error)?;
        }

        tx.commit().await.map_err(map_db_error)?;
        Ok(())
    }

    async fn get_envelopes_for_device(
        &self,
        vault_id: Uuid,
        recipient_device_id: Uuid,
        epoch: Option<u32>,
    ) -> Result<Vec<VaultKeyEnvelope>, DomainError> {
        let rows = if let Some(ep) = epoch {
            sqlx::query(
                "SELECT vault_id, epoch, recipient_device_id, sender_device_id, wrapped_dek, key_agreement_ephemeral_pk, created_at FROM vault_key_envelopes WHERE vault_id = $1 AND recipient_device_id = $2 AND epoch = $3 ORDER BY epoch ASC"
            )
            .bind(vault_id)
            .bind(recipient_device_id)
            .bind(ep as i32)
            .fetch_all(&self.pool)
            .await
            .map_err(map_db_error)?
        } else {
            sqlx::query(
                "SELECT vault_id, epoch, recipient_device_id, sender_device_id, wrapped_dek, key_agreement_ephemeral_pk, created_at FROM vault_key_envelopes WHERE vault_id = $1 AND recipient_device_id = $2 ORDER BY epoch ASC"
            )
            .bind(vault_id)
            .bind(recipient_device_id)
            .fetch_all(&self.pool)
            .await
            .map_err(map_db_error)?
        };

        Ok(rows
            .into_iter()
            .map(|r| VaultKeyEnvelope {
                vault_id: r.get("vault_id"),
                epoch: r.get::<i32, _>("epoch") as u32,
                recipient_device_id: r.get("recipient_device_id"),
                sender_device_id: r.get("sender_device_id"),
                wrapped_dek: r.get("wrapped_dek"),
                key_agreement_ephemeral_pk: r.get("key_agreement_ephemeral_pk"),
                created_at: from_timestamptz(r.get("created_at")),
            })
            .collect())
    }

    async fn list_all_envelopes_for_vault(
        &self,
        vault_id: Uuid,
        epoch: Option<u32>,
    ) -> Result<Vec<VaultKeyEnvelope>, DomainError> {
        let rows = if let Some(ep) = epoch {
            sqlx::query(
                "SELECT vault_id, epoch, recipient_device_id, sender_device_id, wrapped_dek, key_agreement_ephemeral_pk, created_at FROM vault_key_envelopes WHERE vault_id = $1 AND epoch = $2 ORDER BY epoch ASC"
            )
            .bind(vault_id)
            .bind(ep as i32)
            .fetch_all(&self.pool)
            .await
            .map_err(map_db_error)?
        } else {
            sqlx::query(
                "SELECT vault_id, epoch, recipient_device_id, sender_device_id, wrapped_dek, key_agreement_ephemeral_pk, created_at FROM vault_key_envelopes WHERE vault_id = $1 ORDER BY epoch ASC"
            )
            .bind(vault_id)
            .fetch_all(&self.pool)
            .await
            .map_err(map_db_error)?
        };

        Ok(rows
            .into_iter()
            .map(|r| VaultKeyEnvelope {
                vault_id: r.get("vault_id"),
                epoch: r.get::<i32, _>("epoch") as u32,
                recipient_device_id: r.get("recipient_device_id"),
                sender_device_id: r.get("sender_device_id"),
                wrapped_dek: r.get("wrapped_dek"),
                key_agreement_ephemeral_pk: r.get("key_agreement_ephemeral_pk"),
                created_at: from_timestamptz(r.get("created_at")),
            })
            .collect())
    }
}

// ---------------------------------------------------------------------------
// AuditRepository
// ---------------------------------------------------------------------------

#[async_trait]
impl AuditRepository for PgStore {
    async fn append_audit_event(&self, event: &mut AuditEvent) -> Result<(), DomainError> {
        let mut tx = self.pool.begin().await.map_err(map_db_error)?;

        let pred_row = sqlx::query(
            "SELECT event_hash FROM audit_events WHERE vault_id = $1 ORDER BY id DESC LIMIT 1 FOR UPDATE"
        )
        .bind(event.vault_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(map_db_error)?;

        let pred_hash = pred_row
            .map(|r| r.get::<String, _>("event_hash"))
            .unwrap_or_else(|| GENESIS_AUDIT_HASH.to_string());

        event.predecessor_hash = pred_hash;

        let details_val = event
            .details
            .as_ref()
            .and_then(|s| serde_json::from_str::<serde_json::Value>(s).ok());

        let row = sqlx::query(
            r#"
            INSERT INTO audit_events (vault_id, tenant_id, actor_user_id, actor_device_id, action, target_type, target_id, details, predecessor_hash, event_hash, created_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
            RETURNING id
            "#
        )
        .bind(event.vault_id)
        .bind(event.tenant_id)
        .bind(event.actor_user_id)
        .bind(event.actor_device_id)
        .bind(&event.action)
        .bind(&event.target_type)
        .bind(&event.target_id)
        .bind(details_val)
        .bind(&event.predecessor_hash)
        .bind("PENDING")
        .bind(to_timestamptz(event.created_at))
        .fetch_one(&mut *tx)
        .await
        .map_err(map_db_error)?;

        let assigned_id: i64 = row.get("id");
        event.id = assigned_id;
        event.event_hash = compute_audit_hash(
            event.id,
            event.vault_id,
            event.actor_user_id,
            &event.action,
            &event.target_type,
            &event.target_id,
            &event.predecessor_hash,
            event.created_at,
        );

        sqlx::query("UPDATE audit_events SET event_hash = $1 WHERE id = $2")
            .bind(&event.event_hash)
            .bind(event.id)
            .execute(&mut *tx)
            .await
            .map_err(map_db_error)?;

        tx.commit().await.map_err(map_db_error)?;
        Ok(())
    }

    async fn list_audit_events(
        &self,
        vault_id: Uuid,
        limit: usize,
        offset: usize,
    ) -> Result<Vec<AuditEvent>, DomainError> {
        let rows = sqlx::query(
            r#"
            SELECT id, vault_id, tenant_id, actor_user_id, actor_device_id, action, target_type, target_id, details, predecessor_hash, event_hash, created_at
            FROM audit_events
            WHERE vault_id = $1
            ORDER BY id ASC
            LIMIT $2 OFFSET $3
            "#
        )
        .bind(vault_id)
        .bind(limit as i64)
        .bind(offset as i64)
        .fetch_all(&self.pool)
        .await
        .map_err(map_db_error)?;

        Ok(rows
            .into_iter()
            .map(|r| {
                let details_val: Option<serde_json::Value> = r.get("details");
                AuditEvent {
                    id: r.get("id"),
                    vault_id: r.get("vault_id"),
                    tenant_id: r.get("tenant_id"),
                    actor_user_id: r.get("actor_user_id"),
                    actor_device_id: r.get("actor_device_id"),
                    action: r.get("action"),
                    target_type: r.get("target_type"),
                    target_id: r.get("target_id"),
                    details: details_val.map(|v| v.to_string()),
                    predecessor_hash: r.get("predecessor_hash"),
                    event_hash: r.get("event_hash"),
                    created_at: from_timestamptz(r.get("created_at")),
                }
            })
            .collect())
    }

    async fn get_latest_audit_hash(&self, vault_id: Uuid) -> Result<String, DomainError> {
        let row = sqlx::query(
            "SELECT event_hash FROM audit_events WHERE vault_id = $1 ORDER BY id DESC LIMIT 1",
        )
        .bind(vault_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(map_db_error)?;

        Ok(row
            .map(|r| r.get::<String, _>("event_hash"))
            .unwrap_or_else(|| GENESIS_AUDIT_HASH.to_string()))
    }
}

// ---------------------------------------------------------------------------
// SyncRepository
// ---------------------------------------------------------------------------

#[async_trait]
impl SyncRepository for PgStore {
    async fn find_record(
        &self,
        vault_id: Uuid,
        object_id: &str,
    ) -> Result<Option<Record>, DomainError> {
        let row = sqlx::query(
            r#"
            SELECT vault_id, object_id, entity_type, current_revision, key_epoch, author_device_id, deleted, encrypted_envelope, ciphertext_digest, last_server_sequence, updated_at
            FROM records WHERE vault_id = $1 AND object_id = $2
            "#
        )
        .bind(vault_id)
        .bind(object_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(map_db_error)?;

        Ok(row.map(|r| {
            let env_val: Option<serde_json::Value> = r.get("encrypted_envelope");
            Record {
                vault_id: r.get("vault_id"),
                object_id: r.get("object_id"),
                entity_type: r.get("entity_type"),
                current_revision: r.get::<i64, _>("current_revision") as u64,
                key_epoch: r.get::<i32, _>("key_epoch") as u32,
                author_device_id: r.get("author_device_id"),
                deleted: r.get("deleted"),
                encrypted_envelope: env_val.map(|v| v.to_string()),
                ciphertext_digest: r.get("ciphertext_digest"),
                last_server_sequence: r.get::<i64, _>("last_server_sequence") as u64,
                updated_at: from_timestamptz(r.get("updated_at")),
            }
        }))
    }

    async fn find_idempotency(
        &self,
        vault_id: Uuid,
        idempotency_key: &str,
    ) -> Result<Option<MutationIdempotency>, DomainError> {
        let row = sqlx::query(
            "SELECT vault_id, idempotency_key, device_id, request_hash, response_payload, created_at FROM mutation_idempotency WHERE vault_id = $1 AND idempotency_key = $2"
        )
        .bind(vault_id)
        .bind(idempotency_key)
        .fetch_optional(&self.pool)
        .await
        .map_err(map_db_error)?;

        Ok(row.map(|r| {
            let resp_val: serde_json::Value = r.get("response_payload");
            MutationIdempotency {
                vault_id: r.get("vault_id"),
                idempotency_key: r.get("idempotency_key"),
                device_id: r.get("device_id"),
                request_hash: r.get("request_hash"),
                response_payload: resp_val.to_string(),
                created_at: from_timestamptz(r.get("created_at")),
            }
        }))
    }

    async fn apply_commit_batch(
        &self,
        vault_id: Uuid,
        device_id: Uuid,
        req: &CommitBatchRequest,
        request_hash: &str,
    ) -> Result<CommitBatchResponse, DomainError> {
        let mut tx = self.pool.begin().await.map_err(map_db_error)?;

        // 1. Lock vault row for concurrency control
        let vault_row = sqlx::query(
            "SELECT server_sequence, active_key_epoch, deleted_at FROM vaults WHERE id = $1 FOR UPDATE",
        )
        .bind(vault_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(map_db_error)?;

        let (base_sequence, active_key_epoch) = match vault_row {
            Some(r) => {
                let deleted: Option<DateTime<Utc>> = r.get("deleted_at");
                if deleted.is_some() {
                    return Err(DomainError::VaultNotFound(vault_id));
                }
                (
                    r.get::<i64, _>("server_sequence") as u64,
                    r.get::<i32, _>("active_key_epoch") as u32,
                )
            }
            None => return Err(DomainError::VaultNotFound(vault_id)),
        };

        // Serialize authorization with device revocation and membership updates.
        // The vault lock above also serializes key rotation and deletion.
        let device = sqlx::query("SELECT user_id, revoked_at FROM devices WHERE id = $1 FOR SHARE")
            .bind(device_id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(map_db_error)?
            .ok_or(DomainError::DeviceNotFound)?;
        if device.get::<Option<i64>, _>("revoked_at").is_some() {
            return Err(DomainError::DeviceRevoked);
        }
        let user_id: Uuid = device.get("user_id");
        let member = sqlx::query(
            "SELECT role FROM vault_members WHERE vault_id = $1 AND user_id = $2 FOR SHARE",
        )
        .bind(vault_id)
        .bind(user_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(map_db_error)?
        .ok_or(DomainError::NotFound)?;
        let role: String = member.get("role");
        if !matches!(role.as_str(), "owner" | "administrator" | "editor") {
            return Err(DomainError::PermissionDenied(
                "Viewers do not have write access to this vault".to_string(),
            ));
        }

        // Return an authorized exact retry without applying another mutation.
        let idem_row = sqlx::query(
            "SELECT device_id, request_hash, response_payload FROM mutation_idempotency WHERE vault_id = $1 AND idempotency_key = $2",
        )
        .bind(vault_id)
        .bind(&req.idempotency_key)
        .fetch_optional(&mut *tx)
        .await
        .map_err(map_db_error)?;

        if let Some(r) = idem_row {
            let existing_hash: String = r.get("request_hash");
            if r.get::<Uuid, _>("device_id") == device_id && existing_hash == request_hash {
                let payload: serde_json::Value = r.get("response_payload");
                let cached: CommitBatchResponse = serde_json::from_value(payload)
                    .map_err(|e| DomainError::Internal(e.to_string()))?;
                return Ok(cached);
            } else {
                return Err(DomainError::IdempotencyConflict {
                    key: req.idempotency_key.clone(),
                });
            }
        }

        // Validate key epoch for a new mutation.
        for m in &req.mutations {
            if m.key_epoch < active_key_epoch {
                return Err(DomainError::StaleKeyEpoch {
                    current: active_key_epoch,
                    provided: m.key_epoch,
                });
            }
            if m.key_epoch > active_key_epoch {
                return Err(DomainError::FutureKeyEpoch {
                    current: active_key_epoch,
                    provided: m.key_epoch,
                });
            }
        }

        // 4. Anti-replay monotonic device counter check
        let counter_row = sqlx::query(
            "SELECT last_device_counter FROM device_sync_counters WHERE vault_id = $1 AND device_id = $2 FOR UPDATE",
        )
        .bind(vault_id)
        .bind(device_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(map_db_error)?;

        let mut last_counter: u64 = counter_row
            .map(|r| r.get::<i64, _>("last_device_counter") as u64)
            .unwrap_or(0);
        for m in &req.mutations {
            if m.device_counter <= last_counter {
                return Err(DomainError::Conflict(format!(
                    "Stale or replayed device counter: got {}, expected > {}",
                    m.device_counter, last_counter
                )));
            }
            last_counter = m.device_counter;
        }

        // 5. CAS and revision validation for each mutation
        let now = Utc::now().timestamp();
        let mut applied_acks = Vec::with_capacity(req.mutations.len());

        for (idx, mutation) in req.mutations.iter().enumerate() {
            let mutation_seq = base_sequence + 1 + idx as u64;

            let existing_row = sqlx::query(
                "SELECT current_revision, deleted FROM records WHERE vault_id = $1 AND object_id = $2 FOR UPDATE",
            )
            .bind(vault_id)
            .bind(&mutation.object_id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(map_db_error)?;

            let existing = existing_row.map(|r| {
                (
                    r.get::<i64, _>("current_revision") as u64,
                    r.get::<bool, _>("deleted"),
                )
            });

            let assigned_revision = match (mutation.expected_revision, existing) {
                (0, None) => 1,
                (0, Some((rev, deleted))) => {
                    if !deleted {
                        return Err(DomainError::RevisionConflict {
                            object_id: mutation.object_id.clone(),
                            expected: 0,
                            actual: rev,
                        });
                    }
                    rev + 1
                }
                (expected, None) => {
                    return Err(DomainError::RevisionConflict {
                        object_id: mutation.object_id.clone(),
                        expected,
                        actual: 0,
                    });
                }
                (expected, Some((rev, _))) => {
                    if rev != expected {
                        return Err(DomainError::RevisionConflict {
                            object_id: mutation.object_id.clone(),
                            expected,
                            actual: rev,
                        });
                    }
                    expected + 1
                }
            };

            let env_val = mutation
                .encrypted_envelope
                .as_ref()
                .map(|e| serde_json::to_value(e).unwrap());
            let digest = shellumi_server_crypto::compute_ciphertext_digest(
                mutation.encrypted_envelope.as_ref(),
            );

            // Insert into change_log
            sqlx::query(
                r#"
                INSERT INTO change_log (vault_id, sequence, object_id, entity_type, revision, deleted, author_device_id, encrypted_envelope, ciphertext_digest, created_at)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
                "#,
            )
            .bind(vault_id)
            .bind(mutation_seq as i64)
            .bind(&mutation.object_id)
            .bind(&mutation.entity_type)
            .bind(assigned_revision as i64)
            .bind(mutation.deleted)
            .bind(device_id)
            .bind(env_val.clone())
            .bind(&digest)
            .bind(to_timestamptz(now))
            .execute(&mut *tx)
            .await
            .map_err(map_db_error)?;

            // Upsert into records
            sqlx::query(
                r#"
                INSERT INTO records (vault_id, object_id, entity_type, current_revision, key_epoch, author_device_id, deleted, encrypted_envelope, ciphertext_digest, last_server_sequence, updated_at)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
                ON CONFLICT (vault_id, object_id) DO UPDATE SET
                    entity_type = EXCLUDED.entity_type,
                    current_revision = EXCLUDED.current_revision,
                    key_epoch = EXCLUDED.key_epoch,
                    author_device_id = EXCLUDED.author_device_id,
                    deleted = EXCLUDED.deleted,
                    encrypted_envelope = EXCLUDED.encrypted_envelope,
                    ciphertext_digest = EXCLUDED.ciphertext_digest,
                    last_server_sequence = EXCLUDED.last_server_sequence,
                    updated_at = EXCLUDED.updated_at
                "#,
            )
            .bind(vault_id)
            .bind(&mutation.object_id)
            .bind(&mutation.entity_type)
            .bind(assigned_revision as i64)
            .bind(mutation.key_epoch as i32)
            .bind(device_id)
            .bind(mutation.deleted)
            .bind(env_val)
            .bind(&digest)
            .bind(mutation_seq as i64)
            .bind(to_timestamptz(now))
            .execute(&mut *tx)
            .await
            .map_err(map_db_error)?;

            applied_acks.push(MutationAck {
                object_id: mutation.object_id.clone(),
                assigned_revision,
                server_sequence: mutation_seq,
                deleted: mutation.deleted,
            });
        }

        let final_sequence = base_sequence + req.mutations.len() as u64;

        // 6. Update vault sequence
        sqlx::query("UPDATE vaults SET server_sequence = $1, updated_at = $2 WHERE id = $3")
            .bind(final_sequence as i64)
            .bind(to_timestamptz(now))
            .bind(vault_id)
            .execute(&mut *tx)
            .await
            .map_err(map_db_error)?;

        // 7. Upsert device_sync_counters
        sqlx::query(
            r#"
            INSERT INTO device_sync_counters (vault_id, device_id, last_device_counter, updated_at)
            VALUES ($1, $2, $3, $4)
            ON CONFLICT (vault_id, device_id) DO UPDATE SET
                last_device_counter = EXCLUDED.last_device_counter,
                updated_at = EXCLUDED.updated_at
            "#,
        )
        .bind(vault_id)
        .bind(device_id)
        .bind(last_counter as i64)
        .bind(to_timestamptz(now))
        .execute(&mut *tx)
        .await
        .map_err(map_db_error)?;

        // 8. Insert mutation_idempotency
        let response = CommitBatchResponse {
            vault_id,
            commit_sequence: final_sequence,
            next_cursor: format!("seq:{}", final_sequence),
            applied: applied_acks,
        };
        let response_json =
            serde_json::to_value(&response).map_err(|e| DomainError::Internal(e.to_string()))?;

        sqlx::query(
            r#"
            INSERT INTO mutation_idempotency (vault_id, idempotency_key, device_id, request_hash, response_payload, created_at)
            VALUES ($1, $2, $3, $4, $5, $6)
            "#,
        )
        .bind(vault_id)
        .bind(&req.idempotency_key)
        .bind(device_id)
        .bind(request_hash)
        .bind(response_json)
        .bind(to_timestamptz(now))
        .execute(&mut *tx)
        .await
        .map_err(map_db_error)?;

        tx.commit().await.map_err(map_db_error)?;

        Ok(response)
    }

    async fn get_changes(
        &self,
        vault_id: Uuid,
        since_sequence: u64,
        limit: usize,
    ) -> Result<Vec<ChangeLogEntry>, DomainError> {
        let rows = sqlx::query(
            r#"
            SELECT vault_id, sequence, object_id, entity_type, revision, deleted, author_device_id, encrypted_envelope, ciphertext_digest, created_at
            FROM change_log
            WHERE vault_id = $1 AND sequence > $2
            ORDER BY sequence ASC
            LIMIT $3
            "#
        )
        .bind(vault_id)
        .bind(since_sequence as i64)
        .bind(limit as i64)
        .fetch_all(&self.pool)
        .await
        .map_err(map_db_error)?;

        Ok(rows
            .into_iter()
            .map(|r| {
                let env_val: Option<serde_json::Value> = r.get("encrypted_envelope");
                ChangeLogEntry {
                    vault_id: r.get("vault_id"),
                    sequence: r.get::<i64, _>("sequence") as u64,
                    object_id: r.get("object_id"),
                    entity_type: r.get("entity_type"),
                    revision: r.get::<i64, _>("revision") as u64,
                    deleted: r.get("deleted"),
                    author_device_id: r.get("author_device_id"),
                    encrypted_envelope: env_val.map(|v| v.to_string()),
                    ciphertext_digest: r.get("ciphertext_digest"),
                    created_at: from_timestamptz(r.get("created_at")),
                }
            })
            .collect())
    }

    async fn get_snapshot_records(&self, vault_id: Uuid) -> Result<Vec<Record>, DomainError> {
        let rows = sqlx::query(
            r#"
            SELECT vault_id, object_id, entity_type, current_revision, key_epoch, author_device_id, deleted, encrypted_envelope, ciphertext_digest, last_server_sequence, updated_at
            FROM records
            WHERE vault_id = $1 AND deleted = FALSE
            ORDER BY object_id ASC
            "#
        )
        .bind(vault_id)
        .fetch_all(&self.pool)
        .await
        .map_err(map_db_error)?;

        Ok(rows
            .into_iter()
            .map(|r| {
                let env_val: Option<serde_json::Value> = r.get("encrypted_envelope");
                Record {
                    vault_id: r.get("vault_id"),
                    object_id: r.get("object_id"),
                    entity_type: r.get("entity_type"),
                    current_revision: r.get::<i64, _>("current_revision") as u64,
                    key_epoch: r.get::<i32, _>("key_epoch") as u32,
                    author_device_id: r.get("author_device_id"),
                    deleted: r.get("deleted"),
                    encrypted_envelope: env_val.map(|v| v.to_string()),
                    ciphertext_digest: r.get("ciphertext_digest"),
                    last_server_sequence: r.get::<i64, _>("last_server_sequence") as u64,
                    updated_at: from_timestamptz(r.get("updated_at")),
                }
            })
            .collect())
    }

    async fn get_snapshot_consistent(
        &self,
        vault_id: Uuid,
        requested_revision: Option<u64>,
    ) -> Result<(u64, Vec<Record>), DomainError> {
        let mut tx = self.pool.begin().await.map_err(map_db_error)?;

        sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ")
            .execute(&mut *tx)
            .await
            .map_err(map_db_error)?;

        let row = sqlx::query("SELECT server_sequence FROM vaults WHERE id = $1")
            .bind(vault_id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(map_db_error)?;

        let watermark = match row {
            Some(r) => r.get::<i64, _>("server_sequence") as u64,
            None => return Err(DomainError::VaultNotFound(vault_id)),
        };

        if let Some(target_seq) = requested_revision {
            if target_seq > watermark {
                return Err(DomainError::InvalidInput(format!(
                    "Requested snapshot revision {} exceeds current watermark {}",
                    target_seq, watermark
                )));
            }

            if target_seq < watermark {
                return Err(DomainError::InvalidInput(
                    "Historical snapshots are not supported; request the current watermark".into(),
                ));
            }
        }

        let rows = sqlx::query(
            r#"
            SELECT object_id, entity_type, current_revision, key_epoch, author_device_id, deleted, encrypted_envelope, ciphertext_digest, last_server_sequence, updated_at
            FROM records
            WHERE vault_id = $1 AND deleted = FALSE
            ORDER BY object_id ASC
            "#
        )
        .bind(vault_id)
        .fetch_all(&mut *tx)
        .await
        .map_err(map_db_error)?;

        let mut records = Vec::with_capacity(rows.len());
        for r in rows {
            let env_val: Option<serde_json::Value> = r.get("encrypted_envelope");
            let env_str = env_val.map(|v| v.to_string());
            records.push(Record {
                vault_id,
                object_id: r.get("object_id"),
                entity_type: r.get("entity_type"),
                current_revision: r.get::<i64, _>("current_revision") as u64,
                key_epoch: r.get::<i32, _>("key_epoch") as u32,
                author_device_id: r.get("author_device_id"),
                deleted: r.get("deleted"),
                encrypted_envelope: env_str,
                ciphertext_digest: r.get("ciphertext_digest"),
                last_server_sequence: r.get::<i64, _>("last_server_sequence") as u64,
                updated_at: from_timestamptz(r.get("updated_at")),
            });
        }

        tx.commit().await.map_err(map_db_error)?;
        Ok((watermark, records))
    }
}

// ---------------------------------------------------------------------------
// CollabRepository
// ---------------------------------------------------------------------------

#[async_trait]
impl CollabRepository for PgStore {
    async fn create_collab_session(
        &self,
        session: &CollabSession,
        host_participant: &CollabParticipant,
    ) -> Result<(), DomainError> {
        let mut tx = self.pool.begin().await.map_err(map_db_error)?;

        sqlx::query(
            r#"
            INSERT INTO collab_sessions (id, host_user_id, host_device_id, title, mode, active_writer_user_id, active_writer_device_id, lease_token, lease_expires_at, expires_at, terminated_at, created_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
            "#
        )
        .bind(session.id)
        .bind(session.host_user_id)
        .bind(session.host_device_id)
        .bind(&session.title)
        .bind(session.mode.as_str())
        .bind(session.active_writer_user_id)
        .bind(session.active_writer_device_id)
        .bind(session.lease_token as i64)
        .bind(session.lease_expires_at.map(to_timestamptz))
        .bind(to_timestamptz(session.expires_at))
        .bind(session.terminated_at.map(to_timestamptz))
        .bind(to_timestamptz(session.created_at))
        .execute(&mut *tx)
        .await
        .map_err(map_db_error)?;

        sqlx::query(
            "INSERT INTO collab_participants (session_id, user_id, device_id, role, joined_at, revoked_at) VALUES ($1, $2, $3, $4, $5, $6)"
        )
        .bind(host_participant.session_id)
        .bind(host_participant.user_id)
        .bind(host_participant.device_id)
        .bind(host_participant.role.as_str())
        .bind(to_timestamptz(host_participant.joined_at))
        .bind(host_participant.revoked_at.map(to_timestamptz))
        .execute(&mut *tx)
        .await
        .map_err(map_db_error)?;

        tx.commit().await.map_err(map_db_error)?;
        Ok(())
    }

    async fn find_collab_session(
        &self,
        session_id: Uuid,
    ) -> Result<Option<CollabSession>, DomainError> {
        let row = sqlx::query(
            r#"
            SELECT id, host_user_id, host_device_id, title, mode, active_writer_user_id, active_writer_device_id, lease_token, lease_expires_at, expires_at, terminated_at, created_at
            FROM collab_sessions WHERE id = $1
            "#
        )
        .bind(session_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(map_db_error)?;

        Ok(row.map(|r| {
            let mode_str: String = r.get("mode");
            let mode = match mode_str.as_str() {
                "controllable" => CollabMode::Controllable,
                _ => CollabMode::ReadOnly,
            };
            CollabSession {
                id: r.get("id"),
                host_user_id: r.get("host_user_id"),
                host_device_id: r.get("host_device_id"),
                title: r.get("title"),
                mode,
                active_writer_user_id: r.get("active_writer_user_id"),
                active_writer_device_id: r.get("active_writer_device_id"),
                lease_token: r.get::<i64, _>("lease_token") as u64,
                lease_expires_at: r
                    .get::<Option<DateTime<Utc>>, _>("lease_expires_at")
                    .map(from_timestamptz),
                expires_at: from_timestamptz(r.get("expires_at")),
                terminated_at: r
                    .get::<Option<DateTime<Utc>>, _>("terminated_at")
                    .map(from_timestamptz),
                created_at: from_timestamptz(r.get("created_at")),
            }
        }))
    }

    async fn list_active_collab_sessions_for_user(
        &self,
        user_id: Uuid,
    ) -> Result<Vec<CollabSession>, DomainError> {
        let rows = sqlx::query(
            r#"
            SELECT s.id, s.host_user_id, s.host_device_id, s.title, s.mode, s.active_writer_user_id, s.active_writer_device_id, s.lease_token, s.lease_expires_at, s.expires_at, s.terminated_at, s.created_at
            FROM collab_sessions s
            JOIN collab_participants p ON s.id = p.session_id
            WHERE p.user_id = $1 AND s.terminated_at IS NULL AND s.expires_at > NOW()
            ORDER BY s.created_at DESC
            "#
        )
        .bind(user_id)
        .fetch_all(&self.pool)
        .await
        .map_err(map_db_error)?;

        Ok(rows
            .into_iter()
            .map(|r| {
                let mode_str: String = r.get("mode");
                let mode = match mode_str.as_str() {
                    "controllable" => CollabMode::Controllable,
                    _ => CollabMode::ReadOnly,
                };
                CollabSession {
                    id: r.get("id"),
                    host_user_id: r.get("host_user_id"),
                    host_device_id: r.get("host_device_id"),
                    title: r.get("title"),
                    mode,
                    active_writer_user_id: r.get("active_writer_user_id"),
                    active_writer_device_id: r.get("active_writer_device_id"),
                    lease_token: r.get::<i64, _>("lease_token") as u64,
                    lease_expires_at: r
                        .get::<Option<DateTime<Utc>>, _>("lease_expires_at")
                        .map(from_timestamptz),
                    expires_at: from_timestamptz(r.get("expires_at")),
                    terminated_at: r
                        .get::<Option<DateTime<Utc>>, _>("terminated_at")
                        .map(from_timestamptz),
                    created_at: from_timestamptz(r.get("created_at")),
                }
            })
            .collect())
    }

    async fn add_collab_participant(
        &self,
        participant: &CollabParticipant,
    ) -> Result<(), DomainError> {
        sqlx::query(
            r#"
            INSERT INTO collab_participants (session_id, user_id, device_id, role, joined_at, revoked_at)
            VALUES ($1, $2, $3, $4, $5, $6)
            ON CONFLICT (session_id, user_id, device_id) DO UPDATE SET
                role = EXCLUDED.role,
                revoked_at = NULL
            "#
        )
        .bind(participant.session_id)
        .bind(participant.user_id)
        .bind(participant.device_id)
        .bind(participant.role.as_str())
        .bind(to_timestamptz(participant.joined_at))
        .bind(participant.revoked_at.map(to_timestamptz))
        .execute(&self.pool)
        .await
        .map_err(map_db_error)?;

        Ok(())
    }

    async fn find_collab_participant(
        &self,
        session_id: Uuid,
        user_id: Uuid,
        device_id: Uuid,
    ) -> Result<Option<CollabParticipant>, DomainError> {
        let row = sqlx::query(
            "SELECT session_id, user_id, device_id, role, joined_at, revoked_at FROM collab_participants WHERE session_id = $1 AND user_id = $2 AND device_id = $3"
        )
        .bind(session_id)
        .bind(user_id)
        .bind(device_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(map_db_error)?;

        Ok(row.map(|r| {
            let role_str: String = r.get("role");
            let role = match role_str.as_str() {
                "host" => CollabRole::Host,
                "writer" => CollabRole::Writer,
                _ => CollabRole::Viewer,
            };
            CollabParticipant {
                session_id: r.get("session_id"),
                user_id: r.get("user_id"),
                device_id: r.get("device_id"),
                role,
                joined_at: from_timestamptz(r.get("joined_at")),
                revoked_at: r
                    .get::<Option<DateTime<Utc>>, _>("revoked_at")
                    .map(from_timestamptz),
            }
        }))
    }

    async fn list_collab_participants(
        &self,
        session_id: Uuid,
    ) -> Result<Vec<CollabParticipant>, DomainError> {
        let rows = sqlx::query(
            "SELECT session_id, user_id, device_id, role, joined_at, revoked_at FROM collab_participants WHERE session_id = $1 ORDER BY joined_at ASC"
        )
        .bind(session_id)
        .fetch_all(&self.pool)
        .await
        .map_err(map_db_error)?;

        Ok(rows
            .into_iter()
            .map(|r| {
                let role_str: String = r.get("role");
                let role = match role_str.as_str() {
                    "host" => CollabRole::Host,
                    "writer" => CollabRole::Writer,
                    _ => CollabRole::Viewer,
                };
                CollabParticipant {
                    session_id: r.get("session_id"),
                    user_id: r.get("user_id"),
                    device_id: r.get("device_id"),
                    role,
                    joined_at: from_timestamptz(r.get("joined_at")),
                    revoked_at: r
                        .get::<Option<DateTime<Utc>>, _>("revoked_at")
                        .map(from_timestamptz),
                }
            })
            .collect())
    }

    async fn revoke_collab_participant(
        &self,
        session_id: Uuid,
        user_id: Uuid,
        device_id: Uuid,
        revoked_at: i64,
    ) -> Result<(), DomainError> {
        sqlx::query(
            "UPDATE collab_participants SET revoked_at = $1 WHERE session_id = $2 AND user_id = $3 AND device_id = $4"
        )
        .bind(to_timestamptz(revoked_at))
        .bind(session_id)
        .bind(user_id)
        .bind(device_id)
        .execute(&self.pool)
        .await
        .map_err(map_db_error)?;

        Ok(())
    }

    async fn grant_collab_writer_lease(
        &self,
        session_id: Uuid,
        writer_user_id: Uuid,
        writer_device_id: Uuid,
        lease_expires_at: Option<i64>,
    ) -> Result<u64, DomainError> {
        let row = sqlx::query(
            r#"
            UPDATE collab_sessions
            SET active_writer_user_id = $1,
                active_writer_device_id = $2,
                lease_token = lease_token + 1,
                lease_expires_at = $3
            WHERE id = $4
            RETURNING lease_token
            "#,
        )
        .bind(writer_user_id)
        .bind(writer_device_id)
        .bind(lease_expires_at.map(to_timestamptz))
        .bind(session_id)
        .fetch_one(&self.pool)
        .await
        .map_err(map_db_error)?;

        let token: i64 = row.get("lease_token");
        Ok(token as u64)
    }

    async fn revoke_collab_writer_lease(&self, session_id: Uuid) -> Result<u64, DomainError> {
        let row = sqlx::query(
            r#"
            UPDATE collab_sessions
            SET active_writer_user_id = NULL,
                active_writer_device_id = NULL,
                lease_token = lease_token + 1,
                lease_expires_at = NULL
            WHERE id = $1
            RETURNING lease_token
            "#,
        )
        .bind(session_id)
        .fetch_one(&self.pool)
        .await
        .map_err(map_db_error)?;

        let token: i64 = row.get("lease_token");
        Ok(token as u64)
    }

    async fn terminate_collab_session(
        &self,
        session_id: Uuid,
        now: i64,
    ) -> Result<(), DomainError> {
        sqlx::query("UPDATE collab_sessions SET terminated_at = $1 WHERE id = $2")
            .bind(to_timestamptz(now))
            .bind(session_id)
            .execute(&self.pool)
            .await
            .map_err(map_db_error)?;

        Ok(())
    }

    async fn append_collab_frame(&self, frame: &CollabFrame) -> Result<(), DomainError> {
        let mut lock = self.collab_frames.write().await;
        let frames = lock.entry(frame.session_id).or_default();
        frames.push(frame.clone());
        if frames.len() > 100 {
            frames.remove(0);
        }
        Ok(())
    }

    async fn get_collab_frames(
        &self,
        session_id: Uuid,
        since_sequence: u64,
        limit: usize,
    ) -> Result<Vec<CollabFrame>, DomainError> {
        let lock = self.collab_frames.read().await;
        if let Some(frames) = lock.get(&session_id) {
            let filtered: Vec<CollabFrame> = frames
                .iter()
                .filter(|f| f.sequence > since_sequence)
                .take(limit)
                .cloned()
                .collect();
            Ok(filtered)
        } else {
            Ok(Vec::new())
        }
    }
}

// ---------------------------------------------------------------------------
// AnyStore: Enum wrapper delegating to either InMemoryStore or PgStore
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub enum AnyStore {
    Memory(InMemoryStore),
    Postgres(PgStore),
}

impl AnyStore {
    pub fn memory() -> Self {
        Self::Memory(InMemoryStore::new())
    }

    pub fn postgres(pg: PgStore) -> Self {
        Self::Postgres(pg)
    }

    pub async fn is_ready(&self) -> bool {
        match self {
            Self::Memory(_) => true,
            Self::Postgres(pg) => pg.is_ready().await,
        }
    }

    pub async fn notify_sync_event(&self, channel: &str, payload: &str) -> Result<(), DomainError> {
        match self {
            Self::Memory(_) => Ok(()),
            Self::Postgres(pg) => pg.notify_sync_event(channel, payload).await,
        }
    }
}

impl Store for AnyStore {}

#[async_trait]
impl SettingsRepository for AnyStore {
    async fn get_settings(&self) -> Result<ServerSettings, DomainError> {
        match self {
            Self::Memory(s) => s.get_settings().await,
            Self::Postgres(s) => s.get_settings().await,
        }
    }

    async fn update_settings(&self, settings: &ServerSettings) -> Result<(), DomainError> {
        match self {
            Self::Memory(s) => s.update_settings(settings).await,
            Self::Postgres(s) => s.update_settings(settings).await,
        }
    }

    async fn mark_bootstrap_consumed(
        &self,
        expected_token_hash: Option<&str>,
    ) -> Result<(), DomainError> {
        match self {
            Self::Memory(s) => s.mark_bootstrap_consumed(expected_token_hash).await,
            Self::Postgres(s) => s.mark_bootstrap_consumed(expected_token_hash).await,
        }
    }

    async fn complete_bootstrap(
        &self,
        expected_token_hash: Option<&str>,
        user: &User,
        org: &Organization,
        session: &Session,
    ) -> Result<(), DomainError> {
        match self {
            Self::Memory(s) => {
                s.complete_bootstrap(expected_token_hash, user, org, session)
                    .await
            }
            Self::Postgres(s) => {
                s.complete_bootstrap(expected_token_hash, user, org, session)
                    .await
            }
        }
    }

    async fn get_or_init_server_keys(&self) -> Result<(Uuid, Vec<u8>), DomainError> {
        match self {
            Self::Memory(s) => s.get_or_init_server_keys().await,
            Self::Postgres(s) => s.get_or_init_server_keys().await,
        }
    }
}

#[async_trait]
impl UserRepository for AnyStore {
    async fn create_user(&self, user: &User) -> Result<(), DomainError> {
        match self {
            Self::Memory(s) => s.create_user(user).await,
            Self::Postgres(s) => s.create_user(user).await,
        }
    }

    async fn find_user_by_id(&self, id: Uuid) -> Result<Option<User>, DomainError> {
        match self {
            Self::Memory(s) => s.find_user_by_id(id).await,
            Self::Postgres(s) => s.find_user_by_id(id).await,
        }
    }

    async fn find_by_identifier(&self, identifier: &str) -> Result<Option<User>, DomainError> {
        match self {
            Self::Memory(s) => s.find_by_identifier(identifier).await,
            Self::Postgres(s) => s.find_by_identifier(identifier).await,
        }
    }

    async fn list_users(&self) -> Result<Vec<User>, DomainError> {
        match self {
            Self::Memory(s) => s.list_users().await,
            Self::Postgres(s) => s.list_users().await,
        }
    }

    async fn update_user(&self, user: &User) -> Result<(), DomainError> {
        match self {
            Self::Memory(s) => s.update_user(user).await,
            Self::Postgres(s) => s.update_user(user).await,
        }
    }

    async fn list_orgs_for_user(
        &self,
        user_id: Uuid,
    ) -> Result<Vec<(Organization, OrgRole)>, DomainError> {
        match self {
            Self::Memory(s) => s.list_orgs_for_user(user_id).await,
            Self::Postgres(s) => s.list_orgs_for_user(user_id).await,
        }
    }
}

#[async_trait]
impl OrgRepository for AnyStore {
    async fn create_org(&self, org: &Organization, owner_id: Uuid) -> Result<(), DomainError> {
        match self {
            Self::Memory(s) => s.create_org(org, owner_id).await,
            Self::Postgres(s) => s.create_org(org, owner_id).await,
        }
    }

    async fn find_org_by_id(&self, id: Uuid) -> Result<Option<Organization>, DomainError> {
        match self {
            Self::Memory(s) => s.find_org_by_id(id).await,
            Self::Postgres(s) => s.find_org_by_id(id).await,
        }
    }

    async fn add_member(
        &self,
        org_id: Uuid,
        user_id: Uuid,
        role: OrgRole,
    ) -> Result<(), DomainError> {
        match self {
            Self::Memory(s) => s.add_member(org_id, user_id, role).await,
            Self::Postgres(s) => s.add_member(org_id, user_id, role).await,
        }
    }

    async fn get_member_role(
        &self,
        org_id: Uuid,
        user_id: Uuid,
    ) -> Result<Option<OrgRole>, DomainError> {
        match self {
            Self::Memory(s) => s.get_member_role(org_id, user_id).await,
            Self::Postgres(s) => s.get_member_role(org_id, user_id).await,
        }
    }
}

#[async_trait]
impl DeviceRepository for AnyStore {
    async fn create_device(&self, device: &Device) -> Result<(), DomainError> {
        match self {
            Self::Memory(s) => s.create_device(device).await,
            Self::Postgres(s) => s.create_device(device).await,
        }
    }

    async fn find_device_by_id(&self, id: Uuid) -> Result<Option<Device>, DomainError> {
        match self {
            Self::Memory(s) => s.find_device_by_id(id).await,
            Self::Postgres(s) => s.find_device_by_id(id).await,
        }
    }

    async fn list_for_user(&self, user_id: Uuid) -> Result<Vec<Device>, DomainError> {
        match self {
            Self::Memory(s) => s.list_for_user(user_id).await,
            Self::Postgres(s) => s.list_for_user(user_id).await,
        }
    }

    async fn revoke_device(&self, device_id: Uuid, user_id: Uuid) -> Result<(), DomainError> {
        match self {
            Self::Memory(s) => s.revoke_device(device_id, user_id).await,
            Self::Postgres(s) => s.revoke_device(device_id, user_id).await,
        }
    }

    async fn update_last_seen(&self, device_id: Uuid, timestamp: i64) -> Result<(), DomainError> {
        match self {
            Self::Memory(s) => s.update_last_seen(device_id, timestamp).await,
            Self::Postgres(s) => s.update_last_seen(device_id, timestamp).await,
        }
    }
}

#[async_trait]
impl SessionRepository for AnyStore {
    async fn create_session(&self, session: &Session) -> Result<(), DomainError> {
        match self {
            Self::Memory(s) => s.create_session(session).await,
            Self::Postgres(s) => s.create_session(session).await,
        }
    }

    async fn find_session_by_id(&self, session_id: Uuid) -> Result<Option<Session>, DomainError> {
        match self {
            Self::Memory(s) => s.find_session_by_id(session_id).await,
            Self::Postgres(s) => s.find_session_by_id(session_id).await,
        }
    }

    async fn find_active_by_token_hash(&self, hash: &str) -> Result<Option<Session>, DomainError> {
        match self {
            Self::Memory(s) => s.find_active_by_token_hash(hash).await,
            Self::Postgres(s) => s.find_active_by_token_hash(hash).await,
        }
    }

    async fn rotate_refresh_token(
        &self,
        old_hash: &str,
        new_session: &mut Session,
    ) -> Result<Uuid, DomainError> {
        match self {
            Self::Memory(s) => s.rotate_refresh_token(old_hash, new_session).await,
            Self::Postgres(s) => s.rotate_refresh_token(old_hash, new_session).await,
        }
    }

    async fn list_sessions_for_user(&self, user_id: Uuid) -> Result<Vec<Session>, DomainError> {
        match self {
            Self::Memory(s) => s.list_sessions_for_user(user_id).await,
            Self::Postgres(s) => s.list_sessions_for_user(user_id).await,
        }
    }

    async fn revoke_session(&self, session_id: Uuid) -> Result<(), DomainError> {
        match self {
            Self::Memory(s) => s.revoke_session(session_id).await,
            Self::Postgres(s) => s.revoke_session(session_id).await,
        }
    }

    async fn revoke_all_for_device(&self, device_id: Uuid) -> Result<(), DomainError> {
        match self {
            Self::Memory(s) => s.revoke_all_for_device(device_id).await,
            Self::Postgres(s) => s.revoke_all_for_device(device_id).await,
        }
    }

    async fn revoke_all_for_user(&self, user_id: Uuid) -> Result<(), DomainError> {
        match self {
            Self::Memory(s) => s.revoke_all_for_user(user_id).await,
            Self::Postgres(s) => s.revoke_all_for_user(user_id).await,
        }
    }
}

#[async_trait]
impl VaultRepository for AnyStore {
    async fn create_vault(
        &self,
        vault: &Vault,
        initial_member: &VaultMember,
    ) -> Result<(), DomainError> {
        match self {
            Self::Memory(s) => s.create_vault(vault, initial_member).await,
            Self::Postgres(s) => s.create_vault(vault, initial_member).await,
        }
    }

    async fn find_vault_by_id(&self, vault_id: Uuid) -> Result<Option<Vault>, DomainError> {
        match self {
            Self::Memory(s) => s.find_vault_by_id(vault_id).await,
            Self::Postgres(s) => s.find_vault_by_id(vault_id).await,
        }
    }

    async fn list_vaults_for_user(
        &self,
        user_id: Uuid,
    ) -> Result<Vec<(Vault, VaultRole)>, DomainError> {
        match self {
            Self::Memory(s) => s.list_vaults_for_user(user_id).await,
            Self::Postgres(s) => s.list_vaults_for_user(user_id).await,
        }
    }

    async fn update_vault_metadata(
        &self,
        vault_id: Uuid,
        encrypted_name: Option<String>,
    ) -> Result<(), DomainError> {
        match self {
            Self::Memory(s) => s.update_vault_metadata(vault_id, encrypted_name).await,
            Self::Postgres(s) => s.update_vault_metadata(vault_id, encrypted_name).await,
        }
    }

    async fn delete_vault(&self, vault_id: Uuid) -> Result<(), DomainError> {
        match self {
            Self::Memory(s) => s.delete_vault(vault_id).await,
            Self::Postgres(s) => s.delete_vault(vault_id).await,
        }
    }

    async fn get_vault_member_role(
        &self,
        vault_id: Uuid,
        user_id: Uuid,
    ) -> Result<Option<VaultRole>, DomainError> {
        match self {
            Self::Memory(s) => s.get_vault_member_role(vault_id, user_id).await,
            Self::Postgres(s) => s.get_vault_member_role(vault_id, user_id).await,
        }
    }

    async fn add_vault_member(&self, member: &VaultMember) -> Result<(), DomainError> {
        match self {
            Self::Memory(s) => s.add_vault_member(member).await,
            Self::Postgres(s) => s.add_vault_member(member).await,
        }
    }

    async fn list_vault_members(&self, vault_id: Uuid) -> Result<Vec<VaultMember>, DomainError> {
        match self {
            Self::Memory(s) => s.list_vault_members(vault_id).await,
            Self::Postgres(s) => s.list_vault_members(vault_id).await,
        }
    }

    async fn remove_vault_member(&self, vault_id: Uuid, user_id: Uuid) -> Result<(), DomainError> {
        match self {
            Self::Memory(s) => s.remove_vault_member(vault_id, user_id).await,
            Self::Postgres(s) => s.remove_vault_member(vault_id, user_id).await,
        }
    }

    async fn count_vault_owners(&self, vault_id: Uuid) -> Result<usize, DomainError> {
        match self {
            Self::Memory(s) => s.count_vault_owners(vault_id).await,
            Self::Postgres(s) => s.count_vault_owners(vault_id).await,
        }
    }

    async fn update_vault_key_epoch(
        &self,
        vault_id: Uuid,
        new_epoch: u32,
    ) -> Result<(), DomainError> {
        match self {
            Self::Memory(s) => s.update_vault_key_epoch(vault_id, new_epoch).await,
            Self::Postgres(s) => s.update_vault_key_epoch(vault_id, new_epoch).await,
        }
    }
}

#[async_trait]
impl InviteRepository for AnyStore {
    async fn create_invite(&self, invite: &VaultInvite) -> Result<(), DomainError> {
        match self {
            Self::Memory(s) => s.create_invite(invite).await,
            Self::Postgres(s) => s.create_invite(invite).await,
        }
    }

    async fn find_invite_by_id(&self, invite_id: Uuid) -> Result<Option<VaultInvite>, DomainError> {
        match self {
            Self::Memory(s) => s.find_invite_by_id(invite_id).await,
            Self::Postgres(s) => s.find_invite_by_id(invite_id).await,
        }
    }

    async fn find_invite_by_hash(
        &self,
        token_hash: &str,
    ) -> Result<Option<VaultInvite>, DomainError> {
        match self {
            Self::Memory(s) => s.find_invite_by_hash(token_hash).await,
            Self::Postgres(s) => s.find_invite_by_hash(token_hash).await,
        }
    }

    async fn list_active_invites(&self, vault_id: Uuid) -> Result<Vec<VaultInvite>, DomainError> {
        match self {
            Self::Memory(s) => s.list_active_invites(vault_id).await,
            Self::Postgres(s) => s.list_active_invites(vault_id).await,
        }
    }

    async fn revoke_invite(&self, invite_id: Uuid, revoked_at: i64) -> Result<(), DomainError> {
        match self {
            Self::Memory(s) => s.revoke_invite(invite_id, revoked_at).await,
            Self::Postgres(s) => s.revoke_invite(invite_id, revoked_at).await,
        }
    }

    async fn accept_invite(
        &self,
        invite_id: Uuid,
        accepted_by_user_id: Uuid,
        accepted_at: i64,
    ) -> Result<(), DomainError> {
        match self {
            Self::Memory(s) => {
                s.accept_invite(invite_id, accepted_by_user_id, accepted_at)
                    .await
            }
            Self::Postgres(s) => {
                s.accept_invite(invite_id, accepted_by_user_id, accepted_at)
                    .await
            }
        }
    }
}

#[async_trait]
impl KeyEnvelopeRepository for AnyStore {
    async fn save_envelopes(&self, envelopes: &[VaultKeyEnvelope]) -> Result<(), DomainError> {
        match self {
            Self::Memory(s) => s.save_envelopes(envelopes).await,
            Self::Postgres(s) => s.save_envelopes(envelopes).await,
        }
    }

    async fn get_envelopes_for_device(
        &self,
        vault_id: Uuid,
        recipient_device_id: Uuid,
        epoch: Option<u32>,
    ) -> Result<Vec<VaultKeyEnvelope>, DomainError> {
        match self {
            Self::Memory(s) => {
                s.get_envelopes_for_device(vault_id, recipient_device_id, epoch)
                    .await
            }
            Self::Postgres(s) => {
                s.get_envelopes_for_device(vault_id, recipient_device_id, epoch)
                    .await
            }
        }
    }

    async fn list_all_envelopes_for_vault(
        &self,
        vault_id: Uuid,
        epoch: Option<u32>,
    ) -> Result<Vec<VaultKeyEnvelope>, DomainError> {
        match self {
            Self::Memory(s) => s.list_all_envelopes_for_vault(vault_id, epoch).await,
            Self::Postgres(s) => s.list_all_envelopes_for_vault(vault_id, epoch).await,
        }
    }
}

#[async_trait]
impl AuditRepository for AnyStore {
    async fn append_audit_event(&self, event: &mut AuditEvent) -> Result<(), DomainError> {
        match self {
            Self::Memory(s) => s.append_audit_event(event).await,
            Self::Postgres(s) => s.append_audit_event(event).await,
        }
    }

    async fn list_audit_events(
        &self,
        vault_id: Uuid,
        limit: usize,
        offset: usize,
    ) -> Result<Vec<AuditEvent>, DomainError> {
        match self {
            Self::Memory(s) => s.list_audit_events(vault_id, limit, offset).await,
            Self::Postgres(s) => s.list_audit_events(vault_id, limit, offset).await,
        }
    }

    async fn get_latest_audit_hash(&self, vault_id: Uuid) -> Result<String, DomainError> {
        match self {
            Self::Memory(s) => s.get_latest_audit_hash(vault_id).await,
            Self::Postgres(s) => s.get_latest_audit_hash(vault_id).await,
        }
    }
}

#[async_trait]
impl SyncRepository for AnyStore {
    async fn find_record(
        &self,
        vault_id: Uuid,
        object_id: &str,
    ) -> Result<Option<Record>, DomainError> {
        match self {
            Self::Memory(s) => s.find_record(vault_id, object_id).await,
            Self::Postgres(s) => s.find_record(vault_id, object_id).await,
        }
    }

    async fn find_idempotency(
        &self,
        vault_id: Uuid,
        idempotency_key: &str,
    ) -> Result<Option<MutationIdempotency>, DomainError> {
        match self {
            Self::Memory(s) => s.find_idempotency(vault_id, idempotency_key).await,
            Self::Postgres(s) => s.find_idempotency(vault_id, idempotency_key).await,
        }
    }

    async fn apply_commit_batch(
        &self,
        vault_id: Uuid,
        device_id: Uuid,
        req: &CommitBatchRequest,
        request_hash: &str,
    ) -> Result<CommitBatchResponse, DomainError> {
        match self {
            Self::Memory(s) => {
                s.apply_commit_batch(vault_id, device_id, req, request_hash)
                    .await
            }
            Self::Postgres(s) => {
                s.apply_commit_batch(vault_id, device_id, req, request_hash)
                    .await
            }
        }
    }

    async fn get_changes(
        &self,
        vault_id: Uuid,
        since_sequence: u64,
        limit: usize,
    ) -> Result<Vec<ChangeLogEntry>, DomainError> {
        match self {
            Self::Memory(s) => s.get_changes(vault_id, since_sequence, limit).await,
            Self::Postgres(s) => s.get_changes(vault_id, since_sequence, limit).await,
        }
    }

    async fn get_snapshot_records(&self, vault_id: Uuid) -> Result<Vec<Record>, DomainError> {
        match self {
            Self::Memory(s) => s.get_snapshot_records(vault_id).await,
            Self::Postgres(s) => s.get_snapshot_records(vault_id).await,
        }
    }

    async fn get_snapshot_consistent(
        &self,
        vault_id: Uuid,
        requested_revision: Option<u64>,
    ) -> Result<(u64, Vec<Record>), DomainError> {
        match self {
            Self::Memory(s) => {
                s.get_snapshot_consistent(vault_id, requested_revision)
                    .await
            }
            Self::Postgres(s) => {
                s.get_snapshot_consistent(vault_id, requested_revision)
                    .await
            }
        }
    }
}

#[async_trait]
impl CollabRepository for AnyStore {
    async fn create_collab_session(
        &self,
        session: &CollabSession,
        host_participant: &CollabParticipant,
    ) -> Result<(), DomainError> {
        match self {
            Self::Memory(s) => s.create_collab_session(session, host_participant).await,
            Self::Postgres(s) => s.create_collab_session(session, host_participant).await,
        }
    }

    async fn find_collab_session(
        &self,
        session_id: Uuid,
    ) -> Result<Option<CollabSession>, DomainError> {
        match self {
            Self::Memory(s) => s.find_collab_session(session_id).await,
            Self::Postgres(s) => s.find_collab_session(session_id).await,
        }
    }

    async fn list_active_collab_sessions_for_user(
        &self,
        user_id: Uuid,
    ) -> Result<Vec<CollabSession>, DomainError> {
        match self {
            Self::Memory(s) => s.list_active_collab_sessions_for_user(user_id).await,
            Self::Postgres(s) => s.list_active_collab_sessions_for_user(user_id).await,
        }
    }

    async fn add_collab_participant(
        &self,
        participant: &CollabParticipant,
    ) -> Result<(), DomainError> {
        match self {
            Self::Memory(s) => s.add_collab_participant(participant).await,
            Self::Postgres(s) => s.add_collab_participant(participant).await,
        }
    }

    async fn find_collab_participant(
        &self,
        session_id: Uuid,
        user_id: Uuid,
        device_id: Uuid,
    ) -> Result<Option<CollabParticipant>, DomainError> {
        match self {
            Self::Memory(s) => {
                s.find_collab_participant(session_id, user_id, device_id)
                    .await
            }
            Self::Postgres(s) => {
                s.find_collab_participant(session_id, user_id, device_id)
                    .await
            }
        }
    }

    async fn list_collab_participants(
        &self,
        session_id: Uuid,
    ) -> Result<Vec<CollabParticipant>, DomainError> {
        match self {
            Self::Memory(s) => s.list_collab_participants(session_id).await,
            Self::Postgres(s) => s.list_collab_participants(session_id).await,
        }
    }

    async fn revoke_collab_participant(
        &self,
        session_id: Uuid,
        user_id: Uuid,
        device_id: Uuid,
        revoked_at: i64,
    ) -> Result<(), DomainError> {
        match self {
            Self::Memory(s) => {
                s.revoke_collab_participant(session_id, user_id, device_id, revoked_at)
                    .await
            }
            Self::Postgres(s) => {
                s.revoke_collab_participant(session_id, user_id, device_id, revoked_at)
                    .await
            }
        }
    }

    async fn grant_collab_writer_lease(
        &self,
        session_id: Uuid,
        writer_user_id: Uuid,
        writer_device_id: Uuid,
        lease_expires_at: Option<i64>,
    ) -> Result<u64, DomainError> {
        match self {
            Self::Memory(s) => {
                s.grant_collab_writer_lease(
                    session_id,
                    writer_user_id,
                    writer_device_id,
                    lease_expires_at,
                )
                .await
            }
            Self::Postgres(s) => {
                s.grant_collab_writer_lease(
                    session_id,
                    writer_user_id,
                    writer_device_id,
                    lease_expires_at,
                )
                .await
            }
        }
    }

    async fn revoke_collab_writer_lease(&self, session_id: Uuid) -> Result<u64, DomainError> {
        match self {
            Self::Memory(s) => s.revoke_collab_writer_lease(session_id).await,
            Self::Postgres(s) => s.revoke_collab_writer_lease(session_id).await,
        }
    }

    async fn terminate_collab_session(
        &self,
        session_id: Uuid,
        now: i64,
    ) -> Result<(), DomainError> {
        match self {
            Self::Memory(s) => s.terminate_collab_session(session_id, now).await,
            Self::Postgres(s) => s.terminate_collab_session(session_id, now).await,
        }
    }

    async fn append_collab_frame(&self, frame: &CollabFrame) -> Result<(), DomainError> {
        match self {
            Self::Memory(s) => s.append_collab_frame(frame).await,
            Self::Postgres(s) => s.append_collab_frame(frame).await,
        }
    }

    async fn get_collab_frames(
        &self,
        session_id: Uuid,
        since_sequence: u64,
        limit: usize,
    ) -> Result<Vec<CollabFrame>, DomainError> {
        match self {
            Self::Memory(s) => s.get_collab_frames(session_id, since_sequence, limit).await,
            Self::Postgres(s) => s.get_collab_frames(session_id, since_sequence, limit).await,
        }
    }
}
