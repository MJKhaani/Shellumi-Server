//! Synchronization engine: CAS mutation processor, monotonic change feed, idempotency, and tombstones.

use sha2::{Digest, Sha256};
use shellumi_server_crypto::{
    canonical_mutation_preimage, compute_ciphertext_digest, validate_envelope,
    verify_device_signature,
};
use shellumi_server_domain::{
    ChangeLogEntry, DomainError, Record, Vault, VaultMember, VaultRole, VaultType,
};
use shellumi_server_protocol::{
    ChangeFeedResponse, CommitBatchRequest, CommitBatchResponse, CreateVaultRequest,
    EncryptedEnvelope, MutationAck, SnapshotResponse, SyncChangeItem, UpdateVaultRequest,
    VaultListResponse, VaultResponse, CURRENT_PROTOCOL_VERSION,
};
use shellumi_server_store::Store;
use std::sync::Arc;
use uuid::Uuid;

pub struct SyncEngine<S: Store> {
    store: Arc<S>,
    max_record_bytes: usize,
}

impl<S: Store> SyncEngine<S> {
    pub fn new(store: Arc<S>, max_record_bytes: usize) -> Self {
        Self {
            store,
            max_record_bytes,
        }
    }

    /// Creates a new personal or shared team vault.
    pub async fn create_vault(
        &self,
        user_id: Uuid,
        tenant_id: Uuid,
        req: CreateVaultRequest,
    ) -> Result<VaultResponse, DomainError> {
        let now = chrono::Utc::now().timestamp();
        let vault_id = Uuid::new_v4();

        let vtype = match req.vault_type.as_str() {
            "team" => VaultType::Team,
            _ => VaultType::Personal,
        };

        let vault = Vault {
            id: vault_id,
            tenant_id,
            owner_id: user_id,
            vault_type: vtype,
            encrypted_name: req.encrypted_name.or(req.name),
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

        self.store.create_vault(&vault, &member).await?;

        Ok(VaultResponse {
            vault_id: vault.id,
            tenant_id: vault.tenant_id,
            owner_id: vault.owner_id,
            vault_type: vault.vault_type.as_str().to_string(),
            encrypted_name: vault.encrypted_name,
            active_key_epoch: vault.active_key_epoch,
            server_sequence: vault.server_sequence,
            role: VaultRole::Owner.as_str().to_string(),
            created_at: vault.created_at,
            updated_at: vault.updated_at,
        })
    }

    /// Lists all active vaults accessible to the authenticated user.
    pub async fn list_vaults(&self, user_id: Uuid) -> Result<VaultListResponse, DomainError> {
        let list = self.store.list_vaults_for_user(user_id).await?;
        let responses = list
            .into_iter()
            .map(|(v, role)| VaultResponse {
                vault_id: v.id,
                tenant_id: v.tenant_id,
                owner_id: v.owner_id,
                vault_type: v.vault_type.as_str().to_string(),
                encrypted_name: v.encrypted_name,
                active_key_epoch: v.active_key_epoch,
                server_sequence: v.server_sequence,
                role: role.as_str().to_string(),
                created_at: v.created_at,
                updated_at: v.updated_at,
            })
            .collect();

        Ok(VaultListResponse { vaults: responses })
    }

    /// Fetches metadata for a specific vault.
    pub async fn get_vault(
        &self,
        user_id: Uuid,
        vault_id: Uuid,
    ) -> Result<VaultResponse, DomainError> {
        let vault = self
            .store
            .find_vault_by_id(vault_id)
            .await?
            .ok_or(DomainError::NotFound)?;

        if vault.deleted_at.is_some() {
            return Err(DomainError::NotFound);
        }

        let role = self
            .store
            .get_vault_member_role(vault_id, user_id)
            .await?
            .ok_or(DomainError::NotFound)?;

        Ok(VaultResponse {
            vault_id: vault.id,
            tenant_id: vault.tenant_id,
            owner_id: vault.owner_id,
            vault_type: vault.vault_type.as_str().to_string(),
            encrypted_name: vault.encrypted_name,
            active_key_epoch: vault.active_key_epoch,
            server_sequence: vault.server_sequence,
            role: role.as_str().to_string(),
            created_at: vault.created_at,
            updated_at: vault.updated_at,
        })
    }

    /// Updates vault metadata (e.g. client-encrypted name).
    pub async fn update_vault(
        &self,
        user_id: Uuid,
        vault_id: Uuid,
        req: UpdateVaultRequest,
    ) -> Result<VaultResponse, DomainError> {
        let role = self
            .store
            .get_vault_member_role(vault_id, user_id)
            .await?
            .ok_or(DomainError::NotFound)?;

        if !role.can_admin() {
            return Err(DomainError::PermissionDenied(
                "Only vault owners and administrators can update vault metadata".to_string(),
            ));
        }

        self.store
            .update_vault_metadata(vault_id, req.encrypted_name)
            .await?;

        self.get_vault(user_id, vault_id).await
    }

    /// Soft-deletes a vault.
    pub async fn delete_vault(&self, user_id: Uuid, vault_id: Uuid) -> Result<(), DomainError> {
        let role = self
            .store
            .get_vault_member_role(vault_id, user_id)
            .await?
            .ok_or(DomainError::NotFound)?;

        if role != VaultRole::Owner {
            return Err(DomainError::PermissionDenied(
                "Only the vault owner can delete a vault".to_string(),
            ));
        }

        self.store.delete_vault(vault_id).await
    }

    /// Processes an atomic batch of signed conditional mutations with CAS revision checking.
    pub async fn commit_batch(
        &self,
        user_id: Uuid,
        device_id: Uuid,
        req: CommitBatchRequest,
    ) -> Result<CommitBatchResponse, DomainError> {
        if req.protocol_version != CURRENT_PROTOCOL_VERSION {
            return Err(DomainError::InvalidInput(format!(
                "Unsupported protocol version {}: current is {}",
                req.protocol_version, CURRENT_PROTOCOL_VERSION
            )));
        }

        if req.mutations.is_empty() {
            return Err(DomainError::InvalidInput(
                "Commit batch cannot be empty".to_string(),
            ));
        }

        let vault = self
            .store
            .find_vault_by_id(req.vault_id)
            .await?
            .ok_or(DomainError::NotFound)?;

        if vault.deleted_at.is_some() {
            return Err(DomainError::NotFound);
        }

        let role = self
            .store
            .get_vault_member_role(req.vault_id, user_id)
            .await?
            .ok_or(DomainError::NotFound)?;

        if !role.can_write() {
            return Err(DomainError::PermissionDenied(
                "Viewers do not have write access to this vault".to_string(),
            ));
        }

        let device = self
            .store
            .find_device_by_id(device_id)
            .await?
            .ok_or(DomainError::DeviceNotFound)?;

        if device.user_id != user_id {
            return Err(DomainError::PermissionDenied(
                "Device does not belong to the authenticated user".to_string(),
            ));
        }

        if device.revoked_at.is_some() {
            return Err(DomainError::DeviceRevoked);
        }

        // Idempotency check: compute SHA-256 digest of request mutation payload
        let mutations_bytes =
            serde_json::to_vec(&req.mutations).map_err(|e| DomainError::Internal(e.to_string()))?;
        let request_hash = hex::encode(Sha256::digest(&mutations_bytes));

        if let Some(idem) = self
            .store
            .find_idempotency(req.vault_id, &req.idempotency_key)
            .await?
        {
            if idem.request_hash == request_hash {
                let cached: CommitBatchResponse = serde_json::from_str(&idem.response_payload)
                    .map_err(|e| DomainError::Internal(e.to_string()))?;
                return Ok(cached);
            } else {
                return Err(DomainError::IdempotencyConflict {
                    key: req.idempotency_key,
                });
            }
        }

        // Validate cryptographic signatures and envelopes for each mutation
        for mutation in &req.mutations {
            let digest = compute_ciphertext_digest(mutation.encrypted_envelope.as_ref());
            let preimage = canonical_mutation_preimage(
                req.vault_id,
                &mutation.object_id,
                &mutation.entity_type,
                mutation.expected_revision,
                mutation.deleted,
                mutation.key_epoch,
                mutation.device_counter,
                &digest,
            );

            verify_device_signature(
                &device.signing_public_key,
                preimage.as_bytes(),
                &mutation.device_signature,
            )
            .map_err(|e| DomainError::InvalidSignature(e.to_string()))?;

            if mutation.deleted {
                if mutation.encrypted_envelope.is_some() {
                    return Err(DomainError::InvalidInput(
                        "Deletion tombstones must not include ciphertext envelopes".to_string(),
                    ));
                }
            } else {
                let env = mutation.encrypted_envelope.as_ref().ok_or_else(|| {
                    DomainError::InvalidInput(
                        "Active mutations must include an encrypted envelope".to_string(),
                    )
                })?;
                validate_envelope(env, self.max_record_bytes)
                    .map_err(|e| DomainError::InvalidInput(e.to_string()))?;
            }
        }

        // Monotonic sequence allocation and CAS revision checks
        let new_sequence = vault.server_sequence + 1;
        let now = chrono::Utc::now().timestamp();
        let mut records_to_upsert = Vec::with_capacity(req.mutations.len());
        let mut change_log_entries = Vec::with_capacity(req.mutations.len());
        let mut applied_acks = Vec::with_capacity(req.mutations.len());

        for mutation in &req.mutations {
            let existing = self
                .store
                .find_record(req.vault_id, &mutation.object_id)
                .await?;

            let assigned_revision = match (mutation.expected_revision, &existing) {
                (0, None) => 1,
                (0, Some(rec)) => {
                    if !rec.deleted {
                        return Err(DomainError::RevisionConflict {
                            object_id: mutation.object_id.clone(),
                            expected: 0,
                            actual: rec.current_revision,
                        });
                    }
                    rec.current_revision + 1
                }
                (expected, None) => {
                    return Err(DomainError::RevisionConflict {
                        object_id: mutation.object_id.clone(),
                        expected,
                        actual: 0,
                    });
                }
                (expected, Some(rec)) => {
                    if rec.current_revision != expected {
                        return Err(DomainError::RevisionConflict {
                            object_id: mutation.object_id.clone(),
                            expected,
                            actual: rec.current_revision,
                        });
                    }
                    expected + 1
                }
            };

            let envelope_json = mutation
                .encrypted_envelope
                .as_ref()
                .map(|e| serde_json::to_string(e).unwrap());
            let digest = compute_ciphertext_digest(mutation.encrypted_envelope.as_ref());

            let record = Record {
                vault_id: req.vault_id,
                object_id: mutation.object_id.clone(),
                entity_type: mutation.entity_type.clone(),
                current_revision: assigned_revision,
                key_epoch: mutation.key_epoch,
                author_device_id: device_id,
                deleted: mutation.deleted,
                encrypted_envelope: envelope_json.clone(),
                ciphertext_digest: digest.clone(),
                last_server_sequence: new_sequence,
                updated_at: now,
            };

            let entry = ChangeLogEntry {
                vault_id: req.vault_id,
                sequence: new_sequence,
                object_id: mutation.object_id.clone(),
                entity_type: mutation.entity_type.clone(),
                revision: assigned_revision,
                deleted: mutation.deleted,
                author_device_id: device_id,
                encrypted_envelope: envelope_json,
                ciphertext_digest: digest,
                created_at: now,
            };

            records_to_upsert.push(record);
            change_log_entries.push(entry);
            applied_acks.push(MutationAck {
                object_id: mutation.object_id.clone(),
                assigned_revision,
                server_sequence: new_sequence,
                deleted: mutation.deleted,
            });
        }

        let next_cursor = format!("seq:{}", new_sequence);
        let response = CommitBatchResponse {
            vault_id: req.vault_id,
            commit_sequence: new_sequence,
            next_cursor,
            applied: applied_acks,
        };

        let response_payload =
            serde_json::to_string(&response).map_err(|e| DomainError::Internal(e.to_string()))?;

        self.store
            .apply_commit_batch(
                req.vault_id,
                device_id,
                &req.idempotency_key,
                &request_hash,
                &response_payload,
                &records_to_upsert,
                &change_log_entries,
                new_sequence,
            )
            .await?;

        Ok(response)
    }

    /// Fetches delta changes since a given sequence number.
    pub async fn get_changes(
        &self,
        user_id: Uuid,
        vault_id: Uuid,
        since_sequence: u64,
        limit: usize,
    ) -> Result<ChangeFeedResponse, DomainError> {
        let vault = self
            .store
            .find_vault_by_id(vault_id)
            .await?
            .ok_or(DomainError::NotFound)?;

        if vault.deleted_at.is_some() {
            return Err(DomainError::NotFound);
        }

        let _role = self
            .store
            .get_vault_member_role(vault_id, user_id)
            .await?
            .ok_or(DomainError::NotFound)?;

        let capped_limit = limit.clamp(1, 500);
        // Fetch capped_limit + 1 to check has_more
        let mut entries = self
            .store
            .get_changes(vault_id, since_sequence, capped_limit + 1)
            .await?;

        let has_more = entries.len() > capped_limit;
        if has_more {
            entries.truncate(capped_limit);
        }

        let latest_entry_seq = entries.last().map(|e| e.sequence).unwrap_or(since_sequence);
        let next_cursor = format!("seq:{}", latest_entry_seq);

        let records = entries
            .into_iter()
            .map(|e| {
                let env = e
                    .encrypted_envelope
                    .and_then(|json| serde_json::from_str::<EncryptedEnvelope>(&json).ok());
                SyncChangeItem {
                    sequence: e.sequence,
                    object_id: e.object_id,
                    entity_type: e.entity_type,
                    revision: e.revision,
                    deleted: e.deleted,
                    author_device_id: e.author_device_id,
                    encrypted_envelope: env,
                    updated_at: e.created_at,
                }
            })
            .collect();

        Ok(ChangeFeedResponse {
            vault_id,
            latest_sequence: vault.server_sequence,
            next_cursor,
            has_more,
            records,
        })
    }

    /// Generates a full snapshot of current active records for resynchronization.
    pub async fn get_snapshot(
        &self,
        user_id: Uuid,
        vault_id: Uuid,
    ) -> Result<SnapshotResponse, DomainError> {
        let vault = self
            .store
            .find_vault_by_id(vault_id)
            .await?
            .ok_or(DomainError::NotFound)?;

        if vault.deleted_at.is_some() {
            return Err(DomainError::NotFound);
        }

        let _role = self
            .store
            .get_vault_member_role(vault_id, user_id)
            .await?
            .ok_or(DomainError::NotFound)?;

        let records_raw = self.store.get_snapshot_records(vault_id).await?;
        let records = records_raw
            .into_iter()
            .map(|r| {
                let env = r
                    .encrypted_envelope
                    .and_then(|json| serde_json::from_str::<EncryptedEnvelope>(&json).ok());
                SyncChangeItem {
                    sequence: r.last_server_sequence,
                    object_id: r.object_id,
                    entity_type: r.entity_type,
                    revision: r.current_revision,
                    deleted: r.deleted,
                    author_device_id: r.author_device_id,
                    encrypted_envelope: env,
                    updated_at: r.updated_at,
                }
            })
            .collect();

        Ok(SnapshotResponse {
            vault_id,
            server_sequence: vault.server_sequence,
            records,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
    use base64::Engine;
    use ring::signature::Ed25519KeyPair;
    use shellumi_server_crypto::{generate_test_ed25519_keypair, sign_message};
    use shellumi_server_domain::{Device, Organization, User};
    use shellumi_server_protocol::MutationItem;
    use shellumi_server_store::{DeviceRepository, InMemoryStore, OrgRepository, UserRepository};

    async fn setup_test_context() -> (
        Arc<InMemoryStore>,
        SyncEngine<InMemoryStore>,
        Uuid,
        Uuid,
        Uuid,
        Ed25519KeyPair,
    ) {
        let store = Arc::new(InMemoryStore::new());
        let engine = SyncEngine::new(store.clone(), 1024 * 1024);
        let user_id = Uuid::new_v4();
        let org_id = Uuid::new_v4();
        let now = chrono::Utc::now().timestamp();

        let user = User {
            id: user_id,
            username: "sync_tester".to_string(),
            email: "tester@example.com".to_string(),
            password_hash: "hash".to_string(),
            created_at: now,
            updated_at: now,
            is_active: true,
        };
        store.create_user(&user).await.unwrap();

        let org = Organization {
            id: org_id,
            name: "Test Org".to_string(),
            created_at: now,
        };
        store.create_org(&org, user_id).await.unwrap();

        let (keypair, public_key_b64) = generate_test_ed25519_keypair().unwrap();
        let device_id = Uuid::new_v4();
        let device = Device {
            id: device_id,
            user_id,
            device_name: "Test Device".to_string(),
            signing_public_key: public_key_b64,
            agreement_public_key: "agree-key".to_string(),
            created_at: now,
            last_seen_at: None,
            revoked_at: None,
        };
        store.create_device(&device).await.unwrap();

        (store, engine, user_id, org_id, device_id, keypair)
    }

    fn sample_envelope() -> EncryptedEnvelope {
        EncryptedEnvelope {
            salt: BASE64_STANDARD.encode([1u8; 16]),
            nonce: BASE64_STANDARD.encode([2u8; 12]),
            ciphertext: BASE64_STANDARD.encode(b"encrypted_secret_data"),
            associated_data: "host:001".to_string(),
            kdf_iterations: 600_000,
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn sign_test_mutation(
        vault_id: Uuid,
        object_id: &str,
        entity_type: &str,
        expected_revision: u64,
        deleted: bool,
        key_epoch: u32,
        device_counter: u64,
        envelope: Option<&EncryptedEnvelope>,
        keypair: &Ed25519KeyPair,
    ) -> MutationItem {
        let digest = compute_ciphertext_digest(envelope);
        let preimage = canonical_mutation_preimage(
            vault_id,
            object_id,
            entity_type,
            expected_revision,
            deleted,
            key_epoch,
            device_counter,
            &digest,
        );
        let sig = sign_message(keypair, preimage.as_bytes());

        MutationItem {
            object_id: object_id.to_string(),
            entity_type: entity_type.to_string(),
            expected_revision,
            deleted,
            key_epoch,
            device_counter,
            encrypted_envelope: envelope.cloned(),
            device_signature: sig,
        }
    }

    #[tokio::test]
    async fn test_vault_lifecycle() {
        let (_store, engine, user_id, org_id, _device_id, _keypair) = setup_test_context().await;

        let req = CreateVaultRequest {
            name: Some("Personal Vault".to_string()),
            encrypted_name: None,
            vault_type: "personal".to_string(),
        };

        let vault = engine.create_vault(user_id, org_id, req).await.unwrap();
        assert_eq!(vault.role, "owner");
        assert_eq!(vault.server_sequence, 0);

        let list = engine.list_vaults(user_id).await.unwrap();
        assert_eq!(list.vaults.len(), 1);
        assert_eq!(list.vaults[0].vault_id, vault.vault_id);

        let fetched = engine.get_vault(user_id, vault.vault_id).await.unwrap();
        assert_eq!(fetched.vault_id, vault.vault_id);

        let update_req = UpdateVaultRequest {
            encrypted_name: Some("Renamed Vault".to_string()),
        };
        let updated = engine
            .update_vault(user_id, vault.vault_id, update_req)
            .await
            .unwrap();
        assert_eq!(updated.encrypted_name.as_deref(), Some("Renamed Vault"));

        engine.delete_vault(user_id, vault.vault_id).await.unwrap();
        let list_after = engine.list_vaults(user_id).await.unwrap();
        assert_eq!(list_after.vaults.len(), 0);
    }

    #[tokio::test]
    async fn test_commit_batch_and_feed() {
        let (_store, engine, user_id, org_id, device_id, keypair) = setup_test_context().await;

        let vault = engine
            .create_vault(
                user_id,
                org_id,
                CreateVaultRequest {
                    name: Some("Sync Vault".to_string()),
                    encrypted_name: None,
                    vault_type: "personal".to_string(),
                },
            )
            .await
            .unwrap();

        let env = sample_envelope();
        let m1 = sign_test_mutation(
            vault.vault_id,
            "host-1",
            "host",
            0,
            false,
            1,
            1,
            Some(&env),
            &keypair,
        );
        let m2 = sign_test_mutation(
            vault.vault_id,
            "snippet-1",
            "snippet",
            0,
            false,
            1,
            2,
            Some(&env),
            &keypair,
        );

        let commit_req = CommitBatchRequest {
            protocol_version: CURRENT_PROTOCOL_VERSION,
            vault_id: vault.vault_id,
            idempotency_key: "idem-batch-1".to_string(),
            base_cursor: None,
            mutations: vec![m1, m2],
        };

        let ack = engine
            .commit_batch(user_id, device_id, commit_req)
            .await
            .unwrap();
        assert_eq!(ack.commit_sequence, 1);
        assert_eq!(ack.applied.len(), 2);
        assert_eq!(ack.applied[0].assigned_revision, 1);
        assert_eq!(ack.applied[1].assigned_revision, 1);

        // Delta change feed
        let feed = engine
            .get_changes(user_id, vault.vault_id, 0, 10)
            .await
            .unwrap();
        assert_eq!(feed.records.len(), 2);
        assert_eq!(feed.latest_sequence, 1);
        assert!(!feed.has_more);

        // Snapshot
        let snap = engine.get_snapshot(user_id, vault.vault_id).await.unwrap();
        assert_eq!(snap.records.len(), 2);
    }

    #[tokio::test]
    async fn test_cas_revision_conflict() {
        let (_store, engine, user_id, org_id, device_id, keypair) = setup_test_context().await;

        let vault = engine
            .create_vault(
                user_id,
                org_id,
                CreateVaultRequest {
                    name: Some("CAS Vault".to_string()),
                    encrypted_name: None,
                    vault_type: "personal".to_string(),
                },
            )
            .await
            .unwrap();

        let env = sample_envelope();
        let m1 = sign_test_mutation(
            vault.vault_id,
            "host-1",
            "host",
            0,
            false,
            1,
            1,
            Some(&env),
            &keypair,
        );

        let commit_req = CommitBatchRequest {
            protocol_version: CURRENT_PROTOCOL_VERSION,
            vault_id: vault.vault_id,
            idempotency_key: "idem-cas-1".to_string(),
            base_cursor: None,
            mutations: vec![m1],
        };

        engine
            .commit_batch(user_id, device_id, commit_req)
            .await
            .unwrap();

        // Attempting to create same object again with expected_revision = 0 fails with conflict
        let m_dup = sign_test_mutation(
            vault.vault_id,
            "host-1",
            "host",
            0,
            false,
            1,
            2,
            Some(&env),
            &keypair,
        );
        let commit_dup = CommitBatchRequest {
            protocol_version: CURRENT_PROTOCOL_VERSION,
            vault_id: vault.vault_id,
            idempotency_key: "idem-cas-2".to_string(),
            base_cursor: None,
            mutations: vec![m_dup],
        };

        let err = engine
            .commit_batch(user_id, device_id, commit_dup)
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            DomainError::RevisionConflict {
                expected: 0,
                actual: 1,
                ..
            }
        ));

        // Stale update with wrong revision fails with conflict
        let m_stale = sign_test_mutation(
            vault.vault_id,
            "host-1",
            "host",
            5,
            false,
            1,
            3,
            Some(&env),
            &keypair,
        );
        let commit_stale = CommitBatchRequest {
            protocol_version: CURRENT_PROTOCOL_VERSION,
            vault_id: vault.vault_id,
            idempotency_key: "idem-cas-3".to_string(),
            base_cursor: None,
            mutations: vec![m_stale],
        };
        let err2 = engine
            .commit_batch(user_id, device_id, commit_stale)
            .await
            .unwrap_err();
        assert!(matches!(
            err2,
            DomainError::RevisionConflict {
                expected: 5,
                actual: 1,
                ..
            }
        ));

        // Valid update with expected_revision = 1 succeeds
        let m_valid = sign_test_mutation(
            vault.vault_id,
            "host-1",
            "host",
            1,
            false,
            1,
            4,
            Some(&env),
            &keypair,
        );
        let commit_valid = CommitBatchRequest {
            protocol_version: CURRENT_PROTOCOL_VERSION,
            vault_id: vault.vault_id,
            idempotency_key: "idem-cas-4".to_string(),
            base_cursor: None,
            mutations: vec![m_valid],
        };
        let ack = engine
            .commit_batch(user_id, device_id, commit_valid)
            .await
            .unwrap();
        assert_eq!(ack.applied[0].assigned_revision, 2);
    }

    #[tokio::test]
    async fn test_idempotent_retry_and_conflict() {
        let (_store, engine, user_id, org_id, device_id, keypair) = setup_test_context().await;

        let vault = engine
            .create_vault(
                user_id,
                org_id,
                CreateVaultRequest {
                    name: Some("Idem Vault".to_string()),
                    encrypted_name: None,
                    vault_type: "personal".to_string(),
                },
            )
            .await
            .unwrap();

        let env = sample_envelope();
        let m1 = sign_test_mutation(
            vault.vault_id,
            "host-idem",
            "host",
            0,
            false,
            1,
            1,
            Some(&env),
            &keypair,
        );

        let commit_req = CommitBatchRequest {
            protocol_version: CURRENT_PROTOCOL_VERSION,
            vault_id: vault.vault_id,
            idempotency_key: "same-key-1".to_string(),
            base_cursor: None,
            mutations: vec![m1.clone()],
        };

        let first_ack = engine
            .commit_batch(user_id, device_id, commit_req.clone())
            .await
            .unwrap();

        // Exact retry with same idempotency key returns identical ack without incrementing sequence
        let second_ack = engine
            .commit_batch(user_id, device_id, commit_req)
            .await
            .unwrap();
        assert_eq!(first_ack, second_ack);

        // Modified payload with same key returns IdempotencyConflict
        let m2 = sign_test_mutation(
            vault.vault_id,
            "host-different",
            "host",
            0,
            false,
            1,
            2,
            Some(&env),
            &keypair,
        );
        let commit_conflict = CommitBatchRequest {
            protocol_version: CURRENT_PROTOCOL_VERSION,
            vault_id: vault.vault_id,
            idempotency_key: "same-key-1".to_string(),
            base_cursor: None,
            mutations: vec![m2],
        };
        let err = engine
            .commit_batch(user_id, device_id, commit_conflict)
            .await
            .unwrap_err();
        assert!(matches!(err, DomainError::IdempotencyConflict { .. }));
    }

    #[tokio::test]
    async fn test_tombstone_propagation_and_tampered_signature() {
        let (_store, engine, user_id, org_id, device_id, keypair) = setup_test_context().await;

        let vault = engine
            .create_vault(
                user_id,
                org_id,
                CreateVaultRequest {
                    name: Some("Tombstone Vault".to_string()),
                    encrypted_name: None,
                    vault_type: "personal".to_string(),
                },
            )
            .await
            .unwrap();

        let env = sample_envelope();
        let m1 = sign_test_mutation(
            vault.vault_id,
            "host-del",
            "host",
            0,
            false,
            1,
            1,
            Some(&env),
            &keypair,
        );

        engine
            .commit_batch(
                user_id,
                device_id,
                CommitBatchRequest {
                    protocol_version: CURRENT_PROTOCOL_VERSION,
                    vault_id: vault.vault_id,
                    idempotency_key: "tomb-1".to_string(),
                    base_cursor: None,
                    mutations: vec![m1],
                },
            )
            .await
            .unwrap();

        // Tampered signature is rejected
        let mut m_tampered = sign_test_mutation(
            vault.vault_id,
            "host-del",
            "host",
            1,
            true,
            1,
            2,
            None,
            &keypair,
        );
        m_tampered.device_signature = BASE64_STANDARD.encode([99u8; 64]);
        let err = engine
            .commit_batch(
                user_id,
                device_id,
                CommitBatchRequest {
                    protocol_version: CURRENT_PROTOCOL_VERSION,
                    vault_id: vault.vault_id,
                    idempotency_key: "tomb-bad-sig".to_string(),
                    base_cursor: None,
                    mutations: vec![m_tampered],
                },
            )
            .await
            .unwrap_err();
        assert!(matches!(err, DomainError::InvalidSignature(_)));

        // Valid deletion tombstone
        let m_delete = sign_test_mutation(
            vault.vault_id,
            "host-del",
            "host",
            1,
            true,
            1,
            3,
            None,
            &keypair,
        );
        let del_ack = engine
            .commit_batch(
                user_id,
                device_id,
                CommitBatchRequest {
                    protocol_version: CURRENT_PROTOCOL_VERSION,
                    vault_id: vault.vault_id,
                    idempotency_key: "tomb-valid".to_string(),
                    base_cursor: None,
                    mutations: vec![m_delete],
                },
            )
            .await
            .unwrap();
        assert!(del_ack.applied[0].deleted);
        assert_eq!(del_ack.applied[0].assigned_revision, 2);

        // Snapshot excludes deleted record
        let snap = engine.get_snapshot(user_id, vault.vault_id).await.unwrap();
        assert_eq!(snap.records.len(), 0);

        // Change feed includes tombstone
        let changes = engine
            .get_changes(user_id, vault.vault_id, 0, 10)
            .await
            .unwrap();
        assert_eq!(changes.records.len(), 2);
        let last_change = &changes.records[1];
        assert!(last_change.deleted);
        assert_eq!(last_change.object_id, "host-del");
        assert_eq!(last_change.revision, 2);
    }
}
