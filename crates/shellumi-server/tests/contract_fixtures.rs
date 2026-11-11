use shellumi_server_protocol::*;
use uuid::Uuid;

#[test]
fn test_capabilities_and_health_contract_fixture() {
    let health = HealthResponse {
        status: "pass".to_string(),
        service: "shellumi-server".to_string(),
        version: "0.1.0".to_string(),
        details: None,
    };
    let json = serde_json::to_string(&health).expect("serialize health");
    assert!(!json.contains("details"));
    let deserialized: HealthResponse = serde_json::from_str(&json).expect("deserialize health");
    assert_eq!(health, deserialized);

    let caps = CapabilitiesResponse {
        server_version: "0.1.0".to_string(),
        protocol_version: CURRENT_PROTOCOL_VERSION,
        min_protocol_version: MIN_PROTOCOL_VERSION,
        supported_features: vec![
            "argon2id_auth_v1".to_string(),
            "device_keys_v1".to_string(),
            "delta_sync_v1".to_string(),
            "shared_vaults_v1".to_string(),
            "terminal_collab_v1".to_string(),
        ],
        supported_e2ee_suites: vec![
            "x25519_hkdf_aes256gcm".to_string(),
            "argon2id_aes256gcm_legacy".to_string(),
        ],
        limits: ServerLimits {
            max_request_bytes: 10485760,
            max_record_bytes: 1048576,
            max_mutations_per_commit: 1000,
        },
    };
    let json = serde_json::to_string(&caps).expect("serialize caps");
    let deserialized: CapabilitiesResponse = serde_json::from_str(&json).expect("deserialize caps");
    assert_eq!(caps, deserialized);
    assert_eq!(deserialized.protocol_version, 1);
}

#[test]
fn test_auth_and_bootstrap_contract_fixtures() {
    let org_id = Uuid::new_v4();
    let user_id = Uuid::new_v4();

    let bootstrap_req = BootstrapRequest {
        admin_username: "sysadmin".to_string(),
        admin_email: "admin@example.com".to_string(),
        admin_password: "SuperSecretPassword123!".to_string(),
        org_name: "Default Organization".to_string(),
        bootstrap_token: Some("secret_token_123".to_string()),
    };
    let json = serde_json::to_string(&bootstrap_req).expect("serialize bootstrap req");
    let de_req: BootstrapRequest = serde_json::from_str(&json).expect("deserialize bootstrap req");
    assert_eq!(bootstrap_req, de_req);

    let bootstrap_resp = BootstrapResponse {
        org_id,
        user_id,
        username: "sysadmin".to_string(),
        email: "admin@example.com".to_string(),
        access_token: "jwt.access.token".to_string(),
        refresh_token: "opaque_refresh_token_hex".to_string(),
        expires_in_secs: 900,
    };
    let json = serde_json::to_string(&bootstrap_resp).expect("serialize bootstrap resp");
    let de_resp: BootstrapResponse =
        serde_json::from_str(&json).expect("deserialize bootstrap resp");
    assert_eq!(bootstrap_resp, de_resp);

    let login_req = LoginRequest {
        identifier: "sysadmin".to_string(),
        password: "SuperSecretPassword123!".to_string(),
        device_id: None,
    };
    let json = serde_json::to_string(&login_req).expect("serialize login req");
    assert!(!json.contains("device_id"));
    let de_login: LoginRequest = serde_json::from_str(&json).expect("deserialize login req");
    assert_eq!(login_req, de_login);

    let refresh_req = RefreshTokenRequest {
        refresh_token: "opaque_refresh_token_hex".to_string(),
    };
    let json = serde_json::to_string(&refresh_req).expect("serialize refresh req");
    let de_refresh: RefreshTokenRequest =
        serde_json::from_str(&json).expect("deserialize refresh req");
    assert_eq!(refresh_req, de_refresh);

    let me_resp = MeResponse {
        user_id,
        username: "sysadmin".to_string(),
        email: "admin@example.com".to_string(),
        organizations: vec![UserOrgSummary {
            org_id,
            org_name: "Default Organization".to_string(),
            role: "owner".to_string(),
        }],
    };
    let json = serde_json::to_string(&me_resp).expect("serialize me resp");
    let de_me: MeResponse = serde_json::from_str(&json).expect("deserialize me resp");
    assert_eq!(me_resp, de_me);
}

#[test]
fn test_device_registration_contract_fixtures() {
    let device_id = Uuid::new_v4();
    let user_id = Uuid::new_v4();

    let reg_req = RegisterDeviceRequest {
        device_name: "MacBook Pro M3".to_string(),
        signing_public_key: "ed25519_pk_base64".to_string(),
        agreement_public_key: "x25519_pk_base64".to_string(),
    };
    let json = serde_json::to_string(&reg_req).expect("serialize reg req");
    let de_reg: RegisterDeviceRequest = serde_json::from_str(&json).expect("deserialize reg req");
    assert_eq!(reg_req, de_reg);

    let dev_resp = DeviceResponse {
        device_id,
        user_id,
        device_name: "MacBook Pro M3".to_string(),
        signing_public_key: "ed25519_pk_base64".to_string(),
        agreement_public_key: "x25519_pk_base64".to_string(),
        created_at: 1731300000,
        last_seen_at: Some(1731300500),
        revoked_at: None,
    };
    let json = serde_json::to_string(&dev_resp).expect("serialize dev resp");
    assert!(!json.contains("revoked_at"));
    assert!(json.contains("last_seen_at"));
    let de_dev: DeviceResponse = serde_json::from_str(&json).expect("deserialize dev resp");
    assert_eq!(dev_resp, de_dev);
}

#[test]
fn test_encrypted_envelope_and_vault_contract_fixtures() {
    let vault_id = Uuid::new_v4();
    let tenant_id = Uuid::new_v4();
    let owner_id = Uuid::new_v4();

    let envelope = EncryptedEnvelope {
        salt: "salt_base64".to_string(),
        nonce: "nonce_base64".to_string(),
        ciphertext: "ciphertext_base64".to_string(),
        associated_data: "aad_string".to_string(),
        kdf_iterations: 3,
    };
    let json = serde_json::to_string(&envelope).expect("serialize envelope");
    let de_env: EncryptedEnvelope = serde_json::from_str(&json).expect("deserialize envelope");
    assert_eq!(envelope, de_env);

    let create_vault_req = CreateVaultRequest {
        name: Some("Engineering Vault".to_string()),
        encrypted_name: Some("enc_name_base64".to_string()),
        vault_type: "team".to_string(),
    };
    let json = serde_json::to_string(&create_vault_req).expect("serialize create vault req");
    let de_vault_req: CreateVaultRequest =
        serde_json::from_str(&json).expect("deserialize create vault req");
    assert_eq!(create_vault_req, de_vault_req);

    let vault_resp = VaultResponse {
        vault_id,
        tenant_id,
        owner_id,
        vault_type: "team".to_string(),
        encrypted_name: Some("enc_name_base64".to_string()),
        active_key_epoch: 1,
        server_sequence: 42,
        role: "owner".to_string(),
        created_at: 1731300000,
        updated_at: 1731300100,
    };
    let json = serde_json::to_string(&vault_resp).expect("serialize vault resp");
    let de_vault: VaultResponse = serde_json::from_str(&json).expect("deserialize vault resp");
    assert_eq!(vault_resp, de_vault);
}

#[test]
fn test_commit_batch_and_change_feed_contract_fixtures() {
    let vault_id = Uuid::new_v4();
    let author_device_id = Uuid::new_v4();

    let envelope = EncryptedEnvelope {
        salt: "salt_base64".to_string(),
        nonce: "nonce_base64".to_string(),
        ciphertext: "ciphertext_base64".to_string(),
        associated_data: "aad_string".to_string(),
        kdf_iterations: 3,
    };

    let mutation = MutationItem {
        object_id: "host_server_alpha".to_string(),
        entity_type: "ssh_host".to_string(),
        expected_revision: 0,
        deleted: false,
        key_epoch: 1,
        device_counter: 1,
        encrypted_envelope: Some(envelope.clone()),
        device_signature: "sig_base64".to_string(),
    };

    let commit_req = CommitBatchRequest {
        protocol_version: 1,
        vault_id,
        idempotency_key: "idem_uuid_1234".to_string(),
        base_cursor: None,
        mutations: vec![mutation],
    };
    let json = serde_json::to_string(&commit_req).expect("serialize commit req");
    assert!(!json.contains("base_cursor"));
    let de_commit: CommitBatchRequest =
        serde_json::from_str(&json).expect("deserialize commit req");
    assert_eq!(commit_req, de_commit);

    let commit_resp = CommitBatchResponse {
        vault_id,
        commit_sequence: 1,
        next_cursor: "1".to_string(),
        applied: vec![MutationAck {
            object_id: "host_server_alpha".to_string(),
            assigned_revision: 1,
            server_sequence: 1,
            deleted: false,
        }],
    };
    let json = serde_json::to_string(&commit_resp).expect("serialize commit resp");
    let de_commit_resp: CommitBatchResponse =
        serde_json::from_str(&json).expect("deserialize commit resp");
    assert_eq!(commit_resp, de_commit_resp);

    let change_feed_resp = ChangeFeedResponse {
        vault_id,
        latest_sequence: 1,
        next_cursor: "1".to_string(),
        has_more: false,
        records: vec![SyncChangeItem {
            sequence: 1,
            object_id: "host_server_alpha".to_string(),
            entity_type: "ssh_host".to_string(),
            revision: 1,
            deleted: false,
            author_device_id,
            encrypted_envelope: Some(envelope.clone()),
            updated_at: 1731300000,
        }],
    };
    let json = serde_json::to_string(&change_feed_resp).expect("serialize change feed resp");
    let de_feed: ChangeFeedResponse =
        serde_json::from_str(&json).expect("deserialize change feed resp");
    assert_eq!(change_feed_resp, de_feed);

    let snapshot_resp = SnapshotResponse {
        vault_id,
        server_sequence: 1,
        records: vec![SyncChangeItem {
            sequence: 1,
            object_id: "host_server_alpha".to_string(),
            entity_type: "ssh_host".to_string(),
            revision: 1,
            deleted: false,
            author_device_id,
            encrypted_envelope: Some(envelope),
            updated_at: 1731300000,
        }],
    };
    let json = serde_json::to_string(&snapshot_resp).expect("serialize snapshot resp");
    let de_snapshot: SnapshotResponse =
        serde_json::from_str(&json).expect("deserialize snapshot resp");
    assert_eq!(snapshot_resp, de_snapshot);
}

#[test]
fn test_team_invites_and_key_envelopes_contract_fixtures() {
    let vault_id = Uuid::new_v4();
    let invite_id = Uuid::new_v4();
    let recipient_device_id = Uuid::new_v4();
    let sender_device_id = Uuid::new_v4();

    let invite_req = CreateInviteRequest {
        role: "editor".to_string(),
        recipient_email: Some("editor@example.com".to_string()),
        ttl_secs: Some(86400),
    };
    let json = serde_json::to_string(&invite_req).expect("serialize invite req");
    let de_invite_req: CreateInviteRequest =
        serde_json::from_str(&json).expect("deserialize invite req");
    assert_eq!(invite_req, de_invite_req);

    let invite_resp = InviteResponse {
        invite_id,
        vault_id,
        role: "editor".to_string(),
        invite_token: Some("secret_invite_hex".to_string()),
        recipient_email: Some("editor@example.com".to_string()),
        expires_at: 1731386400,
        created_at: 1731300000,
    };
    let json = serde_json::to_string(&invite_resp).expect("serialize invite resp");
    let de_invite: InviteResponse = serde_json::from_str(&json).expect("deserialize invite resp");
    assert_eq!(invite_resp, de_invite);

    let accept_req = AcceptInviteRequest {
        invite_token: "secret_invite_hex".to_string(),
    };
    let json = serde_json::to_string(&accept_req).expect("serialize accept req");
    let de_accept: AcceptInviteRequest =
        serde_json::from_str(&json).expect("deserialize accept req");
    assert_eq!(accept_req, de_accept);

    let accept_resp = AcceptInviteResponse {
        vault_id,
        role: "editor".to_string(),
    };
    let json = serde_json::to_string(&accept_resp).expect("serialize accept resp");
    let de_accept_resp: AcceptInviteResponse =
        serde_json::from_str(&json).expect("deserialize accept resp");
    assert_eq!(accept_resp, de_accept_resp);

    let key_item = KeyEnvelopeItem {
        recipient_device_id,
        wrapped_dek: "wrapped_dek_base64".to_string(),
        key_agreement_ephemeral_pk: Some("ephemeral_pk_base64".to_string()),
    };
    let pub_keys_req = PublishKeyEnvelopesRequest {
        epoch: 1,
        envelopes: vec![key_item],
    };
    let json = serde_json::to_string(&pub_keys_req).expect("serialize pub keys req");
    let de_pub_keys: PublishKeyEnvelopesRequest =
        serde_json::from_str(&json).expect("deserialize pub keys req");
    assert_eq!(pub_keys_req, de_pub_keys);

    let key_resp = KeyEnvelopeResponse {
        vault_id,
        epoch: 1,
        recipient_device_id,
        sender_device_id,
        wrapped_dek: "wrapped_dek_base64".to_string(),
        key_agreement_ephemeral_pk: Some("ephemeral_pk_base64".to_string()),
        created_at: 1731300000,
    };
    let json = serde_json::to_string(&key_resp).expect("serialize key resp");
    let de_key_resp: KeyEnvelopeResponse =
        serde_json::from_str(&json).expect("deserialize key resp");
    assert_eq!(key_resp, de_key_resp);

    let rotate_req = RotateKeyEpochRequest {
        new_epoch: 2,
        envelopes: vec![KeyEnvelopeItem {
            recipient_device_id,
            wrapped_dek: "wrapped_dek_v2_base64".to_string(),
            key_agreement_ephemeral_pk: None,
        }],
    };
    let json = serde_json::to_string(&rotate_req).expect("serialize rotate req");
    let de_rotate: RotateKeyEpochRequest =
        serde_json::from_str(&json).expect("deserialize rotate req");
    assert_eq!(rotate_req, de_rotate);

    let audit_event = AuditEventResponse {
        id: 1,
        vault_id,
        actor_user_id: sender_device_id,
        actor_device_id: Some(sender_device_id),
        action: "key_epoch_rotated".to_string(),
        target_type: "vault".to_string(),
        target_id: vault_id.to_string(),
        details: Some("Rotated to epoch 2".to_string()),
        predecessor_hash: "0000000000000000000000000000000000000000000000000000000000000000"
            .to_string(),
        event_hash: "abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234".to_string(),
        created_at: 1731300000,
    };
    let json = serde_json::to_string(&audit_event).expect("serialize audit event");
    let de_audit: AuditEventResponse = serde_json::from_str(&json).expect("deserialize audit");
    assert_eq!(audit_event, de_audit);
}

#[test]
fn test_collab_session_and_frame_contract_fixtures() {
    let session_id = Uuid::new_v4();
    let host_user_id = Uuid::new_v4();
    let host_device_id = Uuid::new_v4();

    let create_collab_req = CreateCollabSessionRequest {
        title: "Incident Debugging Session".to_string(),
        mode: "controllable".to_string(),
        ttl_secs: Some(3600),
    };
    let json = serde_json::to_string(&create_collab_req).expect("serialize create collab req");
    let de_collab_req: CreateCollabSessionRequest =
        serde_json::from_str(&json).expect("deserialize create collab req");
    assert_eq!(create_collab_req, de_collab_req);

    let collab_resp = CollabSessionResponse {
        session_id,
        host_user_id,
        host_device_id,
        title: "Incident Debugging Session".to_string(),
        mode: "controllable".to_string(),
        active_writer_user_id: Some(host_user_id),
        active_writer_device_id: Some(host_device_id),
        lease_token: 1,
        lease_expires_at: Some(1731303600),
        expires_at: 1731303600,
        terminated_at: None,
        created_at: 1731300000,
    };
    let json = serde_json::to_string(&collab_resp).expect("serialize collab resp");
    assert!(!json.contains("terminated_at"));
    let de_collab: CollabSessionResponse =
        serde_json::from_str(&json).expect("deserialize collab resp");
    assert_eq!(collab_resp, de_collab);

    let frame = CollabFrame {
        session_id,
        sequence: 42,
        frame_type: CollabFrameType::Output,
        sender_user_id: host_user_id,
        sender_device_id: host_device_id,
        lease_token: Some(1),
        encrypted_envelope: "opaque_ciphertext_frame".to_string(),
        created_at: 1731300050,
    };
    let json = serde_json::to_string(&frame).expect("serialize frame");
    let de_frame: CollabFrame = serde_json::from_str(&json).expect("deserialize frame");
    assert_eq!(frame, de_frame);

    let send_frame_req = SendCollabFrameRequest {
        frame_type: CollabFrameType::Input,
        lease_token: Some(1),
        encrypted_envelope: "opaque_input_keystrokes".to_string(),
    };
    let json = serde_json::to_string(&send_frame_req).expect("serialize send frame req");
    let de_send_frame: SendCollabFrameRequest =
        serde_json::from_str(&json).expect("deserialize send frame req");
    assert_eq!(send_frame_req, de_send_frame);

    let poll_resp = CollabPollResponse {
        frames: vec![frame],
        latest_sequence: 42,
    };
    let json = serde_json::to_string(&poll_resp).expect("serialize poll resp");
    let de_poll: CollabPollResponse = serde_json::from_str(&json).expect("deserialize poll resp");
    assert_eq!(poll_resp, de_poll);
}

#[test]
fn test_error_response_contract_fixture() {
    let error_resp = ErrorResponse {
        error_code: "CONFLICT_STALE_REVISION".to_string(),
        message: "Object revision conflict; refresh state before committing".to_string(),
        request_id: Some("req-123e4567-e89b".to_string()),
    };
    let json = serde_json::to_string(&error_resp).expect("serialize error");
    let de_error: ErrorResponse = serde_json::from_str(&json).expect("deserialize error");
    assert_eq!(error_resp, de_error);
    assert!(json.contains("CONFLICT_STALE_REVISION"));

    let bare_error = ErrorResponse {
        error_code: "UNAUTHORIZED".to_string(),
        message: "Missing or invalid bearer token".to_string(),
        request_id: None,
    };
    let bare_json = serde_json::to_string(&bare_error).expect("serialize bare error");
    assert!(!bare_json.contains("request_id"));
}
