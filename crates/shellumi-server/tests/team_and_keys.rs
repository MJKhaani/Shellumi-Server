//! Integration tests for Milestone M3: Team Vaults, RBAC Matrix, Invitations,
//! Recipient-Wrapped Key Envelopes, Epoch Rotation, and Cryptographic Audit Trail.

use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine;
use ring::signature::Ed25519KeyPair;
use serde_json::Value;
use shellumi_server::config::ServerConfig;
use shellumi_server::server::create_router_with_auth_and_sync;
use shellumi_server_auth::{create_access_token, AuthService};
use shellumi_server_crypto::{
    canonical_mutation_preimage, compute_ciphertext_digest, generate_test_ed25519_keypair,
    sign_message,
};
use shellumi_server_domain::{Organization, User, VaultRole};
use shellumi_server_protocol::{
    AcceptInviteRequest, AddVaultMemberRequest, CommitBatchRequest, CreateInviteRequest,
    CreateVaultRequest, EncryptedEnvelope, KeyEnvelopeItem, MutationItem,
    PublishKeyEnvelopesRequest, RegisterDeviceRequest, RotateKeyEpochRequest,
    CURRENT_PROTOCOL_VERSION,
};
use shellumi_server_store::{
    compute_audit_hash, InMemoryStore, OrgRepository, UserRepository, VaultRepository,
    GENESIS_AUDIT_HASH,
};
use shellumi_server_sync::SyncEngine;
use std::sync::Arc;
use tower::ServiceExt;
use uuid::Uuid;

struct TestContext {
    app: axum::Router,
    store: Arc<InMemoryStore>,
    token_secret: Vec<u8>,
    owner_id: Uuid,
    owner_token: String,
    owner_device_id: Uuid,
    owner_keypair: Ed25519KeyPair,
    _tenant_id: Uuid,
}

fn sample_envelope() -> EncryptedEnvelope {
    EncryptedEnvelope {
        salt: BASE64_STANDARD.encode([1u8; 16]),
        nonce: BASE64_STANDARD.encode([2u8; 12]),
        ciphertext: BASE64_STANDARD.encode(b"ciphertext_sample_payload"),
        associated_data: "host:001".to_string(),
        kdf_iterations: 600_000,
    }
}

#[allow(clippy::too_many_arguments)]
fn create_signed_mutation(
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

async fn setup_test_context() -> TestContext {
    let store = Arc::new(InMemoryStore::new());
    let token_secret = b"shellumi_server_test_hmac_secret_key_32bytes!!".to_vec();
    let auth = Arc::new(AuthService::new(
        store.clone(),
        token_secret.clone(),
        3600,
        86400,
    ));
    let sync = Arc::new(SyncEngine::new(store.clone(), 10 * 1024 * 1024));
    let config = ServerConfig {
        access_token_ttl_secs: 3600,
        ..Default::default()
    };
    let app = create_router_with_auth_and_sync(config, auth, sync);

    let owner_id = Uuid::new_v4();
    let tenant_id = Uuid::new_v4();
    let now = chrono::Utc::now().timestamp();

    let owner_user = User {
        id: owner_id,
        username: "vault_owner".to_string(),
        email: "owner@example.com".to_string(),
        password_hash: "dummy_hash".to_string(),
        created_at: now,
        updated_at: now,
        is_active: true,
    };
    store.create_user(&owner_user).await.unwrap();

    let org = Organization {
        id: tenant_id,
        name: "Engineering Org".to_string(),
        created_at: now,
    };
    store.create_org(&org, owner_id).await.unwrap();

    let owner_token = create_access_token(owner_id, "vault_owner", &token_secret, 3600).unwrap();

    let (owner_keypair, public_key_b64) = generate_test_ed25519_keypair().unwrap();
    let owner_device_id = register_device(
        &app,
        &owner_token,
        "owner_macbook",
        &public_key_b64,
        "agree_pk_1",
    )
    .await;

    TestContext {
        app,
        store,
        token_secret,
        owner_id,
        owner_token,
        owner_device_id,
        owner_keypair,
        _tenant_id: tenant_id,
    }
}

async fn create_user(
    ctx: &TestContext,
    username: &str,
    email: &str,
) -> (Uuid, String, Uuid, Ed25519KeyPair) {
    let user_id = Uuid::new_v4();
    let now = chrono::Utc::now().timestamp();
    let user = User {
        id: user_id,
        username: username.to_string(),
        email: email.to_string(),
        password_hash: "dummy_hash".to_string(),
        created_at: now,
        updated_at: now,
        is_active: true,
    };
    ctx.store.create_user(&user).await.unwrap();

    let token = create_access_token(user_id, username, &ctx.token_secret, 3600).unwrap();

    let (keypair, public_key_b64) = generate_test_ed25519_keypair().unwrap();
    let device_id = register_device(
        &ctx.app,
        &token,
        &format!("{username}_device"),
        &public_key_b64,
        &format!("agree_{username}"),
    )
    .await;

    (user_id, token, device_id, keypair)
}

async fn register_device(
    app: &axum::Router,
    token: &str,
    name: &str,
    signing_pk: &str,
    agree_pk: &str,
) -> Uuid {
    let req_body = RegisterDeviceRequest {
        device_name: name.to_string(),
        signing_public_key: signing_pk.to_string(),
        agreement_public_key: agree_pk.to_string(),
    };

    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/devices")
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&req_body).unwrap()))
        .unwrap();

    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: Value = serde_json::from_slice(&bytes).unwrap();
    Uuid::parse_str(json["device_id"].as_str().unwrap()).unwrap()
}

async fn create_team_vault(app: &axum::Router, token: &str, name: &str) -> Uuid {
    let req_body = CreateVaultRequest {
        name: Some(name.to_string()),
        vault_type: "team".to_string(),
        encrypted_name: Some(name.to_string()),
    };

    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/vaults")
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&req_body).unwrap()))
        .unwrap();

    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: Value = serde_json::from_slice(&bytes).unwrap();
    Uuid::parse_str(json["vault_id"].as_str().unwrap()).unwrap()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_vault_members_rbac_matrix_and_hierarchy() {
    let ctx = setup_test_context().await;
    let vault_id = create_team_vault(&ctx.app, &ctx.owner_token, "Engineering Team").await;

    let (alice_id, alice_token, _, _) = create_user(&ctx, "alice_admin", "alice@example.com").await;
    let (bob_id, bob_token, _, _) = create_user(&ctx, "bob_editor", "bob@example.com").await;
    let (charlie_id, charlie_token, _, _) =
        create_user(&ctx, "charlie_viewer", "charlie@example.com").await;

    // 1. Owner adds Alice as Administrator, Bob as Editor, Charlie as Viewer
    for (uid, role) in [
        (alice_id, "administrator"),
        (bob_id, "editor"),
        (charlie_id, "viewer"),
    ] {
        let add_req = AddVaultMemberRequest {
            user_id: uid,
            role: role.to_string(),
        };
        let req = Request::builder()
            .method("POST")
            .uri(format!("/api/v1/vaults/{vault_id}/members"))
            .header(header::AUTHORIZATION, format!("Bearer {}", ctx.owner_token))
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(serde_json::to_vec(&add_req).unwrap()))
            .unwrap();

        let resp = ctx.app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    // 2. All 4 members can list members (even Viewer)
    for token in [&ctx.owner_token, &alice_token, &bob_token, &charlie_token] {
        let req = Request::builder()
            .method("GET")
            .uri(format!("/api/v1/vaults/{vault_id}/members"))
            .header(header::AUTHORIZATION, format!("Bearer {token}"))
            .body(Body::empty())
            .unwrap();

        let resp = ctx.app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(json["members"].as_array().unwrap().len(), 4);
    }

    // 3. Administrator Alice cannot grant Owner or Administrator role
    let promote_req = AddVaultMemberRequest {
        user_id: bob_id,
        role: "owner".to_string(),
    };
    let req = Request::builder()
        .method("POST")
        .uri(format!("/api/v1/vaults/{vault_id}/members"))
        .header(header::AUTHORIZATION, format!("Bearer {alice_token}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&promote_req).unwrap()))
        .unwrap();

    let resp = ctx.app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    // 4. Administrator Alice can update Bob from Editor to Viewer
    let demote_bob = AddVaultMemberRequest {
        user_id: bob_id,
        role: "viewer".to_string(),
    };
    let req = Request::builder()
        .method("POST")
        .uri(format!("/api/v1/vaults/{vault_id}/members"))
        .header(header::AUTHORIZATION, format!("Bearer {alice_token}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&demote_bob).unwrap()))
        .unwrap();

    let resp = ctx.app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // 5. Administrator Alice cannot remove Owner
    let req = Request::builder()
        .method("DELETE")
        .uri(format!(
            "/api/v1/vaults/{vault_id}/members/{}",
            ctx.owner_id
        ))
        .header(header::AUTHORIZATION, format!("Bearer {alice_token}"))
        .body(Body::empty())
        .unwrap();

    let resp = ctx.app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    // 6. Editor and Viewer cannot add or remove members
    for token in [&bob_token, &charlie_token] {
        let req = Request::builder()
            .method("POST")
            .uri(format!("/api/v1/vaults/{vault_id}/members"))
            .header(header::AUTHORIZATION, format!("Bearer {token}"))
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(
                serde_json::to_vec(&AddVaultMemberRequest {
                    user_id: bob_id,
                    role: "viewer".to_string(),
                })
                .unwrap(),
            ))
            .unwrap();

        let resp = ctx.app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }
}

#[tokio::test]
async fn test_last_owner_protection() {
    let ctx = setup_test_context().await;
    let vault_id = create_team_vault(&ctx.app, &ctx.owner_token, "Sole Owner Vault").await;
    let (alice_id, _, _, _) = create_user(&ctx, "alice_user", "alice2@example.com").await;

    // 1. Demoting the sole owner to Editor returns 409 Conflict
    let demote_req = AddVaultMemberRequest {
        user_id: ctx.owner_id,
        role: "editor".to_string(),
    };
    let req = Request::builder()
        .method("POST")
        .uri(format!("/api/v1/vaults/{vault_id}/members"))
        .header(header::AUTHORIZATION, format!("Bearer {}", ctx.owner_token))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&demote_req).unwrap()))
        .unwrap();

    let resp = ctx.app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::CONFLICT);
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(json["error_code"], "CANNOT_REVOKE_LAST_OWNER");

    // 2. Removing the sole owner returns 409 Conflict
    let req = Request::builder()
        .method("DELETE")
        .uri(format!(
            "/api/v1/vaults/{vault_id}/members/{}",
            ctx.owner_id
        ))
        .header(header::AUTHORIZATION, format!("Bearer {}", ctx.owner_token))
        .body(Body::empty())
        .unwrap();

    let resp = ctx.app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::CONFLICT);

    // 3. Adding Alice as second Owner succeeds
    let add_alice_owner = AddVaultMemberRequest {
        user_id: alice_id,
        role: "owner".to_string(),
    };
    let req = Request::builder()
        .method("POST")
        .uri(format!("/api/v1/vaults/{vault_id}/members"))
        .header(header::AUTHORIZATION, format!("Bearer {}", ctx.owner_token))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&add_alice_owner).unwrap()))
        .unwrap();

    let resp = ctx.app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // 4. Now with 2 owners, demoting the original owner succeeds
    let req = Request::builder()
        .method("POST")
        .uri(format!("/api/v1/vaults/{vault_id}/members"))
        .header(header::AUTHORIZATION, format!("Bearer {}", ctx.owner_token))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&demote_req).unwrap()))
        .unwrap();

    let resp = ctx.app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_one_time_scoped_invitations_lifecycle() {
    let ctx = setup_test_context().await;
    let vault_id = create_team_vault(&ctx.app, &ctx.owner_token, "Invite Vault").await;
    let (alice_id, alice_token, _, _) =
        create_user(&ctx, "invitee_alice", "alice_inv@example.com").await;
    let (_, bob_token, _, _) = create_user(&ctx, "invitee_bob", "bob_inv@example.com").await;

    // 1. Owner creates single-use invite
    let invite_req = CreateInviteRequest {
        role: "editor".to_string(),
        recipient_email: Some("alice_inv@example.com".to_string()),
        ttl_secs: Some(3600),
    };
    let req = Request::builder()
        .method("POST")
        .uri(format!("/api/v1/vaults/{vault_id}/invites"))
        .header(header::AUTHORIZATION, format!("Bearer {}", ctx.owner_token))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&invite_req).unwrap()))
        .unwrap();

    let resp = ctx.app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: Value = serde_json::from_slice(&bytes).unwrap();
    let invite_token = json["invite_token"].as_str().unwrap().to_string();
    assert!(!invite_token.is_empty());

    // 2. Listing invites does not expose plaintext token
    let req = Request::builder()
        .method("GET")
        .uri(format!("/api/v1/vaults/{vault_id}/invites"))
        .header(header::AUTHORIZATION, format!("Bearer {}", ctx.owner_token))
        .body(Body::empty())
        .unwrap();

    let resp = ctx.app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: Value = serde_json::from_slice(&bytes).unwrap();
    let invites = json["invites"].as_array().unwrap();
    assert_eq!(invites.len(), 1);
    assert!(invites[0]["invite_token"].is_null());

    // 3. Alice accepts invitation
    let accept_req = AcceptInviteRequest {
        invite_token: invite_token.clone(),
    };
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/invites/accept")
        .header(header::AUTHORIZATION, format!("Bearer {alice_token}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&accept_req).unwrap()))
        .unwrap();

    let resp = ctx.app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(json["role"], "editor");

    // Alice is now confirmed a member in the store
    let role = ctx
        .store
        .get_vault_member_role(vault_id, alice_id)
        .await
        .unwrap();
    assert_eq!(role, Some(VaultRole::Editor));

    // 4. Duplicate acceptance attempt fails with 409 Conflict
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/invites/accept")
        .header(header::AUTHORIZATION, format!("Bearer {bob_token}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&accept_req).unwrap()))
        .unwrap();

    let resp = ctx.app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::CONFLICT);

    // 5. Revoking an invitation prevents acceptance
    let invite_req_2 = CreateInviteRequest {
        role: "viewer".to_string(),
        recipient_email: None,
        ttl_secs: Some(3600),
    };
    let req = Request::builder()
        .method("POST")
        .uri(format!("/api/v1/vaults/{vault_id}/invites"))
        .header(header::AUTHORIZATION, format!("Bearer {}", ctx.owner_token))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&invite_req_2).unwrap()))
        .unwrap();

    let resp = ctx.app.clone().oneshot(req).await.unwrap();
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: Value = serde_json::from_slice(&bytes).unwrap();
    let token_2 = json["invite_token"].as_str().unwrap().to_string();
    let invite_id_2 = json["invite_id"].as_str().unwrap().to_string();

    // Owner revokes it
    let req = Request::builder()
        .method("DELETE")
        .uri(format!("/api/v1/vaults/{vault_id}/invites/{invite_id_2}"))
        .header(header::AUTHORIZATION, format!("Bearer {}", ctx.owner_token))
        .body(Body::empty())
        .unwrap();

    let resp = ctx.app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    // Bob tries to accept revoked invite -> 403 Forbidden
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/invites/accept")
        .header(header::AUTHORIZATION, format!("Bearer {bob_token}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            serde_json::to_vec(&AcceptInviteRequest {
                invite_token: token_2,
            })
            .unwrap(),
        ))
        .unwrap();

    let resp = ctx.app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn test_recipient_wrapped_key_envelope_device_isolation() {
    let ctx = setup_test_context().await;
    let vault_id = create_team_vault(&ctx.app, &ctx.owner_token, "Key Vault").await;

    let (alice_id, alice_token, alice_device_id, _) =
        create_user(&ctx, "key_alice", "alice_k@example.com").await;
    let (bob_id, bob_token, bob_device_id, _) =
        create_user(&ctx, "key_bob", "bob_k@example.com").await;

    // Add Alice and Bob as members
    for (uid, role) in [(alice_id, "editor"), (bob_id, "editor")] {
        ctx.store
            .add_vault_member(&shellumi_server_domain::VaultMember {
                vault_id,
                user_id: uid,
                role: if role == "editor" {
                    VaultRole::Editor
                } else {
                    VaultRole::Viewer
                },
                joined_at: chrono::Utc::now().timestamp(),
            })
            .await
            .unwrap();
    }

    // Owner publishes wrapped envelopes for Alice's device and Bob's device
    let pub_req = PublishKeyEnvelopesRequest {
        epoch: 1,
        envelopes: vec![
            KeyEnvelopeItem {
                recipient_device_id: alice_device_id,
                wrapped_dek: "ciphertext-dek-for-alice".to_string(),
                key_agreement_ephemeral_pk: Some("eph-pk-alice".to_string()),
            },
            KeyEnvelopeItem {
                recipient_device_id: bob_device_id,
                wrapped_dek: "ciphertext-dek-for-bob".to_string(),
                key_agreement_ephemeral_pk: Some("eph-pk-bob".to_string()),
            },
        ],
    };

    let req = Request::builder()
        .method("POST")
        .uri(format!("/api/v1/vaults/{vault_id}/keys/envelopes"))
        .header(header::AUTHORIZATION, format!("Bearer {}", ctx.owner_token))
        .header("X-Device-Id", ctx.owner_device_id.to_string())
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&pub_req).unwrap()))
        .unwrap();

    let resp = ctx.app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);

    // 1. Alice fetches envelopes: receives ONLY Alice's wrap
    let req = Request::builder()
        .method("GET")
        .uri(format!("/api/v1/vaults/{vault_id}/keys/envelopes"))
        .header(header::AUTHORIZATION, format!("Bearer {alice_token}"))
        .header("X-Device-Id", alice_device_id.to_string())
        .body(Body::empty())
        .unwrap();

    let resp = ctx.app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: Value = serde_json::from_slice(&bytes).unwrap();
    let envs = json["envelopes"].as_array().unwrap();
    assert_eq!(envs.len(), 1);
    assert_eq!(envs[0]["wrapped_dek"], "ciphertext-dek-for-alice");
    assert_eq!(envs[0]["recipient_device_id"], alice_device_id.to_string());

    // 2. Bob fetches envelopes: receives ONLY Bob's wrap
    let req = Request::builder()
        .method("GET")
        .uri(format!("/api/v1/vaults/{vault_id}/keys/envelopes"))
        .header(header::AUTHORIZATION, format!("Bearer {bob_token}"))
        .header("X-Device-Id", bob_device_id.to_string())
        .body(Body::empty())
        .unwrap();

    let resp = ctx.app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: Value = serde_json::from_slice(&bytes).unwrap();
    let envs = json["envelopes"].as_array().unwrap();
    assert_eq!(envs.len(), 1);
    assert_eq!(envs[0]["wrapped_dek"], "ciphertext-dek-for-bob");
    assert_eq!(envs[0]["recipient_device_id"], bob_device_id.to_string());

    // 3. Alice attempts to spoof Bob's device ID: returns 403 Forbidden
    let req = Request::builder()
        .method("GET")
        .uri(format!("/api/v1/vaults/{vault_id}/keys/envelopes"))
        .header(header::AUTHORIZATION, format!("Bearer {alice_token}"))
        .header("X-Device-Id", bob_device_id.to_string())
        .body(Body::empty())
        .unwrap();

    let resp = ctx.app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    // 4. Missing X-Device-Id header returns 422 Unprocessable Entity
    let req = Request::builder()
        .method("GET")
        .uri(format!("/api/v1/vaults/{vault_id}/keys/envelopes"))
        .header(header::AUTHORIZATION, format!("Bearer {alice_token}"))
        .body(Body::empty())
        .unwrap();

    let resp = ctx.app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
}

#[tokio::test]
async fn test_epoch_rotation_and_stale_epoch_write_rejection() {
    let ctx = setup_test_context().await;
    let vault_id = create_team_vault(&ctx.app, &ctx.owner_token, "Rotation Vault").await;
    let (viewer_id, viewer_token, viewer_device_id, _) =
        create_user(&ctx, "viewer_user", "viewer@example.com").await;

    ctx.store
        .add_vault_member(&shellumi_server_domain::VaultMember {
            vault_id,
            user_id: viewer_id,
            role: VaultRole::Viewer,
            joined_at: chrono::Utc::now().timestamp(),
        })
        .await
        .unwrap();

    // 1. Commit at epoch 1 succeeds
    let envelope = sample_envelope();
    let mutation = create_signed_mutation(
        vault_id,
        "host-1",
        "host",
        0,
        false,
        1,
        1,
        Some(&envelope),
        &ctx.owner_keypair,
    );

    let commit_req = CommitBatchRequest {
        protocol_version: CURRENT_PROTOCOL_VERSION,
        vault_id,
        idempotency_key: "idem-epoch-1".to_string(),
        base_cursor: None,
        mutations: vec![mutation],
    };

    let req = Request::builder()
        .method("POST")
        .uri(format!("/api/v1/vaults/{vault_id}/commits"))
        .header(header::AUTHORIZATION, format!("Bearer {}", ctx.owner_token))
        .header("X-Device-Id", ctx.owner_device_id.to_string())
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&commit_req).unwrap()))
        .unwrap();

    let resp = ctx.app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // 2. Rotate epoch to 2
    let rot_req = RotateKeyEpochRequest {
        new_epoch: 2,
        envelopes: vec![KeyEnvelopeItem {
            recipient_device_id: ctx.owner_device_id,
            wrapped_dek: "new-dek-epoch-2".to_string(),
            key_agreement_ephemeral_pk: None,
        }],
    };
    let req = Request::builder()
        .method("POST")
        .uri(format!("/api/v1/vaults/{vault_id}/keys/epochs"))
        .header(header::AUTHORIZATION, format!("Bearer {}", ctx.owner_token))
        .header("X-Device-Id", ctx.owner_device_id.to_string())
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&rot_req).unwrap()))
        .unwrap();

    let resp = ctx.app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // 3. Stale epoch rotation (attempting to rotate to epoch 2 or epoch 1) returns 409 Conflict
    let stale_rot = RotateKeyEpochRequest {
        new_epoch: 2,
        envelopes: vec![],
    };
    let req = Request::builder()
        .method("POST")
        .uri(format!("/api/v1/vaults/{vault_id}/keys/epochs"))
        .header(header::AUTHORIZATION, format!("Bearer {}", ctx.owner_token))
        .header("X-Device-Id", ctx.owner_device_id.to_string())
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&stale_rot).unwrap()))
        .unwrap();

    let resp = ctx.app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::CONFLICT);

    // 4. Stale mutation write (using epoch 1 while active epoch is 2) returns 409 Conflict
    let stale_mutation = create_signed_mutation(
        vault_id,
        "host-2",
        "host",
        0,
        false,
        1, // stale epoch!
        2,
        Some(&envelope),
        &ctx.owner_keypair,
    );

    let stale_commit = CommitBatchRequest {
        protocol_version: CURRENT_PROTOCOL_VERSION,
        vault_id,
        idempotency_key: "idem-epoch-stale".to_string(),
        base_cursor: None,
        mutations: vec![stale_mutation],
    };

    let req = Request::builder()
        .method("POST")
        .uri(format!("/api/v1/vaults/{vault_id}/commits"))
        .header(header::AUTHORIZATION, format!("Bearer {}", ctx.owner_token))
        .header("X-Device-Id", ctx.owner_device_id.to_string())
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&stale_commit).unwrap()))
        .unwrap();

    let resp = ctx.app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::CONFLICT);
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(json["error_code"], "STALE_KEY_EPOCH");

    // 5. Commit using new epoch 2 succeeds
    let valid_mutation = create_signed_mutation(
        vault_id,
        "host-2",
        "host",
        0,
        false,
        2, // current epoch
        3,
        Some(&envelope),
        &ctx.owner_keypair,
    );

    let valid_commit = CommitBatchRequest {
        protocol_version: CURRENT_PROTOCOL_VERSION,
        vault_id,
        idempotency_key: "idem-epoch-valid-2".to_string(),
        base_cursor: None,
        mutations: vec![valid_mutation],
    };

    let req = Request::builder()
        .method("POST")
        .uri(format!("/api/v1/vaults/{vault_id}/commits"))
        .header(header::AUTHORIZATION, format!("Bearer {}", ctx.owner_token))
        .header("X-Device-Id", ctx.owner_device_id.to_string())
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&valid_commit).unwrap()))
        .unwrap();

    let resp = ctx.app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // 6. Viewer cannot rotate key epochs (403 Forbidden)
    let req = Request::builder()
        .method("POST")
        .uri(format!("/api/v1/vaults/{vault_id}/keys/epochs"))
        .header(header::AUTHORIZATION, format!("Bearer {viewer_token}"))
        .header("X-Device-Id", viewer_device_id.to_string())
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            serde_json::to_vec(&RotateKeyEpochRequest {
                new_epoch: 3,
                envelopes: vec![],
            })
            .unwrap(),
        ))
        .unwrap();

    let resp = ctx.app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn test_cryptographic_audit_log_hash_chaining() {
    let ctx = setup_test_context().await;
    let vault_id = create_team_vault(&ctx.app, &ctx.owner_token, "Audit Vault").await;
    let (alice_id, _, _, _) = create_user(&ctx, "audit_alice", "alice_aud@example.com").await;
    let (bob_id, bob_token, _, _) = create_user(&ctx, "audit_bob", "bob_aud@example.com").await;

    // Trigger audited actions:
    // 1. Add member Alice
    let add_req = AddVaultMemberRequest {
        user_id: alice_id,
        role: "editor".to_string(),
    };
    let req = Request::builder()
        .method("POST")
        .uri(format!("/api/v1/vaults/{vault_id}/members"))
        .header(header::AUTHORIZATION, format!("Bearer {}", ctx.owner_token))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&add_req).unwrap()))
        .unwrap();
    assert_eq!(
        ctx.app.clone().oneshot(req).await.unwrap().status(),
        StatusCode::OK
    );

    // 2. Add member Bob as Viewer
    let add_bob = AddVaultMemberRequest {
        user_id: bob_id,
        role: "viewer".to_string(),
    };
    let req = Request::builder()
        .method("POST")
        .uri(format!("/api/v1/vaults/{vault_id}/members"))
        .header(header::AUTHORIZATION, format!("Bearer {}", ctx.owner_token))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&add_bob).unwrap()))
        .unwrap();
    assert_eq!(
        ctx.app.clone().oneshot(req).await.unwrap().status(),
        StatusCode::OK
    );

    // 3. Create invite
    let invite_req = CreateInviteRequest {
        role: "viewer".to_string(),
        recipient_email: None,
        ttl_secs: Some(3600),
    };
    let req = Request::builder()
        .method("POST")
        .uri(format!("/api/v1/vaults/{vault_id}/invites"))
        .header(header::AUTHORIZATION, format!("Bearer {}", ctx.owner_token))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&invite_req).unwrap()))
        .unwrap();
    assert_eq!(
        ctx.app.clone().oneshot(req).await.unwrap().status(),
        StatusCode::CREATED
    );

    // 4. Rotate key epoch
    let rot_req = RotateKeyEpochRequest {
        new_epoch: 2,
        envelopes: vec![],
    };
    let req = Request::builder()
        .method("POST")
        .uri(format!("/api/v1/vaults/{vault_id}/keys/epochs"))
        .header(header::AUTHORIZATION, format!("Bearer {}", ctx.owner_token))
        .header("X-Device-Id", ctx.owner_device_id.to_string())
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&rot_req).unwrap()))
        .unwrap();
    assert_eq!(
        ctx.app.clone().oneshot(req).await.unwrap().status(),
        StatusCode::OK
    );

    // 5. Owner retrieves audit log
    let req = Request::builder()
        .method("GET")
        .uri(format!("/api/v1/vaults/{vault_id}/audit"))
        .header(header::AUTHORIZATION, format!("Bearer {}", ctx.owner_token))
        .body(Body::empty())
        .unwrap();

    let resp = ctx.app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: Value = serde_json::from_slice(&bytes).unwrap();
    let events = json["events"].as_array().unwrap();

    assert!(
        events.len() >= 4,
        "Expected at least 4 audit events, got {}",
        events.len()
    );

    // 6. Verify cryptographic hash chain:
    // Event 0 predecessor must be GENESIS_AUDIT_HASH
    assert_eq!(events[0]["predecessor_hash"], GENESIS_AUDIT_HASH);

    for i in 0..events.len() {
        let ev = &events[i];
        let id = ev["id"].as_i64().unwrap();
        let actor = Uuid::parse_str(ev["actor_user_id"].as_str().unwrap()).unwrap();
        let action = ev["action"].as_str().unwrap();
        let target_type = ev["target_type"].as_str().unwrap();
        let target_id = ev["target_id"].as_str().unwrap();
        let pred_hash = ev["predecessor_hash"].as_str().unwrap();
        let created_at = ev["created_at"].as_i64().unwrap();
        let event_hash = ev["event_hash"].as_str().unwrap();

        // Verify predecessor linkage with previous event
        if i > 0 {
            assert_eq!(
                pred_hash,
                events[i - 1]["event_hash"].as_str().unwrap(),
                "Event {} predecessor_hash does not match event {} event_hash",
                i,
                i - 1
            );
        }

        // Verify hash computation
        let expected_hash = compute_audit_hash(
            id,
            vault_id,
            actor,
            action,
            target_type,
            target_id,
            pred_hash,
            created_at,
        );
        assert_eq!(event_hash, expected_hash, "Event {} hash mismatch", i);
    }

    // 7. Viewer Bob cannot view audit log -> 403 Forbidden
    let req = Request::builder()
        .method("GET")
        .uri(format!("/api/v1/vaults/{vault_id}/audit"))
        .header(header::AUTHORIZATION, format!("Bearer {bob_token}"))
        .body(Body::empty())
        .unwrap();

    let resp = ctx.app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}
