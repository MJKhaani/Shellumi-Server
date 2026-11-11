//! Integration tests for Milestone M2: Encrypted Vaults, CAS Commits, Idempotency, and Delta Sync.

use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine;
use ring::signature::Ed25519KeyPair;
use serde_json::Value;
use shellumi_server::config::ServerConfig;
use shellumi_server::server::create_router;
use shellumi_server_crypto::{
    canonical_mutation_preimage, compute_ciphertext_digest, generate_test_ed25519_keypair,
    sign_message,
};
use shellumi_server_protocol::{
    BootstrapRequest, CommitBatchRequest, CreateVaultRequest, EncryptedEnvelope, MutationItem,
    RegisterDeviceRequest, CURRENT_PROTOCOL_VERSION,
};
use tower::ServiceExt;
use uuid::Uuid;

async fn setup_app_and_bootstrap() -> (axum::Router, String, String) {
    let config = ServerConfig {
        access_token_ttl_secs: 3600,
        ..Default::default()
    };
    let app = create_router(config);

    let boot_req = BootstrapRequest {
        admin_username: "vault_admin".to_string(),
        admin_email: "vault_admin@example.com".to_string(),
        admin_password: "AdminSecurePassword123!".to_string(),
        org_name: "Acme Secure Org".to_string(),
        bootstrap_token: None,
    };

    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/bootstrap")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&boot_req).unwrap()))
        .unwrap();

    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);

    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: Value = serde_json::from_slice(&body).unwrap();
    let token = json["access_token"].as_str().unwrap().to_string();
    let user_id = json["user_id"].as_str().unwrap().to_string();

    (app, token, user_id)
}

async fn register_test_device(
    app: &axum::Router,
    token: &str,
    name: &str,
) -> (Uuid, Ed25519KeyPair, String) {
    let (keypair, public_key_b64) = generate_test_ed25519_keypair().unwrap();
    let reg_req = RegisterDeviceRequest {
        device_name: name.to_string(),
        signing_public_key: public_key_b64.clone(),
        agreement_public_key: "agree-key".to_string(),
    };

    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/devices")
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&reg_req).unwrap()))
        .unwrap();

    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);

    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: Value = serde_json::from_slice(&body).unwrap();
    let device_id = Uuid::parse_str(json["device_id"].as_str().unwrap()).unwrap();

    (device_id, keypair, public_key_b64)
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

#[tokio::test]
async fn test_vault_crud_lifecycle() {
    let (app, token, _user_id) = setup_app_and_bootstrap().await;

    // 1. Create vault
    let create_req = CreateVaultRequest {
        name: Some("Personal Vault".to_string()),
        encrypted_name: None,
        vault_type: "personal".to_string(),
    };
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/vaults")
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&create_req).unwrap()))
        .unwrap();

    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: Value = serde_json::from_slice(&body).unwrap();
    let vault_id = json["vault_id"].as_str().unwrap().to_string();
    assert_eq!(json["role"], "owner");
    assert_eq!(json["server_sequence"], 0);

    // 2. List vaults
    let req = Request::builder()
        .method("GET")
        .uri("/api/v1/vaults")
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["vaults"].as_array().unwrap().len(), 1);

    // 3. Get single vault
    let req = Request::builder()
        .method("GET")
        .uri(format!("/api/v1/vaults/{vault_id}"))
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // 4. Update vault metadata
    let update_req = serde_json::json!({
        "encrypted_name": "Updated Encrypted Name"
    });
    let req = Request::builder()
        .method("PATCH")
        .uri(format!("/api/v1/vaults/{vault_id}"))
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&update_req).unwrap()))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["encrypted_name"], "Updated Encrypted Name");

    // 5. Delete vault
    let req = Request::builder()
        .method("DELETE")
        .uri(format!("/api/v1/vaults/{vault_id}"))
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // Vault should no longer be listed
    let req = Request::builder()
        .method("GET")
        .uri("/api/v1/vaults")
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["vaults"].as_array().unwrap().len(), 0);
}

#[tokio::test]
async fn test_two_clients_offline_convergence_without_conflict() {
    let (app, token, _user_id) = setup_app_and_bootstrap().await;

    // Register Device A and Device B
    let (dev_a_id, dev_a_key, _) = register_test_device(&app, &token, "MacBook Air").await;
    let (dev_b_id, dev_b_key, _) = register_test_device(&app, &token, "Linux Desktop").await;

    // Create a vault
    let create_req = CreateVaultRequest {
        name: Some("Convergence Vault".to_string()),
        encrypted_name: None,
        vault_type: "personal".to_string(),
    };
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/vaults")
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&create_req).unwrap()))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: Value = serde_json::from_slice(&body).unwrap();
    let vault_id = Uuid::parse_str(json["vault_id"].as_str().unwrap()).unwrap();

    let env = sample_envelope();

    // Device A commits Object 1 offline (expected_revision = 0)
    let m_a = create_signed_mutation(
        vault_id,
        "host-1",
        "host",
        0,
        false,
        1,
        1,
        Some(&env),
        &dev_a_key,
    );
    let commit_a = CommitBatchRequest {
        protocol_version: CURRENT_PROTOCOL_VERSION,
        vault_id,
        idempotency_key: "idem-a-1".to_string(),
        base_cursor: None,
        mutations: vec![m_a],
    };
    let req = Request::builder()
        .method("POST")
        .uri(format!("/api/v1/vaults/{vault_id}/commits"))
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header("X-Device-Id", dev_a_id.to_string())
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&commit_a).unwrap()))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let json_a: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json_a["commit_sequence"], 1);

    // Device B commits Object 2 offline (expected_revision = 0)
    let m_b = create_signed_mutation(
        vault_id,
        "host-2",
        "host",
        0,
        false,
        1,
        1,
        Some(&env),
        &dev_b_key,
    );
    let commit_b = CommitBatchRequest {
        protocol_version: CURRENT_PROTOCOL_VERSION,
        vault_id,
        idempotency_key: "idem-b-1".to_string(),
        base_cursor: None,
        mutations: vec![m_b],
    };
    let req = Request::builder()
        .method("POST")
        .uri(format!("/api/v1/vaults/{vault_id}/commits"))
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header("X-Device-Id", dev_b_id.to_string())
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&commit_b).unwrap()))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let json_b: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json_b["commit_sequence"], 2);

    // Fetch change feed: both mutations converge in monotonic sequence order!
    let req = Request::builder()
        .method("GET")
        .uri(format!("/api/v1/vaults/{vault_id}/changes?since=0"))
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let feed: Value = serde_json::from_slice(&body).unwrap();
    let records = feed["records"].as_array().unwrap();
    assert_eq!(records.len(), 2);
    assert_eq!(records[0]["sequence"], 1);
    assert_eq!(records[0]["object_id"], "host-1");
    assert_eq!(records[1]["sequence"], 2);
    assert_eq!(records[1]["object_id"], "host-2");
}

#[tokio::test]
async fn test_concurrent_same_object_cas_409_conflict() {
    let (app, token, _user_id) = setup_app_and_bootstrap().await;

    let (dev_a_id, dev_a_key, _) = register_test_device(&app, &token, "Device A").await;
    let (dev_b_id, dev_b_key, _) = register_test_device(&app, &token, "Device B").await;

    // Create vault
    let create_req = CreateVaultRequest {
        name: Some("Conflict Vault".to_string()),
        encrypted_name: None,
        vault_type: "personal".to_string(),
    };
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/vaults")
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&create_req).unwrap()))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: Value = serde_json::from_slice(&body).unwrap();
    let vault_id = Uuid::parse_str(json["vault_id"].as_str().unwrap()).unwrap();

    let env = sample_envelope();

    // Device A and Device B both start with expected_revision = 0 for "host-target"
    let m_a = create_signed_mutation(
        vault_id,
        "host-target",
        "host",
        0,
        false,
        1,
        1,
        Some(&env),
        &dev_a_key,
    );
    let m_b = create_signed_mutation(
        vault_id,
        "host-target",
        "host",
        0,
        false,
        1,
        1,
        Some(&env),
        &dev_b_key,
    );

    // Device A commits first -> Succeeds (revision 1 assigned)
    let commit_a = CommitBatchRequest {
        protocol_version: CURRENT_PROTOCOL_VERSION,
        vault_id,
        idempotency_key: "cas-a".to_string(),
        base_cursor: None,
        mutations: vec![m_a],
    };
    let req = Request::builder()
        .method("POST")
        .uri(format!("/api/v1/vaults/{vault_id}/commits"))
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header("X-Device-Id", dev_a_id.to_string())
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&commit_a).unwrap()))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // Device B attempts to commit concurrently with expected_revision = 0 -> Fails with HTTP 409 Conflict!
    let commit_b = CommitBatchRequest {
        protocol_version: CURRENT_PROTOCOL_VERSION,
        vault_id,
        idempotency_key: "cas-b".to_string(),
        base_cursor: None,
        mutations: vec![m_b],
    };
    let req = Request::builder()
        .method("POST")
        .uri(format!("/api/v1/vaults/{vault_id}/commits"))
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header("X-Device-Id", dev_b_id.to_string())
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&commit_b).unwrap()))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::CONFLICT);
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let err_json: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(err_json["error_code"], "REVISION_CONFLICT");

    // Device B resolves conflict by committing with expected_revision = 1 -> Succeeds (revision 2 assigned)
    let m_b_resolved = create_signed_mutation(
        vault_id,
        "host-target",
        "host",
        1,
        false,
        1,
        2,
        Some(&env),
        &dev_b_key,
    );
    let commit_b_res = CommitBatchRequest {
        protocol_version: CURRENT_PROTOCOL_VERSION,
        vault_id,
        idempotency_key: "cas-b-resolved".to_string(),
        base_cursor: None,
        mutations: vec![m_b_resolved],
    };
    let req = Request::builder()
        .method("POST")
        .uri(format!("/api/v1/vaults/{vault_id}/commits"))
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header("X-Device-Id", dev_b_id.to_string())
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&commit_b_res).unwrap()))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let ack_json: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(ack_json["applied"][0]["assigned_revision"], 2);
}

#[tokio::test]
async fn test_idempotent_retries_and_payload_tamper_rejection() {
    let (app, token, _user_id) = setup_app_and_bootstrap().await;
    let (dev_id, dev_key, _) = register_test_device(&app, &token, "MacBook").await;

    // Create vault
    let create_req = CreateVaultRequest {
        name: Some("Idempotency Vault".to_string()),
        encrypted_name: None,
        vault_type: "personal".to_string(),
    };
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/vaults")
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&create_req).unwrap()))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: Value = serde_json::from_slice(&body).unwrap();
    let vault_id = Uuid::parse_str(json["vault_id"].as_str().unwrap()).unwrap();

    let env = sample_envelope();
    let m = create_signed_mutation(
        vault_id,
        "host-idem",
        "host",
        0,
        false,
        1,
        1,
        Some(&env),
        &dev_key,
    );

    let commit_req = CommitBatchRequest {
        protocol_version: CURRENT_PROTOCOL_VERSION,
        vault_id,
        idempotency_key: "idem-key-stable".to_string(),
        base_cursor: None,
        mutations: vec![m.clone()],
    };

    // First attempt -> Succeeds
    let req = Request::builder()
        .method("POST")
        .uri(format!("/api/v1/vaults/{vault_id}/commits"))
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header("X-Device-Id", dev_id.to_string())
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&commit_req).unwrap()))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let first_body: Value = serde_json::from_slice(&body).unwrap();

    // Exact retry with identical key and payload -> Returns cached response with 200 OK
    let req = Request::builder()
        .method("POST")
        .uri(format!("/api/v1/vaults/{vault_id}/commits"))
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header("X-Device-Id", dev_id.to_string())
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&commit_req).unwrap()))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let retry_body: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(first_body, retry_body);

    // Reusing same idempotency key with modified payload -> Returns HTTP 409 Conflict (IDEMPOTENCY_CONFLICT)
    let m_diff = create_signed_mutation(
        vault_id,
        "host-tampered",
        "host",
        0,
        false,
        1,
        2,
        Some(&env),
        &dev_key,
    );
    let commit_diff = CommitBatchRequest {
        protocol_version: CURRENT_PROTOCOL_VERSION,
        vault_id,
        idempotency_key: "idem-key-stable".to_string(),
        base_cursor: None,
        mutations: vec![m_diff],
    };
    let req = Request::builder()
        .method("POST")
        .uri(format!("/api/v1/vaults/{vault_id}/commits"))
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header("X-Device-Id", dev_id.to_string())
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&commit_diff).unwrap()))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::CONFLICT);
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let err_json: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(err_json["error_code"], "IDEMPOTENCY_CONFLICT");
}

#[tokio::test]
async fn test_tombstone_propagation_and_tampered_signature() {
    let (app, token, _user_id) = setup_app_and_bootstrap().await;
    let (dev_id, dev_key, _) = register_test_device(&app, &token, "MacBook").await;

    // Create vault
    let create_req = CreateVaultRequest {
        name: Some("Tombstone Vault".to_string()),
        encrypted_name: None,
        vault_type: "personal".to_string(),
    };
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/vaults")
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&create_req).unwrap()))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: Value = serde_json::from_slice(&body).unwrap();
    let vault_id = Uuid::parse_str(json["vault_id"].as_str().unwrap()).unwrap();

    let env = sample_envelope();

    // Create object
    let m = create_signed_mutation(
        vault_id,
        "snippet-to-delete",
        "snippet",
        0,
        false,
        1,
        1,
        Some(&env),
        &dev_key,
    );
    let commit = CommitBatchRequest {
        protocol_version: CURRENT_PROTOCOL_VERSION,
        vault_id,
        idempotency_key: "create-snip".to_string(),
        base_cursor: None,
        mutations: vec![m],
    };
    let req = Request::builder()
        .method("POST")
        .uri(format!("/api/v1/vaults/{vault_id}/commits"))
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header("X-Device-Id", dev_id.to_string())
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&commit).unwrap()))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // Tampered signature is rejected with HTTP 403 Forbidden (INVALID_SIGNATURE)
    let mut m_tampered = create_signed_mutation(
        vault_id,
        "snippet-to-delete",
        "snippet",
        1,
        true,
        1,
        2,
        None,
        &dev_key,
    );
    m_tampered.device_signature = BASE64_STANDARD.encode([42u8; 64]);
    let commit_tampered = CommitBatchRequest {
        protocol_version: CURRENT_PROTOCOL_VERSION,
        vault_id,
        idempotency_key: "tampered-sig".to_string(),
        base_cursor: None,
        mutations: vec![m_tampered],
    };
    let req = Request::builder()
        .method("POST")
        .uri(format!("/api/v1/vaults/{vault_id}/commits"))
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header("X-Device-Id", dev_id.to_string())
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&commit_tampered).unwrap()))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let err_json: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(err_json["error_code"], "INVALID_SIGNATURE");

    // Valid deletion tombstone
    let m_del = create_signed_mutation(
        vault_id,
        "snippet-to-delete",
        "snippet",
        1,
        true,
        1,
        3,
        None,
        &dev_key,
    );
    let commit_del = CommitBatchRequest {
        protocol_version: CURRENT_PROTOCOL_VERSION,
        vault_id,
        idempotency_key: "valid-tombstone".to_string(),
        base_cursor: None,
        mutations: vec![m_del],
    };
    let req = Request::builder()
        .method("POST")
        .uri(format!("/api/v1/vaults/{vault_id}/commits"))
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header("X-Device-Id", dev_id.to_string())
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&commit_del).unwrap()))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // Snapshot query has 0 active records
    let req = Request::builder()
        .method("GET")
        .uri(format!("/api/v1/vaults/{vault_id}/snapshots/latest"))
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let snap: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(snap["records"].as_array().unwrap().len(), 0);

    // Change feed has 2 entries (create + tombstone)
    let req = Request::builder()
        .method("GET")
        .uri(format!("/api/v1/vaults/{vault_id}/changes?since=0"))
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let feed: Value = serde_json::from_slice(&body).unwrap();
    let records = feed["records"].as_array().unwrap();
    assert_eq!(records.len(), 2);
    assert_eq!(records[0]["deleted"], false);
    assert_eq!(records[1]["deleted"], true);
}
