//! Integration tests for Milestone M5: Live Terminal Collaboration Relay.
//!
//! Verifies:
//! 1. Feature gating: 403 COLLAB_DISABLED when collab_enabled is false; capability advertised when true.
//! 2. Session lifecycle: Host starts controllable session; unenrolled outsider rejected.
//! 3. Single-writer role policy: Viewers strictly prohibited from transmitting TerminalInput.
//! 4. Non-host prohibited from emitting TerminalOutput.
//! 5. Monotonic writer fencing token: Grant control advances lease_token; valid token accepted.
//! 6. Stale lease token rejected with 409 STALE_LEASE_TOKEN.
//! 7. Host emergency control revocation: Lease token advances; former writer immediately locked out.
//! 8. Host emergency termination: Closes session; subsequent frame submissions rejected with 410 COLLAB_SESSION_TERMINATED.
//! 9. Polling and ordering: Monotonically ordered frames returned across cursor-based polling.
//! 10. Server zero-knowledge: Ciphertext payload preservation (server blind relay).

use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine;
use serde_json::Value;
use shellumi_server::config::ServerConfig;
use shellumi_server::server::create_router_with_auth_and_sync;
use shellumi_server_auth::{create_access_token, AuthService};
use shellumi_server_crypto::generate_test_ed25519_keypair;
use shellumi_server_domain::{Device, Organization, User};
use shellumi_server_protocol::{
    CollabFrameType, CreateCollabSessionRequest, EnrollParticipantRequest, GrantControlRequest,
    SendCollabFrameRequest,
};
use shellumi_server_store::{DeviceRepository, InMemoryStore, OrgRepository, UserRepository};
use shellumi_server_sync::SyncEngine;
use std::sync::Arc;
use tower::ServiceExt;
use uuid::Uuid;

struct TestContext {
    app: axum::Router,
    _host_id: Uuid,
    host_token: String,
    host_device_id: Uuid,
    participant_id: Uuid,
    participant_token: String,
    participant_device_id: Uuid,
    _outsider_id: Uuid,
    outsider_token: String,
    _outsider_device_id: Uuid,
}

async fn setup_collab_context(collab_enabled: bool) -> TestContext {
    let store = Arc::new(InMemoryStore::new());
    let token_secret = b"shellumi_server_test_hmac_secret_key_32bytes!!".to_vec();
    let auth = Arc::new(AuthService::new(
        store.clone(),
        token_secret.clone(),
        3600,
        86400,
    ));
    let sync = Arc::new(SyncEngine::new(store.clone(), 10 * 1024 * 1024));

    let now = chrono::Utc::now().timestamp();
    let org_id = Uuid::new_v4();
    let host_id = Uuid::new_v4();
    let participant_id = Uuid::new_v4();
    let outsider_id = Uuid::new_v4();

    let host_device_id = Uuid::new_v4();
    let participant_device_id = Uuid::new_v4();
    let outsider_device_id = Uuid::new_v4();

    // Create users
    let host_user = User {
        id: host_id,
        username: "host_alice".to_string(),
        email: "alice@example.com".to_string(),
        password_hash: "argon2-dummy".to_string(),
        created_at: now,
        updated_at: now,
        is_active: true,
    };
    let participant_user = User {
        id: participant_id,
        username: "writer_bob".to_string(),
        email: "bob@example.com".to_string(),
        password_hash: "argon2-dummy".to_string(),
        created_at: now,
        updated_at: now,
        is_active: true,
    };
    let outsider_user = User {
        id: outsider_id,
        username: "outsider_eve".to_string(),
        email: "eve@example.com".to_string(),
        password_hash: "argon2-dummy".to_string(),
        created_at: now,
        updated_at: now,
        is_active: true,
    };

    store.create_user(&host_user).await.unwrap();
    store.create_user(&participant_user).await.unwrap();
    store.create_user(&outsider_user).await.unwrap();

    let org = Organization {
        id: org_id,
        name: "Collab Org".to_string(),
        created_at: now,
    };
    store.create_org(&org, host_id).await.unwrap();

    // Create devices
    let (_, host_pk) = generate_test_ed25519_keypair().unwrap();
    let (_, part_pk) = generate_test_ed25519_keypair().unwrap();
    let (_, out_pk) = generate_test_ed25519_keypair().unwrap();

    store
        .create_device(&Device {
            id: host_device_id,
            user_id: host_id,
            device_name: "Alice Mac".to_string(),
            signing_public_key: host_pk,
            agreement_public_key: "x25519-host".to_string(),
            created_at: now,
            last_seen_at: None,
            revoked_at: None,
        })
        .await
        .unwrap();

    store
        .create_device(&Device {
            id: participant_device_id,
            user_id: participant_id,
            device_name: "Bob ThinkPad".to_string(),
            signing_public_key: part_pk,
            agreement_public_key: "x25519-part".to_string(),
            created_at: now,
            last_seen_at: None,
            revoked_at: None,
        })
        .await
        .unwrap();

    store
        .create_device(&Device {
            id: outsider_device_id,
            user_id: outsider_id,
            device_name: "Eve Linux".to_string(),
            signing_public_key: out_pk,
            agreement_public_key: "x25519-out".to_string(),
            created_at: now,
            last_seen_at: None,
            revoked_at: None,
        })
        .await
        .unwrap();

    let host_token = create_access_token(host_id, "host_alice", &token_secret, 3600).unwrap();
    let participant_token =
        create_access_token(participant_id, "writer_bob", &token_secret, 3600).unwrap();
    let outsider_token =
        create_access_token(outsider_id, "outsider_eve", &token_secret, 3600).unwrap();

    let config = ServerConfig {
        collab_enabled,
        ..Default::default()
    };

    let app = create_router_with_auth_and_sync(config, auth, sync);

    TestContext {
        app,
        _host_id: host_id,
        host_token,
        host_device_id,
        participant_id,
        participant_token,
        participant_device_id,
        _outsider_id: outsider_id,
        outsider_token,
        _outsider_device_id: outsider_device_id,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_collab_feature_gate_disabled_rejects_and_hides_capability() {
    let ctx = setup_collab_context(false).await;

    // 1. Capabilities check: terminal_collab_v1 should NOT be present
    let req = Request::builder()
        .uri("/api/v1/capabilities")
        .method("GET")
        .body(Body::empty())
        .unwrap();

    let resp = ctx.app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let val: Value = serde_json::from_slice(&body).unwrap();
    let features: Vec<String> = val["supported_features"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f.as_str().unwrap().to_string())
        .collect();
    assert!(!features.contains(&"terminal_collab_v1".to_string()));

    // 2. Collab session creation attempt rejected with 403 COLLAB_DISABLED
    let create_payload = CreateCollabSessionRequest {
        title: "Forbidden Session".to_string(),
        mode: "controllable".to_string(),
        ttl_secs: Some(3600),
    };
    let req = Request::builder()
        .uri("/api/v1/collab/sessions")
        .method("POST")
        .header(header::AUTHORIZATION, format!("Bearer {}", ctx.host_token))
        .header("X-Device-Id", ctx.host_device_id.to_string())
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&create_payload).unwrap()))
        .unwrap();

    let resp = ctx.app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let val: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(val["error_code"], "COLLAB_DISABLED");
}

#[tokio::test]
async fn test_collab_feature_gate_enabled_advertises_capability() {
    let ctx = setup_collab_context(true).await;

    let req = Request::builder()
        .uri("/api/v1/capabilities")
        .method("GET")
        .body(Body::empty())
        .unwrap();

    let resp = ctx.app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let val: Value = serde_json::from_slice(&body).unwrap();
    let features: Vec<String> = val["supported_features"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f.as_str().unwrap().to_string())
        .collect();
    assert!(features.contains(&"terminal_collab_v1".to_string()));
}

#[tokio::test]
async fn test_full_live_terminal_collaboration_relay_lifecycle() {
    let ctx = setup_collab_context(true).await;

    // 1. Host creates a controllable collaboration session
    let create_req = CreateCollabSessionRequest {
        title: "Pair Debugging Session".to_string(),
        mode: "controllable".to_string(),
        ttl_secs: Some(7200),
    };

    let req = Request::builder()
        .uri("/api/v1/collab/sessions")
        .method("POST")
        .header(header::AUTHORIZATION, format!("Bearer {}", ctx.host_token))
        .header("X-Device-Id", ctx.host_device_id.to_string())
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&create_req).unwrap()))
        .unwrap();

    let resp = ctx.app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let session_val: Value = serde_json::from_slice(&body).unwrap();
    let session_id = session_val["session_id"].as_str().unwrap();
    assert_eq!(session_val["title"], "Pair Debugging Session");
    assert_eq!(session_val["mode"], "controllable");
    assert_eq!(session_val["lease_token"], 1);
    assert!(session_val["active_writer_user_id"].is_null());

    // 2. Outsider attempt to view session is rejected (404 to avoid ID enumeration)
    let req = Request::builder()
        .uri(format!("/api/v1/collab/sessions/{session_id}"))
        .method("GET")
        .header(
            header::AUTHORIZATION,
            format!("Bearer {}", ctx.outsider_token),
        )
        .body(Body::empty())
        .unwrap();

    let resp = ctx.app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);

    // 3. Host enrolls Bob as a Viewer
    let enroll_req = EnrollParticipantRequest {
        user_id: ctx.participant_id,
        device_id: ctx.participant_device_id,
        role: "viewer".to_string(),
    };
    let req = Request::builder()
        .uri(format!("/api/v1/collab/sessions/{session_id}/participants"))
        .method("POST")
        .header(header::AUTHORIZATION, format!("Bearer {}", ctx.host_token))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&enroll_req).unwrap()))
        .unwrap();

    let resp = ctx.app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);

    // 4. Bob (Viewer) can now view session details
    let req = Request::builder()
        .uri(format!("/api/v1/collab/sessions/{session_id}"))
        .method("GET")
        .header(
            header::AUTHORIZATION,
            format!("Bearer {}", ctx.participant_token),
        )
        .body(Body::empty())
        .unwrap();

    let resp = ctx.app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // 5. Host emits TerminalOutput frame (terminal PTY screen update)
    let output_cipher = BASE64_STANDARD.encode(b"ciphertext:terminal_screen_ansi_codes_e2ee");
    let output_req = SendCollabFrameRequest {
        frame_type: CollabFrameType::Output,
        lease_token: None,
        encrypted_envelope: output_cipher.clone(),
    };
    let req = Request::builder()
        .uri(format!("/api/v1/collab/sessions/{session_id}/frames"))
        .method("POST")
        .header(header::AUTHORIZATION, format!("Bearer {}", ctx.host_token))
        .header("X-Device-Id", ctx.host_device_id.to_string())
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&output_req).unwrap()))
        .unwrap();

    let resp = ctx.app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let frame_val: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(frame_val["sequence"], 1);
    assert_eq!(frame_val["frame_type"], "output");
    assert_eq!(frame_val["encrypted_envelope"], output_cipher);

    // 6. Viewer (Bob) attempts to emit TerminalOutput: STRICTLY FORBIDDEN (host only)
    let fake_output = SendCollabFrameRequest {
        frame_type: CollabFrameType::Output,
        lease_token: None,
        encrypted_envelope: "fake-output".to_string(),
    };
    let req = Request::builder()
        .uri(format!("/api/v1/collab/sessions/{session_id}/frames"))
        .method("POST")
        .header(
            header::AUTHORIZATION,
            format!("Bearer {}", ctx.participant_token),
        )
        .header("X-Device-Id", ctx.participant_device_id.to_string())
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&fake_output).unwrap()))
        .unwrap();

    let resp = ctx.app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    // 7. Viewer (Bob) attempts to emit TerminalInput before control is granted: REJECTED
    let input_cipher = BASE64_STANDARD.encode(b"ciphertext:ls -la\n");
    let input_req = SendCollabFrameRequest {
        frame_type: CollabFrameType::Input,
        lease_token: Some(1),
        encrypted_envelope: input_cipher.clone(),
    };
    let req = Request::builder()
        .uri(format!("/api/v1/collab/sessions/{session_id}/frames"))
        .method("POST")
        .header(
            header::AUTHORIZATION,
            format!("Bearer {}", ctx.participant_token),
        )
        .header("X-Device-Id", ctx.participant_device_id.to_string())
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&input_req).unwrap()))
        .unwrap();

    let resp = ctx.app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let err_val: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(err_val["error_code"], "NOT_AUTHORIZED_WRITER");

    // 8. Host grants write control to Bob (increments lease_token to 2)
    let grant_req = GrantControlRequest {
        target_user_id: ctx.participant_id,
        target_device_id: ctx.participant_device_id,
        ttl_secs: Some(300),
    };
    let req = Request::builder()
        .uri(format!(
            "/api/v1/collab/sessions/{session_id}/control/grant"
        ))
        .method("POST")
        .header(header::AUTHORIZATION, format!("Bearer {}", ctx.host_token))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&grant_req).unwrap()))
        .unwrap();

    let resp = ctx.app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let granted_val: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(granted_val["lease_token"], 2);
    assert_eq!(
        granted_val["active_writer_user_id"],
        ctx.participant_id.to_string()
    );

    // 9. Bob submits TerminalInput with STALE lease_token 1: REJECTED (409 Conflict)
    let stale_input = SendCollabFrameRequest {
        frame_type: CollabFrameType::Input,
        lease_token: Some(1),
        encrypted_envelope: input_cipher.clone(),
    };
    let req = Request::builder()
        .uri(format!("/api/v1/collab/sessions/{session_id}/frames"))
        .method("POST")
        .header(
            header::AUTHORIZATION,
            format!("Bearer {}", ctx.participant_token),
        )
        .header("X-Device-Id", ctx.participant_device_id.to_string())
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&stale_input).unwrap()))
        .unwrap();

    let resp = ctx.app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::CONFLICT);
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let err_val: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(err_val["error_code"], "STALE_LEASE_TOKEN");

    // 10. Bob submits TerminalInput with VALID lease_token 2: ACCEPTED
    let valid_input = SendCollabFrameRequest {
        frame_type: CollabFrameType::Input,
        lease_token: Some(2),
        encrypted_envelope: input_cipher.clone(),
    };
    let req = Request::builder()
        .uri(format!("/api/v1/collab/sessions/{session_id}/frames"))
        .method("POST")
        .header(
            header::AUTHORIZATION,
            format!("Bearer {}", ctx.participant_token),
        )
        .header("X-Device-Id", ctx.participant_device_id.to_string())
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&valid_input).unwrap()))
        .unwrap();

    let resp = ctx.app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let frame_val: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(frame_val["frame_type"], "input");
    assert_eq!(frame_val["lease_token"], 2);
    assert_eq!(frame_val["encrypted_envelope"], input_cipher);

    // 11. Host emergency revokes write control (increments lease_token to 3)
    let req = Request::builder()
        .uri(format!(
            "/api/v1/collab/sessions/{session_id}/control/revoke"
        ))
        .method("POST")
        .header(header::AUTHORIZATION, format!("Bearer {}", ctx.host_token))
        .body(Body::empty())
        .unwrap();

    let resp = ctx.app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let revoked_val: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(revoked_val["lease_token"], 3);
    assert!(revoked_val["active_writer_user_id"].is_null());

    // 12. Former writer Bob attempts to type again: IMMEDIATELY REJECTED
    let req = Request::builder()
        .uri(format!("/api/v1/collab/sessions/{session_id}/frames"))
        .method("POST")
        .header(
            header::AUTHORIZATION,
            format!("Bearer {}", ctx.participant_token),
        )
        .header("X-Device-Id", ctx.participant_device_id.to_string())
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&valid_input).unwrap()))
        .unwrap();

    let resp = ctx.app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let err_val: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(err_val["error_code"], "NOT_AUTHORIZED_WRITER");

    // 13. Poll frames cursor: verify frames are returned monotonically
    let req = Request::builder()
        .uri(format!(
            "/api/v1/collab/sessions/{session_id}/poll?since_sequence=0"
        ))
        .method("GET")
        .header(
            header::AUTHORIZATION,
            format!("Bearer {}", ctx.participant_token),
        )
        .body(Body::empty())
        .unwrap();

    let resp = ctx.app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let poll_val: Value = serde_json::from_slice(&body).unwrap();
    let frames = poll_val["frames"].as_array().unwrap();
    assert!(frames.len() >= 4); // output, control_granted, input, control_revoked

    // Verify sequences are strictly increasing
    let mut last_seq = 0;
    for f in frames {
        let seq = f["sequence"].as_u64().unwrap();
        assert!(seq > last_seq);
        last_seq = seq;
    }

    // 14. Host emergency terminates the collaboration session
    let req = Request::builder()
        .uri(format!("/api/v1/collab/sessions/{session_id}/terminate"))
        .method("POST")
        .header(header::AUTHORIZATION, format!("Bearer {}", ctx.host_token))
        .body(Body::empty())
        .unwrap();

    let resp = ctx.app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // 15. Further frame submissions are rejected with 410 Gone / COLLAB_SESSION_TERMINATED
    let req = Request::builder()
        .uri(format!("/api/v1/collab/sessions/{session_id}/frames"))
        .method("POST")
        .header(header::AUTHORIZATION, format!("Bearer {}", ctx.host_token))
        .header("X-Device-Id", ctx.host_device_id.to_string())
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&output_req).unwrap()))
        .unwrap();

    let resp = ctx.app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::GONE);
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let err_val: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(err_val["error_code"], "COLLAB_SESSION_TERMINATED");
}

#[tokio::test]
async fn test_read_only_collab_session_prohibits_all_input_and_control_grants() {
    let ctx = setup_collab_context(true).await;

    // 1. Create a ReadOnly session
    let create_req = CreateCollabSessionRequest {
        title: "Presentation Session".to_string(),
        mode: "read_only".to_string(),
        ttl_secs: Some(3600),
    };

    let req = Request::builder()
        .uri("/api/v1/collab/sessions")
        .method("POST")
        .header(header::AUTHORIZATION, format!("Bearer {}", ctx.host_token))
        .header("X-Device-Id", ctx.host_device_id.to_string())
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&create_req).unwrap()))
        .unwrap();

    let resp = ctx.app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let val: Value = serde_json::from_slice(&body).unwrap();
    let session_id = val["session_id"].as_str().unwrap();
    assert_eq!(val["mode"], "read_only");

    // 2. Enroll participant
    let enroll_req = EnrollParticipantRequest {
        user_id: ctx.participant_id,
        device_id: ctx.participant_device_id,
        role: "viewer".to_string(),
    };
    let req = Request::builder()
        .uri(format!("/api/v1/collab/sessions/{session_id}/participants"))
        .method("POST")
        .header(header::AUTHORIZATION, format!("Bearer {}", ctx.host_token))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&enroll_req).unwrap()))
        .unwrap();
    let resp = ctx.app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);

    // 3. Attempting to grant write control fails with 422 Invalid Input
    let grant_req = GrantControlRequest {
        target_user_id: ctx.participant_id,
        target_device_id: ctx.participant_device_id,
        ttl_secs: Some(60),
    };
    let req = Request::builder()
        .uri(format!(
            "/api/v1/collab/sessions/{session_id}/control/grant"
        ))
        .method("POST")
        .header(header::AUTHORIZATION, format!("Bearer {}", ctx.host_token))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&grant_req).unwrap()))
        .unwrap();

    let resp = ctx.app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);

    // 4. Attempting to send TerminalInput fails with 403 Forbidden
    let input_req = SendCollabFrameRequest {
        frame_type: CollabFrameType::Input,
        lease_token: Some(1),
        encrypted_envelope: "input".to_string(),
    };
    let req = Request::builder()
        .uri(format!("/api/v1/collab/sessions/{session_id}/frames"))
        .method("POST")
        .header(
            header::AUTHORIZATION,
            format!("Bearer {}", ctx.participant_token),
        )
        .header("X-Device-Id", ctx.participant_device_id.to_string())
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&input_req).unwrap()))
        .unwrap();

    let resp = ctx.app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn test_collab_realtime_sse_event_streaming() {
    let ctx = setup_collab_context(true).await;

    // 1. Host creates a controllable session
    let create_req = CreateCollabSessionRequest {
        title: "Streaming Collab Session".to_string(),
        mode: "controllable".to_string(),
        ttl_secs: Some(3600),
    };

    let req = Request::builder()
        .uri("/api/v1/collab/sessions")
        .method("POST")
        .header(header::AUTHORIZATION, format!("Bearer {}", ctx.host_token))
        .header("X-Device-Id", ctx.host_device_id.to_string())
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&create_req).unwrap()))
        .unwrap();

    let resp = ctx.app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let val: Value = serde_json::from_slice(&body).unwrap();
    let session_id = val["session_id"].as_str().unwrap();

    // 2. Enroll Bob as participant
    let enroll_req = EnrollParticipantRequest {
        user_id: ctx.participant_id,
        device_id: ctx.participant_device_id,
        role: "viewer".to_string(),
    };
    let req = Request::builder()
        .uri(format!("/api/v1/collab/sessions/{session_id}/participants"))
        .method("POST")
        .header(header::AUTHORIZATION, format!("Bearer {}", ctx.host_token))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&enroll_req).unwrap()))
        .unwrap();
    let resp = ctx.app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);

    // 3. Connect to SSE endpoint as participant
    let req = Request::builder()
        .uri(format!("/api/v1/collab/sessions/{session_id}/events"))
        .method("GET")
        .header(
            header::AUTHORIZATION,
            format!("Bearer {}", ctx.participant_token),
        )
        .body(Body::empty())
        .unwrap();

    let resp = ctx.app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let content_type = resp
        .headers()
        .get(header::CONTENT_TYPE)
        .unwrap()
        .to_str()
        .unwrap();
    assert!(content_type.contains("text/event-stream"));

    // 4. Outsider attempt to subscribe to SSE is rejected (404)
    let req = Request::builder()
        .uri(format!("/api/v1/collab/sessions/{session_id}/events"))
        .method("GET")
        .header(
            header::AUTHORIZATION,
            format!("Bearer {}", ctx.outsider_token),
        )
        .body(Body::empty())
        .unwrap();

    let resp = ctx.app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}
