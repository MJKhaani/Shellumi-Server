use axum::{body::Body, http::Request};
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine;
use serde_json::{json, Value};
use shellumi_server::{config::ServerConfig, server::create_router};
use shellumi_server_protocol::{VaultWatermark, WsClientMessage, WsServerMessage};
use tower::ServiceExt;
use uuid::Uuid;

#[tokio::test]
async fn websocket_rejects_unauthenticated_upgrade() {
    let app = create_router(ServerConfig::default());
    let req = Request::builder()
        .uri("/api/v1/events/ws")
        .header("connection", "upgrade")
        .header("upgrade", "websocket")
        .header("sec-websocket-version", "13")
        .header("sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ==")
        .body(Body::empty())
        .unwrap();
    let res = app.oneshot(req).await.unwrap();
    assert_eq!(res.status(), 401);
}

#[tokio::test]
async fn poll_rejects_unauthenticated_requests() {
    let app = create_router(ServerConfig::default());
    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/sync/poll")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), 401);
}

#[tokio::test]
async fn team_metadata_change_sends_hint() {
    let app = create_router(ServerConfig::default());
    async fn call(
        app: &axum::Router,
        method: &str,
        path: &str,
        token: Option<&str>,
        body: Value,
    ) -> Value {
        let mut req = Request::builder()
            .method(method)
            .uri(path)
            .header("content-type", "application/json");
        if let Some(token) = token {
            req = req.header("authorization", format!("Bearer {token}"));
        }
        let response = app
            .clone()
            .oneshot(req.body(Body::from(body.to_string())).unwrap())
            .await
            .unwrap();
        assert!(response.status().is_success(), "{}", response.status());
        serde_json::from_slice(
            &axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap()
    }

    let boot = call(
        &app,
        "POST",
        "/api/v1/bootstrap",
        None,
        json!({
            "admin_username": "tester",
            "admin_email": "tester@example.com",
            "admin_password": "AdminSecurePassword123!",
            "org_name": "Test",
            "bootstrap_token": null
        }),
    )
    .await;
    let token = boot["access_token"].as_str().unwrap();

    let (keypair, public_key_b64) =
        shellumi_server_crypto::generate_test_ed25519_keypair().unwrap();
    let chal = call(
        &app,
        "POST",
        "/api/v1/devices/challenge",
        Some(token),
        json!({}),
    )
    .await;
    let challenge_str = chal["challenge"].as_str().unwrap();
    let sig = shellumi_server_crypto::sign_message(&keypair, challenge_str.as_bytes());

    let agreement_key = BASE64_STANDARD.encode([2u8; 32]);
    let device = call(
        &app,
        "POST",
        "/api/v1/devices",
        Some(token),
        json!({
            "device_name": "test_device",
            "signing_public_key": public_key_b64,
            "agreement_public_key": agreement_key,
            "challenge": challenge_str,
            "challenge_signature": sig,
        }),
    )
    .await;
    let device_id = device["device_id"].as_str().unwrap();

    let vault = call(
        &app,
        "POST",
        "/api/v1/vaults",
        Some(token),
        json!({
            "vault_type": "team",
            "encrypted_name": "old"
        }),
    )
    .await;
    let vault_id = vault["vault_id"].as_str().unwrap();

    // Verify WebSocket upgrade: authenticated with valid device passes auth
    let ws_req = Request::builder()
        .uri("/api/v1/events/ws")
        .header("connection", "upgrade")
        .header("upgrade", "websocket")
        .header("sec-websocket-version", "13")
        .header("sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ==")
        .header("authorization", format!("Bearer {token}"))
        .header("x-device-id", device_id)
        .body(Body::empty())
        .unwrap();
    let ws_res = app.clone().oneshot(ws_req).await.unwrap();
    assert!(ws_res.status() == 426 || ws_res.status() == 101);

    // Verify invalid device is rejected with 401
    let bad_device_req = Request::builder()
        .uri("/api/v1/events/ws")
        .header("authorization", format!("Bearer {token}"))
        .header("x-device-id", Uuid::new_v4().to_string())
        .body(Body::empty())
        .unwrap();
    let bad_res = app.clone().oneshot(bad_device_req).await.unwrap();
    assert_eq!(bad_res.status(), 401);

    // Verify long-polling notification delivery
    let poll_app = app.clone();
    let poll_token = token.to_string();
    let poll_device = device_id.to_string();
    let poll = tokio::spawn(async move {
        poll_app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/sync/poll")
                    .header("authorization", format!("Bearer {poll_token}"))
                    .header("x-device-id", poll_device)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap()
    });

    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    call(
        &app,
        "PATCH",
        &format!("/api/v1/vaults/{vault_id}"),
        Some(token),
        json!({"encrypted_name": "new"}),
    )
    .await;

    let poll_response = tokio::time::timeout(std::time::Duration::from_secs(5), poll)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(poll_response.status(), 200);
    let poll_body: Value = serde_json::from_slice(
        &axum::body::to_bytes(poll_response.into_body(), usize::MAX)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(poll_body["type"], "vault_changed");
    assert_eq!(poll_body["vault_id"], vault_id);

    // Verify vault deletion event
    let poll_app = app.clone();
    let poll_token = token.to_string();
    let poll_device = device_id.to_string();
    let poll_del = tokio::spawn(async move {
        poll_app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/sync/poll")
                    .header("authorization", format!("Bearer {poll_token}"))
                    .header("x-device-id", poll_device)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap()
    });

    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    call(
        &app,
        "DELETE",
        &format!("/api/v1/vaults/{vault_id}"),
        Some(token),
        json!({}),
    )
    .await;

    let poll_del_res = tokio::time::timeout(std::time::Duration::from_secs(5), poll_del)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(poll_del_res.status(), 200);
    let poll_del_body: Value = serde_json::from_slice(
        &axum::body::to_bytes(poll_del_res.into_body(), usize::MAX)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(poll_del_body["type"], "vault_deleted");
    assert_eq!(poll_del_body["vault_id"], vault_id);
}

#[test]
fn test_ws_protocol_v1_messages_serialization() {
    let vid = Uuid::new_v4();
    let notif_id = Uuid::new_v4();

    // Client subscribe message
    let client_sub = WsClientMessage::Subscribe {
        request_id: "req-1".to_string(),
        vault_ids: vec![vid],
    };
    let json_str = serde_json::to_string(&client_sub).unwrap();
    assert!(json_str.contains("\"action\":\"subscribe\""));
    assert!(json_str.contains("\"request_id\":\"req-1\""));

    // Server subscribed message
    let server_sub = WsServerMessage::Subscribed {
        request_id: "req-1".to_string(),
        vaults: vec![VaultWatermark {
            vault_id: vid,
            latest_sequence: 42,
        }],
    };
    let json_sub = serde_json::to_string(&server_sub).unwrap();
    assert!(json_sub.contains("\"event\":\"subscribed\""));
    assert!(json_sub.contains("\"latest_sequence\":42"));

    // Server vault.changed message
    let server_changed = WsServerMessage::VaultChanged {
        vault_id: vid,
        latest_sequence: 43,
        notification_id: notif_id,
    };
    let json_changed = serde_json::to_string(&server_changed).unwrap();
    assert!(json_changed.contains("\"event\":\"vault.changed\""));
    assert!(json_changed.contains("\"latest_sequence\":43"));

    // Server vault.key_rotated message
    let server_rotated = WsServerMessage::VaultKeyRotated {
        vault_id: vid,
        epoch: 2,
        notification_id: notif_id,
    };
    let json_rot = serde_json::to_string(&server_rotated).unwrap();
    assert!(json_rot.contains("\"event\":\"vault.key_rotated\""));
    assert!(json_rot.contains("\"epoch\":2"));

    // Server vault.access_revoked message
    let server_rev = WsServerMessage::VaultAccessRevoked {
        vault_id: vid,
        notification_id: notif_id,
    };
    let json_rev = serde_json::to_string(&server_rev).unwrap();
    assert!(json_rev.contains("\"event\":\"vault.access_revoked\""));

    // Server error message
    let server_err = WsServerMessage::Error {
        code: "SUBSCRIPTION_DENIED".to_string(),
        message: "Not a member".to_string(),
        request_id: Some("req-1".to_string()),
    };
    let json_err = serde_json::to_string(&server_err).unwrap();
    assert!(json_err.contains("\"event\":\"error\""));
    assert!(json_err.contains("\"code\":\"SUBSCRIPTION_DENIED\""));
}
