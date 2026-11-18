use axum::{body::Body, http::Request, Router};
use base64::{engine::general_purpose::STANDARD, Engine};
use futures_util::{SinkExt, StreamExt};
use serde_json::{json, Value};
use shellumi_server::{config::ServerConfig, server::create_router_with_store};
use shellumi_server_store::{AnyStore, OrgRepository, PgStore, UserRepository};
use std::future::IntoFuture;
use std::time::Duration;
use tokio_tungstenite::tungstenite::{client::IntoClientRequest, Message};
use tower::ServiceExt;
use uuid::Uuid;

async fn call(app: &Router, method: &str, path: &str, token: Option<&str>, body: Value) -> Value {
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
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap();
    assert!(
        status.is_success(),
        "{status}: {}",
        String::from_utf8_lossy(&bytes)
    );
    serde_json::from_slice(&bytes).unwrap()
}

async fn http_json(
    addr: std::net::SocketAddr,
    method: &str,
    path: &str,
    token: &str,
    device: &str,
    body: &str,
) -> Value {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    let request = format!("{method} {path} HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {token}\r\nX-Device-Id: {device}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len());
    stream.write_all(request.as_bytes()).await.unwrap();
    let mut bytes = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), stream.read_to_end(&mut bytes))
        .await
        .unwrap()
        .unwrap();
    let response = String::from_utf8(bytes).unwrap();
    let (headers, body) = response.split_once("\r\n\r\n").unwrap();
    assert!(headers.starts_with("HTTP/1.1 2"), "{response}");
    serde_json::from_str(body).unwrap()
}

#[tokio::test]
async fn postgres_two_instances_deliver_subscribed_websocket_hints_both_directions() {
    let Ok(base_url) = std::env::var("SHELLUMI_TEST_DATABASE_URL") else {
        assert!(
            std::env::var_os("SHELLUMI_REQUIRE_POSTGRES").is_none(),
            "SHELLUMI_TEST_DATABASE_URL is required for the PostgreSQL job"
        );
        eprintln!("PostgreSQL WebSocket acceptance skipped: SHELLUMI_TEST_DATABASE_URL is unset");
        return;
    };
    let admin = PgStore::connect(&base_url).await.unwrap();
    let db = format!("ws_{}", Uuid::new_v4().simple());
    sqlx::query(&format!("CREATE DATABASE {db}"))
        .execute(admin.pool())
        .await
        .unwrap();
    let (prefix, _) = base_url.rsplit_once('/').unwrap();
    let url = format!("{prefix}/{db}");
    let pg = PgStore::connect(&url).await.unwrap();
    pg.run_migrations().await.unwrap();
    let pg2 = PgStore::connect(&url).await.unwrap();
    let config = ServerConfig {
        database_url: Some(url),
        token_signing_key: Some("test-signing-secret-32-bytes-long-123".into()),
        server_instance_id: Uuid::new_v4(),
        ..ServerConfig::default()
    };
    let app1 = create_router_with_store(config.clone(), AnyStore::postgres(pg.clone()));
    let app2 = create_router_with_store(config, AnyStore::postgres(pg2));
    let boot = call(&app1, "POST", "/api/v1/bootstrap", None, json!({"admin_username":"tester", "admin_email":"tester@example.com", "admin_password":"AdminSecurePassword123!", "org_name":"Test", "bootstrap_token":null})).await;
    let token = boot["access_token"].as_str().unwrap();
    let (keypair, public_key) = shellumi_server_crypto::generate_test_ed25519_keypair().unwrap();
    let challenge = call(
        &app1,
        "POST",
        "/api/v1/devices/challenge",
        Some(token),
        json!({}),
    )
    .await;
    let challenge = challenge["challenge"].as_str().unwrap();
    let device = call(&app1, "POST", "/api/v1/devices", Some(token), json!({"device_name":"test", "signing_public_key":public_key, "agreement_public_key":STANDARD.encode([2u8;32]), "challenge":challenge, "challenge_signature":shellumi_server_crypto::sign_message(&keypair,challenge.as_bytes())})).await;
    let device = device["device_id"].as_str().unwrap();
    let vault = call(
        &app1,
        "POST",
        "/api/v1/vaults",
        Some(token),
        json!({"vault_type":"team","encrypted_name":"old"}),
    )
    .await;
    let vault = vault["vault_id"].as_str().unwrap();
    let listener1 = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let listener2 = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr1 = listener1.local_addr().unwrap();
    let addr2 = listener2.local_addr().unwrap();
    let server1 = tokio::spawn(axum::serve(listener1, app1.clone()).into_future());
    let server2 = tokio::spawn(axum::serve(listener2, app2.clone()).into_future());
    tokio::time::sleep(Duration::from_secs(1)).await;
    let mut req1 = format!("ws://{addr1}/api/v1/events/ws")
        .into_client_request()
        .unwrap();
    req1.headers_mut()
        .insert("authorization", format!("Bearer {token}").parse().unwrap());
    req1.headers_mut()
        .insert("x-device-id", device.parse().unwrap());
    let mut req2 = format!("ws://{addr2}/api/v1/events/ws")
        .into_client_request()
        .unwrap();
    req2.headers_mut()
        .insert("authorization", format!("Bearer {token}").parse().unwrap());
    req2.headers_mut()
        .insert("x-device-id", device.parse().unwrap());
    let (mut ws1, _) = tokio_tungstenite::connect_async(req1).await.unwrap();
    let (mut ws2, _) = tokio_tungstenite::connect_async(req2).await.unwrap();
    let subscription =
        json!({"action":"subscribe","request_id":"one","vault_ids":[vault]}).to_string();
    ws1.send(Message::Text(subscription.clone())).await.unwrap();
    ws2.send(Message::Text(subscription)).await.unwrap();
    for ws in [&mut ws1, &mut ws2] {
        let msg = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let msg = ws.next().await.unwrap().unwrap();
                if msg.is_text() {
                    break msg;
                }
            }
        })
        .await
        .unwrap();
        assert_eq!(
            serde_json::from_str::<Value>(msg.to_text().unwrap()).unwrap()["event"],
            "subscribed"
        );
    }
    // A second user joins this vault and subscribes from its own authenticated device.
    let member_id = Uuid::new_v4();
    pg.create_user(&shellumi_server_domain::User {
        id: member_id,
        username: "member".into(),
        email: "member@example.com".into(),
        password_hash: shellumi_server_auth::hash_password("MemberSecurePassword123!").unwrap(),
        created_at: 1,
        updated_at: 1,
        is_active: true,
    })
    .await
    .unwrap();
    let member_org = shellumi_server_domain::Organization {
        id: Uuid::new_v4(),
        name: "other-tenant".into(),
        created_at: 1,
    };
    pg.create_org(&member_org, member_id).await.unwrap();
    call(
        &app1,
        "POST",
        &format!("/api/v1/vaults/{vault}/members"),
        Some(token),
        json!({"user_id":member_id,"role":"viewer"}),
    )
    .await;
    for ws in [&mut ws1, &mut ws2] {
        let msg = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let msg = ws.next().await.unwrap().unwrap();
                if msg.is_text() {
                    break msg;
                }
            }
        })
        .await
        .unwrap();
        assert_eq!(
            serde_json::from_str::<Value>(msg.to_text().unwrap()).unwrap()["event"],
            "vault.changed"
        );
    }
    let member_login = call(
        &app1,
        "POST",
        "/api/v1/auth/login",
        None,
        json!({"identifier":"member","password":"MemberSecurePassword123!"}),
    )
    .await;
    let member_enrollment_token = member_login["access_token"].as_str().unwrap();
    let other_tenant_vault = call(
        &app1,
        "POST",
        "/api/v1/vaults",
        Some(member_enrollment_token),
        json!({"vault_type":"personal","encrypted_name":"other-tenant"}),
    )
    .await;
    let other_tenant_vault = other_tenant_vault["vault_id"].as_str().unwrap();
    let unauthorized = Request::builder()
        .method("GET")
        .uri(format!("/api/v1/vaults/{other_tenant_vault}"))
        .header("authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();
    assert_eq!(
        app1.clone().oneshot(unauthorized).await.unwrap().status(),
        404
    );
    ws1.send(Message::Text(
        json!({"action":"subscribe","request_id":"cross-tenant","vault_ids":[other_tenant_vault]})
            .to_string(),
    ))
    .await
    .unwrap();
    let denied = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let msg = ws1.next().await.unwrap().unwrap();
            if msg.is_text() {
                break msg;
            }
        }
    })
    .await
    .unwrap();
    assert_eq!(
        serde_json::from_str::<Value>(denied.to_text().unwrap()).unwrap()["code"],
        "SUBSCRIPTION_DENIED"
    );
    let (member_key, member_public) =
        shellumi_server_crypto::generate_test_ed25519_keypair().unwrap();
    let member_challenge = call(
        &app1,
        "POST",
        "/api/v1/devices/challenge",
        Some(member_enrollment_token),
        json!({}),
    )
    .await;
    let member_challenge = member_challenge["challenge"].as_str().unwrap();
    let member_device = call(&app1, "POST", "/api/v1/devices", Some(member_enrollment_token), json!({"device_name":"member-device","signing_public_key":member_public,"agreement_public_key":STANDARD.encode([4u8;32]),"challenge":member_challenge,"challenge_signature":shellumi_server_crypto::sign_message(&member_key,member_challenge.as_bytes())})).await;
    let member_device = member_device["device_id"].as_str().unwrap();
    let member_login = call(&app1, "POST", "/api/v1/auth/login", None, json!({"identifier":"member","password":"MemberSecurePassword123!","device_id":member_device})).await;
    let member_token = member_login["access_token"].as_str().unwrap();
    let mut member_request = format!("ws://{addr1}/api/v1/events/ws")
        .into_client_request()
        .unwrap();
    member_request.headers_mut().insert(
        "authorization",
        format!("Bearer {member_token}").parse().unwrap(),
    );
    member_request
        .headers_mut()
        .insert("x-device-id", member_device.parse().unwrap());
    let (mut member_ws, _) = tokio_tungstenite::connect_async(member_request)
        .await
        .unwrap();
    member_ws
        .send(Message::Text(
            json!({"action":"subscribe","request_id":"member","vault_ids":[vault]}).to_string(),
        ))
        .await
        .unwrap();
    let ack = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let msg = member_ws.next().await.unwrap().unwrap();
            if msg.is_text() {
                break msg;
            }
        }
    })
    .await
    .unwrap();
    assert_eq!(
        serde_json::from_str::<Value>(ack.to_text().unwrap()).unwrap()["event"],
        "subscribed"
    );

    // A second authenticated device subscribes to the same installation.
    let (other_key, other_public) =
        shellumi_server_crypto::generate_test_ed25519_keypair().unwrap();
    let other_challenge = call(
        &app1,
        "POST",
        "/api/v1/devices/challenge",
        Some(token),
        json!({}),
    )
    .await;
    let other_challenge = other_challenge["challenge"].as_str().unwrap();
    let other_device = call(&app1, "POST", "/api/v1/devices", Some(token), json!({"device_name":"second", "signing_public_key":other_public, "agreement_public_key":STANDARD.encode([3u8;32]), "challenge":other_challenge, "challenge_signature":shellumi_server_crypto::sign_message(&other_key, other_challenge.as_bytes())})).await;
    let other_device = other_device["device_id"].as_str().unwrap();
    let other_login = call(&app1, "POST", "/api/v1/auth/login", None, json!({"identifier":"tester","password":"AdminSecurePassword123!","device_id":other_device})).await;
    let other_token = other_login["access_token"].as_str().unwrap();
    let mut wrong_device = format!("ws://{addr1}/api/v1/events/ws")
        .into_client_request()
        .unwrap();
    wrong_device.headers_mut().insert(
        "authorization",
        format!("Bearer {other_token}").parse().unwrap(),
    );
    wrong_device
        .headers_mut()
        .insert("x-device-id", device.parse().unwrap());
    match tokio_tungstenite::connect_async(wrong_device).await {
        Err(tokio_tungstenite::tungstenite::Error::Http(response)) => {
            assert_eq!(response.status(), 403)
        }
        other => panic!("a device-bound token must not authorize another device: {other:?}"),
    }
    let mut request3 = format!("ws://{addr1}/api/v1/events/ws")
        .into_client_request()
        .unwrap();
    request3.headers_mut().insert(
        "authorization",
        format!("Bearer {other_token}").parse().unwrap(),
    );
    request3
        .headers_mut()
        .insert("x-device-id", other_device.parse().unwrap());
    let (mut ws3, _) = tokio_tungstenite::connect_async(request3).await.unwrap();
    ws3.send(Message::Text(
        json!({"action":"subscribe","request_id":"other","vault_ids":[vault]}).to_string(),
    ))
    .await
    .unwrap();
    let ack = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let msg = ws3.next().await.unwrap().unwrap();
            if msg.is_text() {
                break msg;
            }
        }
    })
    .await
    .unwrap();
    assert_eq!(
        serde_json::from_str::<Value>(ack.to_text().unwrap()).unwrap()["event"],
        "subscribed"
    );
    let vault_uuid = Uuid::parse_str(vault).unwrap();
    let envelope = shellumi_server_protocol::EncryptedEnvelope {
        format_version: 1,
        suite: "aes256gcm_dek_v1".into(),
        key_epoch: 1,
        salt: String::new(),
        nonce: STANDARD.encode([2u8; 12]),
        ciphertext: STANDARD.encode(b"ciphertext_sample_payload_with_gcm_tag!"),
        associated_data: "host:001".into(),
        kdf_iterations: 0,
    };
    let digest = shellumi_server_crypto::compute_ciphertext_digest(Some(&envelope));
    let preimage = shellumi_server_crypto::canonical_mutation_preimage_bytes(
        vault_uuid, "entry-1", "snippet", 0, false, 1, 1, &digest,
    );
    let mutation = shellumi_server_protocol::MutationItem {
        object_id: "entry-1".into(),
        entity_type: "snippet".into(),
        expected_revision: 0,
        deleted: false,
        key_epoch: 1,
        device_counter: 1,
        encrypted_envelope: Some(envelope.clone()),
        device_signature: shellumi_server_crypto::sign_message(&keypair, &preimage),
    };
    let batch = shellumi_server_protocol::CommitBatchRequest {
        protocol_version: shellumi_server_protocol::CURRENT_PROTOCOL_VERSION,
        vault_id: vault_uuid,
        idempotency_key: "ws-signed-first".into(),
        base_cursor: None,
        mutations: vec![mutation],
    };
    let committed = http_json(
        addr1,
        "POST",
        &format!("/api/v1/vaults/{vault}/commits"),
        token,
        device,
        &serde_json::to_string(&batch).unwrap(),
    )
    .await;
    assert_eq!(committed["commit_sequence"], 1);
    for ws in [&mut ws1, &mut ws2, &mut ws3, &mut member_ws] {
        let msg = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let msg = ws.next().await.unwrap().unwrap();
                if msg.is_text() {
                    break msg;
                }
            }
        })
        .await
        .unwrap();
        let event: Value = serde_json::from_str(msg.to_text().unwrap()).unwrap();
        assert_eq!(event["event"], "vault.changed");
        assert_eq!(event["latest_sequence"], 1);
    }
    let feed = http_json(
        addr1,
        "GET",
        &format!("/api/v1/vaults/{vault}/changes?since=0&limit=1"),
        other_token,
        other_device,
        "",
    )
    .await;
    assert_eq!(feed["records"][0]["sequence"], 1);
    assert_eq!(
        feed["records"][0]["encrypted_envelope"]["ciphertext"],
        envelope.ciphertext
    );
    let member_feed = http_json(
        addr1,
        "GET",
        &format!("/api/v1/vaults/{vault}/changes?since=0&limit=1"),
        member_token,
        member_device,
        "",
    )
    .await;
    assert_eq!(
        member_feed["records"][0]["encrypted_envelope"]["ciphertext"],
        envelope.ciphertext
    );
    let viewer_digest = shellumi_server_crypto::compute_ciphertext_digest(Some(&envelope));
    let viewer_preimage = shellumi_server_crypto::canonical_mutation_preimage_bytes(
        vault_uuid,
        "viewer-write",
        "snippet",
        0,
        false,
        1,
        1,
        &viewer_digest,
    );
    let viewer_batch = shellumi_server_protocol::CommitBatchRequest {
        protocol_version: shellumi_server_protocol::CURRENT_PROTOCOL_VERSION,
        vault_id: vault_uuid,
        idempotency_key: "viewer-write".into(),
        base_cursor: None,
        mutations: vec![shellumi_server_protocol::MutationItem {
            object_id: "viewer-write".into(),
            entity_type: "snippet".into(),
            expected_revision: 0,
            deleted: false,
            key_epoch: 1,
            device_counter: 1,
            encrypted_envelope: Some(envelope.clone()),
            device_signature: shellumi_server_crypto::sign_message(&member_key, &viewer_preimage),
        }],
    };
    let viewer_request = Request::builder()
        .method("POST")
        .uri(format!("/api/v1/vaults/{vault}/commits"))
        .header("authorization", format!("Bearer {member_token}"))
        .header("x-device-id", member_device)
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&viewer_batch).unwrap()))
        .unwrap();
    assert_eq!(
        app1.clone().oneshot(viewer_request).await.unwrap().status(),
        403
    );
    let remove_member = Request::builder()
        .method("DELETE")
        .uri(format!("/api/v1/vaults/{vault}/members/{member_id}"))
        .header("authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();
    assert_eq!(
        app1.clone().oneshot(remove_member).await.unwrap().status(),
        204
    );
    let revoked = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let msg = member_ws.next().await.unwrap().unwrap();
            if msg.is_text() {
                break msg;
            }
        }
    })
    .await
    .unwrap();
    assert_eq!(
        serde_json::from_str::<Value>(revoked.to_text().unwrap()).unwrap()["event"],
        "vault.access_revoked"
    );
    let forbidden = Request::builder()
        .method("GET")
        .uri(format!("/api/v1/vaults/{vault}/changes?since=0"))
        .header("authorization", format!("Bearer {member_token}"))
        .header("x-device-id", member_device)
        .body(Body::empty())
        .unwrap();
    assert_eq!(app1.clone().oneshot(forbidden).await.unwrap().status(), 404);
    member_ws
        .send(Message::Text(
            json!({"action":"subscribe","request_id":"removed","vault_ids":[vault]}).to_string(),
        ))
        .await
        .unwrap();
    let denied = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let msg = member_ws.next().await.unwrap().unwrap();
            if msg.is_text() {
                break msg;
            }
        }
    })
    .await
    .unwrap();
    assert_eq!(
        serde_json::from_str::<Value>(denied.to_text().unwrap()).unwrap()["code"],
        "SUBSCRIPTION_DENIED"
    );
    // A deactivated user cannot keep using an already-open socket or REST token.
    sqlx::query("UPDATE users SET is_active = false WHERE id = $1")
        .bind(member_id)
        .execute(pg.pool())
        .await
        .unwrap();
    member_ws
        .send(Message::Text(json!({"action":"ping"}).to_string()))
        .await
        .unwrap();
    let closed = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            match member_ws.next().await {
                None | Some(Ok(Message::Close(_))) | Some(Err(_)) => break true,
                Some(Ok(Message::Text(_))) => break false,
                _ => {}
            }
        }
    })
    .await
    .unwrap();
    assert!(
        closed,
        "deactivated user must not receive application frames"
    );
    let inactive = Request::builder()
        .method("GET")
        .uri("/api/v1/me")
        .header("authorization", format!("Bearer {member_token}"))
        .body(Body::empty())
        .unwrap();
    assert_eq!(app1.clone().oneshot(inactive).await.unwrap().status(), 401);
    ws3.close(None).await.unwrap();
    let tombstone_digest = shellumi_server_crypto::compute_ciphertext_digest(None);
    let tombstone_preimage = shellumi_server_crypto::canonical_mutation_preimage_bytes(
        vault_uuid,
        "entry-1",
        "snippet",
        1,
        true,
        1,
        2,
        &tombstone_digest,
    );
    let tombstone = shellumi_server_protocol::MutationItem {
        object_id: "entry-1".into(),
        entity_type: "snippet".into(),
        expected_revision: 1,
        deleted: true,
        key_epoch: 1,
        device_counter: 2,
        encrypted_envelope: None,
        device_signature: shellumi_server_crypto::sign_message(&keypair, &tombstone_preimage),
    };
    let deletion_batch = shellumi_server_protocol::CommitBatchRequest {
        protocol_version: shellumi_server_protocol::CURRENT_PROTOCOL_VERSION,
        vault_id: vault_uuid,
        idempotency_key: "ws-tombstone".into(),
        base_cursor: None,
        mutations: vec![tombstone],
    };
    let committed = http_json(
        addr1,
        "POST",
        &format!("/api/v1/vaults/{vault}/commits"),
        token,
        device,
        &serde_json::to_string(&deletion_batch).unwrap(),
    )
    .await;
    assert_eq!(committed["commit_sequence"], 2);
    for ws in [&mut ws1, &mut ws2] {
        let msg = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let msg = ws.next().await.unwrap().unwrap();
                if msg.is_text() {
                    break msg;
                }
            }
        })
        .await
        .unwrap();
        assert_eq!(
            serde_json::from_str::<Value>(msg.to_text().unwrap()).unwrap()["latest_sequence"],
            2
        );
    }
    let mut reconnect = format!("ws://{addr1}/api/v1/events/ws")
        .into_client_request()
        .unwrap();
    reconnect.headers_mut().insert(
        "authorization",
        format!("Bearer {other_token}").parse().unwrap(),
    );
    reconnect
        .headers_mut()
        .insert("x-device-id", other_device.parse().unwrap());
    let (mut ws3, _) = tokio_tungstenite::connect_async(reconnect).await.unwrap();
    ws3.send(Message::Text(
        json!({"action":"subscribe","request_id":"reconnect","vault_ids":[vault]}).to_string(),
    ))
    .await
    .unwrap();
    let ack = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let msg = ws3.next().await.unwrap().unwrap();
            if msg.is_text() {
                break msg;
            }
        }
    })
    .await
    .unwrap();
    let ack: Value = serde_json::from_str(ack.to_text().unwrap()).unwrap();
    assert_eq!(ack["vaults"][0]["latest_sequence"], 2);
    let feed = http_json(
        addr1,
        "GET",
        &format!("/api/v1/vaults/{vault}/changes?cursor=seq:1&limit=1"),
        other_token,
        other_device,
        "",
    )
    .await;
    assert_eq!(feed["records"][0]["sequence"], 2);
    assert_eq!(feed["records"][0]["deleted"], true);
    ws3.close(None).await.unwrap();

    // Two devices race to create the same object: one succeeds and one conflicts.
    let make_batch = |key: &ring::signature::Ed25519KeyPair, counter: u64, id: &str| {
        let digest = shellumi_server_crypto::compute_ciphertext_digest(Some(&envelope));
        let preimage = shellumi_server_crypto::canonical_mutation_preimage_bytes(
            vault_uuid, "race", "snippet", 0, false, 1, counter, &digest,
        );
        shellumi_server_protocol::CommitBatchRequest {
            protocol_version: shellumi_server_protocol::CURRENT_PROTOCOL_VERSION,
            vault_id: vault_uuid,
            idempotency_key: id.into(),
            base_cursor: None,
            mutations: vec![shellumi_server_protocol::MutationItem {
                object_id: "race".into(),
                entity_type: "snippet".into(),
                expected_revision: 0,
                deleted: false,
                key_epoch: 1,
                device_counter: counter,
                encrypted_envelope: Some(envelope.clone()),
                device_signature: shellumi_server_crypto::sign_message(key, &preimage),
            }],
        }
    };
    let first = make_batch(&keypair, 3, "race-first");
    let second = make_batch(&other_key, 1, "race-second");
    let make_request = |device_id: &str, batch: &shellumi_server_protocol::CommitBatchRequest| {
        Request::builder()
            .method("POST")
            .uri(format!("/api/v1/vaults/{vault}/commits"))
            .header("authorization", format!("Bearer {token}"))
            .header("x-device-id", device_id)
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(batch).unwrap()))
            .unwrap()
    };
    let (a, b) = tokio::join!(
        app1.clone().oneshot(make_request(device, &first)),
        app1.clone().oneshot(make_request(other_device, &second))
    );
    let a = a.unwrap();
    let b = b.unwrap();
    assert!(
        (a.status() == 200 && b.status() == 409) || (a.status() == 409 && b.status() == 200),
        "{} {}",
        a.status(),
        b.status()
    );
    let (winning_device, winning_batch) = if a.status() == 200 {
        (device, &first)
    } else {
        (other_device, &second)
    };
    let retry = app1
        .clone()
        .oneshot(make_request(winning_device, winning_batch))
        .await
        .unwrap();
    assert_eq!(retry.status(), 200);
    let retry: Value = serde_json::from_slice(
        &axum::body::to_bytes(retry.into_body(), 1024 * 1024)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(retry["commit_sequence"], 3);
    let other_id = if winning_device == device {
        other_device
    } else {
        device
    };
    let copied = app1
        .clone()
        .oneshot(make_request(other_id, winning_batch))
        .await
        .unwrap();
    assert_eq!(copied.status(), 409);
    // The retry may produce a duplicate advisory hint; drain all hints before later assertions.
    for ws in [&mut ws1, &mut ws2] {
        for _ in 0..2 {
            let msg = tokio::time::timeout(Duration::from_secs(5), async {
                loop {
                    let msg = ws.next().await.unwrap().unwrap();
                    if msg.is_text() {
                        break msg;
                    }
                }
            })
            .await
            .unwrap();
            assert_eq!(
                serde_json::from_str::<Value>(msg.to_text().unwrap()).unwrap()["latest_sequence"],
                3
            );
        }
    }

    // Equivocation on an existing idempotency key must fail without an event.
    let mut changed = winning_batch.clone();
    changed.mutations[0].object_id = "changed-payload".into();
    let conflict = app1
        .clone()
        .oneshot(make_request(winning_device, &changed))
        .await
        .unwrap();
    assert_eq!(conflict.status(), 409);
    for ws in [&mut ws1, &mut ws2] {
        assert!(tokio::time::timeout(Duration::from_millis(300), async {
            loop {
                let msg = ws.next().await.unwrap().unwrap();
                if msg.is_text() {
                    break msg;
                }
            }
        })
        .await
        .is_err());
    }
    ws1.send(Message::Text("not-json".into())).await.unwrap();
    let invalid = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let msg = ws1.next().await.unwrap().unwrap();
            if msg.is_text() {
                break msg;
            }
        }
    })
    .await
    .unwrap();
    assert_eq!(
        serde_json::from_str::<Value>(invalid.to_text().unwrap()).unwrap()["code"],
        "INVALID_MESSAGE"
    );

    // A failed multi-item batch must roll back its first write and counter.
    let make_item = |object: &str, counter: u64| {
        let digest = shellumi_server_crypto::compute_ciphertext_digest(Some(&envelope));
        let preimage = shellumi_server_crypto::canonical_mutation_preimage_bytes(
            vault_uuid, object, "snippet", 0, false, 1, counter, &digest,
        );
        shellumi_server_protocol::MutationItem {
            object_id: object.into(),
            entity_type: "snippet".into(),
            expected_revision: 0,
            deleted: false,
            key_epoch: 1,
            device_counter: counter,
            encrypted_envelope: Some(envelope.clone()),
            device_signature: shellumi_server_crypto::sign_message(&keypair, &preimage),
        }
    };
    let failed_batch = shellumi_server_protocol::CommitBatchRequest {
        protocol_version: shellumi_server_protocol::CURRENT_PROTOCOL_VERSION,
        vault_id: vault_uuid,
        idempotency_key: "rollback-batch".into(),
        base_cursor: None,
        mutations: vec![make_item("rollback-new", 4), make_item("race", 5)],
    };
    let failed = app1
        .clone()
        .oneshot(make_request(device, &failed_batch))
        .await
        .unwrap();
    assert_eq!(failed.status(), 409);
    let unchanged = http_json(
        addr1,
        "GET",
        &format!("/api/v1/vaults/{vault}/changes?cursor=seq:3"),
        token,
        device,
        "",
    )
    .await;
    assert_eq!(unchanged["latest_sequence"], 3);
    assert!(unchanged["records"].as_array().unwrap().is_empty());
    let recovered_batch = shellumi_server_protocol::CommitBatchRequest {
        protocol_version: shellumi_server_protocol::CURRENT_PROTOCOL_VERSION,
        vault_id: vault_uuid,
        idempotency_key: "rollback-retry".into(),
        base_cursor: None,
        mutations: vec![make_item("rollback-new", 4)],
    };
    let recovered = app1
        .clone()
        .oneshot(make_request(device, &recovered_batch))
        .await
        .unwrap();
    assert_eq!(recovered.status(), 200);
    for ws in [&mut ws1, &mut ws2] {
        let msg = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let msg = ws.next().await.unwrap().unwrap();
                if msg.is_text() {
                    break msg;
                }
            }
        })
        .await
        .unwrap();
        assert_eq!(
            serde_json::from_str::<Value>(msg.to_text().unwrap()).unwrap()["latest_sequence"],
            4
        );
    }

    // A snapshot racing a commit must report records and watermark from one view.
    let concurrent_batch = shellumi_server_protocol::CommitBatchRequest {
        protocol_version: shellumi_server_protocol::CURRENT_PROTOCOL_VERSION,
        vault_id: vault_uuid,
        idempotency_key: "snapshot-race".into(),
        base_cursor: None,
        mutations: vec![make_item("snapshot-race", 5)],
    };
    let snapshot_path = format!("/api/v1/vaults/{vault}/snapshots");
    let (snapshot, committed) = tokio::join!(
        http_json(addr1, "GET", &snapshot_path, token, device, ""),
        app1.clone()
            .oneshot(make_request(device, &concurrent_batch))
    );
    assert_eq!(committed.unwrap().status(), 200);
    let watermark = snapshot["server_sequence"].as_u64().unwrap();
    assert!((4..=5).contains(&watermark));
    let included = snapshot["records"]
        .as_array()
        .unwrap()
        .iter()
        .any(|record| record["object_id"] == "snapshot-race");
    assert_eq!(included, watermark == 5);
    for ws in [&mut ws1, &mut ws2] {
        let msg = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let msg = ws.next().await.unwrap().unwrap();
                if msg.is_text() {
                    break msg;
                }
            }
        })
        .await
        .unwrap();
        assert_eq!(
            serde_json::from_str::<Value>(msg.to_text().unwrap()).unwrap()["latest_sequence"],
            5
        );
    }

    // Distinct-object concurrent writes both commit with unique consecutive sequences.
    let first_distinct = shellumi_server_protocol::CommitBatchRequest {
        protocol_version: shellumi_server_protocol::CURRENT_PROTOCOL_VERSION,
        vault_id: vault_uuid,
        idempotency_key: "distinct-first".into(),
        base_cursor: None,
        mutations: vec![make_item("distinct-first", 6)],
    };
    let digest = shellumi_server_crypto::compute_ciphertext_digest(Some(&envelope));
    let preimage = shellumi_server_crypto::canonical_mutation_preimage_bytes(
        vault_uuid,
        "distinct-second",
        "snippet",
        0,
        false,
        1,
        2,
        &digest,
    );
    let second_distinct = shellumi_server_protocol::CommitBatchRequest {
        protocol_version: shellumi_server_protocol::CURRENT_PROTOCOL_VERSION,
        vault_id: vault_uuid,
        idempotency_key: "distinct-second".into(),
        base_cursor: None,
        mutations: vec![shellumi_server_protocol::MutationItem {
            object_id: "distinct-second".into(),
            entity_type: "snippet".into(),
            expected_revision: 0,
            deleted: false,
            key_epoch: 1,
            device_counter: 2,
            encrypted_envelope: Some(envelope.clone()),
            device_signature: shellumi_server_crypto::sign_message(&other_key, &preimage),
        }],
    };
    let (first_result, second_result) = tokio::join!(
        app1.clone().oneshot(make_request(device, &first_distinct)),
        app1.clone()
            .oneshot(make_request(other_device, &second_distinct))
    );
    let first_result = first_result.unwrap();
    let second_result = second_result.unwrap();
    assert_eq!(first_result.status(), 200);
    assert_eq!(second_result.status(), 200);
    let first_value: Value = serde_json::from_slice(
        &axum::body::to_bytes(first_result.into_body(), 1024 * 1024)
            .await
            .unwrap(),
    )
    .unwrap();
    let second_value: Value = serde_json::from_slice(
        &axum::body::to_bytes(second_result.into_body(), 1024 * 1024)
            .await
            .unwrap(),
    )
    .unwrap();
    let mut sequences = [
        first_value["commit_sequence"].as_u64().unwrap(),
        second_value["commit_sequence"].as_u64().unwrap(),
    ];
    sequences.sort();
    assert_eq!(sequences, [6, 7]);
    for ws in [&mut ws1, &mut ws2] {
        let mut hints = Vec::new();
        for _ in 0..2 {
            let msg = tokio::time::timeout(Duration::from_secs(5), async {
                loop {
                    let msg = ws.next().await.unwrap().unwrap();
                    if msg.is_text() {
                        break msg;
                    }
                }
            })
            .await
            .unwrap();
            hints.push(
                serde_json::from_str::<Value>(msg.to_text().unwrap()).unwrap()["latest_sequence"]
                    .as_u64()
                    .unwrap(),
            );
        }
        hints.sort();
        assert_eq!(hints, [6, 7]);
    }

    // Repeated edits in one batch are evaluated sequentially and remain atomic.
    let digest = shellumi_server_crypto::compute_ciphertext_digest(Some(&envelope));
    let second_preimage = shellumi_server_crypto::canonical_mutation_preimage_bytes(
        vault_uuid, "repeat", "snippet", 1, false, 1, 8, &digest,
    );
    let second_edit = shellumi_server_protocol::MutationItem {
        object_id: "repeat".into(),
        entity_type: "snippet".into(),
        expected_revision: 1,
        deleted: false,
        key_epoch: 1,
        device_counter: 8,
        encrypted_envelope: Some(envelope.clone()),
        device_signature: shellumi_server_crypto::sign_message(&keypair, &second_preimage),
    };
    let repeated = shellumi_server_protocol::CommitBatchRequest {
        protocol_version: shellumi_server_protocol::CURRENT_PROTOCOL_VERSION,
        vault_id: vault_uuid,
        idempotency_key: "repeat-batch".into(),
        base_cursor: None,
        mutations: vec![make_item("repeat", 7), second_edit],
    };
    let response = app1
        .clone()
        .oneshot(make_request(device, &repeated))
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let value: Value = serde_json::from_slice(
        &axum::body::to_bytes(response.into_body(), 1024 * 1024)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(value["commit_sequence"], 9);
    assert_eq!(value["applied"][0]["assigned_revision"], 1);
    assert_eq!(value["applied"][1]["assigned_revision"], 2);
    for ws in [&mut ws1, &mut ws2] {
        let msg = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let msg = ws.next().await.unwrap().unwrap();
                if msg.is_text() {
                    break msg;
                }
            }
        })
        .await
        .unwrap();
        assert_eq!(
            serde_json::from_str::<Value>(msg.to_text().unwrap()).unwrap()["latest_sequence"],
            9
        );
    }
    let mut cursor = "seq:0".to_string();
    let mut sequences = Vec::new();
    let mut found_tombstone = false;
    loop {
        let page = http_json(
            addr1,
            "GET",
            &format!("/api/v1/vaults/{vault}/changes?cursor={cursor}&limit=2"),
            token,
            device,
            "",
        )
        .await;
        for entry in page["records"].as_array().unwrap() {
            sequences.push(entry["sequence"].as_u64().unwrap());
            if entry["sequence"] == 2 {
                found_tombstone = entry["deleted"] == true;
            }
        }
        cursor = page["next_cursor"].as_str().unwrap().to_string();
        if !page["has_more"].as_bool().unwrap() {
            break;
        }
        assert!(sequences.len() < 20, "change feed did not advance");
    }
    assert_eq!(sequences, (1..=9).collect::<Vec<_>>());
    assert!(found_tombstone);

    for (path, expected) in [
        (
            format!("/api/v1/vaults/{vault}/changes?cursor=seq:invalid"),
            400,
        ),
        (
            format!("/api/v1/vaults/{vault}/changes?cursor=seq:999"),
            410,
        ),
        (format!("/api/v1/vaults/{vault}/snapshots/8"), 422),
    ] {
        let request = Request::builder()
            .method("GET")
            .uri(path)
            .header("authorization", format!("Bearer {token}"))
            .header("x-device-id", device)
            .body(Body::empty())
            .unwrap();
        assert_eq!(
            app1.clone().oneshot(request).await.unwrap().status(),
            expected
        );
    }
    let snapshot = http_json(
        addr1,
        "GET",
        &format!("/api/v1/vaults/{vault}/snapshots"),
        token,
        device,
        "",
    )
    .await;
    assert_eq!(snapshot["server_sequence"], 9);
    assert!(!snapshot["records"]
        .as_array()
        .unwrap()
        .iter()
        .any(|record| record["object_id"] == "entry-1"));

    // Simulate retained history pruning: a cursor before the first retained item must require snapshot recovery.
    sqlx::query("DELETE FROM change_log WHERE vault_id = $1 AND sequence <= 5")
        .bind(vault_uuid)
        .execute(pg.pool())
        .await
        .unwrap();
    let stale = Request::builder()
        .method("GET")
        .uri(format!("/api/v1/vaults/{vault}/changes?cursor=seq:0"))
        .header("authorization", format!("Bearer {token}"))
        .header("x-device-id", device)
        .body(Body::empty())
        .unwrap();
    assert_eq!(app1.clone().oneshot(stale).await.unwrap().status(), 410);
    let resumable = http_json(
        addr1,
        "GET",
        &format!("/api/v1/vaults/{vault}/changes?cursor=seq:5"),
        token,
        device,
        "",
    )
    .await;
    assert_eq!(resumable["records"][0]["sequence"], 6);
    sqlx::query("DELETE FROM change_log WHERE vault_id = $1 AND sequence = 7")
        .bind(vault_uuid)
        .execute(pg.pool())
        .await
        .unwrap();
    let missing_middle = Request::builder()
        .method("GET")
        .uri(format!("/api/v1/vaults/{vault}/changes?cursor=seq:5"))
        .header("authorization", format!("Bearer {token}"))
        .header("x-device-id", device)
        .body(Body::empty())
        .unwrap();
    assert_eq!(
        app1.clone().oneshot(missing_middle).await.unwrap().status(),
        410
    );
    sqlx::query("DELETE FROM change_log WHERE vault_id = $1")
        .bind(vault_uuid)
        .execute(pg.pool())
        .await
        .unwrap();
    let missing_all = Request::builder()
        .method("GET")
        .uri(format!("/api/v1/vaults/{vault}/changes?cursor=seq:5"))
        .header("authorization", format!("Bearer {token}"))
        .header("x-device-id", device)
        .body(Body::empty())
        .unwrap();
    assert_eq!(
        app1.clone().oneshot(missing_all).await.unwrap().status(),
        410
    );

    // Reject a replay and out-of-order counters without consuming the valid next counter.
    let replay = shellumi_server_protocol::CommitBatchRequest {
        protocol_version: shellumi_server_protocol::CURRENT_PROTOCOL_VERSION,
        vault_id: vault_uuid,
        idempotency_key: "counter-replay".into(),
        base_cursor: None,
        mutations: vec![make_item("counter-replay", 8)],
    };
    assert_eq!(
        app1.clone()
            .oneshot(make_request(device, &replay))
            .await
            .unwrap()
            .status(),
        409
    );
    let reordered = shellumi_server_protocol::CommitBatchRequest {
        protocol_version: shellumi_server_protocol::CURRENT_PROTOCOL_VERSION,
        vault_id: vault_uuid,
        idempotency_key: "counter-reordered".into(),
        base_cursor: None,
        mutations: vec![
            make_item("counter-first", 10),
            make_item("counter-second", 9),
        ],
    };
    assert_eq!(
        app1.clone()
            .oneshot(make_request(device, &reordered))
            .await
            .unwrap()
            .status(),
        409
    );
    let valid = shellumi_server_protocol::CommitBatchRequest {
        protocol_version: shellumi_server_protocol::CURRENT_PROTOCOL_VERSION,
        vault_id: vault_uuid,
        idempotency_key: "counter-valid".into(),
        base_cursor: None,
        mutations: vec![make_item("counter-valid", 9)],
    };
    assert_eq!(
        app1.clone()
            .oneshot(make_request(device, &valid))
            .await
            .unwrap()
            .status(),
        200
    );
    for ws in [&mut ws1, &mut ws2] {
        let msg = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let msg = ws.next().await.unwrap().unwrap();
                if msg.is_text() {
                    break msg;
                }
            }
        })
        .await
        .unwrap();
        assert_eq!(
            serde_json::from_str::<Value>(msg.to_text().unwrap()).unwrap()["latest_sequence"],
            10
        );
    }

    // One socket can subscribe to multiple vaults. A failed mixed request must not
    // partially add an authorized vault before rejecting an unauthorized ID.
    let vault2_response = call(
        &app1,
        "POST",
        "/api/v1/vaults",
        Some(token),
        json!({"vault_type":"team","encrypted_name":"second"}),
    )
    .await;
    let vault2 = vault2_response["vault_id"].as_str().unwrap();
    // A mutation signed for the first vault cannot be transplanted into another.
    let mut transplanted = batch.clone();
    transplanted.vault_id = Uuid::parse_str(vault2).unwrap();
    transplanted.idempotency_key = "transplanted".into();
    let request = Request::builder()
        .method("POST")
        .uri(format!("/api/v1/vaults/{vault2}/commits"))
        .header("authorization", format!("Bearer {token}"))
        .header("x-device-id", device)
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&transplanted).unwrap()))
        .unwrap();
    assert_eq!(app1.clone().oneshot(request).await.unwrap().status(), 403);
    ws1.send(Message::Text(json!({"action":"subscribe","request_id":"mixed","vault_ids":[vault2,Uuid::new_v4().to_string()]}).to_string())).await.unwrap();
    let denied = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let msg = ws1.next().await.unwrap().unwrap();
            if msg.is_text() {
                break msg;
            }
        }
    })
    .await
    .unwrap();
    assert_eq!(
        serde_json::from_str::<Value>(denied.to_text().unwrap()).unwrap()["code"],
        "SUBSCRIPTION_DENIED"
    );
    call(
        &app1,
        "PATCH",
        &format!("/api/v1/vaults/{vault2}"),
        Some(token),
        json!({"encrypted_name":"test-denied"}),
    )
    .await;
    assert!(tokio::time::timeout(Duration::from_millis(300), async {
        loop {
            let msg = ws1.next().await.unwrap().unwrap();
            if msg.is_text() {
                break msg;
            }
        }
    })
    .await
    .is_err());
    ws1.send(Message::Text(
        json!({"action":"subscribe","request_id":"two","vault_ids":[vault2]}).to_string(),
    ))
    .await
    .unwrap();
    let ack = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let msg = ws1.next().await.unwrap().unwrap();
            if msg.is_text() {
                break msg;
            }
        }
    })
    .await
    .unwrap();
    assert_eq!(
        serde_json::from_str::<Value>(ack.to_text().unwrap()).unwrap()["event"],
        "subscribed"
    );
    call(
        &app1,
        "PATCH",
        &format!("/api/v1/vaults/{vault2}"),
        Some(token),
        json!({"encrypted_name":"test-two"}),
    )
    .await;
    let hint = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let msg = ws1.next().await.unwrap().unwrap();
            if msg.is_text() {
                break msg;
            }
        }
    })
    .await
    .unwrap();
    assert_eq!(
        serde_json::from_str::<Value>(hint.to_text().unwrap()).unwrap()["vault_id"],
        vault2
    );
    ws1.send(Message::Text(
        json!({"action":"unsubscribe","request_id":"remove","vault_ids":[vault2]}).to_string(),
    ))
    .await
    .unwrap();
    // A subsequent ping acknowledges processing of the preceding unsubscribe.
    ws1.send(Message::Text(json!({"action":"ping"}).to_string()))
        .await
        .unwrap();
    let pong = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let msg = ws1.next().await.unwrap().unwrap();
            if msg.is_text() {
                break msg;
            }
        }
    })
    .await
    .unwrap();
    assert_eq!(
        serde_json::from_str::<Value>(pong.to_text().unwrap()).unwrap()["event"],
        "pong"
    );
    call(
        &app1,
        "PATCH",
        &format!("/api/v1/vaults/{vault2}"),
        Some(token),
        json!({"encrypted_name":"after-unsubscribe"}),
    )
    .await;
    assert!(tokio::time::timeout(Duration::from_millis(300), async {
        loop {
            let msg = ws1.next().await.unwrap().unwrap();
            if msg.is_text() {
                break msg;
            }
        }
    })
    .await
    .is_err());
    for app in [&app1, &app2] {
        call(
            app,
            "PATCH",
            &format!("/api/v1/vaults/{vault}"),
            Some(token),
            json!({"encrypted_name":"changed"}),
        )
        .await;
        for ws in [&mut ws1, &mut ws2] {
            let msg = tokio::time::timeout(Duration::from_secs(5), async {
                loop {
                    let msg = ws.next().await.unwrap().unwrap();
                    if msg.is_text() {
                        break msg;
                    }
                }
            })
            .await
            .unwrap();
            assert_eq!(
                serde_json::from_str::<Value>(msg.to_text().unwrap()).unwrap()["event"],
                "vault.changed"
            );
        }
    }
    let publish = Request::builder().method("POST")
        .uri(format!("/api/v1/vaults/{vault}/keys/envelopes"))
        .header("authorization", format!("Bearer {token}"))
        .header("x-device-id", device).header("content-type", "application/json")
        .body(Body::from(json!({"epoch": 1, "envelopes":[{"recipient_device_id":device,"wrapped_dek":"wrapped"}]}).to_string())).unwrap();
    let response = app1.clone().oneshot(publish).await.unwrap();
    assert_eq!(response.status(), axum::http::StatusCode::CREATED);
    for ws in [&mut ws1, &mut ws2] {
        let msg = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let msg = ws.next().await.unwrap().unwrap();
                if msg.is_text() {
                    break msg;
                }
            }
        })
        .await
        .unwrap();
        let event: Value = serde_json::from_str(msg.to_text().unwrap()).unwrap();
        assert_eq!(event["event"], "vault.changed");
        assert_eq!(event["latest_sequence"], 10);
    }
    let rotate = Request::builder().method("POST")
        .uri(format!("/api/v1/vaults/{vault}/keys/epochs"))
        .header("authorization", format!("Bearer {token}"))
        .header("x-device-id", device).header("content-type", "application/json")
        .body(Body::from(json!({"new_epoch":2,"envelopes":[{"recipient_device_id":device,"wrapped_dek":"wrapped-2"}]}).to_string())).unwrap();
    let response = app2.clone().oneshot(rotate).await.unwrap();
    assert_eq!(response.status(), axum::http::StatusCode::OK);
    for ws in [&mut ws1, &mut ws2] {
        let msg = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let msg = ws.next().await.unwrap().unwrap();
                if msg.is_text() {
                    break msg;
                }
            }
        })
        .await
        .unwrap();
        let event: Value = serde_json::from_str(msg.to_text().unwrap()).unwrap();
        assert_eq!(event["event"], "vault.key_rotated");
        assert_eq!(event["epoch"], 2);
    }
    // Store-originated notifications have no process origin and must reach both listeners.
    sqlx::query("SELECT pg_notify('shellumi_sync_events', $1)")
        .bind(json!({"type":"vault_changed", "vault_id":vault, "latest_sequence":0}).to_string())
        .execute(pg.pool())
        .await
        .unwrap();
    for ws in [&mut ws1, &mut ws2] {
        let msg = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let msg = ws.next().await.unwrap().unwrap();
                if msg.is_text() {
                    break msg;
                }
            }
        })
        .await
        .unwrap();
        assert_eq!(
            serde_json::from_str::<Value>(msg.to_text().unwrap()).unwrap()["event"],
            "vault.changed"
        );
    }
    // Revoking a device closes its active socket before further privileged hints.
    let mut device_request = format!("ws://{addr1}/api/v1/events/ws")
        .into_client_request()
        .unwrap();
    device_request.headers_mut().insert(
        "authorization",
        format!("Bearer {other_token}").parse().unwrap(),
    );
    device_request
        .headers_mut()
        .insert("x-device-id", other_device.parse().unwrap());
    let (mut revoked_socket, _) = tokio_tungstenite::connect_async(device_request)
        .await
        .unwrap();
    revoked_socket
        .send(Message::Text(
            json!({"action":"subscribe","request_id":"revoke","vault_ids":[vault]}).to_string(),
        ))
        .await
        .unwrap();
    let ack = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let msg = revoked_socket.next().await.unwrap().unwrap();
            if msg.is_text() {
                break msg;
            }
        }
    })
    .await
    .unwrap();
    assert_eq!(
        serde_json::from_str::<Value>(ack.to_text().unwrap()).unwrap()["event"],
        "subscribed"
    );
    let revoke = Request::builder()
        .method("DELETE")
        .uri(format!("/api/v1/devices/{other_device}"))
        .header("authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();
    assert_eq!(app1.clone().oneshot(revoke).await.unwrap().status(), 204);
    revoked_socket
        .send(Message::Text(json!({"action":"ping"}).to_string()))
        .await
        .unwrap();
    let closed = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            match revoked_socket.next().await {
                None | Some(Ok(Message::Close(_))) | Some(Err(_)) => break true,
                Some(Ok(Message::Text(_))) => break false,
                _ => {}
            }
        }
    })
    .await
    .unwrap();
    assert!(closed, "revoked device must not receive application frames");
    let denied = Request::builder()
        .method("GET")
        .uri(format!("/api/v1/vaults/{vault}/changes?since=0"))
        .header("authorization", format!("Bearer {other_token}"))
        .header("x-device-id", other_device)
        .body(Body::empty())
        .unwrap();
    assert_eq!(app1.clone().oneshot(denied).await.unwrap().status(), 403);

    call(
        &app1,
        "DELETE",
        &format!("/api/v1/vaults/{vault}"),
        Some(token),
        json!({}),
    )
    .await;
    for ws in [&mut ws1, &mut ws2] {
        let msg = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let msg = ws.next().await.unwrap().unwrap();
                if msg.is_text() {
                    break msg;
                }
            }
        })
        .await
        .unwrap();
        assert_eq!(
            serde_json::from_str::<Value>(msg.to_text().unwrap()).unwrap()["event"],
            "vault.access_revoked"
        );
    }
    server1.abort();
    server2.abort();
    sqlx::query(&format!("DROP DATABASE {db} WITH (FORCE)"))
        .execute(admin.pool())
        .await
        .unwrap();
}

#[tokio::test]
async fn postgres_server_process_restart_preserves_identity_and_fails_on_corrupt_key() {
    let Ok(base_url) = std::env::var("SHELLUMI_TEST_DATABASE_URL") else {
        assert!(
            std::env::var_os("SHELLUMI_REQUIRE_POSTGRES").is_none(),
            "SHELLUMI_TEST_DATABASE_URL is required for the PostgreSQL job"
        );
        return;
    };
    let admin = PgStore::connect(&base_url).await.unwrap();
    let db = format!("restart_{}", Uuid::new_v4().simple());
    sqlx::query(&format!("CREATE DATABASE {db}"))
        .execute(admin.pool())
        .await
        .unwrap();
    let (prefix, _) = base_url.rsplit_once('/').unwrap();
    let url = format!("{prefix}/{db}");
    let socket = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = socket.local_addr().unwrap();
    drop(socket);
    let spawn = || {
        std::process::Command::new(env!("CARGO_BIN_EXE_shellumi-server"))
            .env("SHELLUMI_SERVER_DATABASE_URL", &url)
            .env("SHELLUMI_SERVER_LISTEN_ADDR", addr.to_string())
            .env_remove("SHELLUMI_SERVER_TOKEN_SIGNING_KEY")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap()
    };
    async fn wait_ready(addr: std::net::SocketAddr) {
        tokio::time::timeout(Duration::from_secs(15), async {
            loop {
                if tokio::net::TcpStream::connect(addr).await.is_ok() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await
        .expect("server did not become ready");
    }
    let mut first = spawn();
    wait_ready(addr).await;
    let caps = http_json(addr, "GET", "/api/v1/capabilities", "", "", "").await;
    let boot = http_json(addr, "POST", "/api/v1/bootstrap", "", "", &json!({"admin_username":"restart", "admin_email":"restart@example.com", "admin_password":"AdminSecurePassword123!", "org_name":"Test", "bootstrap_token":null}).to_string()).await;
    let token = boot["access_token"].as_str().unwrap();
    let before = http_json(addr, "GET", "/api/v1/me", token, "", "").await;
    first.kill().unwrap();
    first.wait().unwrap();
    let mut second = spawn();
    wait_ready(addr).await;
    let after_caps = http_json(addr, "GET", "/api/v1/capabilities", "", "", "").await;
    let after = http_json(addr, "GET", "/api/v1/me", token, "", "").await;
    assert!(caps["server_instance_id"].is_string());
    assert!(before["user_id"].is_string());
    assert_eq!(caps["server_instance_id"], after_caps["server_instance_id"]);
    assert_eq!(before["user_id"], after["user_id"]);
    second.kill().unwrap();
    second.wait().unwrap();
    let store = PgStore::connect(&url).await.unwrap();
    sqlx::query("UPDATE server_settings SET token_signing_key = 'corrupt'")
        .execute(store.pool())
        .await
        .unwrap();
    let mut third = spawn();
    let status = tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            if let Some(status) = third.try_wait().unwrap() {
                break status;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("server should fail on invalid persistent key");
    assert!(!status.success());
    sqlx::query(&format!("DROP DATABASE {db} WITH (FORCE)"))
        .execute(admin.pool())
        .await
        .unwrap();
}
