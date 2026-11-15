use shellumi_server::{config::ServerConfig, server::create_router};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::test]
async fn websocket_rejects_unauthenticated_upgrade() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        axum::serve(listener, create_router(ServerConfig::default()))
            .await
            .unwrap();
    });
    let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    stream.write_all(b"GET /api/v1/sync/events HTTP/1.1\r\nHost: localhost\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n").await.unwrap();
    let mut response = [0; 1024];
    let n = stream.read(&mut response).await.unwrap();
    assert!(std::str::from_utf8(&response[..n])
        .unwrap()
        .starts_with("HTTP/1.1 401"));
    server.abort();
}

#[tokio::test]
async fn team_metadata_change_sends_hint() {
    use axum::{body::Body, http::Request};
    use serde_json::{json, Value};
    use tower::ServiceExt;
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
    let boot = call(&app, "POST", "/api/v1/bootstrap", None, json!({"admin_username":"tester","admin_email":"tester@example.com","admin_password":"AdminSecurePassword123!","org_name":"Test","bootstrap_token":null})).await;
    let token = boot["access_token"].as_str().unwrap();
    let device = call(
        &app,
        "POST",
        "/api/v1/devices",
        Some(token),
        json!({"device_name":"test","signing_public_key":"test","agreement_public_key":"test"}),
    )
    .await;
    let device = device["device_id"].as_str().unwrap();
    let vault = call(
        &app,
        "POST",
        "/api/v1/vaults",
        Some(token),
        json!({"vault_type":"team","encrypted_name":"old"}),
    )
    .await;
    let vault = vault["vault_id"].as_str().unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server_app = app.clone();
    let server = tokio::spawn(async move {
        axum::serve(listener, server_app).await.unwrap();
    });
    let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    stream.write_all(format!("GET /api/v1/sync/events HTTP/1.1\r\nHost: localhost\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nAuthorization: Bearer {token}\r\nX-Device-Id: {device}\r\n\r\n").as_bytes()).await.unwrap();
    let mut handshake = Vec::new();
    while !handshake.ends_with(b"\r\n\r\n") {
        handshake.push(stream.read_u8().await.unwrap());
    }
    assert!(std::str::from_utf8(&handshake)
        .unwrap()
        .starts_with("HTTP/1.1 101"));
    let poll_app = app.clone();
    let poll_token = token.to_string();
    let poll_device = device.to_string();
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
        &format!("/api/v1/vaults/{vault}"),
        Some(token),
        json!({"encrypted_name":"new"}),
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
    assert_eq!(poll_body["vault_id"], vault);
    let event = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            let first = stream.read_u8().await.unwrap();
            let len = stream.read_u8().await.unwrap() as usize;
            assert!(len < 126);
            let mut payload = vec![0; len];
            stream.read_exact(&mut payload).await.unwrap();
            if first & 15 == 1 {
                break serde_json::from_slice::<Value>(&payload).unwrap();
            }
        }
    })
    .await
    .unwrap();
    assert_eq!(event["type"], "vault_changed");
    assert_eq!(event["vault_id"], vault);
    call(
        &app,
        "DELETE",
        &format!("/api/v1/vaults/{vault}"),
        Some(token),
        json!({}),
    )
    .await;
    let deleted = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            let first = stream.read_u8().await.unwrap();
            let len = stream.read_u8().await.unwrap() as usize;
            let mut payload = vec![0; len];
            stream.read_exact(&mut payload).await.unwrap();
            if first & 15 == 1 {
                break serde_json::from_slice::<Value>(&payload).unwrap();
            }
        }
    })
    .await
    .unwrap();
    assert_eq!(deleted["type"], "vault_deleted");
    assert_eq!(deleted["vault_id"], vault);
    call(
        &app,
        "POST",
        "/api/v1/auth/logout",
        Some(token),
        json!({"refresh_token": boot["refresh_token"]}),
    )
    .await;
    let closed = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            match stream.read_u8().await {
                Err(_) => break true,
                Ok(first) => {
                    let len = stream.read_u8().await.unwrap() as usize;
                    let mut payload = vec![0; len];
                    stream.read_exact(&mut payload).await.unwrap();
                    if first & 15 == 8 {
                        break true;
                    }
                }
            }
        }
    })
    .await
    .unwrap();
    assert!(closed);
    let mut retry = tokio::net::TcpStream::connect(addr).await.unwrap();
    retry.write_all(format!("GET /api/v1/sync/events HTTP/1.1\r\nHost: localhost\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nAuthorization: Bearer {token}\r\nX-Device-Id: {device}\r\n\r\n").as_bytes()).await.unwrap();
    let mut response = [0; 1024];
    let n = retry.read(&mut response).await.unwrap();
    assert!(std::str::from_utf8(&response[..n])
        .unwrap()
        .starts_with("HTTP/1.1 401"));
    server.abort();
}

#[tokio::test]
async fn poll_rejects_unauthenticated_requests() {
    use axum::{body::Body, http::Request};
    use tower::ServiceExt;
    let response = create_router(ServerConfig::default())
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
