use axum::{
    body::Body,
    http::{header, Request, StatusCode},
};
use shellumi_server::config::ServerConfig;
use shellumi_server::server::create_router;
use shellumi_server_protocol::{
    BootstrapRequest, BootstrapResponse, DeviceResponse, ErrorResponse, LoginRequest,
    LoginResponse, MeResponse, RefreshTokenRequest, RefreshTokenResponse, RegisterDeviceRequest,
};
use tower::ServiceExt;

#[tokio::test]
async fn test_bootstrap_flow_and_duplicate_rejection() {
    let config = ServerConfig::default();
    let app = create_router(config);

    let bootstrap_req = BootstrapRequest {
        admin_username: "sysadmin".to_string(),
        admin_email: "admin@corp.internal".to_string(),
        admin_password: "P@ssw0rdSecure2026!".to_string(),
        org_name: "Corporate Org".to_string(),
        bootstrap_token: None,
    };

    let req = Request::builder()
        .uri("/api/v1/bootstrap")
        .method("POST")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&bootstrap_req).unwrap()))
        .unwrap();

    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::CREATED);

    let body = axum::body::to_bytes(res.into_body(), 1024 * 64)
        .await
        .unwrap();
    let boot_res: BootstrapResponse = serde_json::from_slice(&body).unwrap();
    assert_eq!(boot_res.username, "sysadmin");
    assert_eq!(boot_res.email, "admin@corp.internal");
    assert!(!boot_res.access_token.is_empty());
    assert!(!boot_res.refresh_token.is_empty());

    // Duplicate bootstrap must return 409 Conflict
    let req2 = Request::builder()
        .uri("/api/v1/bootstrap")
        .method("POST")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&bootstrap_req).unwrap()))
        .unwrap();

    let res2 = app.oneshot(req2).await.unwrap();
    assert_eq!(res2.status(), StatusCode::CONFLICT);

    let body2 = axum::body::to_bytes(res2.into_body(), 1024 * 64)
        .await
        .unwrap();
    let err: ErrorResponse = serde_json::from_slice(&body2).unwrap();
    assert_eq!(err.error_code, "BOOTSTRAP_ALREADY_CONSUMED");
}

#[tokio::test]
async fn test_auth_login_refresh_and_theft_detection() {
    let config = ServerConfig::default();
    let app = create_router(config);

    // Bootstrap first
    let bootstrap_req = BootstrapRequest {
        admin_username: "john".to_string(),
        admin_email: "john@example.com".to_string(),
        admin_password: "MySecurePassword1!".to_string(),
        org_name: "John Corp".to_string(),
        bootstrap_token: None,
    };

    let req = Request::builder()
        .uri("/api/v1/bootstrap")
        .method("POST")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&bootstrap_req).unwrap()))
        .unwrap();
    let _ = app.clone().oneshot(req).await.unwrap();

    // Login with wrong password -> 401 Unauthorized
    let bad_login = LoginRequest {
        identifier: "john".to_string(),
        password: "WrongPassword!".to_string(),
        device_id: None,
    };
    let req = Request::builder()
        .uri("/api/v1/auth/login")
        .method("POST")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&bad_login).unwrap()))
        .unwrap();
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);

    // Login with correct password -> 200 OK
    let good_login = LoginRequest {
        identifier: "john".to_string(),
        password: "MySecurePassword1!".to_string(),
        device_id: None,
    };
    let req = Request::builder()
        .uri("/api/v1/auth/login")
        .method("POST")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&good_login).unwrap()))
        .unwrap();
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    let body = axum::body::to_bytes(res.into_body(), 1024 * 64)
        .await
        .unwrap();
    let login_res: LoginResponse = serde_json::from_slice(&body).unwrap();
    let initial_refresh = login_res.refresh_token.clone();

    // Access /me with bearer token
    let req = Request::builder()
        .uri("/api/v1/me")
        .method("GET")
        .header(
            header::AUTHORIZATION,
            format!("Bearer {}", login_res.access_token),
        )
        .body(Body::empty())
        .unwrap();
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    let body = axum::body::to_bytes(res.into_body(), 1024 * 64)
        .await
        .unwrap();
    let me: MeResponse = serde_json::from_slice(&body).unwrap();
    assert_eq!(me.username, "john");
    assert_eq!(me.organizations.len(), 1);
    assert_eq!(me.organizations[0].org_name, "John Corp");

    // Rotate refresh token -> 200 OK
    let refresh_req = RefreshTokenRequest {
        refresh_token: initial_refresh.clone(),
    };
    let req = Request::builder()
        .uri("/api/v1/auth/refresh")
        .method("POST")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&refresh_req).unwrap()))
        .unwrap();
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    let body = axum::body::to_bytes(res.into_body(), 1024 * 64)
        .await
        .unwrap();
    let ref_res: RefreshTokenResponse = serde_json::from_slice(&body).unwrap();
    let second_refresh = ref_res.refresh_token;

    // Token reuse: attempting to refresh using initial_refresh again must trigger theft detection!
    let req = Request::builder()
        .uri("/api/v1/auth/refresh")
        .method("POST")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&refresh_req).unwrap()))
        .unwrap();
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::FORBIDDEN);

    let body = axum::body::to_bytes(res.into_body(), 1024 * 64)
        .await
        .unwrap();
    let err: ErrorResponse = serde_json::from_slice(&body).unwrap();
    assert_eq!(err.error_code, "TOKEN_REUSE_DETECTED");

    // Second refresh token was also revoked because of theft detection!
    let req = Request::builder()
        .uri("/api/v1/auth/refresh")
        .method("POST")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            serde_json::to_vec(&RefreshTokenRequest {
                refresh_token: second_refresh,
            })
            .unwrap(),
        ))
        .unwrap();
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::FORBIDDEN);

    // Completely unknown/random refresh token returns 401 Unauthorized
    let req = Request::builder()
        .uri("/api/v1/auth/refresh")
        .method("POST")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            serde_json::to_vec(&RefreshTokenRequest {
                refresh_token: "never_seen_random_refresh_token".to_string(),
            })
            .unwrap(),
        ))
        .unwrap();
    let res = app.oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_device_registration_listing_and_revocation() {
    let config = ServerConfig::default();
    let app = create_router(config);

    // Bootstrap first
    let bootstrap_req = BootstrapRequest {
        admin_username: "alice_dev".to_string(),
        admin_email: "alice@devices.net".to_string(),
        admin_password: "Password#Dev2026!".to_string(),
        org_name: "Alice Engineering".to_string(),
        bootstrap_token: None,
    };

    let req = Request::builder()
        .uri("/api/v1/bootstrap")
        .method("POST")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&bootstrap_req).unwrap()))
        .unwrap();
    let res = app.clone().oneshot(req).await.unwrap();
    let body = axum::body::to_bytes(res.into_body(), 1024 * 64)
        .await
        .unwrap();
    let boot_res: BootstrapResponse = serde_json::from_slice(&body).unwrap();
    let auth_header = format!("Bearer {}", boot_res.access_token);

    // Register a device
    let dev_req = RegisterDeviceRequest {
        device_name: "Workstation-01".to_string(),
        signing_public_key: "ed25519-pk-base64-string".to_string(),
        agreement_public_key: "x25519-pk-base64-string".to_string(),
    };

    let req = Request::builder()
        .uri("/api/v1/devices")
        .method("POST")
        .header(header::AUTHORIZATION, &auth_header)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&dev_req).unwrap()))
        .unwrap();
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::CREATED);

    let body = axum::body::to_bytes(res.into_body(), 1024 * 64)
        .await
        .unwrap();
    let dev_res: DeviceResponse = serde_json::from_slice(&body).unwrap();
    assert_eq!(dev_res.device_name, "Workstation-01");
    let device_id = dev_res.device_id;

    // List devices
    let req = Request::builder()
        .uri("/api/v1/devices")
        .method("GET")
        .header(header::AUTHORIZATION, &auth_header)
        .body(Body::empty())
        .unwrap();
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    let body = axum::body::to_bytes(res.into_body(), 1024 * 64)
        .await
        .unwrap();
    let dev_list: Vec<DeviceResponse> = serde_json::from_slice(&body).unwrap();
    assert_eq!(dev_list.len(), 1);

    // Revoke device
    let req = Request::builder()
        .uri(format!("/api/v1/devices/{}", device_id))
        .method("DELETE")
        .header(header::AUTHORIZATION, &auth_header)
        .body(Body::empty())
        .unwrap();
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::NO_CONTENT);

    // Attempt to login referencing the revoked device -> 403 Forbidden
    let login_with_revoked = LoginRequest {
        identifier: "alice_dev".to_string(),
        password: "Password#Dev2026!".to_string(),
        device_id: Some(device_id),
    };
    let req = Request::builder()
        .uri("/api/v1/auth/login")
        .method("POST")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&login_with_revoked).unwrap()))
        .unwrap();
    let res = app.oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::FORBIDDEN);

    let body = axum::body::to_bytes(res.into_body(), 1024 * 64)
        .await
        .unwrap();
    let err: ErrorResponse = serde_json::from_slice(&body).unwrap();
    assert_eq!(err.error_code, "DEVICE_REVOKED");
}
