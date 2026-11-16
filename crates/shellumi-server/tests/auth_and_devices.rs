use axum::{
    body::Body,
    http::{header, Request, StatusCode},
};
use base64::Engine;
use shellumi_server::config::ServerConfig;
use shellumi_server::server::create_router;
use shellumi_server_protocol::{
    BootstrapRequest, BootstrapResponse, DeviceChallengeResponse, DeviceResponse, ErrorResponse,
    LoginRequest, LoginResponse, LogoutRequest, MeResponse, RefreshTokenRequest,
    RefreshTokenResponse, RegisterDeviceRequest,
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

    // Register a device with PoP challenge
    let (keypair, signing_pk) = shellumi_server_crypto::generate_test_ed25519_keypair().unwrap();
    let agreement_pk = base64::engine::general_purpose::STANDARD.encode([2u8; 32]);

    let chal_req = Request::builder()
        .uri("/api/v1/devices/challenge")
        .method("POST")
        .header(header::AUTHORIZATION, &auth_header)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from("{}"))
        .unwrap();
    let chal_res = app.clone().oneshot(chal_req).await.unwrap();
    assert_eq!(chal_res.status(), StatusCode::OK);
    let chal_bytes = axum::body::to_bytes(chal_res.into_body(), 1024 * 64)
        .await
        .unwrap();
    let chal_json: DeviceChallengeResponse = serde_json::from_slice(&chal_bytes).unwrap();
    let sig = shellumi_server_crypto::sign_message(&keypair, chal_json.challenge.as_bytes());

    let dev_req = RegisterDeviceRequest {
        device_name: "Workstation-01".to_string(),
        signing_public_key: signing_pk,
        agreement_public_key: agreement_pk,
        challenge: Some(chal_json.challenge),
        challenge_signature: Some(sig),
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

#[tokio::test]
async fn test_device_challenge_and_pop_registration() {
    use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
    use shellumi_server_crypto::generate_test_ed25519_keypair;

    let config = ServerConfig::default();
    let app = create_router(config);

    // Bootstrap initial admin
    let bootstrap_req = BootstrapRequest {
        admin_username: "challenge_tester".to_string(),
        admin_email: "challenge@example.com".to_string(),
        admin_password: "ChallengeSecurePass123!".to_string(),
        org_name: "Challenge Org".to_string(),
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
    let auth_header = format!("Bearer {}", boot_res.access_token);

    // Request challenge nonce
    let req = Request::builder()
        .uri("/api/v1/devices/challenge")
        .method("POST")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from("{}"))
        .unwrap();
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body = axum::body::to_bytes(res.into_body(), 1024 * 64)
        .await
        .unwrap();
    let challenge_res: DeviceChallengeResponse = serde_json::from_slice(&body).unwrap();
    assert!(!challenge_res.challenge.is_empty());
    assert!(challenge_res.expires_at > chrono::Utc::now().timestamp());

    // Generate real Ed25519 keypair
    let (keypair, pk_b64) = generate_test_ed25519_keypair().unwrap();
    let agreement_pk = BASE64_STANDARD.encode([5u8; 32]);

    // Negative case: Register device with invalid challenge signature -> 401 Unauthorized
    let bad_dev_req = RegisterDeviceRequest {
        device_name: "Tampered-Device".to_string(),
        signing_public_key: pk_b64.clone(),
        agreement_public_key: agreement_pk.clone(),
        challenge: Some(challenge_res.challenge.clone()),
        challenge_signature: Some(BASE64_STANDARD.encode([9u8; 64])),
    };
    let req = Request::builder()
        .uri("/api/v1/devices")
        .method("POST")
        .header(header::AUTHORIZATION, &auth_header)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&bad_dev_req).unwrap()))
        .unwrap();
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::FORBIDDEN);

    // Positive case: Request a fresh challenge nonce
    let req = Request::builder()
        .uri("/api/v1/devices/challenge")
        .method("POST")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from("{}"))
        .unwrap();
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body = axum::body::to_bytes(res.into_body(), 1024 * 64)
        .await
        .unwrap();
    let fresh_challenge_res: DeviceChallengeResponse = serde_json::from_slice(&body).unwrap();

    // Sign fresh challenge nonce correctly
    let sig = keypair.sign(fresh_challenge_res.challenge.as_bytes());
    let sig_b64 = BASE64_STANDARD.encode(sig.as_ref());

    let good_dev_req = RegisterDeviceRequest {
        device_name: "Verified-Device".to_string(),
        signing_public_key: pk_b64,
        agreement_public_key: agreement_pk,
        challenge: Some(fresh_challenge_res.challenge),
        challenge_signature: Some(sig_b64),
    };
    let req = Request::builder()
        .uri("/api/v1/devices")
        .method("POST")
        .header(header::AUTHORIZATION, &auth_header)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&good_dev_req).unwrap()))
        .unwrap();
    let res = app.oneshot(req).await.unwrap();
    let status = res.status();
    let body = axum::body::to_bytes(res.into_body(), 1024 * 64)
        .await
        .unwrap();
    println!("STATUS: {status}, BODY: {}", String::from_utf8_lossy(&body));
    assert_eq!(status, StatusCode::CREATED);
    let dev_res: DeviceResponse = serde_json::from_slice(&body).unwrap();
    assert_eq!(dev_res.device_name, "Verified-Device");
}

#[tokio::test]
async fn test_rest_endpoints_enforce_session_revocation_after_logout() {
    let config = ServerConfig::default();
    let app = create_router(config);

    // 1. Bootstrap
    let bootstrap_req = BootstrapRequest {
        admin_username: "revocation_admin".to_string(),
        admin_email: "revocation@example.com".to_string(),
        admin_password: "SecurePassword123!".to_string(),
        org_name: "Revocation Org".to_string(),
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
    let access_token = boot_res.access_token;
    let refresh_token = boot_res.refresh_token;

    // 2. Verified access token works on /api/v1/me and /api/v1/vaults
    let req = Request::builder()
        .uri("/api/v1/me")
        .method("GET")
        .header(header::AUTHORIZATION, format!("Bearer {access_token}"))
        .body(Body::empty())
        .unwrap();
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    let req = Request::builder()
        .uri("/api/v1/vaults")
        .method("GET")
        .header(header::AUTHORIZATION, format!("Bearer {access_token}"))
        .body(Body::empty())
        .unwrap();
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    // 3. Logout session
    let logout_req = LogoutRequest {
        refresh_token: Some(refresh_token),
    };
    let req = Request::builder()
        .uri("/api/v1/auth/logout")
        .method("POST")
        .header(header::AUTHORIZATION, format!("Bearer {access_token}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&logout_req).unwrap()))
        .unwrap();
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    // 4. Critical security check: The access token MUST be rejected immediately across REST routes
    let req = Request::builder()
        .uri("/api/v1/me")
        .method("GET")
        .header(header::AUTHORIZATION, format!("Bearer {access_token}"))
        .body(Body::empty())
        .unwrap();
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);

    let req = Request::builder()
        .uri("/api/v1/vaults")
        .method("GET")
        .header(header::AUTHORIZATION, format!("Bearer {access_token}"))
        .body(Body::empty())
        .unwrap();
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);

    let req = Request::builder()
        .uri("/api/v1/devices")
        .method("GET")
        .header(header::AUTHORIZATION, format!("Bearer {access_token}"))
        .body(Body::empty())
        .unwrap();
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_device_registration_rejects_missing_challenge_pop() {
    let config = ServerConfig::default();
    let app = create_router(config);

    // Bootstrap
    let bootstrap_req = BootstrapRequest {
        admin_username: "pop_tester".to_string(),
        admin_email: "pop@example.com".to_string(),
        admin_password: "SecurePassword123!".to_string(),
        org_name: "PoP Org".to_string(),
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

    // Missing challenge and signature must be rejected with 400 Bad Request
    let signing_pk = base64::engine::general_purpose::STANDARD.encode([1u8; 32]);
    let agreement_pk = base64::engine::general_purpose::STANDARD.encode([2u8; 32]);
    let bad_dev_req = RegisterDeviceRequest {
        device_name: "Unauthenticated-Device".to_string(),
        signing_public_key: signing_pk,
        agreement_public_key: agreement_pk,
        challenge: None,
        challenge_signature: None,
    };

    let req = Request::builder()
        .uri("/api/v1/devices")
        .method("POST")
        .header(header::AUTHORIZATION, &auth_header)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&bad_dev_req).unwrap()))
        .unwrap();
    let res = app.oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::FORBIDDEN);
}
