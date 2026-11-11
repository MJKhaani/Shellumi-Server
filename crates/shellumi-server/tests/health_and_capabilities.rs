use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use shellumi_server::config::ServerConfig;
use shellumi_server::server::create_router;
use shellumi_server_protocol::{
    CapabilitiesResponse, ErrorResponse, HealthResponse, CURRENT_PROTOCOL_VERSION,
};
use tower::ServiceExt;

#[tokio::test]
async fn test_health_live_endpoint_returns_ok() {
    let config = ServerConfig::default();
    let app = create_router(config);

    let request = Request::builder()
        .uri("/health/live")
        .method("GET")
        .body(Body::empty())
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let body_bytes = axum::body::to_bytes(response.into_body(), 1024 * 64)
        .await
        .unwrap();
    let health: HealthResponse = serde_json::from_slice(&body_bytes).unwrap();

    assert_eq!(health.status, "ok");
    assert_eq!(health.service, "shellumi-server");
    assert_eq!(health.version, env!("CARGO_PKG_VERSION"));
    assert!(health.details.is_none());
}

#[tokio::test]
async fn test_health_ready_endpoint_returns_ready() {
    let config = ServerConfig::default();
    let app = create_router(config);

    let request = Request::builder()
        .uri("/health/ready")
        .method("GET")
        .body(Body::empty())
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let body_bytes = axum::body::to_bytes(response.into_body(), 1024 * 64)
        .await
        .unwrap();
    let health: HealthResponse = serde_json::from_slice(&body_bytes).unwrap();

    assert_eq!(health.status, "ok");
    assert_eq!(health.service, "shellumi-server");
    assert_eq!(health.details.as_deref(), Some("System ready"));
}

#[tokio::test]
async fn test_capabilities_endpoint_returns_protocol_and_limits() {
    let config = ServerConfig {
        max_request_bytes: 8 * 1024 * 1024,
        max_record_bytes: 512 * 1024,
        ..Default::default()
    };

    let app = create_router(config);

    let request = Request::builder()
        .uri("/api/v1/capabilities")
        .method("GET")
        .body(Body::empty())
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let body_bytes = axum::body::to_bytes(response.into_body(), 1024 * 64)
        .await
        .unwrap();
    let caps: CapabilitiesResponse = serde_json::from_slice(&body_bytes).unwrap();

    assert_eq!(caps.server_version, env!("CARGO_PKG_VERSION"));
    assert_eq!(caps.protocol_version, CURRENT_PROTOCOL_VERSION);
    assert!(caps
        .supported_features
        .contains(&"vault_sync_v1".to_string()));
    assert_eq!(caps.limits.max_request_bytes, 8 * 1024 * 1024);
    assert_eq!(caps.limits.max_record_bytes, 512 * 1024);
    assert_eq!(caps.limits.max_mutations_per_commit, 100);
}

#[tokio::test]
async fn test_unknown_route_returns_404_json_error() {
    let config = ServerConfig::default();
    let app = create_router(config);

    let request = Request::builder()
        .uri("/api/v1/nonexistent")
        .method("GET")
        .body(Body::empty())
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);

    let body_bytes = axum::body::to_bytes(response.into_body(), 1024 * 64)
        .await
        .unwrap();
    let error: ErrorResponse = serde_json::from_slice(&body_bytes).unwrap();

    assert_eq!(error.error_code, "NOT_FOUND");
    assert!(error.message.contains("not found"));
}
