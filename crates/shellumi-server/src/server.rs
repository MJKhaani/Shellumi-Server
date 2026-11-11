//! HTTP server routing, handlers, middleware, and lifecycle.

use crate::config::ServerConfig;
use axum::{
    extract::{DefaultBodyLimit, State},
    http::{HeaderValue, StatusCode},
    response::{IntoResponse, Json},
    routing::get,
    Router,
};
use shellumi_server_protocol::{
    CapabilitiesResponse, ErrorResponse, HealthResponse, ServerLimits, CURRENT_PROTOCOL_VERSION,
    MIN_PROTOCOL_VERSION,
};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tower_http::cors::{Any, CorsLayer};
use tower_http::timeout::TimeoutLayer;
use tower_http::trace::TraceLayer;
use tracing::info;

#[derive(Clone)]
pub struct AppState {
    pub config: Arc<ServerConfig>,
}

pub fn create_router(config: ServerConfig) -> Router {
    let limits_max_request = config.max_request_bytes;
    let allowed_origins = config.allowed_origins.clone();
    let state = AppState {
        config: Arc::new(config),
    };

    let mut router = Router::new()
        .route("/health/live", get(health_live_handler))
        .route("/health/ready", get(health_ready_handler))
        .route("/api/v1/capabilities", get(capabilities_handler))
        .fallback(not_found_handler);

    // Apply CORS
    if !allowed_origins.is_empty() {
        let origins: Vec<HeaderValue> = allowed_origins
            .iter()
            .filter_map(|o| o.parse().ok())
            .collect();
        let cors = CorsLayer::new()
            .allow_origin(origins)
            .allow_methods(Any)
            .allow_headers(Any);
        router = router.layer(cors);
    }

    router
        .layer(TraceLayer::new_for_http())
        .layer(TimeoutLayer::with_status_code(
            StatusCode::REQUEST_TIMEOUT,
            Duration::from_secs(30),
        ))
        .layer(DefaultBodyLimit::max(limits_max_request))
        .with_state(state)
}

async fn health_live_handler() -> impl IntoResponse {
    (
        StatusCode::OK,
        Json(HealthResponse {
            status: "ok".to_string(),
            service: "shellumi-server".to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            details: None,
        }),
    )
}

async fn health_ready_handler() -> impl IntoResponse {
    (
        StatusCode::OK,
        Json(HealthResponse {
            status: "ok".to_string(),
            service: "shellumi-server".to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            details: Some("System ready".to_string()),
        }),
    )
}

async fn capabilities_handler(State(state): State<AppState>) -> impl IntoResponse {
    let limits = ServerLimits {
        max_request_bytes: state.config.max_request_bytes,
        max_record_bytes: state.config.max_record_bytes,
        max_mutations_per_commit: 100,
    };

    let capabilities = CapabilitiesResponse {
        server_version: env!("CARGO_PKG_VERSION").to_string(),
        protocol_version: CURRENT_PROTOCOL_VERSION,
        min_protocol_version: MIN_PROTOCOL_VERSION,
        supported_features: vec![
            "vault_sync_v1".to_string(),
            "device_auth".to_string(),
            "team_sharing".to_string(),
        ],
        supported_e2ee_suites: vec![
            "x25519_hkdf_aes256gcm".to_string(),
            "argon2id_aes256gcm_legacy".to_string(),
        ],
        limits,
    };

    (StatusCode::OK, Json(capabilities))
}

async fn not_found_handler() -> impl IntoResponse {
    (
        StatusCode::NOT_FOUND,
        Json(ErrorResponse {
            error_code: "NOT_FOUND".to_string(),
            message: "The requested resource was not found".to_string(),
            request_id: None,
        }),
    )
}

pub async fn run(config: ServerConfig) -> Result<(), Box<dyn std::error::Error>> {
    let listen_addr = config.listen_addr;
    let app = create_router(config);

    let listener = tokio::net::TcpListener::bind(listen_addr).await?;
    info!("Shellumi Server listening on {}", listen_addr);

    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await?;

    info!("Shellumi Server shut down gracefully");
    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install SIGTERM signal handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {
            info!("Received SIGINT (Ctrl+C), starting graceful shutdown...");
        },
        _ = terminate => {
            info!("Received SIGTERM, starting graceful shutdown...");
        },
    }
}
