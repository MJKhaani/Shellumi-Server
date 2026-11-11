//! HTTP server routing, handlers, middleware, and lifecycle.

use crate::config::ServerConfig;
use crate::metrics::MetricsRegistry;
use crate::rate_limit::{extract_client_ip, rate_limit_response, RateLimitCategory, RateLimiter};
use axum::{
    extract::{DefaultBodyLimit, Path, Query, State},
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Json, Response},
    routing::{delete, get, post},
    Router,
};
use shellumi_server_auth::{AccessTokenClaims, AuthService};
use shellumi_server_domain::DomainError;
use shellumi_server_protocol::{
    AcceptInviteRequest, AddVaultMemberRequest, BootstrapRequest, CapabilitiesResponse,
    CommitBatchRequest, CreateInviteRequest, CreateVaultRequest, ErrorResponse, HealthResponse,
    LoginRequest, LogoutRequest, PublishKeyEnvelopesRequest, RefreshTokenRequest,
    RegisterDeviceRequest, RotateKeyEpochRequest, ServerLimits, UpdateVaultRequest,
    CURRENT_PROTOCOL_VERSION, MIN_PROTOCOL_VERSION,
};
use shellumi_server_store::{InMemoryStore, UserRepository};
use shellumi_server_sync::SyncEngine;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tower_http::cors::{Any, CorsLayer};
use tower_http::timeout::TimeoutLayer;
use tower_http::trace::TraceLayer;
use tracing::info;
use uuid::Uuid;

#[derive(Clone)]
pub struct AppState {
    pub config: Arc<ServerConfig>,
    pub auth: Arc<AuthService<InMemoryStore>>,
    pub sync: Arc<SyncEngine<InMemoryStore>>,
    pub rate_limiter: Arc<RateLimiter>,
    pub metrics: Arc<MetricsRegistry>,
}

pub fn create_router(config: ServerConfig) -> Router {
    let store = Arc::new(InMemoryStore::new());
    let token_secret = b"shellumi_server_hmac_secret_key_32bytes!!".to_vec();
    let auth = Arc::new(AuthService::new(
        store.clone(),
        token_secret,
        config.access_token_ttl_secs,
        config.refresh_token_ttl_secs,
    ));
    let sync = Arc::new(SyncEngine::new(store, config.max_record_bytes));

    create_router_with_auth_and_sync(config, auth, sync)
}

pub fn create_router_with_auth(
    config: ServerConfig,
    auth: Arc<AuthService<InMemoryStore>>,
) -> Router {
    let sync = Arc::new(SyncEngine::new(
        auth.store().clone(),
        config.max_record_bytes,
    ));
    create_router_with_auth_and_sync(config, auth, sync)
}

pub fn create_router_with_auth_and_sync(
    config: ServerConfig,
    auth: Arc<AuthService<InMemoryStore>>,
    sync: Arc<SyncEngine<InMemoryStore>>,
) -> Router {
    let limits_max_request = config.max_request_bytes;
    let allowed_origins = config.allowed_origins.clone();
    let rate_limiter = Arc::new(RateLimiter::new(
        config.rate_limit_per_minute,
        Duration::from_secs(60),
    ));
    let metrics = Arc::new(MetricsRegistry::new());

    let state = AppState {
        config: Arc::new(config),
        auth,
        sync,
        rate_limiter,
        metrics,
    };

    let mut router = Router::new()
        // Health & capabilities
        .route("/health/live", get(health_live_handler))
        .route("/health/ready", get(health_ready_handler))
        .route("/api/v1/capabilities", get(capabilities_handler))
        .route("/metrics", get(metrics_route_handler))
        // Authentication & bootstrap
        .route("/api/v1/bootstrap", post(bootstrap_handler))
        .route("/api/v1/auth/login", post(login_handler))
        .route("/api/v1/auth/refresh", post(refresh_handler))
        .route("/api/v1/auth/logout", post(logout_handler))
        .route("/api/v1/me", get(me_handler))
        // Devices
        .route(
            "/api/v1/devices",
            get(list_devices_handler).post(register_device_handler),
        )
        .route("/api/v1/devices/:id", delete(revoke_device_handler))
        // Vaults & Synchronization
        .route(
            "/api/v1/vaults",
            get(list_vaults_handler).post(create_vault_handler),
        )
        .route(
            "/api/v1/vaults/:id",
            get(get_vault_handler)
                .patch(update_vault_handler)
                .delete(delete_vault_handler),
        )
        .route("/api/v1/vaults/:id/commits", post(commit_batch_handler))
        .route("/api/v1/vaults/:id/changes", get(get_changes_handler))
        .route(
            "/api/v1/vaults/:id/snapshots/:revision",
            get(get_snapshot_handler),
        )
        // Team Members
        .route(
            "/api/v1/vaults/:id/members",
            get(list_members_handler).post(add_member_handler),
        )
        .route(
            "/api/v1/vaults/:id/members/:user_id",
            delete(remove_member_handler),
        )
        // Invitations
        .route(
            "/api/v1/vaults/:id/invites",
            get(list_invites_handler).post(create_invite_handler),
        )
        .route(
            "/api/v1/vaults/:id/invites/:invite_id",
            delete(revoke_invite_handler),
        )
        .route("/api/v1/invites/accept", post(accept_invite_handler))
        // Recipient-Wrapped Key Envelopes & Epoch Rotation
        .route(
            "/api/v1/vaults/:id/keys/envelopes",
            get(get_key_envelopes_handler).post(publish_key_envelopes_handler),
        )
        .route(
            "/api/v1/vaults/:id/keys/epochs",
            post(rotate_key_epoch_handler),
        )
        // Audit Log
        .route("/api/v1/vaults/:id/audit", get(get_audit_log_handler))
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
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            record_metrics_middleware,
        ))
        .layer(TraceLayer::new_for_http())
        .layer(TimeoutLayer::with_status_code(
            StatusCode::REQUEST_TIMEOUT,
            Duration::from_secs(30),
        ))
        .layer(DefaultBodyLimit::max(limits_max_request))
        .with_state(state)
}

async fn record_metrics_middleware(
    State(state): State<AppState>,
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> Response {
    let start = std::time::Instant::now();
    let method = req.method().to_string();
    let path = req.uri().path().to_string();

    let response = next.run(req).await;

    let duration = start.elapsed();
    let status = response.status().as_u16();

    state
        .metrics
        .record_http_request(&method, &path, status, duration);

    response
}

fn check_rate_limit(
    state: &AppState,
    headers: &HeaderMap,
    category: RateLimitCategory,
) -> Option<Response> {
    let client_ip = extract_client_ip(headers, &state.config.trusted_proxies);
    if let Err(retry_after) = state.rate_limiter.check(client_ip, category) {
        state.metrics.record_rate_limit_exceeded(category.as_str());
        return Some(rate_limit_response(retry_after));
    }
    None
}

async fn metrics_route_handler(State(state): State<AppState>) -> Response {
    if !state.config.metrics_enabled {
        return (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error_code: "NOT_FOUND".to_string(),
                message: "Metrics endpoint is disabled".to_string(),
                request_id: Some(Uuid::now_v7().to_string()),
            }),
        )
            .into_response();
    }

    // Update active counters from store
    let user_count = state
        .auth
        .store()
        .list_users()
        .await
        .map(|u| u.len())
        .unwrap_or(0);
    state.metrics.update_gauges(user_count as u64, 0, 0);

    crate::metrics::metrics_handler(state.metrics.clone()).await
}

// ---------------------------------------------------------------------------
// Health Handlers
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Auth Handlers
// ---------------------------------------------------------------------------

async fn bootstrap_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<BootstrapRequest>,
) -> Response {
    if let Some(resp) = check_rate_limit(&state, &headers, RateLimitCategory::Bootstrap) {
        return resp;
    }
    match state.auth.bootstrap(req).await {
        Ok(resp) => (
            StatusCode::CREATED,
            Json(serde_json::to_value(resp).unwrap()),
        )
            .into_response(),
        Err(err) => {
            let (status, err_resp) = map_domain_error(err);
            (status, Json(serde_json::to_value(err_resp.0).unwrap())).into_response()
        }
    }
}

async fn login_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<LoginRequest>,
) -> Response {
    if let Some(resp) = check_rate_limit(&state, &headers, RateLimitCategory::AuthLogin) {
        return resp;
    }
    match state.auth.login(req).await {
        Ok(resp) => (StatusCode::OK, Json(serde_json::to_value(resp).unwrap())).into_response(),
        Err(err) => {
            let (status, err_resp) = map_domain_error(err);
            (status, Json(serde_json::to_value(err_resp.0).unwrap())).into_response()
        }
    }
}

async fn refresh_handler(
    State(state): State<AppState>,
    Json(req): Json<RefreshTokenRequest>,
) -> impl IntoResponse {
    match state.auth.refresh(req).await {
        Ok(resp) => (StatusCode::OK, Json(serde_json::to_value(resp).unwrap())),
        Err(err) => {
            let (status, err_resp) = map_domain_error(err);
            (status, Json(serde_json::to_value(err_resp.0).unwrap()))
        }
    }
}

async fn logout_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<LogoutRequest>,
) -> impl IntoResponse {
    let claims = match extract_auth_claims(&state.auth, &headers) {
        Ok(c) => c,
        Err(err) => {
            let (status, err_resp) = map_domain_error(err);
            return (status, Json(serde_json::to_value(err_resp.0).unwrap()));
        }
    };

    match state.auth.logout(claims.sub, req).await {
        Ok(()) => (
            StatusCode::OK,
            Json(serde_json::json!({ "status": "logged_out" })),
        ),
        Err(err) => {
            let (status, err_resp) = map_domain_error(err);
            (status, Json(serde_json::to_value(err_resp.0).unwrap()))
        }
    }
}

async fn me_handler(State(state): State<AppState>, headers: HeaderMap) -> impl IntoResponse {
    let claims = match extract_auth_claims(&state.auth, &headers) {
        Ok(c) => c,
        Err(err) => {
            let (status, err_resp) = map_domain_error(err);
            return (status, Json(serde_json::to_value(err_resp.0).unwrap()));
        }
    };

    match state.auth.get_me(claims.sub).await {
        Ok(resp) => (StatusCode::OK, Json(serde_json::to_value(resp).unwrap())),
        Err(err) => {
            let (status, err_resp) = map_domain_error(err);
            (status, Json(serde_json::to_value(err_resp.0).unwrap()))
        }
    }
}

// ---------------------------------------------------------------------------
// Device Handlers
// ---------------------------------------------------------------------------

async fn list_devices_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let claims = match extract_auth_claims(&state.auth, &headers) {
        Ok(c) => c,
        Err(err) => {
            let (status, err_resp) = map_domain_error(err);
            return (status, Json(serde_json::to_value(err_resp.0).unwrap()));
        }
    };

    match state.auth.list_devices(claims.sub).await {
        Ok(resp) => (StatusCode::OK, Json(serde_json::to_value(resp).unwrap())),
        Err(err) => {
            let (status, err_resp) = map_domain_error(err);
            (status, Json(serde_json::to_value(err_resp.0).unwrap()))
        }
    }
}

async fn register_device_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<RegisterDeviceRequest>,
) -> impl IntoResponse {
    let claims = match extract_auth_claims(&state.auth, &headers) {
        Ok(c) => c,
        Err(err) => {
            let (status, err_resp) = map_domain_error(err);
            return (status, Json(serde_json::to_value(err_resp.0).unwrap()));
        }
    };

    match state.auth.register_device(claims.sub, req).await {
        Ok(resp) => (
            StatusCode::CREATED,
            Json(serde_json::to_value(resp).unwrap()),
        ),
        Err(err) => {
            let (status, err_resp) = map_domain_error(err);
            (status, Json(serde_json::to_value(err_resp.0).unwrap()))
        }
    }
}

async fn revoke_device_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(device_id): Path<Uuid>,
) -> impl IntoResponse {
    let claims = match extract_auth_claims(&state.auth, &headers) {
        Ok(c) => c,
        Err(err) => {
            let (status, err_resp) = map_domain_error(err);
            return (status, Json(serde_json::to_value(err_resp.0).unwrap()));
        }
    };

    match state.auth.revoke_device(claims.sub, device_id).await {
        Ok(()) => (StatusCode::NO_CONTENT, Json(serde_json::Value::Null)),
        Err(err) => {
            let (status, err_resp) = map_domain_error(err);
            (status, Json(serde_json::to_value(err_resp.0).unwrap()))
        }
    }
}

// ---------------------------------------------------------------------------
// Vault & Sync Handlers
// ---------------------------------------------------------------------------

async fn list_vaults_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let claims = match extract_auth_claims(&state.auth, &headers) {
        Ok(c) => c,
        Err(err) => {
            let (status, err_resp) = map_domain_error(err);
            return (status, Json(serde_json::to_value(err_resp.0).unwrap()));
        }
    };

    match state.sync.list_vaults(claims.sub).await {
        Ok(resp) => (StatusCode::OK, Json(serde_json::to_value(resp).unwrap())),
        Err(err) => {
            let (status, err_resp) = map_domain_error(err);
            (status, Json(serde_json::to_value(err_resp.0).unwrap()))
        }
    }
}

async fn create_vault_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<CreateVaultRequest>,
) -> impl IntoResponse {
    let claims = match extract_auth_claims(&state.auth, &headers) {
        Ok(c) => c,
        Err(err) => {
            let (status, err_resp) = map_domain_error(err);
            return (status, Json(serde_json::to_value(err_resp.0).unwrap()));
        }
    };

    let me = match state.auth.get_me(claims.sub).await {
        Ok(m) => m,
        Err(err) => {
            let (status, err_resp) = map_domain_error(err);
            return (status, Json(serde_json::to_value(err_resp.0).unwrap()));
        }
    };

    let tenant_id = match me.organizations.first() {
        Some(o) => o.org_id,
        None => {
            let (status, err_resp) = map_domain_error(DomainError::PermissionDenied(
                "User is not a member of any organization".to_string(),
            ));
            return (status, Json(serde_json::to_value(err_resp.0).unwrap()));
        }
    };

    match state.sync.create_vault(claims.sub, tenant_id, req).await {
        Ok(resp) => (
            StatusCode::CREATED,
            Json(serde_json::to_value(resp).unwrap()),
        ),
        Err(err) => {
            let (status, err_resp) = map_domain_error(err);
            (status, Json(serde_json::to_value(err_resp.0).unwrap()))
        }
    }
}

async fn get_vault_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(vault_id): Path<Uuid>,
) -> impl IntoResponse {
    let claims = match extract_auth_claims(&state.auth, &headers) {
        Ok(c) => c,
        Err(err) => {
            let (status, err_resp) = map_domain_error(err);
            return (status, Json(serde_json::to_value(err_resp.0).unwrap()));
        }
    };

    match state.sync.get_vault(claims.sub, vault_id).await {
        Ok(resp) => (StatusCode::OK, Json(serde_json::to_value(resp).unwrap())),
        Err(err) => {
            let (status, err_resp) = map_domain_error(err);
            (status, Json(serde_json::to_value(err_resp.0).unwrap()))
        }
    }
}

async fn update_vault_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(vault_id): Path<Uuid>,
    Json(req): Json<UpdateVaultRequest>,
) -> impl IntoResponse {
    let claims = match extract_auth_claims(&state.auth, &headers) {
        Ok(c) => c,
        Err(err) => {
            let (status, err_resp) = map_domain_error(err);
            return (status, Json(serde_json::to_value(err_resp.0).unwrap()));
        }
    };

    match state.sync.update_vault(claims.sub, vault_id, req).await {
        Ok(resp) => (StatusCode::OK, Json(serde_json::to_value(resp).unwrap())),
        Err(err) => {
            let (status, err_resp) = map_domain_error(err);
            (status, Json(serde_json::to_value(err_resp.0).unwrap()))
        }
    }
}

async fn delete_vault_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(vault_id): Path<Uuid>,
) -> impl IntoResponse {
    let claims = match extract_auth_claims(&state.auth, &headers) {
        Ok(c) => c,
        Err(err) => {
            let (status, err_resp) = map_domain_error(err);
            return (status, Json(serde_json::to_value(err_resp.0).unwrap()));
        }
    };

    match state.sync.delete_vault(claims.sub, vault_id).await {
        Ok(()) => (
            StatusCode::OK,
            Json(serde_json::json!({ "status": "deleted" })),
        ),
        Err(err) => {
            let (status, err_resp) = map_domain_error(err);
            (status, Json(serde_json::to_value(err_resp.0).unwrap()))
        }
    }
}

async fn commit_batch_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(path_vault_id): Path<Uuid>,
    Json(req): Json<CommitBatchRequest>,
) -> impl IntoResponse {
    let claims = match extract_auth_claims(&state.auth, &headers) {
        Ok(c) => c,
        Err(err) => {
            let (status, err_resp) = map_domain_error(err);
            return (status, Json(serde_json::to_value(err_resp.0).unwrap()));
        }
    };

    if req.vault_id != path_vault_id {
        let (status, err_resp) = map_domain_error(DomainError::InvalidInput(
            "Path vault ID does not match body vault ID".to_string(),
        ));
        return (status, Json(serde_json::to_value(err_resp.0).unwrap()));
    }

    let device_id = match headers.get("X-Device-Id") {
        Some(v) => match v.to_str().ok().and_then(|s| s.parse::<Uuid>().ok()) {
            Some(id) => id,
            None => {
                let (status, err_resp) = map_domain_error(DomainError::InvalidInput(
                    "Invalid X-Device-Id header: must be a valid UUID".to_string(),
                ));
                return (status, Json(serde_json::to_value(err_resp.0).unwrap()));
            }
        },
        None => {
            let (status, err_resp) = map_domain_error(DomainError::InvalidInput(
                "Missing required X-Device-Id header".to_string(),
            ));
            return (status, Json(serde_json::to_value(err_resp.0).unwrap()));
        }
    };

    match state.sync.commit_batch(claims.sub, device_id, req).await {
        Ok(resp) => (StatusCode::OK, Json(serde_json::to_value(resp).unwrap())),
        Err(err) => {
            let (status, err_resp) = map_domain_error(err);
            (status, Json(serde_json::to_value(err_resp.0).unwrap()))
        }
    }
}

#[derive(Debug, serde::Deserialize)]
pub struct ChangesQuery {
    pub since: Option<u64>,
    pub cursor: Option<String>,
    pub limit: Option<usize>,
}

async fn get_changes_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(vault_id): Path<Uuid>,
    Query(query): Query<ChangesQuery>,
) -> impl IntoResponse {
    let claims = match extract_auth_claims(&state.auth, &headers) {
        Ok(c) => c,
        Err(err) => {
            let (status, err_resp) = map_domain_error(err);
            return (status, Json(serde_json::to_value(err_resp.0).unwrap()));
        }
    };

    let since_seq = if let Some(cursor_str) = query.cursor {
        if let Some(seq_part) = cursor_str.strip_prefix("seq:") {
            seq_part.parse::<u64>().unwrap_or(0)
        } else {
            0
        }
    } else {
        query.since.unwrap_or(0)
    };

    let limit = query.limit.unwrap_or(100);

    match state
        .sync
        .get_changes(claims.sub, vault_id, since_seq, limit)
        .await
    {
        Ok(resp) => (StatusCode::OK, Json(serde_json::to_value(resp).unwrap())),
        Err(err) => {
            let (status, err_resp) = map_domain_error(err);
            (status, Json(serde_json::to_value(err_resp.0).unwrap()))
        }
    }
}

async fn get_snapshot_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((vault_id, _revision)): Path<(Uuid, String)>,
) -> impl IntoResponse {
    let claims = match extract_auth_claims(&state.auth, &headers) {
        Ok(c) => c,
        Err(err) => {
            let (status, err_resp) = map_domain_error(err);
            return (status, Json(serde_json::to_value(err_resp.0).unwrap()));
        }
    };

    match state.sync.get_snapshot(claims.sub, vault_id).await {
        Ok(resp) => (StatusCode::OK, Json(serde_json::to_value(resp).unwrap())),
        Err(err) => {
            let (status, err_resp) = map_domain_error(err);
            (status, Json(serde_json::to_value(err_resp.0).unwrap()))
        }
    }
}

// ---------------------------------------------------------------------------
// Team Member Handlers
// ---------------------------------------------------------------------------

async fn list_members_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(vault_id): Path<Uuid>,
) -> impl IntoResponse {
    let claims = match extract_auth_claims(&state.auth, &headers) {
        Ok(c) => c,
        Err(err) => {
            let (status, err_resp) = map_domain_error(err);
            return (status, Json(serde_json::to_value(err_resp.0).unwrap()));
        }
    };

    match state.sync.list_members(claims.sub, vault_id).await {
        Ok(resp) => (StatusCode::OK, Json(serde_json::to_value(resp).unwrap())),
        Err(err) => {
            let (status, err_resp) = map_domain_error(err);
            (status, Json(serde_json::to_value(err_resp.0).unwrap()))
        }
    }
}

async fn add_member_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(vault_id): Path<Uuid>,
    Json(req): Json<AddVaultMemberRequest>,
) -> impl IntoResponse {
    let claims = match extract_auth_claims(&state.auth, &headers) {
        Ok(c) => c,
        Err(err) => {
            let (status, err_resp) = map_domain_error(err);
            return (status, Json(serde_json::to_value(err_resp.0).unwrap()));
        }
    };

    match state
        .sync
        .add_or_update_member(claims.sub, vault_id, req)
        .await
    {
        Ok(resp) => (StatusCode::OK, Json(serde_json::to_value(resp).unwrap())),
        Err(err) => {
            let (status, err_resp) = map_domain_error(err);
            (status, Json(serde_json::to_value(err_resp.0).unwrap()))
        }
    }
}

async fn remove_member_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((vault_id, target_user_id)): Path<(Uuid, Uuid)>,
) -> impl IntoResponse {
    let claims = match extract_auth_claims(&state.auth, &headers) {
        Ok(c) => c,
        Err(err) => {
            let (status, err_resp) = map_domain_error(err);
            return (status, Json(serde_json::to_value(err_resp.0).unwrap()));
        }
    };

    match state
        .sync
        .remove_member(claims.sub, vault_id, target_user_id)
        .await
    {
        Ok(()) => (StatusCode::NO_CONTENT, Json(serde_json::Value::Null)),
        Err(err) => {
            let (status, err_resp) = map_domain_error(err);
            (status, Json(serde_json::to_value(err_resp.0).unwrap()))
        }
    }
}

// ---------------------------------------------------------------------------
// Invitation Handlers
// ---------------------------------------------------------------------------

async fn create_invite_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(vault_id): Path<Uuid>,
    Json(req): Json<CreateInviteRequest>,
) -> impl IntoResponse {
    let claims = match extract_auth_claims(&state.auth, &headers) {
        Ok(c) => c,
        Err(err) => {
            let (status, err_resp) = map_domain_error(err);
            return (status, Json(serde_json::to_value(err_resp.0).unwrap()));
        }
    };

    match state.sync.create_invite(claims.sub, vault_id, req).await {
        Ok(resp) => (
            StatusCode::CREATED,
            Json(serde_json::to_value(resp).unwrap()),
        ),
        Err(err) => {
            let (status, err_resp) = map_domain_error(err);
            (status, Json(serde_json::to_value(err_resp.0).unwrap()))
        }
    }
}

async fn list_invites_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(vault_id): Path<Uuid>,
) -> impl IntoResponse {
    let claims = match extract_auth_claims(&state.auth, &headers) {
        Ok(c) => c,
        Err(err) => {
            let (status, err_resp) = map_domain_error(err);
            return (status, Json(serde_json::to_value(err_resp.0).unwrap()));
        }
    };

    match state.sync.list_invites(claims.sub, vault_id).await {
        Ok(resp) => (StatusCode::OK, Json(serde_json::to_value(resp).unwrap())),
        Err(err) => {
            let (status, err_resp) = map_domain_error(err);
            (status, Json(serde_json::to_value(err_resp.0).unwrap()))
        }
    }
}

async fn revoke_invite_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((vault_id, invite_id)): Path<(Uuid, Uuid)>,
) -> impl IntoResponse {
    let claims = match extract_auth_claims(&state.auth, &headers) {
        Ok(c) => c,
        Err(err) => {
            let (status, err_resp) = map_domain_error(err);
            return (status, Json(serde_json::to_value(err_resp.0).unwrap()));
        }
    };

    match state
        .sync
        .revoke_invite(claims.sub, vault_id, invite_id)
        .await
    {
        Ok(()) => (StatusCode::NO_CONTENT, Json(serde_json::Value::Null)),
        Err(err) => {
            let (status, err_resp) = map_domain_error(err);
            (status, Json(serde_json::to_value(err_resp.0).unwrap()))
        }
    }
}

async fn accept_invite_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<AcceptInviteRequest>,
) -> Response {
    if let Some(resp) = check_rate_limit(&state, &headers, RateLimitCategory::InviteAccept) {
        return resp;
    }
    let claims = match extract_auth_claims(&state.auth, &headers) {
        Ok(c) => c,
        Err(err) => {
            let (status, err_resp) = map_domain_error(err);
            return (status, Json(serde_json::to_value(err_resp.0).unwrap())).into_response();
        }
    };

    match state.sync.accept_invite(claims.sub, req).await {
        Ok(resp) => (StatusCode::OK, Json(serde_json::to_value(resp).unwrap())).into_response(),
        Err(err) => {
            let (status, err_resp) = map_domain_error(err);
            (status, Json(serde_json::to_value(err_resp.0).unwrap())).into_response()
        }
    }
}

// ---------------------------------------------------------------------------
// Recipient-Wrapped Key Envelope Handlers
// ---------------------------------------------------------------------------

#[derive(Debug, serde::Deserialize)]
pub struct KeyEnvelopesQuery {
    pub epoch: Option<u32>,
}

async fn publish_key_envelopes_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(vault_id): Path<Uuid>,
    Json(req): Json<PublishKeyEnvelopesRequest>,
) -> impl IntoResponse {
    let claims = match extract_auth_claims(&state.auth, &headers) {
        Ok(c) => c,
        Err(err) => {
            let (status, err_resp) = map_domain_error(err);
            return (status, Json(serde_json::to_value(err_resp.0).unwrap()));
        }
    };

    let device_id = match extract_device_id(&headers) {
        Ok(d) => d,
        Err(err) => {
            let (status, err_resp) = map_domain_error(err);
            return (status, Json(serde_json::to_value(err_resp.0).unwrap()));
        }
    };

    match state
        .sync
        .publish_key_envelopes(claims.sub, device_id, vault_id, req)
        .await
    {
        Ok(count) => (
            StatusCode::CREATED,
            Json(serde_json::json!({ "published": count })),
        ),
        Err(err) => {
            let (status, err_resp) = map_domain_error(err);
            (status, Json(serde_json::to_value(err_resp.0).unwrap()))
        }
    }
}

async fn get_key_envelopes_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(vault_id): Path<Uuid>,
    Query(query): Query<KeyEnvelopesQuery>,
) -> impl IntoResponse {
    let claims = match extract_auth_claims(&state.auth, &headers) {
        Ok(c) => c,
        Err(err) => {
            let (status, err_resp) = map_domain_error(err);
            return (status, Json(serde_json::to_value(err_resp.0).unwrap()));
        }
    };

    let device_id = match extract_device_id(&headers) {
        Ok(d) => d,
        Err(err) => {
            let (status, err_resp) = map_domain_error(err);
            return (status, Json(serde_json::to_value(err_resp.0).unwrap()));
        }
    };

    match state
        .sync
        .get_envelopes_for_device(claims.sub, device_id, vault_id, query.epoch)
        .await
    {
        Ok(resp) => (StatusCode::OK, Json(serde_json::to_value(resp).unwrap())),
        Err(err) => {
            let (status, err_resp) = map_domain_error(err);
            (status, Json(serde_json::to_value(err_resp.0).unwrap()))
        }
    }
}

async fn rotate_key_epoch_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(vault_id): Path<Uuid>,
    Json(req): Json<RotateKeyEpochRequest>,
) -> impl IntoResponse {
    let claims = match extract_auth_claims(&state.auth, &headers) {
        Ok(c) => c,
        Err(err) => {
            let (status, err_resp) = map_domain_error(err);
            return (status, Json(serde_json::to_value(err_resp.0).unwrap()));
        }
    };

    let device_id = match extract_device_id(&headers) {
        Ok(d) => d,
        Err(err) => {
            let (status, err_resp) = map_domain_error(err);
            return (status, Json(serde_json::to_value(err_resp.0).unwrap()));
        }
    };

    match state
        .sync
        .rotate_key_epoch(claims.sub, device_id, vault_id, req)
        .await
    {
        Ok(resp) => (StatusCode::OK, Json(serde_json::to_value(resp).unwrap())),
        Err(err) => {
            let (status, err_resp) = map_domain_error(err);
            (status, Json(serde_json::to_value(err_resp.0).unwrap()))
        }
    }
}

// ---------------------------------------------------------------------------
// Audit Log Handler
// ---------------------------------------------------------------------------

#[derive(Debug, serde::Deserialize)]
pub struct AuditLogQuery {
    pub limit: Option<usize>,
    pub offset: Option<usize>,
}

async fn get_audit_log_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(vault_id): Path<Uuid>,
    Query(query): Query<AuditLogQuery>,
) -> impl IntoResponse {
    let claims = match extract_auth_claims(&state.auth, &headers) {
        Ok(c) => c,
        Err(err) => {
            let (status, err_resp) = map_domain_error(err);
            return (status, Json(serde_json::to_value(err_resp.0).unwrap()));
        }
    };

    match state
        .sync
        .get_audit_log(
            claims.sub,
            vault_id,
            query.limit.unwrap_or(50),
            query.offset.unwrap_or(0),
        )
        .await
    {
        Ok(resp) => (StatusCode::OK, Json(serde_json::to_value(resp).unwrap())),
        Err(err) => {
            let (status, err_resp) = map_domain_error(err);
            (status, Json(serde_json::to_value(err_resp.0).unwrap()))
        }
    }
}

fn extract_device_id(headers: &HeaderMap) -> Result<Uuid, DomainError> {
    let header_val = headers
        .get("x-device-id")
        .or_else(|| headers.get("X-Device-Id"))
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| DomainError::InvalidInput("Missing X-Device-Id header".to_string()))?;

    Uuid::parse_str(header_val)
        .map_err(|_| DomainError::InvalidInput("Invalid X-Device-Id UUID format".to_string()))
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

fn extract_auth_claims(
    auth: &AuthService<InMemoryStore>,
    headers: &HeaderMap,
) -> Result<AccessTokenClaims, DomainError> {
    let auth_header = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .ok_or(DomainError::Unauthenticated)?;

    let token = auth_header
        .strip_prefix("Bearer ")
        .ok_or_else(|| DomainError::InvalidToken("Expected Bearer token".to_string()))?;

    auth.verify_token(token.trim())
}

fn map_domain_error(err: DomainError) -> (StatusCode, Json<ErrorResponse>) {
    let (status, code) = match &err {
        DomainError::InvalidCredentials => (StatusCode::UNAUTHORIZED, "INVALID_CREDENTIALS"),
        DomainError::Unauthenticated => (StatusCode::UNAUTHORIZED, "UNAUTHENTICATED"),
        DomainError::InvalidToken(_) => (StatusCode::UNAUTHORIZED, "INVALID_TOKEN"),
        DomainError::TokenExpired => (StatusCode::UNAUTHORIZED, "TOKEN_EXPIRED"),
        DomainError::TokenReuseDetected => (StatusCode::FORBIDDEN, "TOKEN_REUSE_DETECTED"),
        DomainError::BootstrapAlreadyConsumed => {
            (StatusCode::CONFLICT, "BOOTSTRAP_ALREADY_CONSUMED")
        }
        DomainError::InvalidBootstrapToken => (StatusCode::FORBIDDEN, "INVALID_BOOTSTRAP_TOKEN"),
        DomainError::DeviceRevoked => (StatusCode::FORBIDDEN, "DEVICE_REVOKED"),
        DomainError::DeviceNotFound => (StatusCode::NOT_FOUND, "DEVICE_NOT_FOUND"),
        DomainError::NotFound => (StatusCode::NOT_FOUND, "NOT_FOUND"),
        DomainError::PermissionDenied(_) => (StatusCode::FORBIDDEN, "PERMISSION_DENIED"),
        DomainError::Conflict(_) => (StatusCode::CONFLICT, "CONFLICT"),
        DomainError::RevisionConflict { .. } => (StatusCode::CONFLICT, "REVISION_CONFLICT"),
        DomainError::IdempotencyConflict { .. } => (StatusCode::CONFLICT, "IDEMPOTENCY_CONFLICT"),
        DomainError::InvalidSignature(_) => (StatusCode::FORBIDDEN, "INVALID_SIGNATURE"),
        DomainError::VaultNotFound(_) => (StatusCode::NOT_FOUND, "NOT_FOUND"),
        DomainError::InviteNotFound => (StatusCode::NOT_FOUND, "INVITE_NOT_FOUND"),
        DomainError::InviteExpired => (StatusCode::GONE, "INVITE_EXPIRED"),
        DomainError::InviteAlreadyAccepted => (StatusCode::CONFLICT, "INVITE_ALREADY_ACCEPTED"),
        DomainError::InviteRevoked => (StatusCode::FORBIDDEN, "INVITE_REVOKED"),
        DomainError::CannotRevokeLastOwner => (StatusCode::CONFLICT, "CANNOT_REVOKE_LAST_OWNER"),
        DomainError::StaleKeyEpoch { .. } => (StatusCode::CONFLICT, "STALE_KEY_EPOCH"),
        DomainError::InvalidInput(_) | DomainError::InvalidPublicKey(_) => {
            (StatusCode::UNPROCESSABLE_ENTITY, "INVALID_INPUT")
        }
        DomainError::PayloadTooLarge { .. } => (StatusCode::PAYLOAD_TOO_LARGE, "PAYLOAD_TOO_LARGE"),
        DomainError::Configuration(_) | DomainError::Internal(_) => {
            (StatusCode::INTERNAL_SERVER_ERROR, "INTERNAL_ERROR")
        }
    };

    (
        status,
        Json(ErrorResponse {
            error_code: code.to_string(),
            message: err.to_string(),
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
