//! HTTP server routing, handlers, middleware, and lifecycle.

use crate::collab::{into_collab_stream, CollabHub};
use crate::config::ServerConfig;
use crate::metrics::MetricsRegistry;
use crate::rate_limit::{extract_client_ip, rate_limit_response, RateLimitCategory, RateLimiter};
use axum::{
    extract::{
        ws::{rejection::WebSocketUpgradeRejection, Message, WebSocket, WebSocketUpgrade},
        DefaultBodyLimit, Path, Query, State,
    },
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Json, Response},
    routing::{delete, get, post},
    Router,
};
use shellumi_server_auth::{AccessTokenClaims, AuthService};
use shellumi_server_domain::DomainError;
use shellumi_server_protocol::{
    AcceptInviteRequest, AddVaultMemberRequest, BootstrapRequest, CapabilitiesResponse,
    CollabParticipantListResponse, CollabPollQuery, CollabPollResponse, CollabSessionListResponse,
    CommitBatchRequest, CreateCollabSessionRequest, CreateInviteRequest, CreateVaultRequest,
    DeviceChallengeRequest, EnrollParticipantRequest, ErrorResponse, GrantControlRequest,
    HealthResponse, LoginRequest, LogoutRequest, PublishKeyEnvelopesRequest, RefreshTokenRequest,
    RegisterDeviceRequest, RotateKeyEpochRequest, SendCollabFrameRequest, ServerLimits,
    UpdateVaultRequest, VaultWatermark, WsClientMessage, WsServerMessage, CURRENT_PROTOCOL_VERSION,
    MIN_PROTOCOL_VERSION,
};
use shellumi_server_store::{
    AnyStore, DeviceRepository, PgStore, SettingsRepository, UserRepository, VaultRepository,
};
use shellumi_server_sync::SyncEngine;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{broadcast, Semaphore};
use tower_http::cors::{Any, CorsLayer};
use tower_http::timeout::TimeoutLayer;
use tower_http::trace::TraceLayer;
use tracing::info;
use uuid::Uuid;

#[derive(Clone, Debug)]
enum SyncEvent {
    VaultChanged {
        vault_id: Uuid,
        latest_sequence: u64,
        notification_id: Uuid,
    },
    KeyRotated {
        vault_id: Uuid,
        epoch: u32,
        notification_id: Uuid,
    },
    AccessRevoked {
        vault_id: Uuid,
        user_id: Option<Uuid>,
        notification_id: Uuid,
    },
    Logout(Uuid),
}

#[derive(Clone)]
pub struct AppState {
    pub config: Arc<ServerConfig>,
    pub store: Arc<AnyStore>,
    pub auth: Arc<AuthService<AnyStore>>,
    pub sync: Arc<SyncEngine<AnyStore>>,
    pub collab: Arc<CollabHub<AnyStore>>,
    pub rate_limiter: Arc<RateLimiter>,
    pub metrics: Arc<MetricsRegistry>,
    notification_origin: Uuid,
    notifications: broadcast::Sender<SyncEvent>,
    notification_connections: Arc<Semaphore>,
}

impl AppState {
    /// Broadcast an event locally and via PostgreSQL NOTIFY for multi-instance fanout.
    async fn broadcast_sync_event(&self, event: SyncEvent) {
        let instance_id = self.notification_origin;
        let payload = match &event {
            SyncEvent::VaultChanged {
                vault_id,
                latest_sequence,
                ..
            } => {
                serde_json::json!({
                    "type": "vault_changed",
                    "vault_id": vault_id,
                    "latest_sequence": latest_sequence,
                    "source_instance": instance_id,
                })
            }
            SyncEvent::KeyRotated {
                vault_id, epoch, ..
            } => {
                serde_json::json!({
                    "type": "key_rotated",
                    "vault_id": vault_id,
                    "epoch": epoch,
                    "source_instance": instance_id,
                })
            }
            SyncEvent::AccessRevoked {
                vault_id, user_id, ..
            } => {
                serde_json::json!({
                    "type": "access_revoked",
                    "vault_id": vault_id,
                    "user_id": user_id,
                    "source_instance": instance_id,
                })
            }
            SyncEvent::Logout(user_id) => {
                serde_json::json!({
                    "type": "logout",
                    "user_id": user_id,
                    "source_instance": instance_id,
                })
            }
        };

        // Local broadcast
        let _ = self.notifications.send(event);

        // Cross-instance via PostgreSQL NOTIFY (best-effort, non-blocking)
        if let Err(error) = self
            .store
            .notify_sync_event("shellumi_sync_events", &payload.to_string())
            .await
        {
            tracing::warn!("Failed to publish sync hint: {error}");
        }
    }
}

pub fn create_router(config: ServerConfig) -> Router {
    create_router_with_store(config, AnyStore::memory())
}

pub fn create_router_with_store(config: ServerConfig, store: AnyStore) -> Router {
    let store_arc = Arc::new(store);
    let token_secret = if let Some(key) = &config.token_signing_key {
        key.as_bytes().to_vec()
    } else {
        use ring::rand::SecureRandom;
        let mut key = vec![0u8; 32];
        let rng = ring::rand::SystemRandom::new();
        rng.fill(&mut key)
            .expect("Cryptographically secure random key generation failed");
        key
    };
    let auth = Arc::new(AuthService::new(
        store_arc.clone(),
        token_secret,
        config.access_token_ttl_secs,
        config.refresh_token_ttl_secs,
    ));
    let sync = Arc::new(SyncEngine::new(store_arc, config.max_record_bytes));

    create_router_with_auth_and_sync(config, auth, sync)
}

pub fn create_router_with_auth(config: ServerConfig, auth: Arc<AuthService<AnyStore>>) -> Router {
    let sync = Arc::new(SyncEngine::new(
        auth.store().clone(),
        config.max_record_bytes,
    ));
    create_router_with_auth_and_sync(config, auth, sync)
}

pub fn create_router_with_auth_and_sync(
    config: ServerConfig,
    auth: Arc<AuthService<AnyStore>>,
    sync: Arc<SyncEngine<AnyStore>>,
) -> Router {
    let store = auth.store().clone();
    let limits_max_request = config.max_request_bytes;
    let allowed_origins = config.allowed_origins.clone();
    let rate_limiter = Arc::new(RateLimiter::new(
        config.rate_limit_per_minute,
        Duration::from_secs(60),
    ));
    let metrics = Arc::new(MetricsRegistry::new());
    let collab = Arc::new(CollabHub::new(store.clone()));
    let (notifications, _) = broadcast::channel(256);

    let notification_origin = Uuid::new_v4();

    // If PostgreSQL database is configured, bridge cross-instance events via LISTEN/NOTIFY
    if let Some(db_url) = config.database_url.clone() {
        let notif_tx = notifications.clone();
        let instance_id = notification_origin;
        tokio::spawn(async move {
            let mut backoff_secs = 1u64;
            loop {
                match sqlx::postgres::PgListener::connect(&db_url).await {
                    Ok(mut listener) => {
                        if listener.listen("shellumi_sync_events").await.is_err() {
                            tracing::warn!(
                                "PgListener: failed to LISTEN, retrying in {backoff_secs}s"
                            );
                            tokio::time::sleep(Duration::from_secs(backoff_secs)).await;
                            backoff_secs = (backoff_secs * 2).min(60);
                            continue;
                        }
                        backoff_secs = 1; // reset on successful connect
                        loop {
                            match listener.recv().await {
                                Ok(notification) => {
                                    if let Ok(val) = serde_json::from_str::<serde_json::Value>(
                                        notification.payload(),
                                    ) {
                                        // Skip self-echoed events
                                        if let Some(src) =
                                            val.get("source_instance").and_then(|v| v.as_str())
                                        {
                                            if src == instance_id.to_string() {
                                                continue;
                                            }
                                        }
                                        if let Some(event_type) =
                                            val.get("type").and_then(|v| v.as_str())
                                        {
                                            match event_type {
                                                "vault_changed" => {
                                                    if let (Some(vid_str), Some(seq)) = (
                                                        val.get("vault_id")
                                                            .and_then(|v| v.as_str()),
                                                        val.get("latest_sequence")
                                                            .and_then(|v| v.as_u64()),
                                                    ) {
                                                        if let Ok(vault_id) =
                                                            Uuid::parse_str(vid_str)
                                                        {
                                                            let _ = notif_tx.send(
                                                                SyncEvent::VaultChanged {
                                                                    vault_id,
                                                                    latest_sequence: seq,
                                                                    notification_id: Uuid::new_v4(),
                                                                },
                                                            );
                                                        }
                                                    }
                                                }
                                                "key_rotated" => {
                                                    if let (Some(vid_str), Some(epoch)) = (
                                                        val.get("vault_id")
                                                            .and_then(|v| v.as_str()),
                                                        val.get("epoch").and_then(|v| v.as_u64()),
                                                    ) {
                                                        if let Ok(vault_id) =
                                                            Uuid::parse_str(vid_str)
                                                        {
                                                            let _ = notif_tx.send(
                                                                SyncEvent::KeyRotated {
                                                                    vault_id,
                                                                    epoch: epoch as u32,
                                                                    notification_id: Uuid::new_v4(),
                                                                },
                                                            );
                                                        }
                                                    }
                                                }
                                                "access_revoked" => {
                                                    if let Some(vid_str) =
                                                        val.get("vault_id").and_then(|v| v.as_str())
                                                    {
                                                        if let Ok(vault_id) =
                                                            Uuid::parse_str(vid_str)
                                                        {
                                                            let user_id = val
                                                                .get("user_id")
                                                                .and_then(|v| v.as_str())
                                                                .and_then(|s| {
                                                                    Uuid::parse_str(s).ok()
                                                                });
                                                            let _ = notif_tx.send(
                                                                SyncEvent::AccessRevoked {
                                                                    vault_id,
                                                                    user_id,
                                                                    notification_id: Uuid::new_v4(),
                                                                },
                                                            );
                                                        }
                                                    }
                                                }
                                                "logout" => {
                                                    if let Some(uid_str) =
                                                        val.get("user_id").and_then(|v| v.as_str())
                                                    {
                                                        if let Ok(user_id) =
                                                            Uuid::parse_str(uid_str)
                                                        {
                                                            let _ = notif_tx
                                                                .send(SyncEvent::Logout(user_id));
                                                        }
                                                    }
                                                }
                                                _ => {}
                                            }
                                        }
                                    }
                                }
                                Err(e) => {
                                    tracing::warn!("PgListener: recv error: {e}, reconnecting in {backoff_secs}s");
                                    break; // break inner loop to reconnect
                                }
                            }
                        }
                    }
                    Err(e) => {
                        tracing::warn!(
                            "PgListener: connect error: {e}, retrying in {backoff_secs}s"
                        );
                    }
                }
                tokio::time::sleep(Duration::from_secs(backoff_secs)).await;
                backoff_secs = (backoff_secs * 2).min(60);
            }
        });
    }

    let state = AppState {
        config: Arc::new(config),
        store,
        auth,
        sync,
        collab,
        rate_limiter,
        metrics,
        notification_origin,
        notifications,
        notification_connections: Arc::new(Semaphore::new(1024)),
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
        .route("/api/v1/events/ws", get(events_ws_handler))
        .route("/api/v1/sync/events", get(events_ws_handler))
        .route("/api/v1/sync/poll", get(sync_poll_handler))
        // Devices
        .route(
            "/api/v1/devices",
            get(list_devices_handler).post(register_device_handler),
        )
        .route("/api/v1/devices/challenge", post(device_challenge_handler))
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
        .route(
            "/api/v1/vaults/:id/recipient-devices",
            get(list_recipient_devices_handler),
        )
        .route("/api/v1/vaults/:id/commits", post(commit_batch_handler))
        .route("/api/v1/vaults/:id/changes", get(get_changes_handler))
        .route("/api/v1/vaults/:id/snapshots", get(get_snapshot_handler))
        .route(
            "/api/v1/vaults/:id/snapshots/:revision",
            get(get_snapshot_with_revision_handler),
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
        // Live Terminal Collaboration (Milestone M5)
        .route(
            "/api/v1/collab/sessions",
            get(list_collab_sessions_handler).post(create_collab_session_handler),
        )
        .route(
            "/api/v1/collab/sessions/:id",
            get(get_collab_session_handler),
        )
        .route(
            "/api/v1/collab/sessions/:id/participants",
            get(list_collab_participants_handler).post(enroll_collab_participant_handler),
        )
        .route(
            "/api/v1/collab/sessions/:id/control/grant",
            post(grant_collab_control_handler),
        )
        .route(
            "/api/v1/collab/sessions/:id/control/revoke",
            post(revoke_collab_control_handler),
        )
        .route(
            "/api/v1/collab/sessions/:id/terminate",
            post(terminate_collab_session_handler),
        )
        .route(
            "/api/v1/collab/sessions/:id/frames",
            post(send_collab_frame_handler),
        )
        .route(
            "/api/v1/collab/sessions/:id/poll",
            get(poll_collab_frames_handler),
        )
        .route(
            "/api/v1/collab/sessions/:id/events",
            get(collab_events_sse_handler),
        )
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

async fn health_ready_handler(State(state): State<AppState>) -> impl IntoResponse {
    if !state.store.is_ready().await {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(HealthResponse {
                status: "degraded".to_string(),
                service: "shellumi-server".to_string(),
                version: env!("CARGO_PKG_VERSION").to_string(),
                details: Some("Storage backend is unreachable or degraded".to_string()),
            }),
        );
    }

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
        max_change_page: 500,
    };

    let mut supported_features = vec![
        "vault_sync_v1".to_string(),
        "device_auth_v1".to_string(),
        "device_wrapped_keys_v1".to_string(),
        "signed_mutations_v1".to_string(),
        "delta_sync_v1".to_string(),
        "websocket_notifications_v1".to_string(),
        "team_sharing_v1".to_string(),
    ];
    if state.config.collab_enabled {
        supported_features.push("terminal_collab_v1".to_string());
    }

    let capabilities = CapabilitiesResponse {
        server_instance_id: state.config.server_instance_id,
        server_version: env!("CARGO_PKG_VERSION").to_string(),
        protocol_version: CURRENT_PROTOCOL_VERSION,
        min_protocol_version: MIN_PROTOCOL_VERSION,
        supported_features,
        supported_e2ee_suites: vec![
            "aes256gcm_dek_v1".to_string(),
            "hpke_x25519_hkdfsha256_aes256gcm_v1".to_string(),
            "argon2id_aes256gcm_legacy".to_string(),
        ],
        websocket: Some(shellumi_server_protocol::WebSocketCapability {
            endpoint: "/api/v1/events/ws".to_string(),
            heartbeat_seconds: 25,
        }),
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
    let claims = match extract_auth_claims(&state.auth, &headers).await {
        Ok(c) => c,
        Err(err) => {
            let (status, err_resp) = map_domain_error(err);
            return (status, Json(serde_json::to_value(err_resp.0).unwrap()));
        }
    };

    match state.auth.logout(claims.sub, req).await {
        Ok(()) => {
            state
                .broadcast_sync_event(SyncEvent::Logout(claims.sub))
                .await;
            (
                StatusCode::OK,
                Json(serde_json::json!({ "status": "logged_out" })),
            )
        }
        Err(err) => {
            let (status, err_resp) = map_domain_error(err);
            (status, Json(serde_json::to_value(err_resp.0).unwrap()))
        }
    }
}

async fn me_handler(State(state): State<AppState>, headers: HeaderMap) -> impl IntoResponse {
    let claims = match extract_auth_claims(&state.auth, &headers).await {
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
    let claims = match extract_auth_claims(&state.auth, &headers).await {
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
    let claims = match extract_auth_claims(&state.auth, &headers).await {
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
    let claims = match extract_auth_claims(&state.auth, &headers).await {
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

async fn device_challenge_handler(
    State(state): State<AppState>,
    _req: Option<Json<DeviceChallengeRequest>>,
) -> Response {
    let res = state.auth.create_device_challenge().await;
    (StatusCode::OK, Json(res)).into_response()
}

async fn list_recipient_devices_handler(
    State(state): State<AppState>,
    Path(vault_id): Path<Uuid>,
    headers: HeaderMap,
) -> Response {
    let claims = match extract_auth_claims(&state.auth, &headers).await {
        Ok(claims) => claims,
        Err(err) => return map_domain_error(err).into_response(),
    };
    match state
        .sync
        .list_recipient_devices(claims.sub, vault_id)
        .await
    {
        Ok(res) => (StatusCode::OK, Json(res)).into_response(),
        Err(err) => map_domain_error(err).into_response(),
    }
}

async fn events_ws_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    ws: Result<WebSocketUpgrade, WebSocketUpgradeRejection>,
) -> Response {
    let claims = match extract_auth_claims(&state.auth, &headers).await {
        Ok(claims) => claims,
        Err(err) => return map_domain_error(err).into_response(),
    };
    let device_id = match extract_device_id(&headers) {
        Ok(id) => id,
        Err(err) => return map_domain_error(err).into_response(),
    };
    if !sync_session_valid(&state, &claims, device_id).await {
        return map_domain_error(DomainError::Unauthenticated).into_response();
    }
    match state.auth.store().find_device_by_id(device_id).await {
        Ok(Some(device)) if device.user_id == claims.sub && device.revoked_at.is_none() => {}
        _ => return map_domain_error(DomainError::Unauthenticated).into_response(),
    }
    let ws = match ws {
        Ok(ws) => ws,
        Err(rejection) => return rejection.into_response(),
    };
    let permit = match state.notification_connections.clone().try_acquire_owned() {
        Ok(permit) => permit,
        Err(_) => return StatusCode::TOO_MANY_REQUESTS.into_response(),
    };
    let rx = state.notifications.subscribe();
    ws.max_message_size(4096)
        .on_upgrade(move |socket| async move {
            let _permit = permit;
            events_ws_socket(socket, state, claims, device_id, rx).await;
        })
}

async fn sync_session_valid(state: &AppState, claims: &AccessTokenClaims, device_id: Uuid) -> bool {
    state
        .auth
        .validate_active_session(claims, Some(device_id))
        .await
        .is_ok()
}

async fn sync_poll_handler(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let claims = match extract_auth_claims(&state.auth, &headers).await {
        Ok(claims) => claims,
        Err(err) => return map_domain_error(err).into_response(),
    };
    let device_id = match extract_device_id(&headers) {
        Ok(id) => id,
        Err(err) => return map_domain_error(err).into_response(),
    };
    if !notification_access_valid(&state, &claims, device_id).await {
        return map_domain_error(DomainError::Unauthenticated).into_response();
    }
    let _permit = match state.notification_connections.clone().try_acquire_owned() {
        Ok(permit) => permit,
        Err(_) => return StatusCode::TOO_MANY_REQUESTS.into_response(),
    };
    let mut rx = state.notifications.subscribe();
    let result = tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            match rx.recv().await {
                Ok(SyncEvent::Logout(user)) if user == claims.sub => {
                    return StatusCode::UNAUTHORIZED.into_response()
                }
                Ok(SyncEvent::Logout(_)) => continue,
                Err(_) => {
                    return (
                        StatusCode::CONFLICT,
                        Json(serde_json::json!({"code":"RESYNC_REQUIRED"})),
                    )
                        .into_response()
                }
                Ok(event) => {
                    if !notification_access_valid(&state, &claims, device_id).await {
                        return StatusCode::UNAUTHORIZED.into_response();
                    }
                    match event {
                        SyncEvent::VaultChanged {
                            vault_id,
                            latest_sequence,
                            ..
                        } => {
                            if let Ok(role) = state
                                .auth
                                .store()
                                .get_vault_member_role(vault_id, claims.sub)
                                .await
                            {
                                if role.is_some() {
                                    return Json(serde_json::json!({
                                        "type": "vault_changed",
                                        "vault_id": vault_id,
                                        "latest_sequence": latest_sequence,
                                    }))
                                    .into_response();
                                }
                            }
                        }
                        SyncEvent::AccessRevoked {
                            vault_id, user_id, ..
                        } => {
                            if user_id.is_none() || user_id == Some(claims.sub) {
                                return Json(serde_json::json!({
                                    "type": "vault_deleted",
                                    "vault_id": vault_id,
                                }))
                                .into_response();
                            }
                        }
                        SyncEvent::KeyRotated {
                            vault_id, epoch, ..
                        } => {
                            if let Ok(role) = state
                                .auth
                                .store()
                                .get_vault_member_role(vault_id, claims.sub)
                                .await
                            {
                                if role.is_some() {
                                    return Json(serde_json::json!({
                                        "type": "key_rotated",
                                        "vault_id": vault_id,
                                        "epoch": epoch,
                                    }))
                                    .into_response();
                                }
                            }
                        }
                        SyncEvent::Logout(_) => continue,
                    }
                }
            }
        }
    })
    .await;
    match result {
        Ok(response) => response,
        Err(_) if notification_access_valid(&state, &claims, device_id).await => {
            StatusCode::NO_CONTENT.into_response()
        }
        Err(_) => StatusCode::UNAUTHORIZED.into_response(),
    }
}

async fn notification_access_valid(
    state: &AppState,
    claims: &AccessTokenClaims,
    device_id: Uuid,
) -> bool {
    chrono::Utc::now().timestamp() < claims.exp
        && sync_session_valid(state, claims, device_id).await
        && matches!(state.auth.store().find_device_by_id(device_id).await, Ok(Some(device)) if device.user_id == claims.sub && device.revoked_at.is_none())
}

async fn events_ws_socket(
    mut socket: WebSocket,
    state: AppState,
    claims: AccessTokenClaims,
    device_id: Uuid,
    mut rx: broadcast::Receiver<SyncEvent>,
) {
    use std::collections::HashSet;

    let mut subscribed_vaults: HashSet<Uuid> = HashSet::new();
    let mut heartbeat = tokio::time::interval(Duration::from_secs(30));

    loop {
        tokio::select! {
            _ = heartbeat.tick() => {
                if chrono::Utc::now().timestamp() >= claims.exp {
                    break;
                }
                if state.auth.validate_active_session(&claims, Some(device_id)).await.is_err() {
                    break;
                }
                if socket.send(Message::Ping(Vec::new())).await.is_err() {
                    break;
                }
            }
            msg = socket.recv() => {
                match msg {
                    Some(Ok(Message::Text(text))) => {
                        if !notification_access_valid(&state, &claims, device_id).await {
                            break;
                        }
                        let parsed: Result<WsClientMessage, _> = serde_json::from_str(&text);
                        match parsed {
                            Ok(WsClientMessage::Subscribe { request_id, vault_ids }) => {
                                let mut watermarks = Vec::with_capacity(vault_ids.len());
                                let mut error_occurred = false;
                                let requested: HashSet<Uuid> = vault_ids.into_iter().collect();
                                if subscribed_vaults.union(&requested).count() > 128 {
                                    let err = WsServerMessage::Error {
                                        code: "SUBSCRIPTION_LIMIT".to_string(),
                                        message: "Too many vault subscriptions".to_string(),
                                        request_id: Some(request_id.clone()),
                                    };
                                    if let Ok(json) = serde_json::to_string(&err) {
                                        let _ = socket.send(Message::Text(json)).await;
                                    }
                                    continue;
                                }
                                for vid in requested {
                                    let role = state.auth.store().get_vault_member_role(vid, claims.sub).await;
                                    let vault = state.auth.store().find_vault_by_id(vid).await;

                                    match (role, vault) {
                                        (Ok(Some(_)), Ok(Some(v))) if v.deleted_at.is_none() => {
                                            watermarks.push(VaultWatermark {
                                                vault_id: vid,
                                                latest_sequence: v.server_sequence,
                                            });
                                        }
                                        _ => {
                                            let err_msg = WsServerMessage::Error {
                                                code: "SUBSCRIPTION_DENIED".to_string(),
                                                message: format!("User is not an active member of vault {vid}"),
                                                request_id: Some(request_id.clone()),
                                            };
                                            if let Ok(json) = serde_json::to_string(&err_msg) {
                                                let _ = socket.send(Message::Text(json)).await;
                                            }
                                            error_occurred = true;
                                            break;
                                        }
                                    }
                                }

                                if !error_occurred {
                                    subscribed_vaults.extend(watermarks.iter().map(|watermark| watermark.vault_id));
                                    let conf = WsServerMessage::Subscribed {
                                        request_id,
                                        vaults: watermarks,
                                    };
                                    if let Ok(json) = serde_json::to_string(&conf) {
                                        if socket.send(Message::Text(json)).await.is_err() {
                                            break;
                                        }
                                    }
                                }
                            }
                            Ok(WsClientMessage::Unsubscribe { request_id: _, vault_ids }) => {
                                for vid in vault_ids {
                                    subscribed_vaults.remove(&vid);
                                }
                            }
                            Ok(WsClientMessage::Ping) => {
                                let pong = WsServerMessage::Pong;
                                if let Ok(json) = serde_json::to_string(&pong) {
                                    if socket.send(Message::Text(json)).await.is_err() {
                                        break;
                                    }
                                }
                            }
                            Err(_) => {
                                let err_msg = WsServerMessage::Error {
                                    code: "INVALID_MESSAGE".to_string(),
                                    message: "Malformed WebSocket message payload".to_string(),
                                    request_id: None,
                                };
                                if let Ok(json) = serde_json::to_string(&err_msg) {
                                    let _ = socket.send(Message::Text(json)).await;
                                }
                            }
                        }
                    }
                    Some(Ok(Message::Ping(payload))) => {
                        if socket.send(Message::Pong(payload)).await.is_err() {
                            break;
                        }
                    }
                    Some(Ok(Message::Pong(_))) => {}
                    Some(Ok(Message::Close(_))) | None => {
                        break;
                    }
                    Some(Err(_)) => {
                        break;
                    }
                    _ => {}
                }
            }
            event = rx.recv() => {
                if !notification_access_valid(&state, &claims, device_id).await {
                    break;
                }
                match event {
                    Ok(SyncEvent::VaultChanged { vault_id, latest_sequence, notification_id }) => {
                        if subscribed_vaults.contains(&vault_id) {
                            let role = state.auth.store().get_vault_member_role(vault_id, claims.sub).await;
                            if matches!(role, Ok(Some(_))) {
                                let msg = WsServerMessage::VaultChanged {
                                    vault_id,
                                    latest_sequence,
                                    notification_id,
                                };
                                if let Ok(json) = serde_json::to_string(&msg) {
                                    if socket.send(Message::Text(json)).await.is_err() {
                                        break;
                                    }
                                }
                            }
                        }
                    }
                    Ok(SyncEvent::KeyRotated { vault_id, epoch, notification_id }) => {
                        if subscribed_vaults.contains(&vault_id) {
                            let role = state.auth.store().get_vault_member_role(vault_id, claims.sub).await;
                            if matches!(role, Ok(Some(_))) {
                                let msg = WsServerMessage::VaultKeyRotated {
                                    vault_id,
                                    epoch,
                                    notification_id,
                                };
                                if let Ok(json) = serde_json::to_string(&msg) {
                                    if socket.send(Message::Text(json)).await.is_err() {
                                        break;
                                    }
                                }
                            }
                        }
                    }
                    Ok(SyncEvent::AccessRevoked {
                        vault_id,
                        user_id,
                        notification_id,
                    }) => {
                        if subscribed_vaults.contains(&vault_id)
                            && (user_id.is_none() || user_id == Some(claims.sub))
                        {
                            subscribed_vaults.remove(&vault_id);
                            let msg = WsServerMessage::VaultAccessRevoked {
                                vault_id,
                                notification_id,
                            };
                            if let Ok(json) = serde_json::to_string(&msg) {
                                if socket.send(Message::Text(json)).await.is_err() {
                                    break;
                                }
                            }
                        }
                    }
                    Ok(SyncEvent::Logout(user_id)) => {
                        if user_id == claims.sub {
                            break;
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(_)) => {
                        let err_msg = WsServerMessage::Error {
                            code: "RESYNC_REQUIRED".to_string(),
                            message: "Notification queue lagged, please re-synchronize vaults".to_string(),
                            request_id: None,
                        };
                        if let Ok(json) = serde_json::to_string(&err_msg) {
                            let _ = socket.send(Message::Text(json)).await;
                        }
                    }
                    Err(broadcast::error::RecvError::Closed) => {
                        break;
                    }
                }
            }
        }
    }
}

async fn list_vaults_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let claims = match extract_auth_claims(&state.auth, &headers).await {
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
    let claims = match extract_auth_claims(&state.auth, &headers).await {
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
    let claims = match extract_auth_claims(&state.auth, &headers).await {
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
    let claims = match extract_auth_claims(&state.auth, &headers).await {
        Ok(c) => c,
        Err(err) => {
            let (status, err_resp) = map_domain_error(err);
            return (status, Json(serde_json::to_value(err_resp.0).unwrap()));
        }
    };

    match state.sync.update_vault(claims.sub, vault_id, req).await {
        Ok(resp) => {
            let notif_id = Uuid::new_v4();
            state
                .broadcast_sync_event(SyncEvent::VaultChanged {
                    vault_id,
                    latest_sequence: resp.server_sequence,
                    notification_id: notif_id,
                })
                .await;
            (StatusCode::OK, Json(serde_json::to_value(resp).unwrap()))
        }
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
    let claims = match extract_auth_claims(&state.auth, &headers).await {
        Ok(c) => c,
        Err(err) => {
            let (status, err_resp) = map_domain_error(err);
            return (status, Json(serde_json::to_value(err_resp.0).unwrap()));
        }
    };

    match state.sync.delete_vault(claims.sub, vault_id).await {
        Ok(()) => {
            let notif_id = Uuid::new_v4();
            state
                .broadcast_sync_event(SyncEvent::AccessRevoked {
                    vault_id,
                    user_id: None,
                    notification_id: notif_id,
                })
                .await;
            (
                StatusCode::OK,
                Json(serde_json::json!({ "status": "deleted" })),
            )
        }
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
    let claims = match extract_auth_claims(&state.auth, &headers).await {
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
        Ok(resp) => {
            let notif_id = Uuid::new_v4();
            state
                .broadcast_sync_event(SyncEvent::VaultChanged {
                    vault_id: path_vault_id,
                    latest_sequence: resp.commit_sequence,
                    notification_id: notif_id,
                })
                .await;
            (StatusCode::OK, Json(serde_json::to_value(resp).unwrap()))
        }
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
    let claims = match extract_auth_claims(&state.auth, &headers).await {
        Ok(c) => c,
        Err(err) => {
            let (status, err_resp) = map_domain_error(err);
            return (status, Json(serde_json::to_value(err_resp.0).unwrap()));
        }
    };

    let since_seq = if let Some(cursor_str) = query.cursor {
        if let Some(seq_part) = cursor_str.strip_prefix("seq:") {
            match seq_part.parse::<u64>() {
                Ok(s) => s,
                Err(_) => {
                    let err = DomainError::InvalidCursor(format!(
                        "Malformed sequence number in cursor: '{seq_part}'"
                    ));
                    let (status, err_resp) = map_domain_error(err);
                    return (status, Json(serde_json::to_value(err_resp.0).unwrap()));
                }
            }
        } else {
            let err =
                DomainError::InvalidCursor("Cursor must start with 'seq:' prefix".to_string());
            let (status, err_resp) = map_domain_error(err);
            return (status, Json(serde_json::to_value(err_resp.0).unwrap()));
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
    Path(vault_id): Path<Uuid>,
) -> impl IntoResponse {
    let claims = match extract_auth_claims(&state.auth, &headers).await {
        Ok(c) => c,
        Err(err) => {
            let (status, err_resp) = map_domain_error(err);
            return (status, Json(serde_json::to_value(err_resp.0).unwrap()));
        }
    };

    match state.sync.get_snapshot(claims.sub, vault_id, None).await {
        Ok(resp) => (StatusCode::OK, Json(serde_json::to_value(resp).unwrap())),
        Err(err) => {
            let (status, err_resp) = map_domain_error(err);
            (status, Json(serde_json::to_value(err_resp.0).unwrap()))
        }
    }
}

async fn get_snapshot_with_revision_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((vault_id, revision_str)): Path<(Uuid, String)>,
) -> impl IntoResponse {
    let claims = match extract_auth_claims(&state.auth, &headers).await {
        Ok(c) => c,
        Err(err) => {
            let (status, err_resp) = map_domain_error(err);
            return (status, Json(serde_json::to_value(err_resp.0).unwrap()));
        }
    };

    let req_rev = if revision_str == "latest" {
        None
    } else {
        match revision_str.parse::<u64>() {
            Ok(rev) => Some(rev),
            Err(_) => {
                let err = DomainError::InvalidInput(
                    "Snapshot revision must be an integer sequence number or 'latest'".to_string(),
                );
                let (status, err_resp) = map_domain_error(err);
                return (status, Json(serde_json::to_value(err_resp.0).unwrap()));
            }
        }
    };

    match state.sync.get_snapshot(claims.sub, vault_id, req_rev).await {
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
    let claims = match extract_auth_claims(&state.auth, &headers).await {
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
    let claims = match extract_auth_claims(&state.auth, &headers).await {
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
        Ok(resp) => {
            let notif_id = Uuid::new_v4();
            if let Ok(Some(vault)) = state.store.find_vault_by_id(vault_id).await {
                state
                    .broadcast_sync_event(SyncEvent::VaultChanged {
                        vault_id,
                        latest_sequence: vault.server_sequence,
                        notification_id: notif_id,
                    })
                    .await;
            }
            (StatusCode::OK, Json(serde_json::to_value(resp).unwrap()))
        }
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
    let claims = match extract_auth_claims(&state.auth, &headers).await {
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
        Ok(()) => {
            let notif_id = Uuid::new_v4();
            state
                .broadcast_sync_event(SyncEvent::AccessRevoked {
                    vault_id,
                    user_id: Some(target_user_id),
                    notification_id: notif_id,
                })
                .await;
            (StatusCode::NO_CONTENT, Json(serde_json::Value::Null))
        }
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
    let claims = match extract_auth_claims(&state.auth, &headers).await {
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
    let claims = match extract_auth_claims(&state.auth, &headers).await {
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
    let claims = match extract_auth_claims(&state.auth, &headers).await {
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
    let claims = match extract_auth_claims(&state.auth, &headers).await {
        Ok(c) => c,
        Err(err) => {
            let (status, err_resp) = map_domain_error(err);
            return (status, Json(serde_json::to_value(err_resp.0).unwrap())).into_response();
        }
    };

    match state.sync.accept_invite(claims.sub, req).await {
        Ok(resp) => {
            let notif_id = Uuid::new_v4();
            if let Ok(Some(vault)) = state.store.find_vault_by_id(resp.vault_id).await {
                state
                    .broadcast_sync_event(SyncEvent::VaultChanged {
                        vault_id: resp.vault_id,
                        latest_sequence: vault.server_sequence,
                        notification_id: notif_id,
                    })
                    .await;
            }
            (StatusCode::OK, Json(serde_json::to_value(resp).unwrap())).into_response()
        }
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
    let claims = match extract_auth_claims(&state.auth, &headers).await {
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
        Ok(count) => {
            let notif_id = Uuid::new_v4();
            if let Ok(Some(vault)) = state.store.find_vault_by_id(vault_id).await {
                state
                    .broadcast_sync_event(SyncEvent::VaultChanged {
                        vault_id,
                        latest_sequence: vault.server_sequence,
                        notification_id: notif_id,
                    })
                    .await;
            }
            (
                StatusCode::CREATED,
                Json(serde_json::json!({ "published": count })),
            )
        }
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
    let claims = match extract_auth_claims(&state.auth, &headers).await {
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
    let claims = match extract_auth_claims(&state.auth, &headers).await {
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
        Ok(resp) => {
            let notif_id = Uuid::new_v4();
            state
                .broadcast_sync_event(SyncEvent::KeyRotated {
                    vault_id,
                    epoch: resp.active_key_epoch,
                    notification_id: notif_id,
                })
                .await;
            (StatusCode::OK, Json(serde_json::to_value(resp).unwrap()))
        }
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
    let claims = match extract_auth_claims(&state.auth, &headers).await {
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

// ---------------------------------------------------------------------------
// Live Terminal Collaboration Handlers (Milestone M5)
// ---------------------------------------------------------------------------

fn check_collab_enabled(state: &AppState) -> Result<(), DomainError> {
    if !state.config.collab_enabled {
        return Err(DomainError::CollabDisabled);
    }
    Ok(())
}

async fn create_collab_session_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<CreateCollabSessionRequest>,
) -> impl IntoResponse {
    if let Err(err) = check_collab_enabled(&state) {
        let (status, err_resp) = map_domain_error(err);
        return (status, Json(serde_json::to_value(err_resp.0).unwrap()));
    }

    let claims = match extract_auth_claims(&state.auth, &headers).await {
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

    let now = chrono::Utc::now().timestamp();
    match state
        .collab
        .create_session(claims.sub, device_id, req, now)
        .await
    {
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

async fn list_collab_sessions_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Err(err) = check_collab_enabled(&state) {
        let (status, err_resp) = map_domain_error(err);
        return (status, Json(serde_json::to_value(err_resp.0).unwrap()));
    }

    let claims = match extract_auth_claims(&state.auth, &headers).await {
        Ok(c) => c,
        Err(err) => {
            let (status, err_resp) = map_domain_error(err);
            return (status, Json(serde_json::to_value(err_resp.0).unwrap()));
        }
    };

    match state.collab.list_active_sessions(claims.sub).await {
        Ok(sessions) => (
            StatusCode::OK,
            Json(serde_json::to_value(CollabSessionListResponse { sessions }).unwrap()),
        ),
        Err(err) => {
            let (status, err_resp) = map_domain_error(err);
            (status, Json(serde_json::to_value(err_resp.0).unwrap()))
        }
    }
}

async fn get_collab_session_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(session_id): Path<Uuid>,
) -> impl IntoResponse {
    if let Err(err) = check_collab_enabled(&state) {
        let (status, err_resp) = map_domain_error(err);
        return (status, Json(serde_json::to_value(err_resp.0).unwrap()));
    }

    let claims = match extract_auth_claims(&state.auth, &headers).await {
        Ok(c) => c,
        Err(err) => {
            let (status, err_resp) = map_domain_error(err);
            return (status, Json(serde_json::to_value(err_resp.0).unwrap()));
        }
    };

    match state.collab.get_session(session_id, claims.sub).await {
        Ok(resp) => (StatusCode::OK, Json(serde_json::to_value(resp).unwrap())),
        Err(err) => {
            let (status, err_resp) = map_domain_error(err);
            (status, Json(serde_json::to_value(err_resp.0).unwrap()))
        }
    }
}

async fn enroll_collab_participant_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(session_id): Path<Uuid>,
    Json(req): Json<EnrollParticipantRequest>,
) -> impl IntoResponse {
    if let Err(err) = check_collab_enabled(&state) {
        let (status, err_resp) = map_domain_error(err);
        return (status, Json(serde_json::to_value(err_resp.0).unwrap()));
    }

    let claims = match extract_auth_claims(&state.auth, &headers).await {
        Ok(c) => c,
        Err(err) => {
            let (status, err_resp) = map_domain_error(err);
            return (status, Json(serde_json::to_value(err_resp.0).unwrap()));
        }
    };

    let now = chrono::Utc::now().timestamp();
    match state
        .collab
        .enroll_participant(session_id, claims.sub, req, now)
        .await
    {
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

async fn list_collab_participants_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(session_id): Path<Uuid>,
) -> impl IntoResponse {
    if let Err(err) = check_collab_enabled(&state) {
        let (status, err_resp) = map_domain_error(err);
        return (status, Json(serde_json::to_value(err_resp.0).unwrap()));
    }

    let claims = match extract_auth_claims(&state.auth, &headers).await {
        Ok(c) => c,
        Err(err) => {
            let (status, err_resp) = map_domain_error(err);
            return (status, Json(serde_json::to_value(err_resp.0).unwrap()));
        }
    };

    match state.collab.list_participants(session_id, claims.sub).await {
        Ok(participants) => (
            StatusCode::OK,
            Json(serde_json::to_value(CollabParticipantListResponse { participants }).unwrap()),
        ),
        Err(err) => {
            let (status, err_resp) = map_domain_error(err);
            (status, Json(serde_json::to_value(err_resp.0).unwrap()))
        }
    }
}

async fn grant_collab_control_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(session_id): Path<Uuid>,
    Json(req): Json<GrantControlRequest>,
) -> impl IntoResponse {
    if let Err(err) = check_collab_enabled(&state) {
        let (status, err_resp) = map_domain_error(err);
        return (status, Json(serde_json::to_value(err_resp.0).unwrap()));
    }

    let claims = match extract_auth_claims(&state.auth, &headers).await {
        Ok(c) => c,
        Err(err) => {
            let (status, err_resp) = map_domain_error(err);
            return (status, Json(serde_json::to_value(err_resp.0).unwrap()));
        }
    };

    let now = chrono::Utc::now().timestamp();
    match state
        .collab
        .grant_control(session_id, claims.sub, req, now)
        .await
    {
        Ok(resp) => (StatusCode::OK, Json(serde_json::to_value(resp).unwrap())),
        Err(err) => {
            let (status, err_resp) = map_domain_error(err);
            (status, Json(serde_json::to_value(err_resp.0).unwrap()))
        }
    }
}

async fn revoke_collab_control_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(session_id): Path<Uuid>,
) -> impl IntoResponse {
    if let Err(err) = check_collab_enabled(&state) {
        let (status, err_resp) = map_domain_error(err);
        return (status, Json(serde_json::to_value(err_resp.0).unwrap()));
    }

    let claims = match extract_auth_claims(&state.auth, &headers).await {
        Ok(c) => c,
        Err(err) => {
            let (status, err_resp) = map_domain_error(err);
            return (status, Json(serde_json::to_value(err_resp.0).unwrap()));
        }
    };

    let now = chrono::Utc::now().timestamp();
    match state
        .collab
        .revoke_control(session_id, claims.sub, now)
        .await
    {
        Ok(resp) => (StatusCode::OK, Json(serde_json::to_value(resp).unwrap())),
        Err(err) => {
            let (status, err_resp) = map_domain_error(err);
            (status, Json(serde_json::to_value(err_resp.0).unwrap()))
        }
    }
}

async fn terminate_collab_session_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(session_id): Path<Uuid>,
) -> impl IntoResponse {
    if let Err(err) = check_collab_enabled(&state) {
        let (status, err_resp) = map_domain_error(err);
        return (status, Json(serde_json::to_value(err_resp.0).unwrap()));
    }

    let claims = match extract_auth_claims(&state.auth, &headers).await {
        Ok(c) => c,
        Err(err) => {
            let (status, err_resp) = map_domain_error(err);
            return (status, Json(serde_json::to_value(err_resp.0).unwrap()));
        }
    };

    let now = chrono::Utc::now().timestamp();
    match state
        .collab
        .terminate_session(session_id, claims.sub, now)
        .await
    {
        Ok(()) => (
            StatusCode::OK,
            Json(serde_json::json!({ "status": "terminated" })),
        ),
        Err(err) => {
            let (status, err_resp) = map_domain_error(err);
            (status, Json(serde_json::to_value(err_resp.0).unwrap()))
        }
    }
}

async fn send_collab_frame_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(session_id): Path<Uuid>,
    Json(req): Json<SendCollabFrameRequest>,
) -> impl IntoResponse {
    if let Err(err) = check_collab_enabled(&state) {
        let (status, err_resp) = map_domain_error(err);
        return (status, Json(serde_json::to_value(err_resp.0).unwrap()));
    }

    let claims = match extract_auth_claims(&state.auth, &headers).await {
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

    let now = chrono::Utc::now().timestamp();
    match state
        .collab
        .send_frame(session_id, claims.sub, device_id, req, now)
        .await
    {
        Ok(frame) => (
            StatusCode::CREATED,
            Json(serde_json::to_value(frame).unwrap()),
        ),
        Err(err) => {
            let (status, err_resp) = map_domain_error(err);
            (status, Json(serde_json::to_value(err_resp.0).unwrap()))
        }
    }
}

async fn poll_collab_frames_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(session_id): Path<Uuid>,
    Query(query): Query<CollabPollQuery>,
) -> impl IntoResponse {
    if let Err(err) = check_collab_enabled(&state) {
        let (status, err_resp) = map_domain_error(err);
        return (status, Json(serde_json::to_value(err_resp.0).unwrap()));
    }

    let claims = match extract_auth_claims(&state.auth, &headers).await {
        Ok(c) => c,
        Err(err) => {
            let (status, err_resp) = map_domain_error(err);
            return (status, Json(serde_json::to_value(err_resp.0).unwrap()));
        }
    };

    let since = query.since_sequence.unwrap_or(0);
    let limit = query.limit.unwrap_or(50);

    match state
        .collab
        .poll_frames(session_id, claims.sub, since, limit)
        .await
    {
        Ok(frames) => {
            let latest_sequence = frames.last().map(|f| f.sequence).unwrap_or(since);
            (
                StatusCode::OK,
                Json(
                    serde_json::to_value(CollabPollResponse {
                        frames,
                        latest_sequence,
                    })
                    .unwrap(),
                ),
            )
        }
        Err(err) => {
            let (status, err_resp) = map_domain_error(err);
            (status, Json(serde_json::to_value(err_resp.0).unwrap()))
        }
    }
}

async fn collab_events_sse_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(session_id): Path<Uuid>,
) -> Response {
    if let Err(err) = check_collab_enabled(&state) {
        let (status, err_resp) = map_domain_error(err);
        return (status, Json(serde_json::to_value(err_resp.0).unwrap())).into_response();
    }

    let claims = match extract_auth_claims(&state.auth, &headers).await {
        Ok(c) => c,
        Err(err) => {
            let (status, err_resp) = map_domain_error(err);
            return (status, Json(serde_json::to_value(err_resp.0).unwrap())).into_response();
        }
    };

    let rx = match state.collab.subscribe(session_id, claims.sub).await {
        Ok(r) => r,
        Err(err) => {
            let (status, err_resp) = map_domain_error(err);
            return (status, Json(serde_json::to_value(err_resp.0).unwrap())).into_response();
        }
    };

    use futures_util::StreamExt;
    let stream = into_collab_stream(rx).filter_map(|item| async move {
        match item {
            Ok(frame) => {
                let data = serde_json::to_string(&frame).unwrap_or_default();
                let event = axum::response::sse::Event::default()
                    .event(frame.frame_type.as_str())
                    .data(data);
                Some(Ok::<_, std::convert::Infallible>(event))
            }
            Err(_) => None,
        }
    });

    axum::response::sse::Sse::new(stream)
        .keep_alive(axum::response::sse::KeepAlive::default())
        .into_response()
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

async fn extract_auth_claims(
    auth: &AuthService<AnyStore>,
    headers: &HeaderMap,
) -> Result<AccessTokenClaims, DomainError> {
    let auth_header = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .ok_or(DomainError::Unauthenticated)?;

    let token = auth_header
        .strip_prefix("Bearer ")
        .ok_or_else(|| DomainError::InvalidToken("Expected Bearer token".to_string()))?;

    let claims = auth.verify_token(token.trim())?;

    let header_device_id = headers
        .get("x-device-id")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| Uuid::parse_str(v).ok());

    if let (Some(token_dev), Some(req_dev)) = (claims.device_id, header_device_id) {
        if token_dev != req_dev {
            return Err(DomainError::PermissionDenied(
                "Device mismatch between token and request".to_string(),
            ));
        }
    }

    let check_device = header_device_id.or(claims.device_id);
    auth.validate_active_session(&claims, check_device).await?;

    Ok(claims)
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
        DomainError::FutureKeyEpoch { .. } => (StatusCode::CONFLICT, "FUTURE_KEY_EPOCH"),
        DomainError::InvalidCursor(_) => (StatusCode::BAD_REQUEST, "INVALID_CURSOR"),
        DomainError::CursorExpired => (StatusCode::GONE, "CURSOR_EXPIRED"),
        DomainError::ChallengeExpired => (StatusCode::GONE, "CHALLENGE_EXPIRED"),
        DomainError::InvalidChallenge => (StatusCode::FORBIDDEN, "INVALID_CHALLENGE"),
        DomainError::UnsupportedSuite(_) => (StatusCode::UNPROCESSABLE_ENTITY, "UNSUPPORTED_SUITE"),
        DomainError::InvalidEnvelope(_) => (StatusCode::UNPROCESSABLE_ENTITY, "INVALID_ENVELOPE"),
        DomainError::MembershipRevoked => (StatusCode::FORBIDDEN, "MEMBERSHIP_REVOKED"),
        DomainError::InvalidInput(_) | DomainError::InvalidPublicKey(_) => {
            (StatusCode::UNPROCESSABLE_ENTITY, "INVALID_INPUT")
        }
        DomainError::PayloadTooLarge { .. } => (StatusCode::PAYLOAD_TOO_LARGE, "PAYLOAD_TOO_LARGE"),
        DomainError::CollabDisabled => (StatusCode::FORBIDDEN, "COLLAB_DISABLED"),
        DomainError::CollabSessionNotFound(_) => {
            (StatusCode::NOT_FOUND, "COLLAB_SESSION_NOT_FOUND")
        }
        DomainError::CollabSessionExpired => (StatusCode::GONE, "COLLAB_SESSION_EXPIRED"),
        DomainError::CollabSessionTerminated => (StatusCode::GONE, "COLLAB_SESSION_TERMINATED"),
        DomainError::NotAuthorizedWriter => (StatusCode::FORBIDDEN, "NOT_AUTHORIZED_WRITER"),
        DomainError::StaleLeaseToken { .. } => (StatusCode::CONFLICT, "STALE_LEASE_TOKEN"),
        DomainError::ParticipantRevoked => (StatusCode::FORBIDDEN, "PARTICIPANT_REVOKED"),
        DomainError::NotSessionHost => (StatusCode::FORBIDDEN, "NOT_SESSION_HOST"),
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

pub async fn run(mut config: ServerConfig) -> Result<(), Box<dyn std::error::Error>> {
    let store = if let Some(ref db_url) = config.database_url {
        info!("Connecting to PostgreSQL database...");
        let pg = PgStore::connect(db_url).await?;
        info!("Applying database migrations...");
        pg.run_migrations().await?;
        info!("PostgreSQL database migrations applied successfully.");
        AnyStore::postgres(pg)
    } else {
        info!("No database URL configured; running with in-memory store.");
        AnyStore::memory()
    };

    // Persist server identity and token signing key across restarts
    if config.token_signing_key.is_none() {
        let (install_id, key_bytes) = store.get_or_init_server_keys().await?;
        config.server_instance_id = install_id;
        config.token_signing_key = Some(hex::encode(&key_bytes));
        info!("Loaded persistent server identity: {}", install_id);
    }

    let listen_addr = config.listen_addr;
    let app = create_router_with_store(config, store);

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
