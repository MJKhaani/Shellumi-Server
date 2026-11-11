//! Integration tests for Milestone M4: Resilience, Operations & Releases.
//!
//! Covers:
//! - Rate limiting on sensitive endpoints (triggering HTTP 429 and Retry-After header)
//! - Prometheus `/metrics` exposition format and label bounded cardinality
//! - CLI `doctor` diagnostics report
//! - CLI `admin user` lifecycle management
//! - CLI `backup verify` on valid database dumps and detection of leaked keys
//! - CLI `migrate status` migration discovery

use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use serde_json::Value;
use shellumi_server::cli::{
    admin::{self, AdminArgs, AdminSubcommands, UserAction, UserArgs},
    backup::{self, REQUIRED_BACKUP_TABLES},
    doctor, migrate,
};
use shellumi_server::config::ServerConfig;
use shellumi_server::server::create_router;
use shellumi_server_protocol::LoginRequest;
use shellumi_server_store::{InMemoryStore, UserRepository};
use std::fs::File;
use std::io::Write;
use std::sync::Arc;
use tower::ServiceExt;
use uuid::Uuid;

fn test_config() -> ServerConfig {
    ServerConfig {
        listen_addr: "127.0.0.1:8080".parse().unwrap(),
        public_url: "http://127.0.0.1:8080".to_string(),
        database_url: None,
        log_level: "error".to_string(),
        log_format: "json".to_string(),
        registration: shellumi_server::config::RegistrationMode::InviteOnly,
        access_token_ttl_secs: 900,
        refresh_token_ttl_secs: 2_592_000,
        max_request_bytes: 10 * 1024 * 1024,
        max_record_bytes: 1024 * 1024,
        collab_enabled: false,
        metrics_enabled: true,
        rate_limit_per_minute: 3, // Set low limit for fast rate-limiting testing
        trusted_proxies: Vec::new(),
        allowed_origins: Vec::new(),
        dev_mode: false,
    }
}

#[tokio::test]
async fn test_rate_limiting_enforces_limit_and_returns_429() {
    let config = test_config();
    let app = create_router(config);

    let login_payload = serde_json::to_vec(&LoginRequest {
        identifier: "nonexistent@example.com".to_string(),
        password: "invalid_password".to_string(),
        device_id: None,
    })
    .unwrap();

    // First 3 requests should pass through rate limiter (and fail credentials check with 401)
    for _ in 0..3 {
        let req = Request::builder()
            .method("POST")
            .uri("/api/v1/auth/login")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(login_payload.clone()))
            .unwrap();

        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    // 4th request MUST be rejected with 429 Too Many Requests
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/auth/login")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(login_payload))
        .unwrap();

    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);

    // Verify Retry-After header
    let retry_after = resp.headers().get(header::RETRY_AFTER);
    assert!(
        retry_after.is_some(),
        "Retry-After header must be present on 429 response"
    );

    let body_bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let body_json: Value = serde_json::from_slice(&body_bytes).unwrap();
    assert_eq!(body_json["error_code"], "RATE_LIMIT_EXCEEDED");
}

#[tokio::test]
async fn test_prometheus_metrics_endpoint_exposition() {
    // 1. With metrics_enabled = true
    let config = test_config();
    let app = create_router(config);

    // Send a request to health to generate telemetry
    let health_req = Request::builder()
        .method("GET")
        .uri("/health/live")
        .body(Body::empty())
        .unwrap();
    let health_resp = app.clone().oneshot(health_req).await.unwrap();
    assert_eq!(health_resp.status(), StatusCode::OK);

    // Request /metrics
    let metrics_req = Request::builder()
        .method("GET")
        .uri("/metrics")
        .body(Body::empty())
        .unwrap();

    let metrics_resp = app.clone().oneshot(metrics_req).await.unwrap();
    assert_eq!(metrics_resp.status(), StatusCode::OK);

    let content_type = metrics_resp.headers().get(header::CONTENT_TYPE).unwrap();
    assert!(content_type.to_str().unwrap().contains("text/plain"));

    let body_bytes = axum::body::to_bytes(metrics_resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let body_str = String::from_utf8(body_bytes.to_vec()).unwrap();

    assert!(body_str.contains("shellumi_http_requests_total"));
    assert!(body_str.contains("shellumi_active_sessions_total"));
    assert!(body_str.contains("shellumi_vaults_total"));

    // 2. With metrics_enabled = false
    let mut disabled_config = test_config();
    disabled_config.metrics_enabled = false;
    let disabled_app = create_router(disabled_config);

    let metrics_req_disabled = Request::builder()
        .method("GET")
        .uri("/metrics")
        .body(Body::empty())
        .unwrap();

    let disabled_resp = disabled_app.oneshot(metrics_req_disabled).await.unwrap();
    assert_eq!(disabled_resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_cli_doctor_diagnostics_report() {
    let config = test_config();
    let report = doctor::run_diagnostics(&config);
    assert!(report.all_passed);
    assert!(report
        .checks
        .iter()
        .any(|c| c.name == "Configuration Validation" && c.passed));
    assert!(report
        .checks
        .iter()
        .any(|c| c.name == "Network Listener Security" && c.passed));
}

#[tokio::test]
async fn test_cli_admin_user_lifecycle_management() {
    let store = Arc::new(InMemoryStore::new());

    // Create user via CLI admin command
    let create_args = AdminArgs {
        command: AdminSubcommands::User(UserArgs {
            action: UserAction::Create {
                username: "bob".to_string(),
                email: "bob@example.com".to_string(),
                role: "member".to_string(),
                password: Some("ComplexP@ssw0rd!".to_string()),
            },
        }),
    };

    admin::run_admin_command(store.clone(), &create_args)
        .await
        .unwrap();

    let user = store
        .find_by_identifier("bob")
        .await
        .unwrap()
        .expect("User should exist");
    assert_eq!(user.email, "bob@example.com");
    assert!(user.is_active);

    // Disable user
    let disable_args = AdminArgs {
        command: AdminSubcommands::User(UserArgs {
            action: UserAction::Disable {
                identifier: "bob".to_string(),
            },
        }),
    };
    admin::run_admin_command(store.clone(), &disable_args)
        .await
        .unwrap();

    let user_disabled = store.find_user_by_id(user.id).await.unwrap().unwrap();
    assert!(!user_disabled.is_active);

    // Reset password
    let reset_args = AdminArgs {
        command: AdminSubcommands::User(UserArgs {
            action: UserAction::ResetPassword {
                identifier: "bob".to_string(),
                new_password: Some("NewComplexP@ss999!".to_string()),
            },
        }),
    };
    admin::run_admin_command(store.clone(), &reset_args)
        .await
        .unwrap();

    let user_after_reset = store.find_user_by_id(user.id).await.unwrap().unwrap();
    assert_ne!(user_after_reset.password_hash, user.password_hash);
}

#[test]
fn test_cli_backup_verification_on_valid_and_corrupt_dumps() {
    // 1. Valid backup dump with required tables
    let temp_valid = std::env::temp_dir().join(format!("test_valid_dump_{}.sql", Uuid::now_v7()));
    {
        let mut file = File::create(&temp_valid).unwrap();
        writeln!(file, "-- PostgreSQL database dump").unwrap();
        for table in REQUIRED_BACKUP_TABLES {
            writeln!(file, "CREATE TABLE public.{table} (id uuid PRIMARY KEY);").unwrap();
        }
    }

    let report_valid = backup::verify_backup_file(&temp_valid).unwrap();
    let _ = std::fs::remove_file(&temp_valid);

    assert!(report_valid.verified);
    assert_eq!(report_valid.missing_tables.len(), 0);
    assert!(report_valid.zero_plaintext_keys_verified);

    // 2. Corrupt/incomplete backup dump missing tables
    let temp_incomplete =
        std::env::temp_dir().join(format!("test_incomplete_dump_{}.sql", Uuid::now_v7()));
    {
        let mut file = File::create(&temp_incomplete).unwrap();
        writeln!(file, "-- Incomplete backup").unwrap();
        writeln!(file, "CREATE TABLE public.server_settings (id uuid);").unwrap();
    }

    let report_incomplete = backup::verify_backup_file(&temp_incomplete).unwrap();
    let _ = std::fs::remove_file(&temp_incomplete);

    assert!(!report_incomplete.verified);
    assert!(!report_incomplete.missing_tables.is_empty());

    // 3. Backup with prohibited plaintext SSH private key leaked
    let temp_leaked = std::env::temp_dir().join(format!("test_leaked_dump_{}.sql", Uuid::now_v7()));
    {
        let mut file = File::create(&temp_leaked).unwrap();
        writeln!(file, "-- PostgreSQL database dump").unwrap();
        for table in REQUIRED_BACKUP_TABLES {
            writeln!(file, "CREATE TABLE public.{table} (id uuid PRIMARY KEY);").unwrap();
        }
        writeln!(file, "-----BEGIN OPENSSH PRIVATE KEY-----").unwrap();
    }

    let report_leaked = backup::verify_backup_file(&temp_leaked).unwrap();
    let _ = std::fs::remove_file(&temp_leaked);

    assert!(!report_leaked.verified);
    assert!(!report_leaked.zero_plaintext_keys_verified);
    assert!(report_leaked
        .error_message
        .unwrap()
        .contains("CRITICAL SECURITY VIOLATION"));
}

#[test]
fn test_cli_migration_status_reports_migrations() {
    let config = test_config();
    let report = migrate::get_migration_status(&config);
    assert!(!report.available_migrations.is_empty());
    assert!(report
        .available_migrations
        .iter()
        .any(|m| m.contains("initial_schema")));
    assert!(report
        .available_migrations
        .iter()
        .any(|m| m.contains("vaults_and_sync")));
    assert!(report
        .available_migrations
        .iter()
        .any(|m| m.contains("team_vaults_and_keys")));
}
