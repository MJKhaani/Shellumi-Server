use shellumi_server_domain::{Organization, Session, User};
use shellumi_server_store::{PgStore, SettingsRepository, UserRepository};
use uuid::Uuid;

fn bootstrap_data(name: &str) -> (User, Organization, Session) {
    let user = User {
        id: Uuid::new_v4(),
        username: name.into(),
        email: format!("{name}@example.com"),
        password_hash: "test-verifier".into(),
        created_at: 1,
        updated_at: 1,
        is_active: true,
    };
    let org = Organization {
        id: Uuid::new_v4(),
        name: name.into(),
        created_at: 1,
    };
    let session = Session {
        id: Uuid::new_v4(),
        user_id: user.id,
        device_id: None,
        refresh_token_hash: name.into(),
        expires_at: 100,
        created_at: 1,
        revoked_at: None,
    };
    (user, org, session)
}

#[tokio::test]
async fn fresh_database_bootstrap_is_atomic_and_single_use() {
    let Ok(url) = std::env::var("SHELLUMI_TEST_DATABASE_URL") else {
        eprintln!("PostgreSQL acceptance skipped: SHELLUMI_TEST_DATABASE_URL is unset");
        return;
    };
    let store = PgStore::connect(&url).await.unwrap();
    store.run_migrations().await.unwrap();
    let mut settings = store.get_settings().await.unwrap();
    settings.bootstrap_token_hash = Some("expected-hash".into());
    store.update_settings(&settings).await.unwrap();
    let (a, oa, sa) = bootstrap_data("first");
    assert!(store.complete_bootstrap(None, &a, &oa, &sa).await.is_err());
    assert!(store
        .complete_bootstrap(Some("wrong"), &a, &oa, &sa)
        .await
        .is_err());
    let (b, ob, sb) = bootstrap_data("second");
    let (r1, r2) = tokio::join!(
        store.complete_bootstrap(Some("expected-hash"), &a, &oa, &sa),
        store.complete_bootstrap(Some("expected-hash"), &b, &ob, &sb)
    );
    assert_ne!(
        r1.is_ok(),
        r2.is_ok(),
        "exactly one bootstrap must succeed: {r1:?}, {r2:?}"
    );
    let users = store.list_users().await.unwrap();
    assert_eq!(users.len(), 1);
    let first = store.get_or_init_server_keys().await.unwrap();
    let reopened = PgStore::connect(&url).await.unwrap();
    assert_eq!(first, reopened.get_or_init_server_keys().await.unwrap());
    assert!(reopened
        .complete_bootstrap(None, &a, &oa, &sa)
        .await
        .is_err());
}

#[tokio::test]
async fn singleton_migration_preserves_existing_settings_and_rejects_duplicates() {
    let Ok(url) = std::env::var("SHELLUMI_TEST_DATABASE_URL") else {
        eprintln!("PostgreSQL acceptance skipped: SHELLUMI_TEST_DATABASE_URL is unset");
        return;
    };
    let store = PgStore::connect(&url).await.unwrap();
    for duplicate in [false, true] {
        let mut tx = store.pool().begin().await.unwrap();
        let schema = format!("upgrade_{}", Uuid::new_v4().simple());
        sqlx::query(&format!("CREATE SCHEMA {schema}"))
            .execute(&mut *tx)
            .await
            .unwrap();
        sqlx::query(&format!("SET LOCAL search_path TO {schema}"))
            .execute(&mut *tx)
            .await
            .unwrap();
        sqlx::raw_sql(include_str!(
            "../../../migrations/20261111000001_initial_schema.sql"
        ))
        .execute(&mut *tx)
        .await
        .unwrap();
        let install = Uuid::new_v4();
        sqlx::query("INSERT INTO server_settings (id, install_id, bootstrap_consumed, created_at, updated_at) VALUES ($1, $2, true, 1, 1)")
            .bind(Uuid::new_v4()).bind(install).execute(&mut *tx).await.unwrap();
        if duplicate {
            sqlx::query("INSERT INTO server_settings (id, install_id, created_at, updated_at) VALUES ($1, $2, 1, 1)")
                .bind(Uuid::new_v4()).bind(Uuid::new_v4()).execute(&mut *tx).await.unwrap();
        }
        let result = sqlx::raw_sql(include_str!(
            "../../../migrations/20261116000002_persistent_install_keys.sql"
        ))
        .execute(&mut *tx)
        .await;
        if duplicate {
            assert!(result.is_err());
        } else {
            result.unwrap();
            let row: (Uuid, bool) =
                sqlx::query_as("SELECT install_id, bootstrap_consumed FROM server_settings")
                    .fetch_one(&mut *tx)
                    .await
                    .unwrap();
            assert_eq!(row, (install, true));
        }
        tx.rollback().await.unwrap();
    }
}
