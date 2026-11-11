//! Administrative command-line utilities (`shellumi-server admin`).

use clap::{Args, Subcommand};
use shellumi_server_auth::hash_password;
use shellumi_server_domain::{DomainError, OrgRole, Organization, User};
use shellumi_server_store::Store;
use std::sync::Arc;
use uuid::Uuid;

#[derive(Debug, Args, Clone)]
pub struct AdminArgs {
    #[command(subcommand)]
    pub command: AdminSubcommands,
}

#[derive(Debug, Subcommand, Clone)]
pub enum AdminSubcommands {
    /// Initial bootstrap utilities
    Bootstrap,
    /// Manage user accounts
    User(UserArgs),
    /// Manage authenticated sessions
    Session(SessionArgs),
}

#[derive(Debug, Args, Clone)]
pub struct UserArgs {
    #[command(subcommand)]
    pub action: UserAction,
}

#[derive(Debug, Subcommand, Clone)]
pub enum UserAction {
    /// Create a new user account
    Create {
        #[arg(long)]
        username: String,
        #[arg(long)]
        email: String,
        #[arg(long, default_value = "member")]
        role: String,
        #[arg(long)]
        password: Option<String>,
    },
    /// Disable a user account
    Disable {
        #[arg(long)]
        identifier: String,
    },
    /// Enable a user account
    Enable {
        #[arg(long)]
        identifier: String,
    },
    /// Reset a user's password
    ResetPassword {
        #[arg(long)]
        identifier: String,
        #[arg(long)]
        new_password: Option<String>,
    },
    /// List all registered users
    List,
}

#[derive(Debug, Args, Clone)]
pub struct SessionArgs {
    #[command(subcommand)]
    pub action: SessionAction,
}

#[derive(Debug, Subcommand, Clone)]
pub enum SessionAction {
    /// List active sessions for a user
    List {
        #[arg(long)]
        user_id: Uuid,
    },
    /// Revoke a specific session
    Revoke {
        #[arg(long)]
        session_id: Uuid,
    },
    /// Revoke all active sessions for a user
    RevokeAll {
        #[arg(long)]
        user_id: Uuid,
    },
}

/// Executes administrative commands against storage.
pub async fn run_admin_command<S: Store>(
    store: Arc<S>,
    admin_args: &AdminArgs,
) -> Result<(), DomainError> {
    match &admin_args.command {
        AdminSubcommands::Bootstrap => {
            println!("\n=== Shellumi Server Bootstrap Guide ===\n");
            println!("To initialize a fresh server instance:");
            println!("1. Start the server: `shellumi-server serve`");
            println!("2. Submit bootstrap request to: POST /api/v1/bootstrap");
            println!("   Payload: {{ \"organization_name\": \"My Org\", \"admin_email\": \"admin@example.com\", \"admin_username\": \"admin\", \"admin_password\": \"...\" }}");
            println!("\nOnce consumed, bootstrap cannot be repeated.");
            Ok(())
        }
        AdminSubcommands::User(user_args) => handle_user_command(store, &user_args.action).await,
        AdminSubcommands::Session(session_args) => {
            handle_session_command(store, &session_args.action).await
        }
    }
}

async fn handle_user_command<S: Store>(
    store: Arc<S>,
    action: &UserAction,
) -> Result<(), DomainError> {
    match action {
        UserAction::Create {
            username,
            email,
            role,
            password,
        } => {
            let pass = password.clone().unwrap_or_else(|| {
                // In automated or test environments, default or prompt
                "ChangeMe123!".to_string()
            });
            let hashed = hash_password(&pass)?;
            let now = chrono::Utc::now().timestamp();
            let user_id = Uuid::new_v4();

            let user = User {
                id: user_id,
                username: username.clone(),
                email: email.clone(),
                password_hash: hashed,
                created_at: now,
                updated_at: now,
                is_active: true,
            };

            store.create_user(&user).await?;

            // Create default personal organization for user
            let org = Organization {
                id: Uuid::new_v4(),
                name: format!("{username}'s Org"),
                created_at: now,
            };
            store.create_org(&org, user.id).await?;

            let parsed_role = if role.to_lowercase() == "admin" || role.to_lowercase() == "owner" {
                OrgRole::Admin
            } else {
                OrgRole::Member
            };
            store.add_member(org.id, user.id, parsed_role).await?;

            println!("\n[ OK ] Created user '{username}' (ID: {user_id}, Email: {email}, Role: {parsed_role})");
            Ok(())
        }
        UserAction::Disable { identifier } => {
            let user = find_user_by_id_or_identifier(store.clone(), identifier).await?;
            let mut updated = user.clone();
            updated.is_active = false;
            updated.updated_at = chrono::Utc::now().timestamp();
            store.update_user(&updated).await?;

            // Revoke all sessions on account disable
            store.revoke_all_for_user(user.id).await?;

            println!(
                "\n[ OK ] Disabled user '{}' and revoked all active sessions",
                user.username
            );
            Ok(())
        }
        UserAction::Enable { identifier } => {
            let user = find_user_by_id_or_identifier(store.clone(), identifier).await?;
            let mut updated = user.clone();
            updated.is_active = true;
            updated.updated_at = chrono::Utc::now().timestamp();
            store.update_user(&updated).await?;

            println!("\n[ OK ] Enabled user '{}'", user.username);
            Ok(())
        }
        UserAction::ResetPassword {
            identifier,
            new_password,
        } => {
            let user = find_user_by_id_or_identifier(store.clone(), identifier).await?;
            let pass = new_password
                .clone()
                .unwrap_or_else(|| "ChangeMe123!".to_string());
            let hashed = hash_password(&pass)?;

            let mut updated = user.clone();
            updated.password_hash = hashed;
            updated.updated_at = chrono::Utc::now().timestamp();
            store.update_user(&updated).await?;

            // Revoke active sessions on password reset
            store.revoke_all_for_user(user.id).await?;

            println!(
                "\n[ OK ] Reset password for user '{}' and revoked active sessions",
                user.username
            );
            Ok(())
        }
        UserAction::List => {
            let users = store.list_users().await?;
            println!("\n=== Shellumi Server Users ({}) ===\n", users.len());
            println!(
                "{:<38} {:<20} {:<30} {:<8}",
                "USER ID", "USERNAME", "EMAIL", "STATUS"
            );
            println!("{:-<100}", "");
            for u in &users {
                let status = if u.is_active { "ACTIVE" } else { "DISABLED" };
                println!(
                    "{:<38} {:<20} {:<30} {:<8}",
                    u.id, u.username, u.email, status
                );
            }
            println!();
            Ok(())
        }
    }
}

async fn handle_session_command<S: Store>(
    store: Arc<S>,
    action: &SessionAction,
) -> Result<(), DomainError> {
    match action {
        SessionAction::List { user_id } => {
            let sessions = store.list_sessions_for_user(*user_id).await?;
            println!(
                "\n=== Active Sessions for User {user_id} ({}) ===\n",
                sessions.len()
            );
            println!("{:<38} {:<38} {:<10}", "SESSION ID", "DEVICE ID", "STATE");
            println!("{:-<90}", "");
            for s in &sessions {
                let dev_id = s
                    .device_id
                    .map(|d| d.to_string())
                    .unwrap_or_else(|| "N/A".to_string());
                let state = if s.revoked_at.is_some() {
                    "REVOKED"
                } else {
                    "ACTIVE"
                };
                println!("{:<38} {:<38} {:<10}", s.id, dev_id, state);
            }
            println!();
            Ok(())
        }
        SessionAction::Revoke { session_id } => {
            store.revoke_session(*session_id).await?;
            println!("\n[ OK ] Revoked session {session_id}");
            Ok(())
        }
        SessionAction::RevokeAll { user_id } => {
            store.revoke_all_for_user(*user_id).await?;
            println!("\n[ OK ] Revoked all active sessions for user {user_id}");
            Ok(())
        }
    }
}

async fn find_user_by_id_or_identifier<S: Store>(
    store: Arc<S>,
    identifier: &str,
) -> Result<User, DomainError> {
    if let Ok(uid) = Uuid::parse_str(identifier) {
        if let Some(user) = store.find_user_by_id(uid).await? {
            return Ok(user);
        }
    }

    if let Some(user) = store.find_by_identifier(identifier).await? {
        return Ok(user);
    }

    Err(DomainError::NotFound)
}

#[cfg(test)]
mod tests {
    use super::*;
    use shellumi_server_store::{InMemoryStore, UserRepository};

    #[tokio::test]
    async fn test_admin_user_lifecycle() {
        let store = Arc::new(InMemoryStore::new());

        // 1. Create user
        let create_args = AdminArgs {
            command: AdminSubcommands::User(UserArgs {
                action: UserAction::Create {
                    username: "alice".to_string(),
                    email: "alice@example.com".to_string(),
                    role: "admin".to_string(),
                    password: Some("SecureP@ss123".to_string()),
                },
            }),
        };
        run_admin_command(store.clone(), &create_args)
            .await
            .unwrap();

        let users = store.list_users().await.unwrap();
        assert_eq!(users.len(), 1);
        assert_eq!(users[0].username, "alice");
        assert!(users[0].is_active);

        // 2. Disable user
        let disable_args = AdminArgs {
            command: AdminSubcommands::User(UserArgs {
                action: UserAction::Disable {
                    identifier: "alice".to_string(),
                },
            }),
        };
        run_admin_command(store.clone(), &disable_args)
            .await
            .unwrap();

        let alice = store.find_by_identifier("alice").await.unwrap().unwrap();
        assert!(!alice.is_active);

        // 3. Enable user
        let enable_args = AdminArgs {
            command: AdminSubcommands::User(UserArgs {
                action: UserAction::Enable {
                    identifier: alice.id.to_string(),
                },
            }),
        };
        run_admin_command(store.clone(), &enable_args)
            .await
            .unwrap();

        let alice_enabled = store.find_by_identifier("alice").await.unwrap().unwrap();
        assert!(alice_enabled.is_active);
    }
}
