//! Authentication, credential verification, token management, and device security.

use argon2::password_hash::rand_core::OsRng;
use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::Argon2;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use shellumi_server_domain::{Device, DomainError, Organization, Session, User};
use shellumi_server_protocol::{
    BootstrapRequest, BootstrapResponse, DeviceResponse, LoginRequest, LoginResponse,
    LogoutRequest, MeResponse, RefreshTokenRequest, RefreshTokenResponse, RegisterDeviceRequest,
    UserOrgSummary,
};
use shellumi_server_store::Store;
use std::sync::Arc;
use subtle::ConstantTimeEq;
use uuid::Uuid;

/// Claims embedded within a signed bearer access token.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccessTokenClaims {
    pub sub: Uuid,
    pub username: String,
    pub exp: i64,
    pub iat: i64,
}

// ---------------------------------------------------------------------------
// Cryptographic Utility Functions
// ---------------------------------------------------------------------------

/// Hashes a password using Argon2id with memory-hard parameters and secure salt.
pub fn hash_password(password: &str) -> Result<String, DomainError> {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    let hash = argon2
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| DomainError::Internal(format!("Password hashing failed: {e}")))?;
    Ok(hash.to_string())
}

/// Verifies a password against an Argon2id password hash string.
pub fn verify_password(password: &str, password_hash: &str) -> Result<bool, DomainError> {
    let parsed_hash = match PasswordHash::new(password_hash) {
        Ok(h) => h,
        Err(_) => return Ok(false),
    };
    Ok(Argon2::default()
        .verify_password(password.as_bytes(), &parsed_hash)
        .is_ok())
}

/// Generates a cryptographically random 32-byte hex refresh token.
pub fn generate_refresh_token() -> String {
    let mut bytes = [0u8; 32];
    rand::rng().fill_bytes(&mut bytes);
    let mut hex = String::with_capacity(64);
    for b in bytes {
        use std::fmt::Write;
        let _ = write!(&mut hex, "{:02x}", b);
    }
    hex
}

/// Computes the SHA-256 digest of a refresh token to store in the database.
pub fn hash_refresh_token(token: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    let result = hasher.finalize();
    let mut hex = String::with_capacity(64);
    for b in result {
        use std::fmt::Write;
        let _ = write!(&mut hex, "{:02x}", b);
    }
    hex
}

/// Creates a signed HMAC-SHA256 bearer access token.
pub fn create_access_token(
    user_id: Uuid,
    username: &str,
    secret: &[u8],
    ttl_secs: u64,
) -> Result<String, DomainError> {
    let now = chrono::Utc::now().timestamp();
    let exp = now + (ttl_secs as i64);

    let claims = AccessTokenClaims {
        sub: user_id,
        username: username.to_string(),
        exp,
        iat: now,
    };

    let claims_json = serde_json::to_string(&claims)
        .map_err(|e| DomainError::Internal(format!("Failed to serialize claims: {e}")))?;

    let encoded_claims = base64_url_encode(claims_json.as_bytes());

    let mut hasher = Sha256::new();
    hasher.update(secret);
    hasher.update(b".");
    hasher.update(encoded_claims.as_bytes());
    let signature = hasher.finalize();
    let encoded_sig = base64_url_encode(&signature);

    Ok(format!("{encoded_claims}.{encoded_sig}"))
}

/// Verifies a signed HMAC-SHA256 bearer access token and returns its claims.
pub fn verify_access_token(token: &str, secret: &[u8]) -> Result<AccessTokenClaims, DomainError> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 2 {
        return Err(DomainError::InvalidToken("Malformed token".to_string()));
    }

    let encoded_claims = parts[0];
    let encoded_sig = parts[1];

    let mut hasher = Sha256::new();
    hasher.update(secret);
    hasher.update(b".");
    hasher.update(encoded_claims.as_bytes());
    let expected_sig = hasher.finalize();
    let expected_encoded_sig = base64_url_encode(&expected_sig);

    // Constant-time signature comparison to prevent timing attacks
    if encoded_sig
        .as_bytes()
        .ct_eq(expected_encoded_sig.as_bytes())
        .unwrap_u8()
        != 1
    {
        return Err(DomainError::InvalidToken(
            "Invalid token signature".to_string(),
        ));
    }

    let claims_bytes = base64_url_decode(encoded_claims)
        .map_err(|_| DomainError::InvalidToken("Failed to decode token claims".to_string()))?;

    let claims: AccessTokenClaims = serde_json::from_slice(&claims_bytes)
        .map_err(|_| DomainError::InvalidToken("Failed to parse token claims".to_string()))?;

    let now = chrono::Utc::now().timestamp();
    if claims.exp < now {
        return Err(DomainError::TokenExpired);
    }

    Ok(claims)
}

fn base64_url_encode(input: &[u8]) -> String {
    const CHARSET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::new();
    let mut i = 0;
    while i < input.len() {
        let b0 = input[i] as u32;
        let b1 = if i + 1 < input.len() {
            input[i + 1] as u32
        } else {
            0
        };
        let b2 = if i + 2 < input.len() {
            input[i + 2] as u32
        } else {
            0
        };

        let triple = (b0 << 16) | (b1 << 8) | b2;

        out.push(CHARSET[((triple >> 18) & 0x3F) as usize] as char);
        out.push(CHARSET[((triple >> 12) & 0x3F) as usize] as char);

        if i + 1 < input.len() {
            out.push(CHARSET[((triple >> 6) & 0x3F) as usize] as char);
        }
        if i + 2 < input.len() {
            out.push(CHARSET[(triple & 0x3F) as usize] as char);
        }

        i += 3;
    }
    out
}

fn base64_url_decode(input: &str) -> Result<Vec<u8>, ()> {
    fn decode_char(c: u8) -> Result<u32, ()> {
        match c {
            b'A'..=b'Z' => Ok((c - b'A') as u32),
            b'a'..=b'z' => Ok((c - b'a' + 26) as u32),
            b'0'..=b'9' => Ok((c - b'0' + 52) as u32),
            b'-' => Ok(62),
            b'_' => Ok(63),
            _ => Err(()),
        }
    }

    let bytes = input.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;

    while i < bytes.len() {
        let rem = bytes.len() - i;
        let c0 = decode_char(bytes[i])?;
        let c1 = if rem > 1 {
            decode_char(bytes[i + 1])?
        } else {
            0
        };
        let c2 = if rem > 2 {
            decode_char(bytes[i + 2])?
        } else {
            0
        };
        let c3 = if rem > 3 {
            decode_char(bytes[i + 3])?
        } else {
            0
        };

        let triple = (c0 << 18) | (c1 << 12) | (c2 << 6) | c3;

        out.push(((triple >> 16) & 0xFF) as u8);
        if rem > 2 {
            out.push(((triple >> 8) & 0xFF) as u8);
        }
        if rem > 3 {
            out.push((triple & 0xFF) as u8);
        }

        i += 4;
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// AuthService
// ---------------------------------------------------------------------------

pub struct AuthService<S: Store> {
    store: Arc<S>,
    token_secret: Vec<u8>,
    access_token_ttl_secs: u64,
    refresh_token_ttl_secs: u64,
}

impl<S: Store> AuthService<S> {
    pub fn new(
        store: Arc<S>,
        token_secret: Vec<u8>,
        access_token_ttl_secs: u64,
        refresh_token_ttl_secs: u64,
    ) -> Self {
        Self {
            store,
            token_secret,
            access_token_ttl_secs,
            refresh_token_ttl_secs,
        }
    }

    pub fn store(&self) -> &Arc<S> {
        &self.store
    }

    pub fn verify_token(&self, token: &str) -> Result<AccessTokenClaims, DomainError> {
        verify_access_token(token, &self.token_secret)
    }

    /// One-time interactive bootstrap creating the initial organization and admin account.
    pub async fn bootstrap(&self, req: BootstrapRequest) -> Result<BootstrapResponse, DomainError> {
        // Validate inputs
        if req.admin_username.trim().len() < 3 {
            return Err(DomainError::InvalidInput(
                "Username must be at least 3 characters long".to_string(),
            ));
        }
        if !req.admin_email.contains('@') {
            return Err(DomainError::InvalidInput(
                "Invalid email address".to_string(),
            ));
        }
        if req.admin_password.len() < 8 {
            return Err(DomainError::InvalidInput(
                "Password must be at least 8 characters long".to_string(),
            ));
        }
        if req.org_name.trim().is_empty() {
            return Err(DomainError::InvalidInput(
                "Organization name cannot be empty".to_string(),
            ));
        }

        // Verify and mark bootstrap as consumed atomically
        let token_hash = req.bootstrap_token.as_deref().map(hash_refresh_token);
        self.store
            .mark_bootstrap_consumed(token_hash.as_deref())
            .await?;

        let now = chrono::Utc::now().timestamp();
        let user_id = Uuid::new_v4();
        let password_hash = hash_password(&req.admin_password)?;

        let user = User {
            id: user_id,
            username: req.admin_username.clone(),
            email: req.admin_email.clone(),
            password_hash,
            created_at: now,
            updated_at: now,
            is_active: true,
        };
        self.store.create_user(&user).await?;

        let org_id = Uuid::new_v4();
        let org = Organization {
            id: org_id,
            name: req.org_name,
            created_at: now,
        };
        self.store.create_org(&org, user_id).await?;

        // Issue initial access and refresh tokens
        let access_token = create_access_token(
            user_id,
            &user.username,
            &self.token_secret,
            self.access_token_ttl_secs,
        )?;

        let refresh_token = generate_refresh_token();
        let refresh_hash = hash_refresh_token(&refresh_token);

        let session = Session {
            id: Uuid::new_v4(),
            user_id,
            device_id: None,
            refresh_token_hash: refresh_hash,
            expires_at: now + (self.refresh_token_ttl_secs as i64),
            created_at: now,
            revoked_at: None,
        };
        self.store.create_session(&session).await?;

        Ok(BootstrapResponse {
            org_id,
            user_id,
            username: user.username,
            email: user.email,
            access_token,
            refresh_token,
            expires_in_secs: self.access_token_ttl_secs,
        })
    }

    /// Authenticates a user and issues token pair.
    pub async fn login(&self, req: LoginRequest) -> Result<LoginResponse, DomainError> {
        let user = self
            .store
            .find_by_identifier(&req.identifier)
            .await?
            .ok_or(DomainError::InvalidCredentials)?;

        if !user.is_active {
            return Err(DomainError::InvalidCredentials);
        }

        if !verify_password(&req.password, &user.password_hash)? {
            return Err(DomainError::InvalidCredentials);
        }

        // If device_id provided, verify it is not revoked
        if let Some(dev_id) = req.device_id {
            if let Some(dev) = self.store.find_device_by_id(dev_id).await? {
                if dev.user_id != user.id || dev.revoked_at.is_some() {
                    return Err(DomainError::DeviceRevoked);
                }
                self.store
                    .update_last_seen(dev_id, chrono::Utc::now().timestamp())
                    .await?;
            } else {
                return Err(DomainError::DeviceNotFound);
            }
        }

        let now = chrono::Utc::now().timestamp();
        let access_token = create_access_token(
            user.id,
            &user.username,
            &self.token_secret,
            self.access_token_ttl_secs,
        )?;

        let refresh_token = generate_refresh_token();
        let refresh_hash = hash_refresh_token(&refresh_token);

        let session = Session {
            id: Uuid::new_v4(),
            user_id: user.id,
            device_id: req.device_id,
            refresh_token_hash: refresh_hash,
            expires_at: now + (self.refresh_token_ttl_secs as i64),
            created_at: now,
            revoked_at: None,
        };
        self.store.create_session(&session).await?;

        Ok(LoginResponse {
            user_id: user.id,
            username: user.username,
            email: user.email,
            access_token,
            refresh_token,
            expires_in_secs: self.access_token_ttl_secs,
        })
    }

    /// Rotates a refresh token and issues a new access/refresh token pair.
    pub async fn refresh(
        &self,
        req: RefreshTokenRequest,
    ) -> Result<RefreshTokenResponse, DomainError> {
        let old_hash = hash_refresh_token(&req.refresh_token);
        let now = chrono::Utc::now().timestamp();
        let new_refresh_token = generate_refresh_token();
        let new_refresh_hash = hash_refresh_token(&new_refresh_token);

        let mut new_session = Session {
            id: Uuid::new_v4(),
            user_id: Uuid::nil(),
            device_id: None,
            refresh_token_hash: new_refresh_hash,
            expires_at: now + (self.refresh_token_ttl_secs as i64),
            created_at: now,
            revoked_at: None,
        };

        // Atomically rotate token and detect reuse in the store
        let user_id = self
            .store
            .rotate_refresh_token(&old_hash, &mut new_session)
            .await?;

        let user = self
            .store
            .find_user_by_id(user_id)
            .await?
            .ok_or(DomainError::Unauthenticated)?;

        if !user.is_active {
            return Err(DomainError::Unauthenticated);
        }

        let access_token = create_access_token(
            user.id,
            &user.username,
            &self.token_secret,
            self.access_token_ttl_secs,
        )?;

        Ok(RefreshTokenResponse {
            access_token,
            refresh_token: new_refresh_token,
            expires_in_secs: self.access_token_ttl_secs,
        })
    }

    /// Revokes a session / refresh token.
    pub async fn logout(&self, user_id: Uuid, req: LogoutRequest) -> Result<(), DomainError> {
        if let Some(token) = req.refresh_token {
            let hash = hash_refresh_token(&token);
            if let Some(session) = self.store.find_active_by_token_hash(&hash).await? {
                if session.user_id == user_id {
                    self.store.revoke_session(session.id).await?;
                }
            }
        } else {
            self.store.revoke_all_for_user(user_id).await?;
        }
        Ok(())
    }

    /// Retrieves user profile and organization memberships.
    pub async fn get_me(&self, user_id: Uuid) -> Result<MeResponse, DomainError> {
        let user = self
            .store
            .find_user_by_id(user_id)
            .await?
            .ok_or(DomainError::NotFound)?;

        let orgs_tuples = self.store.list_orgs_for_user(user_id).await?;
        let organizations = orgs_tuples
            .into_iter()
            .map(|(org, role)| UserOrgSummary {
                org_id: org.id,
                org_name: org.name,
                role: role.to_string(),
            })
            .collect();

        Ok(MeResponse {
            user_id: user.id,
            username: user.username,
            email: user.email,
            organizations,
        })
    }

    /// Registers a client device with signing and agreement keys.
    pub async fn register_device(
        &self,
        user_id: Uuid,
        req: RegisterDeviceRequest,
    ) -> Result<DeviceResponse, DomainError> {
        if req.device_name.trim().is_empty() {
            return Err(DomainError::InvalidInput(
                "Device name cannot be empty".to_string(),
            ));
        }
        if req.signing_public_key.trim().is_empty() {
            return Err(DomainError::InvalidPublicKey(
                "Signing public key cannot be empty".to_string(),
            ));
        }
        if req.agreement_public_key.trim().is_empty() {
            return Err(DomainError::InvalidPublicKey(
                "Agreement public key cannot be empty".to_string(),
            ));
        }

        let now = chrono::Utc::now().timestamp();
        let device_id = Uuid::new_v4();

        let device = Device {
            id: device_id,
            user_id,
            device_name: req.device_name,
            signing_public_key: req.signing_public_key,
            agreement_public_key: req.agreement_public_key,
            created_at: now,
            last_seen_at: Some(now),
            revoked_at: None,
        };

        self.store.create_device(&device).await?;

        Ok(DeviceResponse {
            device_id: device.id,
            user_id: device.user_id,
            device_name: device.device_name,
            signing_public_key: device.signing_public_key,
            agreement_public_key: device.agreement_public_key,
            created_at: device.created_at,
            last_seen_at: device.last_seen_at,
            revoked_at: device.revoked_at,
        })
    }

    /// Lists all registered devices for a user.
    pub async fn list_devices(&self, user_id: Uuid) -> Result<Vec<DeviceResponse>, DomainError> {
        let devices = self.store.list_for_user(user_id).await?;
        let responses = devices
            .into_iter()
            .map(|d| DeviceResponse {
                device_id: d.id,
                user_id: d.user_id,
                device_name: d.device_name,
                signing_public_key: d.signing_public_key,
                agreement_public_key: d.agreement_public_key,
                created_at: d.created_at,
                last_seen_at: d.last_seen_at,
                revoked_at: d.revoked_at,
            })
            .collect();
        Ok(responses)
    }

    /// Revokes a device.
    pub async fn revoke_device(&self, user_id: Uuid, device_id: Uuid) -> Result<(), DomainError> {
        self.store.revoke_device(device_id, user_id).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use shellumi_server_store::{InMemoryStore, UserRepository};

    #[test]
    fn test_argon2id_hash_and_verification() {
        let password = "SuperSecretPassword123!";
        let hash = hash_password(password).unwrap();
        assert!(verify_password(password, &hash).unwrap());
        assert!(!verify_password("WrongPassword!", &hash).unwrap());
    }

    #[test]
    fn test_access_token_creation_and_verification() {
        let user_id = Uuid::new_v4();
        let username = "bob";
        let secret = b"a_very_secure_and_long_secret_key_32bytes";

        let token = create_access_token(user_id, username, secret, 300).unwrap();
        let claims = verify_access_token(&token, secret).unwrap();

        assert_eq!(claims.sub, user_id);
        assert_eq!(claims.username, username);

        // Verification fails with wrong secret
        let wrong_secret = b"wrong_secret_key_here_32bytes_long";
        assert!(verify_access_token(&token, wrong_secret).is_err());
    }

    #[tokio::test]
    async fn test_auth_service_bootstrap_and_login() {
        let store = Arc::new(InMemoryStore::new());
        let secret = b"master_auth_secret_key_1234567890".to_vec();
        let auth = AuthService::new(store.clone(), secret, 900, 2_592_000);

        let bootstrap_req = BootstrapRequest {
            admin_username: "admin".to_string(),
            admin_email: "admin@shellumi.org".to_string(),
            admin_password: "AdminSecurePassword2026!".to_string(),
            org_name: "Shellumi Core".to_string(),
            bootstrap_token: None,
        };

        let res = auth.bootstrap(bootstrap_req.clone()).await.unwrap();
        assert_eq!(res.username, "admin");
        assert_eq!(res.email, "admin@shellumi.org");

        // Second bootstrap must be rejected!
        let err = auth.bootstrap(bootstrap_req).await.unwrap_err();
        match err {
            DomainError::BootstrapAlreadyConsumed => {}
            _ => panic!("Expected BootstrapAlreadyConsumed error"),
        }

        // Login with correct credentials
        let login_req = LoginRequest {
            identifier: "admin".to_string(),
            password: "AdminSecurePassword2026!".to_string(),
            device_id: None,
        };
        let login_res = auth.login(login_req).await.unwrap();
        assert_eq!(login_res.user_id, res.user_id);

        // Login with wrong password
        let bad_login = LoginRequest {
            identifier: "admin".to_string(),
            password: "WrongPassword!".to_string(),
            device_id: None,
        };
        assert!(auth.login(bad_login).await.is_err());
    }

    #[tokio::test]
    async fn test_device_registration_and_revocation() {
        let store = Arc::new(InMemoryStore::new());
        let secret = b"secret_key_for_testing_1234567890".to_vec();
        let auth = AuthService::new(store.clone(), secret, 900, 2_592_000);

        let user_id = Uuid::new_v4();
        let user = User {
            id: user_id,
            username: "carol".to_string(),
            email: "carol@example.com".to_string(),
            password_hash: hash_password("pass12345!").unwrap(),
            created_at: 100,
            updated_at: 100,
            is_active: true,
        };
        store.create_user(&user).await.unwrap();

        let dev_req = RegisterDeviceRequest {
            device_name: "Carol's Laptop".to_string(),
            signing_public_key: "ed25519-public-key-carol".to_string(),
            agreement_public_key: "x25519-public-key-carol".to_string(),
        };

        let device = auth.register_device(user_id, dev_req).await.unwrap();
        assert_eq!(device.device_name, "Carol's Laptop");

        let devices = auth.list_devices(user_id).await.unwrap();
        assert_eq!(devices.len(), 1);

        auth.revoke_device(user_id, device.device_id).await.unwrap();
        let devices = auth.list_devices(user_id).await.unwrap();
        assert!(devices[0].revoked_at.is_some());
    }
}
