//! Cryptographic utilities: canonical signing formats, signature verification, and envelope checks.

use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine;
use ring::rand::SystemRandom;
use ring::signature::{Ed25519KeyPair, KeyPair, UnparsedPublicKey, ED25519};
use sha2::{Digest, Sha256};
use shellumi_server_protocol::EncryptedEnvelope;
use thiserror::Error;
use uuid::Uuid;

pub const SALT_LEN: usize = 16;
pub const NONCE_LEN: usize = 12;
pub const MIN_KDF_ITERATIONS: u32 = 10_000;

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("Invalid base64 encoding: {0}")]
    InvalidBase64(String),

    #[error("Invalid public key length: expected 32 bytes, got {0}")]
    InvalidPublicKeyLength(usize),

    #[error("Invalid signature length: expected 64 bytes, got {0}")]
    InvalidSignatureLength(usize),

    #[error("Signature verification failed: {0}")]
    SignatureVerificationFailed(String),

    #[error("Invalid salt length: expected {SALT_LEN} bytes, got {0}")]
    InvalidSaltLength(usize),

    #[error("Invalid nonce length: expected {NONCE_LEN} bytes, got {0}")]
    InvalidNonceLength(usize),

    #[error("Ciphertext too large: max {max_bytes} bytes, got {actual_bytes} bytes")]
    CiphertextTooLarge {
        max_bytes: usize,
        actual_bytes: usize,
    },

    #[error("KDF iterations too low: minimum {MIN_KDF_ITERATIONS}, got {0}")]
    KdfIterationsTooLow(u32),

    #[error("Key generation failed: {0}")]
    KeyGen(String),
}

/// Generates the canonical UTF-8 preimage string for a mutation signature per ADR 0003.
#[allow(clippy::too_many_arguments)]
pub fn canonical_mutation_preimage(
    vault_id: Uuid,
    object_id: &str,
    entity_type: &str,
    expected_revision: u64,
    deleted: bool,
    key_epoch: u32,
    device_counter: u64,
    ciphertext_digest: &str,
) -> String {
    format!(
        "shellumi-v1-mutation:{}:{}:{}:{}:{}:{}:{}:{}",
        vault_id,
        object_id,
        entity_type,
        expected_revision,
        deleted,
        key_epoch,
        device_counter,
        ciphertext_digest
    )
}

/// Computes a hex-encoded SHA-256 digest of the ciphertext envelope.
/// Returns an empty string for tombstones with no envelope.
pub fn compute_ciphertext_digest(envelope: Option<&EncryptedEnvelope>) -> String {
    match envelope {
        Some(env) => {
            let mut hasher = Sha256::new();
            hasher.update(env.ciphertext.as_bytes());
            hex::encode(hasher.finalize())
        }
        None => String::new(),
    }
}

/// Validates the structure and limits of an `EncryptedEnvelope`.
pub fn validate_envelope(
    envelope: &EncryptedEnvelope,
    max_record_bytes: usize,
) -> Result<(), CryptoError> {
    if envelope.kdf_iterations < MIN_KDF_ITERATIONS {
        return Err(CryptoError::KdfIterationsTooLow(envelope.kdf_iterations));
    }

    let salt_bytes = BASE64_STANDARD
        .decode(&envelope.salt)
        .map_err(|e| CryptoError::InvalidBase64(e.to_string()))?;
    if salt_bytes.len() != SALT_LEN {
        return Err(CryptoError::InvalidSaltLength(salt_bytes.len()));
    }

    let nonce_bytes = BASE64_STANDARD
        .decode(&envelope.nonce)
        .map_err(|e| CryptoError::InvalidBase64(e.to_string()))?;
    if nonce_bytes.len() != NONCE_LEN {
        return Err(CryptoError::InvalidNonceLength(nonce_bytes.len()));
    }

    let ciphertext_bytes = BASE64_STANDARD
        .decode(&envelope.ciphertext)
        .map_err(|e| CryptoError::InvalidBase64(e.to_string()))?;
    if ciphertext_bytes.len() > max_record_bytes {
        return Err(CryptoError::CiphertextTooLarge {
            max_bytes: max_record_bytes,
            actual_bytes: ciphertext_bytes.len(),
        });
    }

    Ok(())
}

/// Verifies a base64-encoded Ed25519 signature against a base64-encoded public key.
pub fn verify_device_signature(
    public_key_b64: &str,
    message: &[u8],
    signature_b64: &str,
) -> Result<(), CryptoError> {
    let pk_bytes = BASE64_STANDARD
        .decode(public_key_b64)
        .map_err(|e| CryptoError::InvalidBase64(e.to_string()))?;
    if pk_bytes.len() != 32 {
        return Err(CryptoError::InvalidPublicKeyLength(pk_bytes.len()));
    }

    let sig_bytes = BASE64_STANDARD
        .decode(signature_b64)
        .map_err(|e| CryptoError::InvalidBase64(e.to_string()))?;
    if sig_bytes.len() != 64 {
        return Err(CryptoError::InvalidSignatureLength(sig_bytes.len()));
    }

    let peer_public_key = UnparsedPublicKey::new(&ED25519, &pk_bytes);
    peer_public_key
        .verify(message, &sig_bytes)
        .map_err(|e| CryptoError::SignatureVerificationFailed(e.to_string()))
}

/// Generates a test Ed25519 keypair and its base64-encoded public key.
pub fn generate_test_ed25519_keypair() -> Result<(Ed25519KeyPair, String), CryptoError> {
    let rng = SystemRandom::new();
    let pkcs8_bytes =
        Ed25519KeyPair::generate_pkcs8(&rng).map_err(|e| CryptoError::KeyGen(e.to_string()))?;
    let key_pair = Ed25519KeyPair::from_pkcs8(pkcs8_bytes.as_ref())
        .map_err(|e| CryptoError::KeyGen(e.to_string()))?;
    let public_key_b64 = BASE64_STANDARD.encode(key_pair.public_key().as_ref());
    Ok((key_pair, public_key_b64))
}

/// Signs a message with an Ed25519 keypair, returning a base64-encoded signature.
pub fn sign_message(keypair: &Ed25519KeyPair, message: &[u8]) -> String {
    let signature = keypair.sign(message);
    BASE64_STANDARD.encode(signature.as_ref())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_canonical_preimage_formatting() {
        let vault_id = Uuid::new_v4();
        let preimage = canonical_mutation_preimage(
            vault_id,
            "host-123",
            "host",
            5,
            false,
            1,
            42,
            "abcdef123456",
        );
        let expected = format!(
            "shellumi-v1-mutation:{}:host-123:host:5:false:1:42:abcdef123456",
            vault_id
        );
        assert_eq!(preimage, expected);
    }

    #[test]
    fn test_signature_verification_success_and_tamper_rejection() {
        let (keypair, public_key_b64) = generate_test_ed25519_keypair().unwrap();
        let message = b"shellumi canonical mutation test payload";
        let signature_b64 = sign_message(&keypair, message);

        // Verification should succeed
        assert!(verify_device_signature(&public_key_b64, message, &signature_b64).is_ok());

        // Verification must fail if message is tampered
        let tampered_message = b"shellumi canonical mutation test payload tampered";
        assert!(
            verify_device_signature(&public_key_b64, tampered_message, &signature_b64).is_err()
        );

        // Verification must fail if signature is invalid
        let invalid_sig = BASE64_STANDARD.encode([0u8; 64]);
        assert!(verify_device_signature(&public_key_b64, message, &invalid_sig).is_err());
    }

    #[test]
    fn test_envelope_validation() {
        let valid_envelope = EncryptedEnvelope {
            salt: BASE64_STANDARD.encode([1u8; SALT_LEN]),
            nonce: BASE64_STANDARD.encode([2u8; NONCE_LEN]),
            ciphertext: BASE64_STANDARD.encode(vec![3u8; 100]),
            associated_data: "host:001".to_string(),
            kdf_iterations: 600_000,
        };

        assert!(validate_envelope(&valid_envelope, 1024).is_ok());

        // Too low iterations
        let mut low_iter = valid_envelope.clone();
        low_iter.kdf_iterations = 100;
        assert!(matches!(
            validate_envelope(&low_iter, 1024),
            Err(CryptoError::KdfIterationsTooLow(_))
        ));

        // Invalid salt length
        let mut bad_salt = valid_envelope.clone();
        bad_salt.salt = BASE64_STANDARD.encode([1u8; 8]);
        assert!(matches!(
            validate_envelope(&bad_salt, 1024),
            Err(CryptoError::InvalidSaltLength(8))
        ));

        // Oversized ciphertext
        assert!(matches!(
            validate_envelope(&valid_envelope, 50),
            Err(CryptoError::CiphertextTooLarge { .. })
        ));
    }
}
