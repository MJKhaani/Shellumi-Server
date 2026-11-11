//! Core domain logic, configuration models, authorization roles, and domain errors.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum DomainError {
    #[error("Configuration error: {0}")]
    Configuration(String),

    #[error("Authentication required")]
    Unauthenticated,

    #[error("Permission denied: {0}")]
    PermissionDenied(String),

    #[error("Resource not found")]
    NotFound,

    #[error("Conflict: {0}")]
    Conflict(String),

    #[error("Payload too large: limit {limit} bytes, actual {actual} bytes")]
    PayloadTooLarge { limit: usize, actual: usize },

    #[error("Invalid input: {0}")]
    InvalidInput(String),

    #[error("Internal server error")]
    Internal,
}
