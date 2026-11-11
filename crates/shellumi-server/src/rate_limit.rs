//! In-memory sliding-window rate limiter for sensitive authentication and bootstrap endpoints.
//!
//! Mitigates brute-force attacks and abuse on `/api/v1/auth/login`, `/api/v1/bootstrap`,
//! and `/api/v1/invites/accept`.

use axum::{
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Json, Response},
};
use shellumi_server_protocol::ErrorResponse;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tracing::warn;
use uuid::Uuid;

/// Category of sensitive endpoint subject to rate limiting.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RateLimitCategory {
    AuthLogin,
    Bootstrap,
    InviteAccept,
}

impl RateLimitCategory {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::AuthLogin => "auth_login",
            Self::Bootstrap => "bootstrap",
            Self::InviteAccept => "invite_accept",
        }
    }
}

/// In-memory storage type for rate limit history.
type RateLimitMap = HashMap<(IpAddr, RateLimitCategory), Vec<Instant>>;

/// In-memory sliding-window rate limiter.
#[derive(Debug, Clone)]
pub struct RateLimiter {
    max_requests: usize,
    window: Duration,
    entries: Arc<Mutex<RateLimitMap>>,
}

impl RateLimiter {
    /// Creates a new rate limiter with specified max requests within a given duration window.
    pub fn new(max_requests: usize, window: Duration) -> Self {
        Self {
            max_requests,
            window,
            entries: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Default rate limiter for sensitive endpoints: 10 requests per 60-second window.
    pub fn default_sensitive() -> Self {
        Self::new(10, Duration::from_secs(60))
    }

    /// Checks if a request from `client_ip` for `category` is allowed.
    ///
    /// If allowed, records the request timestamp and returns `Ok(())`.
    /// If rejected, returns `Err(retry_after_secs)`.
    pub fn check(&self, client_ip: IpAddr, category: RateLimitCategory) -> Result<(), u64> {
        let mut entries = self
            .entries
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());

        let now = Instant::now();
        let cutoff = now.checked_sub(self.window).unwrap_or(now);

        let key = (client_ip, category);
        let timestamps = entries.entry(key).or_default();

        // Evict expired timestamps
        timestamps.retain(|&t| t > cutoff);

        if timestamps.len() >= self.max_requests {
            // Find earliest timestamp in the current window to compute Retry-After
            let earliest = timestamps.first().copied().unwrap_or(now);
            let elapsed_since_earliest = now.duration_since(earliest);
            let retry_after = self
                .window
                .saturating_sub(elapsed_since_earliest)
                .as_secs()
                .max(1);

            warn!(
                client_ip = %client_ip,
                category = category.as_str(),
                retry_after_secs = retry_after,
                "Rate limit exceeded on sensitive endpoint"
            );

            return Err(retry_after);
        }

        timestamps.push(now);

        // Periodic cleanup if map grows large (> 5000 entries)
        if entries.len() > 5000 {
            entries.retain(|_, ts| {
                ts.retain(|&t| t > cutoff);
                !ts.is_empty()
            });
        }

        Ok(())
    }

    /// Resets all rate limit records (useful in tests).
    pub fn reset(&self) {
        let mut entries = self
            .entries
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        entries.clear();
    }
}

/// Helper to generate a 429 Too Many Requests response with standard headers and error body.
pub fn rate_limit_response(retry_after_secs: u64) -> Response {
    let mut headers = HeaderMap::new();
    headers.insert(
        header::RETRY_AFTER,
        HeaderValue::from_str(&retry_after_secs.to_string())
            .unwrap_or(HeaderValue::from_static("60")),
    );

    let error_body = ErrorResponse {
        error_code: "RATE_LIMIT_EXCEEDED".to_string(),
        message: format!(
            "Too many requests. Please wait {retry_after_secs} seconds before retrying."
        ),
        request_id: Some(Uuid::now_v7().to_string()),
    };

    (StatusCode::TOO_MANY_REQUESTS, headers, Json(error_body)).into_response()
}

/// Extracts client IP address, checking X-Forwarded-For if behind trusted proxies or falling back to 127.0.0.1.
pub fn extract_client_ip(headers: &HeaderMap, trusted_proxies: &[IpAddr]) -> IpAddr {
    if !trusted_proxies.is_empty() {
        if let Some(forwarded) = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()) {
            if let Some(first_ip_str) = forwarded.split(',').next() {
                if let Ok(ip) = first_ip_str.trim().parse::<IpAddr>() {
                    return ip;
                }
            }
        }
    }

    // Default loopback for tests or direct local connections
    IpAddr::from([127, 0, 0, 1])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rate_limiter_allows_under_limit_and_blocks_over_limit() {
        let limiter = RateLimiter::new(3, Duration::from_secs(10));
        let ip = IpAddr::from([192, 168, 1, 100]);
        let category = RateLimitCategory::AuthLogin;

        assert!(limiter.check(ip, category).is_ok());
        assert!(limiter.check(ip, category).is_ok());
        assert!(limiter.check(ip, category).is_ok());

        // 4th request must be rejected
        let result = limiter.check(ip, category);
        assert!(result.is_err());
        let retry_after = result.unwrap_err();
        assert!((1..=10).contains(&retry_after));

        // Different category for same IP should still be allowed
        assert!(limiter.check(ip, RateLimitCategory::Bootstrap).is_ok());

        // Different IP for same category should still be allowed
        let ip2 = IpAddr::from([192, 168, 1, 101]);
        assert!(limiter.check(ip2, category).is_ok());
    }

    #[test]
    fn test_extract_client_ip_with_trusted_proxies() {
        let trusted = vec![IpAddr::from([127, 0, 0, 1])];
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-forwarded-for",
            HeaderValue::from_static("203.0.113.195, 127.0.0.1"),
        );

        let ip = extract_client_ip(&headers, &trusted);
        assert_eq!(ip, IpAddr::from([203, 0, 113, 195]));

        // Untrusted proxy ignores X-Forwarded-For
        let ip_untrusted = extract_client_ip(&headers, &[]);
        assert_eq!(ip_untrusted, IpAddr::from([127, 0, 0, 1]));
    }
}
