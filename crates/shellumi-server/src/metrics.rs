//! Prometheus metrics collector and exposition formatter.
//!
//! Provides opt-in `/metrics` telemetry adhering strictly to Prometheus 0.0.4 text format.
//! Enforces bounded label cardinality: route paths are normalized to canonical templates,
//! completely excluding user, device, and vault UUIDs.

use axum::{
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use uuid::Uuid;

/// Normalizes raw request URI paths to canonical route templates with bounded cardinality.
///
/// Converts concrete UUIDs to `:id` and numeric revision sequences to `:revision`.
pub fn normalize_metric_path(path: &str) -> String {
    let segments: Vec<&str> = path.split('/').collect();
    let mut normalized = Vec::with_capacity(segments.len());

    for seg in segments {
        if seg.is_empty() {
            normalized.push("");
        } else if Uuid::parse_str(seg).is_ok() {
            normalized.push(":id");
        } else if !seg.is_empty() && seg.chars().all(|c| c.is_ascii_digit()) {
            normalized.push(":revision");
        } else {
            normalized.push(seg);
        }
    }

    normalized.join("/")
}

/// Central metrics registry for tracking HTTP and runtime counters.
#[derive(Debug, Default)]
pub struct MetricsRegistry {
    /// Request counts by (method, normalized_path, status_code)
    request_counts: Mutex<HashMap<(String, String, u16), u64>>,
    /// Request duration sum and count by (method, normalized_path)
    request_durations: Mutex<HashMap<(String, String), (Duration, u64)>>,
    /// Total rate limit violations by category
    rate_limits_total: Mutex<HashMap<String, u64>>,
    /// Active sessions gauge
    active_sessions: AtomicU64,
    /// Registered devices gauge
    registered_devices: AtomicU64,
    /// Total vaults gauge
    total_vaults: AtomicU64,
}

impl MetricsRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Records an HTTP request completion.
    pub fn record_http_request(
        &self,
        method: &str,
        raw_path: &str,
        status_code: u16,
        duration: Duration,
    ) {
        let normalized = normalize_metric_path(raw_path);

        // Update count
        {
            let mut counts = self
                .request_counts
                .lock()
                .unwrap_or_else(|p| p.into_inner());
            let entry = counts
                .entry((method.to_string(), normalized.clone(), status_code))
                .or_insert(0);
            *entry += 1;
        }

        // Update duration
        {
            let mut durations = self
                .request_durations
                .lock()
                .unwrap_or_else(|p| p.into_inner());
            let (sum, count) = durations
                .entry((method.to_string(), normalized))
                .or_insert((Duration::ZERO, 0));
            *sum += duration;
            *count += 1;
        }
    }

    /// Records a rate limit rejection.
    pub fn record_rate_limit_exceeded(&self, category: &str) {
        let mut limits = self
            .rate_limits_total
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        let entry = limits.entry(category.to_string()).or_insert(0);
        *entry += 1;
    }

    /// Updates live gauges from the database/store state.
    pub fn update_gauges(&self, sessions: u64, devices: u64, vaults: u64) {
        self.active_sessions.store(sessions, Ordering::Relaxed);
        self.registered_devices.store(devices, Ordering::Relaxed);
        self.total_vaults.store(vaults, Ordering::Relaxed);
    }

    /// Renders all metrics in the Prometheus 0.0.4 text exposition format.
    pub fn render_prometheus(&self) -> String {
        let mut output = String::with_capacity(2048);

        // 1. HTTP Requests Total
        output.push_str(
            "# HELP shellumi_http_requests_total Total number of HTTP requests processed.\n",
        );
        output.push_str("# TYPE shellumi_http_requests_total counter\n");
        {
            let counts = self
                .request_counts
                .lock()
                .unwrap_or_else(|p| p.into_inner());
            let mut sorted: Vec<_> = counts.iter().collect();
            sorted.sort_by_key(|a| (a.0 .0.clone(), a.0 .1.clone(), a.0 .2));
            for ((method, path, status), count) in sorted {
                output.push_str(&format!(
                    "shellumi_http_requests_total{{method=\"{method}\",path=\"{path}\",status=\"{status}\"}} {count}\n"
                ));
            }
        }
        output.push('\n');

        // 2. HTTP Request Duration Seconds (Sum and Count)
        output.push_str("# HELP shellumi_http_request_duration_seconds_total Total duration of HTTP requests in seconds.\n");
        output.push_str("# TYPE shellumi_http_request_duration_seconds_total counter\n");
        {
            let durations = self
                .request_durations
                .lock()
                .unwrap_or_else(|p| p.into_inner());
            let mut sorted: Vec<_> = durations.iter().collect();
            sorted.sort_by_key(|a| (a.0 .0.clone(), a.0 .1.clone()));
            for ((method, path), (sum, _)) in &sorted {
                output.push_str(&format!(
                    "shellumi_http_request_duration_seconds_total{{method=\"{method}\",path=\"{path}\"}} {:.6}\n",
                    sum.as_secs_f64()
                ));
            }
        }
        output.push('\n');

        output.push_str("# HELP shellumi_http_request_duration_seconds_count Total count of timed HTTP requests.\n");
        output.push_str("# TYPE shellumi_http_request_duration_seconds_count counter\n");
        {
            let durations = self
                .request_durations
                .lock()
                .unwrap_or_else(|p| p.into_inner());
            let mut sorted: Vec<_> = durations.iter().collect();
            sorted.sort_by_key(|a| (a.0 .0.clone(), a.0 .1.clone()));
            for ((method, path), (_, count)) in &sorted {
                output.push_str(&format!(
                    "shellumi_http_request_duration_seconds_count{{method=\"{method}\",path=\"{path}\"}} {count}\n"
                ));
            }
        }
        output.push('\n');

        // 3. Rate Limit Violations
        output.push_str("# HELP shellumi_rate_limit_exceeded_total Total number of rate-limited requests rejected with HTTP 429.\n");
        output.push_str("# TYPE shellumi_rate_limit_exceeded_total counter\n");
        {
            let limits = self
                .rate_limits_total
                .lock()
                .unwrap_or_else(|p| p.into_inner());
            let mut sorted: Vec<_> = limits.iter().collect();
            sorted.sort_by_key(|a| a.0.clone());
            for (category, count) in sorted {
                output.push_str(&format!(
                    "shellumi_rate_limit_exceeded_total{{category=\"{category}\"}} {count}\n"
                ));
            }
        }
        output.push('\n');

        // 4. Runtime Gauges
        output.push_str("# HELP shellumi_active_sessions_total Current number of active authenticated user sessions.\n");
        output.push_str("# TYPE shellumi_active_sessions_total gauge\n");
        output.push_str(&format!(
            "shellumi_active_sessions_total {}\n\n",
            self.active_sessions.load(Ordering::Relaxed)
        ));

        output.push_str("# HELP shellumi_registered_devices_total Current number of registered client devices.\n");
        output.push_str("# TYPE shellumi_registered_devices_total gauge\n");
        output.push_str(&format!(
            "shellumi_registered_devices_total {}\n\n",
            self.registered_devices.load(Ordering::Relaxed)
        ));

        output.push_str(
            "# HELP shellumi_vaults_total Current number of vaults stored on the server.\n",
        );
        output.push_str("# TYPE shellumi_vaults_total gauge\n");
        output.push_str(&format!(
            "shellumi_vaults_total {}\n",
            self.total_vaults.load(Ordering::Relaxed)
        ));

        output
    }
}

/// Handler for the `/metrics` endpoint.
pub async fn metrics_handler(metrics: Arc<MetricsRegistry>) -> Response {
    let body = metrics.render_prometheus();
    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/plain; version=0.0.4; charset=utf-8"),
    );

    (StatusCode::OK, headers, body).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normalize_metric_path_replaces_uuids_and_revisions() {
        let uuid_str = "b6194b15-2882-4113-a41e-3608bfa0c8c1";
        let raw = format!("/api/v1/vaults/{uuid_str}/commits");
        assert_eq!(normalize_metric_path(&raw), "/api/v1/vaults/:id/commits");

        let raw_snapshot = format!("/api/v1/vaults/{uuid_str}/snapshots/42");
        assert_eq!(
            normalize_metric_path(&raw_snapshot),
            "/api/v1/vaults/:id/snapshots/:revision"
        );

        let static_path = "/health/live";
        assert_eq!(normalize_metric_path(static_path), "/health/live");
    }

    #[test]
    fn test_metrics_registry_render_format() {
        let registry = MetricsRegistry::new();
        registry.record_http_request("GET", "/health/live", 200, Duration::from_millis(5));
        registry.record_rate_limit_exceeded("auth_login");
        registry.update_gauges(10, 5, 2);

        let rendered = registry.render_prometheus();
        assert!(rendered.contains(
            "shellumi_http_requests_total{method=\"GET\",path=\"/health/live\",status=\"200\"} 1"
        ));
        assert!(rendered.contains("shellumi_rate_limit_exceeded_total{category=\"auth_login\"} 1"));
        assert!(rendered.contains("shellumi_active_sessions_total 10"));
        assert!(rendered.contains("shellumi_registered_devices_total 5"));
        assert!(rendered.contains("shellumi_vaults_total 2"));
    }
}
