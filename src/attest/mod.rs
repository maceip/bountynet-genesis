//! Remote attestation HTTP endpoint.
//!
//! Serves a lightweight API that returns the UnifiedQuote on demand.
//! Rate-limited to mitigate DDoS — attestation involves TEE hardware
//! calls that have limited throughput.
//!
//! Endpoints:
//!   GET  /attest          → current UnifiedQuote (compact, no raw platform quote)
//!   POST /attest/full     → full UnifiedQuote with platform quote (for deep verification)
//!   GET  /attest/value-x  → just the Value X hex string
//!   GET  /health          → liveness check
//!
//! Rate limiting:
//!   GET endpoints: 60 req/min (cheap — serves cached data)
//!   POST /attest/full: 5 req/min (expensive — triggers TEE hardware call)

use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::{
    extract::State,
    http::StatusCode,
    response::Json,
    routing::{get, post},
    Router,
};
use serde::Serialize;
use tokio::sync::{Mutex, RwLock};

use crate::quote::UnifiedQuote;

/// Shared state for the attestation endpoint.
pub struct AttestState {
    /// The current attestation quote — refreshed periodically or on demand.
    pub current_quote: RwLock<Option<UnifiedQuote>>,
    /// Callback to generate a fresh quote (involves TEE hardware call).
    pub refresh_fn: Box<dyn Fn() -> Result<UnifiedQuote, String> + Send + Sync>,
    /// Rate limiter for the full quote endpoint.
    full_quote_limiter: Mutex<RateLimiter>,
    /// Rate limiter for read endpoints.
    read_limiter: Mutex<RateLimiter>,
}

impl AttestState {
    pub fn new(
        initial_quote: Option<UnifiedQuote>,
        refresh_fn: Box<dyn Fn() -> Result<UnifiedQuote, String> + Send + Sync>,
    ) -> Self {
        Self {
            current_quote: RwLock::new(initial_quote),
            refresh_fn,
            // POST /attest/full: max 5 requests per 60 seconds
            full_quote_limiter: Mutex::new(RateLimiter::new(5, Duration::from_secs(60))),
            // GET endpoints: max 60 requests per 60 seconds
            read_limiter: Mutex::new(RateLimiter::new(60, Duration::from_secs(60))),
        }
    }
}

pub fn attestation_router(state: Arc<AttestState>) -> Router {
    Router::new()
        .route("/attest", get(get_compact_quote))
        .route("/attest/full", post(get_full_quote))
        .route("/attest/value-x", get(get_value_x))
        .route("/health", get(health))
        .with_state(state)
}

#[derive(Serialize)]
struct ValueXResponse {
    value_x: String,
    platform: String,
    timestamp: u64,
}

#[derive(Serialize)]
struct ErrorResponse {
    error: String,
}

async fn get_compact_quote(
    State(state): State<Arc<AttestState>>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    // Rate limit
    if !state.read_limiter.lock().await.allow() {
        return Err((
            StatusCode::TOO_MANY_REQUESTS,
            Json(ErrorResponse {
                error: "rate limited — max 60 req/min".into(),
            }),
        ));
    }

    let guard = state.current_quote.read().await;
    match guard.as_ref() {
        Some(q) => Ok(Json(serde_json::to_value(q.compact()).unwrap())),
        None => Err((
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ErrorResponse {
                error: "no attestation available — TEE not initialized".into(),
            }),
        )),
    }
}

async fn get_full_quote(
    State(state): State<Arc<AttestState>>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    // Strict rate limit — this triggers a TEE hardware call
    if !state.full_quote_limiter.lock().await.allow() {
        return Err((
            StatusCode::TOO_MANY_REQUESTS,
            Json(ErrorResponse {
                error: "rate limited — max 5 fresh attestations/min".into(),
            }),
        ));
    }

    let quote = (state.refresh_fn)().map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: format!("attestation failed: {e}"),
            }),
        )
    })?;

    // Update cached quote
    {
        let mut guard = state.current_quote.write().await;
        *guard = Some(quote.clone());
    }

    Ok(Json(serde_json::to_value(quote).unwrap()))
}

async fn get_value_x(
    State(state): State<Arc<AttestState>>,
) -> Result<Json<ValueXResponse>, (StatusCode, Json<ErrorResponse>)> {
    if !state.read_limiter.lock().await.allow() {
        return Err((
            StatusCode::TOO_MANY_REQUESTS,
            Json(ErrorResponse {
                error: "rate limited".into(),
            }),
        ));
    }

    let guard = state.current_quote.read().await;
    match guard.as_ref() {
        Some(q) => Ok(Json(ValueXResponse {
            value_x: hex::encode(q.value_x),
            platform: format!("{:?}", q.platform),
            timestamp: q.timestamp,
        })),
        None => Err((
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ErrorResponse {
                error: "no attestation available".into(),
            }),
        )),
    }
}

async fn health() -> &'static str {
    "ok"
}

/// Simple sliding-window rate limiter.
struct RateLimiter {
    max_requests: usize,
    window: Duration,
    timestamps: Vec<Instant>,
}

impl RateLimiter {
    fn new(max_requests: usize, window: Duration) -> Self {
        Self {
            max_requests,
            window,
            timestamps: Vec::with_capacity(max_requests),
        }
    }

    fn allow(&mut self) -> bool {
        let now = Instant::now();
        // Remove expired timestamps
        self.timestamps.retain(|&t| now.duration_since(t) < self.window);
        if self.timestamps.len() < self.max_requests {
            self.timestamps.push(now);
            true
        } else {
            false
        }
    }
}
