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
    http::{HeaderValue, StatusCode},
    middleware::{self, Next},
    response::{Json, Response},
    routing::{get, post},
    Router,
};
use serde::Serialize;
use tokio::sync::{Mutex, RwLock};

use crate::integrity::SharedIntegrity;
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
    /// Runtime integrity status (TOCTOU defense).
    pub integrity: Option<SharedIntegrity>,
    /// Cached EAT token (base64) for HTTP-A header.
    /// Updated whenever the quote is refreshed.
    pub eat_token_b64: RwLock<Option<String>>,
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
            integrity: None,
            eat_token_b64: RwLock::new(None),
        }
    }

    /// Set the integrity monitor handle.
    pub fn with_integrity(mut self, integrity: SharedIntegrity) -> Self {
        self.integrity = Some(integrity);
        self
    }

    /// Update the cached EAT token (call after quote refresh).
    pub async fn set_eat_token(&self, b64: String) {
        let mut guard = self.eat_token_b64.write().await;
        *guard = Some(b64);
    }
}

pub fn attestation_router(state: Arc<AttestState>) -> Router {
    Router::new()
        .route("/attest", get(get_compact_quote))
        .route("/attest/full", post(get_full_quote))
        .route("/attest/value-x", get(get_value_x))
        .route("/attest/integrity", get(get_integrity))
        .route("/health", get(health))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            http_a_middleware,
        ))
        .with_state(state)
}

/// HTTP-A middleware: attach `Attestation-Token` header to every response.
/// Clients that understand it get per-request attestation proof.
/// Clients that don't simply ignore the header.
async fn http_a_middleware(
    State(state): State<Arc<AttestState>>,
    request: axum::extract::Request,
    next: Next,
) -> Response {
    let mut response = next.run(request).await;

    // Attach the EAT token if available
    if let Some(ref b64) = *state.eat_token_b64.read().await {
        if let Ok(val) = HeaderValue::from_str(b64) {
            response
                .headers_mut()
                .insert("Attestation-Token", val);
        }
    }

    response
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
        Some(q) => Ok(Json(serde_json::to_value(q.compact()).expect("UnifiedQuote serialization"))),
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

    Ok(Json(serde_json::to_value(quote).expect("UnifiedQuote serialization")))
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

async fn get_integrity(
    State(state): State<Arc<AttestState>>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    if !state.read_limiter.lock().await.allow() {
        return Err((
            StatusCode::TOO_MANY_REQUESTS,
            Json(ErrorResponse {
                error: "rate limited".into(),
            }),
        ));
    }

    match &state.integrity {
        Some(integrity) => {
            let guard: tokio::sync::RwLockReadGuard<'_, crate::integrity::IntegrityStatus> = integrity.read().await;
            Ok(Json(serde_json::json!({
                "integrity_ok": guard.integrity_ok,
                "boot_value_x": hex::encode(guard.boot_value_x),
                "current_value_x": hex::encode(guard.current_value_x),
                "check_count": guard.check_count,
                "last_check": guard.last_check,
                "rtmr_extended": guard.rtmr_extended,
            })))
        }
        None => Ok(Json(serde_json::json!({
            "integrity_ok": true,
            "monitoring": false,
            "note": "integrity monitor not started"
        }))),
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
