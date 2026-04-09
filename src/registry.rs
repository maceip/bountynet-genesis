//! Known-good registry: Value X + platform measurements.
//!
//! See INVARIANT.md. A verifier must check TWO things:
//!   1. Platform measurement (MRTD/MEASUREMENT/PCR0) matches expected
//!   2. Value X matches expected
//!
//! This registry stores both. Without the platform measurement check,
//! Value X alone proves nothing — a compromised shim could lie about it.

use serde::{Deserialize, Serialize};

/// A single entry: one known-good build.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistryEntry {
    /// Value X: sha384 of runner files (NOT the shim). Hex-encoded.
    pub value_x: String,

    /// Expected platform measurements for this build.
    /// Verifier checks the quote's measurement against these.
    /// At least one must be present for the entry to be useful.
    #[serde(default)]
    pub platform_measurements: PlatformMeasurements,

    /// Git commit that produced this build.
    pub git_commit: String,
    /// Runner version.
    pub runner_version: String,
    /// Docker image digest.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub image_digest: Option<String>,
    /// When registered.
    pub registered_at: String,
    pub recommended: bool,
    pub deprecated: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
}

/// Expected platform measurements per TEE type.
/// These come from building the image and recording what the TEE measures.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PlatformMeasurements {
    /// TDX: hex(MRTD) — hash of the TD image at launch.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tdx_mrtd: Option<String>,
    /// SNP: hex(MEASUREMENT) — hash of the guest image at launch.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub snp_measurement: Option<String>,
    /// Nitro: hex(PCR0) — hash of the enclave image.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nitro_pcr0: Option<String>,
}

/// The full registry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValueXRegistry {
    /// Schema version.
    pub version: u32,
    /// All known-good entries.
    pub entries: Vec<RegistryEntry>,
}

impl ValueXRegistry {
    pub fn new() -> Self {
        Self {
            version: 1,
            entries: Vec::new(),
        }
    }

    /// Check if a Value X is in the registry.
    pub fn is_known(&self, value_x: &str) -> bool {
        self.entries.iter().any(|e| e.value_x == value_x)
    }

    /// Check if a Value X is recommended (known and not deprecated).
    pub fn is_recommended(&self, value_x: &str) -> bool {
        self.entries
            .iter()
            .any(|e| e.value_x == value_x && e.recommended && !e.deprecated)
    }

    /// Get the entry for a Value X.
    pub fn get(&self, value_x: &str) -> Option<&RegistryEntry> {
        self.entries.iter().find(|e| e.value_x == value_x)
    }

    /// Get the latest recommended entry.
    pub fn latest_recommended(&self) -> Option<&RegistryEntry> {
        self.entries
            .iter()
            .filter(|e| e.recommended && !e.deprecated)
            .last()
    }
}

/// TCB (Trusted Computing Base) policy for key rotation handling.
///
/// Intel updates PCK certs ~4x/year. AMD updates VCEK on firmware updates.
/// This policy defines what TCB levels are acceptable.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TcbPolicy {
    /// Minimum acceptable TCB version per platform.
    /// Key: platform name ("Tdx", "SevSnp", "Nitro")
    /// Value: minimum TCB version string
    pub minimum_tcb: std::collections::HashMap<String, String>,

    /// Maximum age of a quote in seconds before it's considered stale.
    /// Default: 300 (5 minutes) for real-time verification.
    pub max_quote_age_secs: u64,

    /// Whether to accept quotes with "OutOfDate" TCB status.
    /// true = warn but accept, false = reject.
    pub accept_out_of_date: bool,

    /// Whether to accept quotes without TCB version info.
    /// true = accept (permissive), false = reject (strict).
    pub require_tcb_version: bool,
}

impl Default for TcbPolicy {
    fn default() -> Self {
        Self {
            minimum_tcb: std::collections::HashMap::new(),
            max_quote_age_secs: 300,
            accept_out_of_date: true,
            require_tcb_version: false,
        }
    }
}
