//! Known-good Value X registry.
//!
//! Maintains a list of trusted Value X hashes, each linked to:
//! - The git commit that produced the runner image
//! - The build attestation hash (Sigstore provenance)
//! - The runner version
//! - When it was registered
//!
//! Verifiers can check: "Is this Value X in the registry?"
//! If yes, the runner is running a known release.
//! If no, it's either a new/unknown build or has been tampered with.
//!
//! The registry is published as a signed JSON file in the repo
//! and can be fetched by verifiers.

use serde::{Deserialize, Serialize};

/// A single entry in the Value X registry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistryEntry {
    /// The Value X hash (hex-encoded sha384).
    pub value_x: String,
    /// Git commit SHA that produced this build.
    pub git_commit: String,
    /// Runner version (e.g., "2.323.0").
    pub runner_version: String,
    /// sha256 of the GitHub Actions build attestation (Sigstore bundle).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub build_attestation_hash: Option<String>,
    /// Docker image digest (sha256).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub image_digest: Option<String>,
    /// When this entry was registered (ISO 8601).
    pub registered_at: String,
    /// Whether this version is currently recommended.
    pub recommended: bool,
    /// Whether this version has known security issues.
    pub deprecated: bool,
    /// Human-readable notes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
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
