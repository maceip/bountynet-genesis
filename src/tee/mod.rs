//! TEE platform detection and evidence collection.
//!
//! Each platform module implements `TeeProvider` to collect attestation
//! evidence from the hardware. The shim auto-detects which TEE it's
//! running in at boot.

pub mod detect;
#[cfg(feature = "sev-snp")]
pub mod kds;
#[cfg(feature = "nitro")]
pub mod nitro;
#[cfg(feature = "sev-snp")]
pub mod snp;
#[cfg(feature = "tdx")]
pub mod tdx;

use crate::quote::Platform;

/// Raw attestation evidence from the TEE hardware.
pub struct TeeEvidence {
    pub platform: Platform,
    /// The raw platform-specific quote/report bytes.
    pub raw_quote: Vec<u8>,
    /// Certificate chain for the quote (platform-specific).
    /// Nitro: embedded in COSE. SNP: VCEK chain. TDX: PCK chain.
    pub cert_chain: Vec<Vec<u8>>,
}

/// Trait implemented by each TEE platform for evidence collection.
pub trait TeeProvider: Send + Sync {
    /// Request an attestation report from the hardware.
    /// `report_data` is bound into the quote (typically contains value_x + nonce).
    fn collect_evidence(&self, report_data: &[u8; 64]) -> Result<TeeEvidence, TeeError>;

    /// Which platform this provider serves.
    fn platform(&self) -> Platform;
}

#[derive(Debug, thiserror::Error)]
pub enum TeeError {
    #[error("TEE device not available: {0}")]
    DeviceNotFound(String),
    #[error("ioctl failed: {0}")]
    Ioctl(#[from] nix::Error),
    #[error("invalid response from TEE: {0}")]
    InvalidResponse(String),
    #[error("no TEE detected on this platform")]
    NoTeeDetected,
}
