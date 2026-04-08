//! Auto-detect which TEE platform we're running in.
//!
//! Detection order: check for platform-specific devices.
//! - /dev/nsm → AWS Nitro
//! - /dev/sev-guest → AMD SEV-SNP
//! - /dev/tdx-guest OR /sys/kernel/config/tsm/report → Intel TDX

use std::path::Path;

use super::{TeeError, TeeProvider};

/// Detect the TEE platform and return the appropriate provider.
pub fn detect_tee() -> Result<Box<dyn TeeProvider>, TeeError> {
    // AWS Nitro: Nitro Security Module device
    #[cfg(feature = "nitro")]
    if Path::new("/dev/nsm").exists() {
        return Ok(Box::new(super::nitro::NitroProvider::new()?));
    }

    // Intel TDX: check both legacy and configfs-tsm paths
    #[cfg(feature = "tdx")]
    if Path::new("/dev/tdx-guest").exists()
        || Path::new("/dev/tdx_guest").exists()
        || Path::new("/sys/kernel/config/tsm/report").exists()
    {
        return Ok(Box::new(super::tdx::TdxProvider::new()?));
    }

    // AMD SEV-SNP
    #[cfg(feature = "sev-snp")]
    if Path::new("/dev/sev-guest").exists() || Path::new("/dev/sev").exists() {
        return Ok(Box::new(super::snp::SnpProvider::new()?));
    }

    Err(TeeError::NoTeeDetected)
}
