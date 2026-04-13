//! NitroTPM PCR reading for kernel measurement linking.
//!
//! On AWS SNP, the SNP MEASUREMENT only covers OVMF firmware.
//! The kernel, initrd, and cmdline are measured by NitroTPM into PCR 0-7.
//! We read these PCRs from sysfs and bind sha256(PCRs) into the SNP
//! REPORT_DATA, cryptographically linking the two attestation domains.
//!
//! Trust model: SNP report is AMD-signed (hardware root of trust).
//! Our code is verified via SNP MEASUREMENT. Our code reads PCRs
//! and binds them — so the PCR hash in REPORT_DATA is trustworthy.

use sha2::{Digest, Sha256};

const TPM_SYSFS_BASE: &str = "/sys/class/tpm/tpm0/pcr-sha256";

/// Check if a TPM with sysfs PCR interface is available.
pub fn tpm_available() -> bool {
    std::path::Path::new(TPM_SYSFS_BASE).exists()
}

/// Read PCR 0-7 from the SHA-256 bank via sysfs.
/// Returns 8 raw 32-byte PCR values.
pub fn read_pcrs() -> Result<Vec<[u8; 32]>, String> {
    (0..8)
        .map(|i| {
            let path = format!("{TPM_SYSFS_BASE}/{i}");
            let text = std::fs::read_to_string(&path)
                .map_err(|e| format!("read PCR{i}: {e}"))?;
            let bytes = hex::decode(text.trim())
                .map_err(|e| format!("PCR{i} hex decode: {e}"))?;
            let arr: [u8; 32] = bytes
                .try_into()
                .map_err(|_| format!("PCR{i} not 32 bytes"))?;
            Ok(arr)
        })
        .collect()
}

/// Compute sha256(PCR0 || PCR1 || ... || PCR7).
/// This is the kernel measurement digest bound into SNP REPORT_DATA.
pub fn pcr_digest(pcrs: &[[u8; 32]]) -> [u8; 32] {
    let mut h = Sha256::new();
    for pcr in pcrs {
        h.update(pcr);
    }
    h.finalize().into()
}
