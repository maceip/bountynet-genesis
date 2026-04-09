//! Pinned root CA fingerprints for TEE vendors.
//!
//! These are the trust anchors. If the root cert in a quote's chain
//! doesn't match one of these fingerprints, the quote is rejected.
//! Without this check, an attacker with their own CA could forge
//! an entire cert chain.

use sha2::{Digest, Sha256};

/// AWS Nitro Attestation Root CA fingerprint (SHA-256 of DER-encoded cert).
/// Source: https://aws-nitro-enclaves.amazonaws.com/AWS_NitroEnclaves_Root-G1.zip
pub const AWS_NITRO_ROOT_SHA256: &str =
    "8cf60e2b2efca96c6a9e71e851d00c1b6f001d714de2d0f5eb46b4c8f8454f18";

/// AMD ARK (Root Key) fingerprint for Milan (SEV-SNP v2).
/// Source: https://kdsintf.amd.com/vcek/v1/Milan/cert_chain
pub const AMD_ARK_MILAN_SHA256: &str =
    "5b38a09f3ee23a2bd80091e57b884c40e58a4e18cda8a584018ebc1c3202ed57";

/// AMD ARK fingerprint for Genoa (SEV-SNP v5).
/// Source: https://kdsintf.amd.com/vcek/v1/Genoa/cert_chain
pub const AMD_ARK_GENOA_SHA256: &str =
    "5a600e367c89b26e7db78ce18e0aa94bdd67e0e80f74b9f5173e4e91ead34141";

/// Intel SGX Root CA fingerprint (SHA-256 of DER-encoded cert).
/// Source: Intel SGX Attestation Service documentation.
pub const INTEL_SGX_ROOT_SHA256: &str =
    "0e0c87d569c58699d59a0fb080b090842e2546e6fd50f61d34836dd46e1e34e0";

/// Check if a DER-encoded certificate matches a pinned fingerprint.
pub fn verify_root_fingerprint(cert_der: &[u8], expected_fingerprint: &str) -> bool {
    let actual = hex::encode(Sha256::digest(cert_der));
    actual == expected_fingerprint
}
