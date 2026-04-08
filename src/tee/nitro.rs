//! AWS Nitro Enclaves evidence collection.
//!
//! Nitro attestation documents are COSE_Sign1 structures containing:
//! - PCR0: enclave image hash
//! - PCR1: kernel + boot config hash
//! - PCR2: application hash
//! - PCR8: signing cert hash (if signed EIF)
//! - user_data: arbitrary 512 bytes (we put sha256(pubkey) + value_x here)
//! - nonce: 40 bytes
//! - public_key: DER-encoded public key (we put our TEE-derived ed25519 key)
//!
//! Communication with the Nitro Security Module is via /dev/nsm using
//! a simple request/response protocol over virtio-vsock.

use crate::quote::Platform;
use super::{TeeError, TeeEvidence, TeeProvider};

pub struct NitroProvider;

impl NitroProvider {
    pub fn new() -> Result<Self, TeeError> {
        if !std::path::Path::new("/dev/nsm").exists() {
            return Err(TeeError::DeviceNotFound("/dev/nsm".into()));
        }
        Ok(Self)
    }
}

impl TeeProvider for NitroProvider {
    fn collect_evidence(&self, report_data: &[u8; 64]) -> Result<TeeEvidence, TeeError> {
        // The NSM API works via ioctl on /dev/nsm:
        // 1. Open /dev/nsm
        // 2. Send Attestation request with user_data, nonce, public_key
        // 3. Receive COSE_Sign1 attestation document
        //
        // The attestation document is self-contained — the cert chain is
        // embedded in the COSE unprotected header. No external fetch needed.

        // TODO: Implement NSM ioctl
        // For now, this is a compilation stub that documents the interface.
        //
        // Real implementation:
        //   let fd = open("/dev/nsm", O_RDWR)?;
        //   let req = NsmRequest::Attestation {
        //       user_data: Some(report_data[..].to_vec()),
        //       nonce: None,
        //       public_key: Some(tee_pubkey_der),
        //   };
        //   let resp = nsm_ioctl(fd, req)?;
        //   // resp.document is the COSE_Sign1 bytes

        let _ = report_data;
        Err(TeeError::DeviceNotFound(
            "NSM ioctl not yet implemented".into(),
        ))
    }

    fn platform(&self) -> Platform {
        Platform::Nitro
    }
}
