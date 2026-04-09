//! AWS Nitro Enclaves evidence collection.
//!
//! STATUS: UNIMPLEMENTED — device detection works, evidence collection does not.
//!
//! The NitroProvider can detect /dev/nsm but cannot collect attestation evidence.
//! The NSM ioctl interface requires virtio-vsock bindings that are not yet
//! implemented. Tests use real Nitro attestation data captured from hardware
//! (testdata/nitro_attestation.json) but this module cannot produce it live.
//!
//! Nitro attestation documents are COSE_Sign1 structures containing:
//! - PCR0-15: platform measurement registers
//! - user_data: arbitrary 512 bytes (we put sha256(pubkey) + value_x here)
//! - public_key: DER-encoded public key
//! - certificate + cabundle: cert chain to AWS Nitro Root CA
//!
//! Communication with the Nitro Security Module is via /dev/nsm using
//! a request/response protocol over virtio-vsock.

use super::{TeeError, TeeEvidence, TeeProvider};
use crate::quote::Platform;

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
    fn collect_evidence(&self, _report_data: &[u8; 64]) -> Result<TeeEvidence, TeeError> {
        // UNIMPLEMENTED: NSM ioctl binding.
        //
        // The NSM API works via ioctl on /dev/nsm:
        //   1. Open /dev/nsm
        //   2. Send Attestation request with user_data, nonce, public_key
        //   3. Receive COSE_Sign1 attestation document
        //
        // Requires: aws-nitro-enclaves-nsm-api crate or raw ioctl bindings.
        // The attestation document is self-contained — the cert chain is
        // embedded in the COSE structure. No external fetch needed.
        //
        // This will fail at runtime with a clear error. Tests pass because
        // they use captured hardware data, not this function.
        Err(TeeError::DeviceNotFound(
            "Nitro NSM ioctl not implemented — evidence collection unavailable. \
             Device /dev/nsm detected but communication requires virtio-vsock bindings. \
             See: https://github.com/aws/aws-nitro-enclaves-nsm-api"
                .into(),
        ))
    }

    fn platform(&self) -> Platform {
        Platform::Nitro
    }
}
