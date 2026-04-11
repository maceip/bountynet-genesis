//! vsock proxy for Nitro Enclaves.
//!
//! Nitro Enclaves have no network — only vsock to the parent instance.
//! This module provides:
//!   - Enclave side: listen on vsock, serve attestation JSON
//!   - Parent side: proxy TCP connections to/from the enclave's vsock
//!
//! The parent runs TLS termination. The enclave serves plaintext over vsock.
//! The trust boundary is the enclave — TLS is between the verifier and the parent,
//! and the attestation proves the enclave's identity regardless of the transport.

use anyhow::Result;
use std::os::unix::io::{FromRawFd, RawFd};

/// vsock port for attestation service inside the enclave
pub const VSOCK_PORT: u32 = 9384;

/// CID for the parent instance (always 3 for Nitro)
pub const PARENT_CID: u32 = 3;

/// Listen on vsock inside the enclave. Serves attestation JSON to any connection.
pub fn serve_vsock(attestation_json: &str) -> Result<()> {
    // Create vsock socket
    let fd = unsafe {
        libc::socket(
            libc::AF_VSOCK,
            libc::SOCK_STREAM,
            0,
        )
    };
    if fd < 0 {
        anyhow::bail!("Failed to create vsock socket: {}", std::io::Error::last_os_error());
    }

    // Bind to VMADDR_CID_ANY (listen for connections from parent)
    let mut addr: libc::sockaddr_vm = unsafe { std::mem::zeroed() };
    addr.svm_family = libc::AF_VSOCK as u16;
    addr.svm_port = VSOCK_PORT;
    addr.svm_cid = libc::VMADDR_CID_ANY;

    let ret = unsafe {
        libc::bind(
            fd,
            &addr as *const libc::sockaddr_vm as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_vm>() as u32,
        )
    };
    if ret < 0 {
        anyhow::bail!("Failed to bind vsock: {}", std::io::Error::last_os_error());
    }

    let ret = unsafe { libc::listen(fd, 5) };
    if ret < 0 {
        anyhow::bail!("Failed to listen on vsock: {}", std::io::Error::last_os_error());
    }

    eprintln!("[bountynet/vsock] Listening on vsock port {VSOCK_PORT}");

    // Accept connections and serve attestation JSON
    loop {
        let client_fd = unsafe {
            libc::accept(fd, std::ptr::null_mut(), std::ptr::null_mut())
        };
        if client_fd < 0 {
            eprintln!("[bountynet/vsock] Accept failed: {}", std::io::Error::last_os_error());
            continue;
        }

        // Write the attestation JSON as an HTTP response
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            attestation_json.len(),
            attestation_json
        );

        let bytes = response.as_bytes();
        let mut written = 0;
        while written < bytes.len() {
            let n = unsafe {
                libc::write(
                    client_fd,
                    bytes[written..].as_ptr() as *const libc::c_void,
                    bytes.len() - written,
                )
            };
            if n <= 0 {
                break;
            }
            written += n as usize;
        }

        unsafe { libc::close(client_fd) };
    }
}

/// Connect to the enclave over vsock from the parent instance.
/// Returns a raw fd connected to the enclave's attestation service.
pub fn connect_to_enclave(enclave_cid: u32) -> Result<RawFd> {
    let fd = unsafe {
        libc::socket(
            libc::AF_VSOCK,
            libc::SOCK_STREAM,
            0,
        )
    };
    if fd < 0 {
        anyhow::bail!("Failed to create vsock socket");
    }

    let mut addr: libc::sockaddr_vm = unsafe { std::mem::zeroed() };
    addr.svm_family = libc::AF_VSOCK as u16;
    addr.svm_port = VSOCK_PORT;
    addr.svm_cid = enclave_cid;

    let ret = unsafe {
        libc::connect(
            fd,
            &addr as *const libc::sockaddr_vm as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_vm>() as u32,
        )
    };
    if ret < 0 {
        unsafe { libc::close(fd) };
        anyhow::bail!("Failed to connect to enclave CID {enclave_cid}: {}", std::io::Error::last_os_error());
    }

    Ok(fd)
}

/// Read the attestation JSON from the enclave via vsock.
pub fn fetch_attestation(enclave_cid: u32) -> Result<String> {
    let fd = connect_to_enclave(enclave_cid)?;

    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        let n = unsafe {
            libc::read(fd, chunk.as_mut_ptr() as *mut libc::c_void, chunk.len())
        };
        if n <= 0 {
            break;
        }
        buf.extend_from_slice(&chunk[..n as usize]);
    }

    unsafe { libc::close(fd) };

    let response = String::from_utf8(buf)?;
    // Skip HTTP headers — find the empty line
    if let Some(body_start) = response.find("\r\n\r\n") {
        Ok(response[body_start + 4..].to_string())
    } else {
        Ok(response)
    }
}
