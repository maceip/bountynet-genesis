//! vsock networking for Nitro Enclaves.
//!
//! TLS terminates INSIDE the enclave. The host never sees plaintext.
//!
//! Architecture (following Evervault/Turnkey pattern):
//!   Verifier → TCP:443 → [Parent: tcp-to-vsock bridge] → vsock →
//!     [Enclave: vsock-to-loopback bridge] → 127.0.0.1:443 →
//!       rustls TLS termination → attestation JSON
//!
//! Two commands:
//!   bountynet enclave  — runs inside the enclave (vsock listener + TLS server)
//!   bountynet proxy    — runs on the parent (TCP:443 → vsock bridge)

use anyhow::Result;
use std::io::{Read, Write};

/// vsock port for the bridge
pub const VSOCK_PORT: u32 = 9384;

/// Set up loopback interface inside the enclave.
/// Nitro Enclaves have no network interfaces by default.
pub fn setup_loopback() -> Result<()> {
    let status = std::process::Command::new("ifconfig")
        .args(["lo", "127.0.0.1", "up"])
        .status();

    match status {
        Ok(s) if s.success() => {
            eprintln!("[bountynet/vsock] Loopback interface up");
            Ok(())
        }
        _ => {
            // ifconfig might not exist in minimal images — try ip command
            let status2 = std::process::Command::new("ip")
                .args(["link", "set", "lo", "up"])
                .status();
            match status2 {
                Ok(s) if s.success() => {
                    let _ = std::process::Command::new("ip")
                        .args(["addr", "add", "127.0.0.1/8", "dev", "lo"])
                        .status();
                    eprintln!("[bountynet/vsock] Loopback interface up (via ip)");
                    Ok(())
                }
                _ => {
                    eprintln!("[bountynet/vsock] WARNING: could not set up loopback");
                    Ok(()) // Continue anyway — vsock direct serving still works
                }
            }
        }
    }
}

/// Bridge: vsock → TCP loopback.
/// Runs inside the enclave. Accepts vsock connections from the parent
/// and forwards them to the TLS server on 127.0.0.1:443.
pub fn bridge_vsock_to_loopback(loopback_port: u16) -> Result<()> {
    let fd = create_vsock_listener()?;
    eprintln!("[bountynet/vsock] Bridge listening: vsock:{VSOCK_PORT} → 127.0.0.1:{loopback_port}");

    loop {
        let client_fd = unsafe {
            libc::accept(fd, std::ptr::null_mut(), std::ptr::null_mut())
        };
        if client_fd < 0 {
            eprintln!("[bountynet/vsock] Accept failed");
            continue;
        }

        let loopback_port = loopback_port;
        std::thread::spawn(move || {
            if let Err(e) = pipe_vsock_to_tcp(client_fd, loopback_port) {
                eprintln!("[bountynet/vsock] Pipe error: {e}");
            }
        });
    }
}

/// Bridge: TCP → vsock.
/// Runs on the parent instance. Accepts TCP connections on a port
/// and forwards them to the enclave's vsock.
pub fn bridge_tcp_to_vsock(listen_port: u16, enclave_cid: u32) -> Result<()> {
    let listener = std::net::TcpListener::bind(format!("0.0.0.0:{listen_port}"))?;
    eprintln!("[bountynet/vsock] Proxy listening: TCP:{listen_port} → vsock CID {enclave_cid}:{VSOCK_PORT}");

    for stream in listener.incoming() {
        let stream = match stream {
            Ok(s) => s,
            Err(e) => {
                eprintln!("[bountynet/vsock] TCP accept error: {e}");
                continue;
            }
        };

        let cid = enclave_cid;
        std::thread::spawn(move || {
            if let Err(e) = pipe_tcp_to_vsock(stream, cid) {
                eprintln!("[bountynet/vsock] Proxy pipe error: {e}");
            }
        });
    }

    Ok(())
}

/// Serve attestation JSON directly over vsock (simple mode, no TLS).
/// Used as a fallback when loopback is not available.
pub fn serve_vsock(attestation_json: &str) -> Result<()> {
    let fd = create_vsock_listener()?;
    eprintln!("[bountynet/vsock] Serving attestation on vsock port {VSOCK_PORT}");

    loop {
        let client_fd = unsafe {
            libc::accept(fd, std::ptr::null_mut(), std::ptr::null_mut())
        };
        if client_fd < 0 {
            continue;
        }

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
            if n <= 0 { break; }
            written += n as usize;
        }
        unsafe { libc::close(client_fd) };
    }
}

/// TLS server directly on vsock. No loopback needed.
/// Each vsock connection gets a rustls TLS handshake.
/// The parent proxy forwards raw TCP bytes from the verifier.
pub fn serve_tls_vsock(
    tls_config: std::sync::Arc<rustls::ServerConfig>,
    attestation_json: &str,
) -> Result<()> {
    let fd = create_vsock_listener()?;
    eprintln!("[bountynet/vsock] TLS+vsock listening on port {VSOCK_PORT}");

    loop {
        let client_fd = unsafe {
            libc::accept(fd, std::ptr::null_mut(), std::ptr::null_mut())
        };
        if client_fd < 0 {
            eprintln!("[bountynet/vsock] Accept failed");
            continue;
        }

        let config = tls_config.clone();
        let body = attestation_json.to_string();
        std::thread::spawn(move || {
            use std::io::{Read, Write};

            // Wrap vsock fd as a File for Read/Write
            let vsock_stream = unsafe { std::fs::File::from_raw_fd(client_fd) };
            let vsock_read = match vsock_stream.try_clone() {
                Ok(f) => f,
                Err(_) => return,
            };

            // Create a ReadWrite wrapper for rustls
            let mut stream = VsockStream {
                read: vsock_read,
                write: vsock_stream,
            };

            // TLS handshake on the vsock connection
            let conn = match rustls::ServerConnection::new(config) {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("[bountynet/vsock] TLS conn: {e}");
                    return;
                }
            };
            let mut tls = rustls::StreamOwned::new(conn, stream);

            // Read the HTTP request
            let mut buf = [0u8; 4096];
            let _ = tls.read(&mut buf);

            // Serve attestation
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                body.len(), body
            );
            let _ = tls.write_all(response.as_bytes());
            let _ = tls.conn.send_close_notify();
            let _ = tls.flush();
        });
    }
}

/// Wrapper to give a vsock fd both Read and Write via separate cloned fds.
struct VsockStream {
    read: std::fs::File,
    write: std::fs::File,
}

impl std::io::Read for VsockStream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.read.read(buf)
    }
}

impl std::io::Write for VsockStream {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.write.write(buf)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.write.flush()
    }
}

// --- Internal helpers ---

fn create_vsock_listener() -> Result<i32> {
    let fd = unsafe {
        libc::socket(libc::AF_VSOCK, libc::SOCK_STREAM, 0)
    };
    if fd < 0 {
        anyhow::bail!("Failed to create vsock socket: {}", std::io::Error::last_os_error());
    }

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

    Ok(fd)
}

fn pipe_vsock_to_tcp(vsock_fd: i32, loopback_port: u16) -> Result<()> {
    let tcp = std::net::TcpStream::connect(format!("127.0.0.1:{loopback_port}"))?;
    let mut tcp_read = tcp.try_clone()?;
    let mut tcp_write = tcp;

    // vsock fd → safe File wrapper
    let vsock_file = unsafe { std::fs::File::from_raw_fd(vsock_fd) };
    let mut vsock_read = vsock_file.try_clone()?;
    let mut vsock_write = vsock_file;

    // Bidirectional pipe: vsock ↔ tcp
    let handle = std::thread::spawn(move || {
        let mut buf = [0u8; 8192];
        loop {
            let n = match vsock_read.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => n,
            };
            if tcp_write.write_all(&buf[..n]).is_err() { break; }
        }
    });

    let mut buf = [0u8; 8192];
    loop {
        let n = match tcp_read.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => n,
        };
        if vsock_write.write_all(&buf[..n]).is_err() { break; }
    }

    let _ = handle.join();
    Ok(())
}

use std::os::unix::io::FromRawFd;

fn pipe_tcp_to_vsock(tcp: std::net::TcpStream, enclave_cid: u32) -> Result<()> {
    // Connect to enclave vsock
    let vsock_fd = unsafe {
        libc::socket(libc::AF_VSOCK, libc::SOCK_STREAM, 0)
    };
    if vsock_fd < 0 {
        anyhow::bail!("vsock socket failed");
    }

    let mut addr: libc::sockaddr_vm = unsafe { std::mem::zeroed() };
    addr.svm_family = libc::AF_VSOCK as u16;
    addr.svm_port = VSOCK_PORT;
    addr.svm_cid = enclave_cid;

    let ret = unsafe {
        libc::connect(
            vsock_fd,
            &addr as *const libc::sockaddr_vm as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_vm>() as u32,
        )
    };
    if ret < 0 {
        unsafe { libc::close(vsock_fd) };
        anyhow::bail!("vsock connect to CID {enclave_cid} failed: {}", std::io::Error::last_os_error());
    }

    let vsock_file = unsafe { std::fs::File::from_raw_fd(vsock_fd) };
    let mut vsock_read = vsock_file.try_clone()?;
    let mut vsock_write = vsock_file;

    let mut tcp_read = tcp.try_clone()?;
    let mut tcp_write = tcp;

    // Bidirectional pipe: tcp ↔ vsock
    let handle = std::thread::spawn(move || {
        let mut buf = [0u8; 8192];
        loop {
            let n = match tcp_read.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => n,
            };
            if vsock_write.write_all(&buf[..n]).is_err() { break; }
        }
    });

    let mut buf = [0u8; 8192];
    loop {
        let n = match vsock_read.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => n,
        };
        if tcp_write.write_all(&buf[..n]).is_err() { break; }
    }

    let _ = handle.join();
    Ok(())
}
