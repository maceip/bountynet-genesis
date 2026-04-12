//! TLS server for ACME challenge + attestation serving.
//!
//! Runs on port 443. Two phases:
//! 1. ACME challenge: present the challenge cert with acmeIdentifier extension
//! 2. Normal operation: present the Let's Encrypt cert, serve attestation JSON

use anyhow::Result;
use rustls::server::ServerConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::RwLock;
use tokio_rustls::TlsAcceptor;

/// Shared TLS state — hot-swappable cert.
pub struct TlsState {
    config: RwLock<Arc<ServerConfig>>,
    attestation_json: RwLock<String>,
}

impl TlsState {
    /// Create with a self-signed cert (for ACME challenge phase).
    pub fn new_self_signed(domain: &str) -> Result<Self> {
        // Install ring crypto provider for rustls
        let _ = rustls::crypto::ring::default_provider().install_default();
        let key_pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)?;
        let params = rcgen::CertificateParams::new(vec![domain.to_string()])?;
        let cert = params.self_signed(&key_pair)?;

        let config = make_server_config(
            cert.pem().as_bytes(),
            key_pair.serialize_pem().as_bytes(),
        )?;

        Ok(Self {
            config: RwLock::new(Arc::new(config)),
            attestation_json: RwLock::new("{}".to_string()),
        })
    }

    /// Update the cert (after ACME provisioning completes).
    pub async fn set_cert(&self, cert_pem: &[u8], key_pem: &[u8]) -> Result<()> {
        let config = make_server_config(cert_pem, key_pem)?;
        let mut guard = self.config.write().await;
        *guard = Arc::new(config);
        Ok(())
    }

    /// Set the attestation JSON to serve.
    pub async fn set_attestation(&self, json: String) {
        let mut guard = self.attestation_json.write().await;
        *guard = json;
    }

    async fn get_config(&self) -> Arc<ServerConfig> {
        self.config.read().await.clone()
    }

    async fn get_attestation(&self) -> String {
        self.attestation_json.read().await.clone()
    }

    /// Sync version for use inside Nitro Enclaves (no tokio)
    pub fn get_config_sync(&self) -> Arc<ServerConfig> {
        self.config.blocking_read().clone()
    }

    /// Sync version for use inside Nitro Enclaves (no tokio)
    pub fn get_attestation_sync(&self) -> String {
        self.attestation_json.blocking_read().clone()
    }

    /// Sync version of set_attestation
    pub fn set_attestation_sync(&self, json: String) {
        let mut guard = self.attestation_json.blocking_write();
        *guard = json;
    }
}

/// Start the TLS server. Runs until cancelled.
pub async fn serve(state: Arc<TlsState>, port: u16) -> Result<()> {
    let listener = TcpListener::bind(format!("0.0.0.0:{port}")).await?;
    eprintln!("[bountynet/tls] Listening on :{port}");

    loop {
        let (stream, addr) = listener.accept().await?;
        let state = state.clone();

        tokio::spawn(async move {
            let config = state.get_config().await;
            let acceptor = TlsAcceptor::from(config);

            match acceptor.accept(stream).await {
                Ok(mut tls_stream) => {
                    // Read the request (we only care that they connected)
                    let mut buf = [0u8; 4096];
                    let _ = tls_stream.read(&mut buf).await;

                    // Serve the attestation JSON as an HTTP response
                    let body = state.get_attestation().await;
                    let response = format!(
                        "HTTP/1.1 200 OK\r\n\
                         Content-Type: application/json\r\n\
                         Content-Length: {}\r\n\
                         Access-Control-Allow-Origin: *\r\n\
                         \r\n\
                         {}",
                        body.len(),
                        body
                    );
                    let _ = tls_stream.write_all(response.as_bytes()).await;
                    let _ = tls_stream.shutdown().await;
                }
                Err(e) => {
                    // TLS handshake failed — this is normal during ACME challenges
                    // when Let's Encrypt probes with non-matching SNI
                    eprintln!("[bountynet/tls] Handshake failed from {addr}: {e}");
                }
            }
        });
    }
}

fn make_server_config(cert_pem: &[u8], key_pem: &[u8]) -> Result<ServerConfig> {
    let certs: Vec<CertificateDer> = rustls_pemfile::certs(&mut &*cert_pem)
        .collect::<Result<Vec<_>, _>>()?;

    let key = rustls_pemfile::private_key(&mut &*key_pem)?
        .ok_or_else(|| anyhow::anyhow!("no private key found in PEM"))?;

    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)?;

    Ok(config)
}
