//! ACME TLS-ALPN-01 certificate provisioning.
//!
//! At boot, stage 1 requests a TLS cert from Let's Encrypt for its
//! Value X domain: <value_x_prefix>.aeon.site
//!
//! TLS-ALPN-01: Let's Encrypt connects to port 443, the TEE responds.
//! The cert appears in Certificate Transparency logs automatically.

use anyhow::Result;
use instant_acme::{
    Account, AuthorizationStatus, ChallengeType, Identifier, LetsEncrypt, NewAccount, NewOrder,
    OrderStatus, RetryPolicy,
};

/// Derive the domain name from Value X.
/// Uses the first 12 hex chars of Value X as the subdomain.
pub fn domain_from_value_x(value_x: &[u8; 48]) -> String {
    let prefix = hex::encode(&value_x[..6]);
    format!("{prefix}.aeon.site")
}

/// Request a TLS certificate from Let's Encrypt.
///
/// Returns (cert_chain_pem, private_key_pem).
///
/// For TLS-ALPN-01, the caller must handle the challenge by running a
/// TLS server on port 443 that presents the challenge response.
/// This function uses DNS-01 as a starting point — TLS-ALPN-01 requires
/// integration with the TLS listener which we wire in cmd_run.
pub async fn provision_cert(
    value_x: &[u8; 48],
    use_staging: bool,
) -> Result<(String, String)> {
    let domain = domain_from_value_x(value_x);
    eprintln!("[bountynet/acme] Requesting cert for: {domain}");

    let url = if use_staging {
        LetsEncrypt::Staging.url()
    } else {
        LetsEncrypt::Production.url()
    };

    // Create ACME account
    let (account, _credentials) = Account::builder()?
        .create(
            &NewAccount {
                contact: &[],
                terms_of_service_agreed: true,
                only_return_existing: false,
            },
            url.to_owned(),
            None,
        )
        .await?;

    eprintln!("[bountynet/acme] Account created");

    // Create order
    let identifiers = vec![Identifier::Dns(domain.clone())];
    let mut order = account
        .new_order(&NewOrder::new(&identifiers))
        .await?;

    eprintln!("[bountynet/acme] Order created");

    // Process authorizations
    let mut authorizations = order.authorizations();
    while let Some(result) = authorizations.next().await {
        let mut authz = result?;
        match authz.status {
            AuthorizationStatus::Pending => {}
            AuthorizationStatus::Valid => continue,
            status => anyhow::bail!("Unexpected authorization status: {status:?}"),
        }

        // Get TLS-ALPN-01 challenge
        let mut challenge = authz
            .challenge(ChallengeType::TlsAlpn01)
            .ok_or_else(|| anyhow::anyhow!("No TLS-ALPN-01 challenge offered"))?;

        let key_auth = challenge.key_authorization();
        eprintln!(
            "[bountynet/acme] TLS-ALPN-01 challenge for {}",
            challenge.identifier()
        );
        eprintln!(
            "[bountynet/acme] Key authorization: {}",
            key_auth.as_str()
        );

        // TODO: The caller needs to set up a TLS listener on port 443
        // that presents a self-signed cert with the acmeIdentifier extension
        // containing sha256(key_authorization).
        // For now, print what's needed and the caller handles it.

        challenge.set_ready().await?;
    }

    // Wait for order to be ready
    let status = order.poll_ready(&RetryPolicy::default()).await?;
    if status != OrderStatus::Ready {
        anyhow::bail!("Order not ready: {status:?}");
    }

    eprintln!("[bountynet/acme] Challenge passed, finalizing...");

    // Finalize — this generates the key and CSR internally
    let private_key_pem = order.finalize().await?;
    let cert_chain_pem = order.poll_certificate(&RetryPolicy::default()).await?;

    eprintln!("[bountynet/acme] Certificate issued for {domain}");
    eprintln!("[bountynet/acme] Cert will appear in CT logs.");

    Ok((cert_chain_pem, private_key_pem))
}
