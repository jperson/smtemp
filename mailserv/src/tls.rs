//! TLS setup: the certificate and key for STARTTLS and implicit TLS, the
//! extra resolver CA for DNS-over-TLS, and the server-side handshake.

use anyhow::Result;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio_rustls::rustls::pki_types::pem::PemObject as _;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio_rustls::TlsAcceptor;
use tracing::info;

/// Run the server side of a TLS handshake with `acceptor` on `stream`
/// from `peer`, within 10 s.
///
/// Returns the TLS stream, or `None` (logged at `info`) when the
/// handshake fails or times out.
pub(crate) async fn tls_handshake(
    acceptor: &TlsAcceptor,
    stream: TcpStream,
    peer: SocketAddr,
) -> Option<tokio_rustls::server::TlsStream<TcpStream>> {
    match tokio::time::timeout(Duration::from_secs(10), acceptor.accept(stream)).await {
        Ok(Ok(tls)) => {
            info!(peer = %peer, "TLS established");
            Some(tls)
        }
        Ok(Err(e)) => {
            info!(peer = %peer, error = %e, "TLS handshake failed");
            None
        }
        Err(_) => {
            info!(peer = %peer, "TLS handshake timed out");
            None
        }
    }
}

/// Build a TLS acceptor from the PEM-encoded certificate chain at
/// `cert_path` and private key at `key_path`.
///
/// # Errors
///
/// Either file cannot be read, or their contents are rejected (see
/// [`tls_acceptor_from_pem`]).
pub(crate) async fn build_tls_acceptor(cert_path: &str, key_path: &str) -> Result<TlsAcceptor> {
    let cert_pem = tokio::fs::read(cert_path).await?;
    let key_pem = tokio::fs::read(key_path).await?;
    tls_acceptor_from_pem(&cert_pem, &key_pem)
}

/// Read the `--resolver-ca` PEM file at `path`.
///
/// Returns every certificate in the file, in order.
///
/// # Errors
///
/// The file can't be read, isn't valid PEM, or holds no certificate at
/// all — an empty or mistyped CA file must stop startup, not silently
/// leave the local resolver untrusted.
pub(crate) async fn load_resolver_ca(path: &str) -> Result<Vec<CertificateDer<'static>>> {
    let pem = tokio::fs::read(path)
        .await
        .map_err(|e| anyhow::anyhow!("cannot read resolver CA file {path}: {e}"))?;
    resolver_ca_from_pem(&pem).map_err(|e| anyhow::anyhow!("invalid resolver CA file {path}: {e}"))
}

/// Parse the PEM certificates in `pem` for [`load_resolver_ca`].
///
/// Returns every certificate, in order; other PEM sections are skipped.
///
/// # Errors
///
/// A malformed PEM section, or no certificate at all.
pub(crate) fn resolver_ca_from_pem(pem: &[u8]) -> Result<Vec<CertificateDer<'static>>> {
    let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(pem)
        .collect::<std::result::Result<_, _>>()
        .map_err(|e| anyhow::anyhow!("malformed PEM: {e}"))?;
    if certs.is_empty() {
        anyhow::bail!("no PEM certificates found");
    }
    Ok(certs)
}

/// Build a TLS acceptor (no client authentication) from the PEM
/// certificate chain `cert_pem` and the PEM private key `key_pem` (the
/// first key in it).
///
/// # Errors
///
/// Malformed PEM, no private key, or a certificate/key pair rustls
/// rejects.
pub(crate) fn tls_acceptor_from_pem(cert_pem: &[u8], key_pem: &[u8]) -> Result<TlsAcceptor> {
    let certs: Vec<CertificateDer> = CertificateDer::pem_slice_iter(cert_pem)
        .collect::<std::result::Result<_, _>>()
        .map_err(|e| anyhow::anyhow!("malformed certificate PEM: {e}"))?;
    let key = PrivateKeyDer::from_pem_slice(key_pem).map_err(|e| match e {
        tokio_rustls::rustls::pki_types::pem::Error::NoItemsFound => {
            anyhow::anyhow!("no private key found")
        }
        e => anyhow::anyhow!("malformed private key PEM: {e}"),
    })?;

    let config = tokio_rustls::rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)?;
    Ok(TlsAcceptor::from(Arc::new(config)))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The CA file loads every certificate it holds, and a missing,
    /// empty, or non-certificate file is a startup error, never a silent
    /// fallback to "local resolver untrusted".
    #[tokio::test]
    async fn resolver_ca_file_loading() {
        let a = rcgen::generate_simple_self_signed(vec!["127.0.0.1".into()]).unwrap();
        let b = rcgen::generate_simple_self_signed(vec!["10.0.0.53".into()]).unwrap();
        let pem = format!("{}{}", a.cert.pem(), b.cert.pem());

        let certs = resolver_ca_from_pem(pem.as_bytes()).unwrap();
        assert_eq!(certs.len(), 2);
        assert_eq!(certs[0].as_ref(), a.cert.der().as_ref());

        // The loaded roots are accepted by the DNS client (and public
        // roots stay; see the dns crate's extra_roots tests).
        dns::DnsClient::new("127.0.0.1".parse().unwrap())
            .with_extra_roots(&certs)
            .unwrap();

        assert!(resolver_ca_from_pem(b"").is_err());
        // A private key alone is not a CA file.
        assert!(resolver_ca_from_pem(a.key_pair.serialize_pem().as_bytes()).is_err());

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ca.pem");
        std::fs::write(&path, &pem).unwrap();
        assert_eq!(
            load_resolver_ca(path.to_str().unwrap())
                .await
                .unwrap()
                .len(),
            2
        );
        let missing = dir.path().join("missing.pem");
        let err = load_resolver_ca(missing.to_str().unwrap())
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("cannot read resolver CA file"),
            "{err}"
        );
    }
}
