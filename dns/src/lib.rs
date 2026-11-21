//! DNS client: wire-format codec and DNS-over-TLS queries.
//!
//! Response parsing is total (bounds-checked everywhere): responses come
//! from the configured resolver, which may be buggy, spoofed, or
//! compromised — a malformed answer is an `Err`, never a panic.
#![warn(missing_docs)]

use anyhow::{anyhow, Result};
//use rand::Rng;
use rand::prelude::*;
use rand::rngs::StdRng;
use rustls_pki_types::ServerName;
use std::net::Ipv4Addr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::net::UdpSocket;
use tokio_rustls::rustls::ClientConfig;
use tokio_rustls::TlsConnector;

/// The DNS protocol module: message/record codec and wire helpers.
pub mod proto;
use crate::proto::{DnsMessage, DnsQuestion, Label};

/// Verify a response actually answers our query (RFC 5452 hardening
/// against resolver confusion and spoofed datagrams): the transaction ID
/// matches, it is marked as a response, and the question section echoes
/// the question.
fn validate_response(query: &DnsMessage, resp: &DnsMessage) -> Result<()> {
    if resp.header.transaction_id != query.header.transaction_id {
        return Err(anyhow!(
            "DNS response transaction ID mismatch ({} != {})",
            resp.header.transaction_id,
            query.header.transaction_id
        ));
    }
    if resp.header.qr != 1 {
        return Err(anyhow!("DNS response is not marked as a response"));
    }
    if resp.questions.first() != query.questions.first() {
        return Err(anyhow!("DNS response question mismatch"));
    }
    Ok(())
}

/// Query over DNS-over-TLS (port 853): the authenticated, preferred
/// transport. The response is validated (ID, QR, question echo) before
/// it is returned.
pub async fn query_tls<'query>(
    dest: &'query Ipv4Addr,
    domain: &'query str,
    record_type: u16,
    record_class: u16,
) -> Result<DnsMessage> {
    let mut rng = StdRng::from_entropy();
    let id: u16 = rng.gen();

    let question = DnsQuestion {
        name: Label::new(domain.to_string()),
        record_type,
        record_class,
    };

    let msg = DnsMessage::new(id, vec![question]);
    let query = msg.to_vec()?;

    let mut root_cert_store = tokio_rustls::rustls::RootCertStore::empty();
    root_cert_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    let config = ClientConfig::builder()
        .with_root_certificates(root_cert_store)
        .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(config));
    let stream = TcpStream::connect(format!("{}:853", dest)).await?;
    let dnsname = ServerName::try_from(dest.to_string()).unwrap().to_owned();

    let mut stream = connector.connect(dnsname, stream).await?;

    stream.write_u16(query.len() as u16).await?;
    stream.write_all(query.as_slice()).await?;

    let len: u16 = stream.read_u16().await?;
    let mut buf = vec![0; len.into()];
    let count = stream.read_exact(&mut buf).await?;

    let (_, dq) = DnsMessage::from_bytes(&buf[0..count])?;
    validate_response(&msg, &dq)?;
    Ok(dq)
}

/// Query over plain TCP (port 53). The response is validated before it
/// is returned. No timeout is applied; prefer [`query_tls`].
pub async fn query_tcp<'query>(
    dest: &'query Ipv4Addr,
    domain: &'query str,
    record_type: u16,
    record_class: u16,
) -> Result<DnsMessage> {
    let mut rng = rand::thread_rng();
    let id: u16 = rng.gen();

    let question = DnsQuestion {
        name: Label::new(domain.to_string()),
        record_type,
        record_class,
    };

    let msg = DnsMessage::new(id, vec![question]);
    let query = msg.to_vec()?;
    let mut stream = TcpStream::connect(format!("{}:53", dest)).await?;

    stream.write_u16(query.len() as u16).await?;
    stream.write_all(query.as_slice()).await?;

    let len: u16 = stream.read_u16().await?;
    let mut buf = vec![0; len.into()];
    let count = stream.read_exact(&mut buf).await?;

    let (_, dq) = DnsMessage::from_bytes(&buf[0..count])?;
    validate_response(&msg, &dq)?;
    Ok(dq)
}

/// Query over UDP (port 53). Single datagram, no retry, no timeout, and
/// only ID-based validation — not robust against spoofing. Prefer
/// [`query_tls`] in production.
pub async fn query_udp<'query>(
    dest: &'query Ipv4Addr,
    domain: &'query str,
    record_type: u16,
    record_class: u16,
) -> Result<DnsMessage> {
    let mut rng = rand::thread_rng();
    let id: u16 = rng.gen();

    let question = DnsQuestion {
        name: Label::new(domain.to_string()),
        record_type,
        record_class,
    };

    let msg = DnsMessage::new(id, vec![question]);
    let query = msg.to_vec()?;

    let sock = UdpSocket::bind("0.0.0.0:0").await?;
    sock.connect(format!("{}:53", dest)).await?;
    let _ = sock.send(query.as_slice()).await?;

    let mut buf = [0; 65535];
    let len = sock.recv(&mut buf).await?;

    // `recv` returns at most `buf.len()` bytes; slicing `..=len` would
    // panic when len == buf.len() (off-by-one).
    let (_, dq) = DnsMessage::from_bytes(&buf[..len])?;
    validate_response(&msg, &dq)?;
    Ok(dq)
}
