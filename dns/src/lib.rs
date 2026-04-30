use anyhow::Result;
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

pub mod proto;
use crate::proto::{DnsMessage, DnsQuestion, Label};

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

    let query = DnsMessage::new(id, vec![question]).to_vec()?;

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
    Ok(dq)
}

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

    let query = DnsMessage::new(id, vec![question]).to_vec()?;
    let mut stream = TcpStream::connect(format!("{}:53", dest)).await?;

    stream.write_u16(query.len() as u16).await?;
    stream.write_all(query.as_slice()).await?;

    let len: u16 = stream.read_u16().await?;
    let mut buf = vec![0; len.into()];
    let count = stream.read_exact(&mut buf).await?;

    let (_, dq) = DnsMessage::from_bytes(&buf[0..count])?;
    Ok(dq)
}

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

    let query = DnsMessage::new(id, vec![question]).to_vec()?;

    let sock = UdpSocket::bind("0.0.0.0:0").await?;
    sock.connect(format!("{}:53", dest)).await?;
    let _ = sock.send(query.as_slice()).await?;

    let mut buf = [0; 65535];
    let len = sock.recv(&mut buf).await?;

    let (_, dq) = DnsMessage::from_bytes(&buf[0..=len])?;
    Ok(dq)
}
