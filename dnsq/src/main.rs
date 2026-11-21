use anyhow::Result;
use clap::Parser;
use serde::Serialize;
use std::net::Ipv4Addr;
// use rand::Rng;
// use rustls_pki_types::ServerName;
// use std::sync::Arc;
// use tokio::io::{AsyncReadExt, AsyncWriteExt};
// use tokio::net::TcpStream;
// use tokio::net::UdpSocket;
// use tokio_rustls::rustls::ClientConfig;
// use tokio_rustls::TlsConnector;
// use webpki_roots;

use dns::{query_tcp, query_tls};

#[repr(u16)]
#[derive(Debug, Clone, Default, clap::ValueEnum, Serialize)]
enum QueryType {
    #[default]
    A = 1,
    NS = 2,
    CNAME = 5,
    SOA = 6,
    PTR = 12,
    HINFO = 13,
    MX = 15,
    TXT = 16,
    RP = 17,
    AFSDB = 18,
    SIG = 24,
    KEY = 25,
    AAAA = 28,
    LOC = 29,
    SRV = 33,
    NAPTR = 35,
    KX = 36,
    CERT = 37,
    DNAME = 39,
    OPT = 41,
    APL = 42,
    DS = 43,
    SSHFP = 44,
    IPSECKEY = 45,
    RRSIG = 46,
    NSEC = 47,
    DNSKEY = 48,
    DHCID = 49,
    NSEC3 = 50,
    NSEC3PARAM = 51,
    TLSA = 52,
    SMIMEA = 53,
    HIP = 55,
    CDS = 59,
    CDNSKEY = 60,
    OPENPGPKEY = 61,
    CSYNC = 62,
    ZONEMD = 63,
    SVCB = 64,
    HTTPS = 65,
    EUI48 = 108,
    EUI64 = 109,
    TKEY = 249,
    TSIG = 250,
    IXFR = 251,
    AXFR = 252,
    STAR = 255,
    URI = 256,
    CAA = 257,
    TA = 32768,
    DLV = 32769,
}

#[derive(Parser, Debug, Clone)]
#[command(version, about, long_about = None)]
struct Args {
    #[arg(long)]
    domain: String,
    #[clap(short, long, default_value_t, value_enum)]
    query_type: QueryType,
    #[clap(short, long, default_value_t = 0x01)]
    record_class: u16,
    #[arg(long, default_value_t = false)]
    tcp: bool,
    #[arg(long, default_value_t = false)]
    tls: bool,
    #[arg(long, default_value = "1.1.1.1")]
    server: Ipv4Addr,
}

#[tokio::main]
async fn main() -> Result<()> {
    let _app_name = concat!(env!("CARGO_PKG_NAME"), "-", env!("CARGO_PKG_VERSION")).to_string();
    let args = Args::parse();
    let query_type = args.query_type as u16;

    if args.tls {
        let dq = query_tls(&args.server, &args.domain, query_type, args.record_class).await?;
        println!("{}", serde_json::to_string(&dq)?);
    } else {
        let dq = query_tcp(&args.server, &args.domain, query_type, args.record_class).await?;
        println!("{}", serde_json::to_string(&dq)?);
    }

    Ok(())
}
