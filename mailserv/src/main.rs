use anyhow::Result;
use clap::Parser;
use serde::Serialize;
use std::net::{Ipv4Addr, SocketAddr};
use std::str;
use std::time::Duration;
use tokio::io::BufReader;
use tokio::net::TcpListener;
use tokio::time::{timeout_at, Instant};
use tracing::{info, instrument};
use tracing_bunyan_formatter::{BunyanFormattingLayer, JsonStorageLayer};
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::{EnvFilter, Registry};
use uuid::Uuid;

use smtp::SmtpSession;
use spf::SpfResult;

/// Simple program to greet a person
#[derive(Parser, Debug, Clone)]
#[command(version, about, long_about = None)]
struct Args {
    #[arg(long, default_value_t = String::from("0.0.0.0"))]
    host: String,

    #[arg(long, default_value_t = 2525)]
    port: u16,

    #[arg(long)]
    domain: String,

    /// Number of times to greet
    #[arg(long, default_value_t = 1024*1024)]
    max_data_bytes: usize,

    #[arg(long, default_value_t = 30*1000)]
    max_conn_duration_ms: u64,

    #[arg(long, default_value_t = 15*1000)]
    max_read_duration_ms: u64,
}

#[derive(Debug, Eq, PartialEq, Serialize)]
struct UserSession<'session> {
    #[serde(skip_serializing)]
    pub max_data: usize,

    #[serde(skip_serializing)]
    pub total_data: usize,

    pub session_id: Uuid,
    domain: &'session str,
    dns: Ipv4Addr,
    peer: SocketAddr,

    #[serde(skip_serializing)]
    greet: String,

    helo: Option<String>,
    mail_from: Option<String>,
    rcpt_to: Vec<String>,
    data: String,
    spf_result: Option<SpfResult>,
}

impl<'session> UserSession<'session> {
    fn new(domain: &'session str, peer: SocketAddr, max_data: usize) -> Self {
        UserSession {
            max_data,
            total_data: 0,
            session_id: Uuid::new_v4(),

            domain,
            greet: format!("220 {} SMTP service ready\n", domain),
            dns: "1.1.1.1".parse::<Ipv4Addr>().unwrap(),
            peer,

            helo: None,
            mail_from: None,
            rcpt_to: Vec::new(),
            data: String::new(),
            spf_result: None,
        }
    }
}

impl smtp::SmtpSession for UserSession<'_> {
    #[instrument(skip(self), fields(session = self.session_id.to_string(), peer = self.peer.to_string()))]
    fn server_greet(
        &self,
    ) -> impl std::future::Future<Output = Result<&[u8], smtp::SmtpError>> + Send {
        async { Ok(self.greet.as_bytes()) }
    }

    #[instrument(skip(self, helo), fields(session = self.session_id.to_string(), peer = self.peer.to_string()))]
    fn helo_callback(
        &mut self,
        helo: Option<&str>,
    ) -> impl std::future::Future<Output = Result<&[u8], smtp::SmtpError>> + Send {
        async {
            if let Some(h) = helo {
                self.helo = Some(h.to_string());

                self.spf_result = Some(
                    spf::check_host(
                        &self.dns,
                        self.peer.ip(),
                        &h.to_string(),
                        self.domain.to_string(),
                        &self.helo,
                    )
                    .await?,
                );

                match self.spf_result {
                    Some(SpfResult::Pass) | Some(SpfResult::Neutral) => Ok(self.greet.as_bytes()),
                    _ => Ok(UserSession::SPF_FAILED),
                }
            } else {
                Err(smtp::SmtpError::FailedCmd("HELO Failed".to_string()))
            }
        }
    }

    #[instrument(skip(self, mail_from), fields(session = self.session_id.to_string(), peer = self.peer.to_string()))]
    fn mail_from_callback(
        &mut self,
        mail_from: Option<&str>,
    ) -> impl std::future::Future<Output = Result<&[u8], smtp::SmtpError>> + Send {
        async {
            if self.helo.is_none() {
                Ok(UserSession::INVALID_SEQ)
            } else if self.mail_from.is_some() {
                Ok(UserSession::MULTI_MAIL)
            } else if let Some(mail_from) = mail_from {
                self.mail_from = Some(mail_from.to_string());
                self.spf_result = Some(
                    spf::check_host(
                        &self.dns,
                        self.peer.ip(),
                        &mail_from.to_string(),
                        self.domain.to_string(),
                        &self.helo,
                    )
                    .await?,
                );

                if self.spf_result != Some(spf::SpfResult::Pass) {
                    Ok(UserSession::SPF_FAILED)
                } else {
                    Ok(UserSession::OK)
                }
            } else {
                Err(smtp::SmtpError::FailedCmd("MAIL FROM Failed".to_string()))
            }
        }
    }

    #[instrument(skip(self, rcpt_to), fields(session = self.session_id.to_string(), peer = self.peer.to_string()))]
    fn rcpt_to_callback(
        &mut self,
        rcpt_to: Option<&str>,
    ) -> impl std::future::Future<Output = Result<&[u8], smtp::SmtpError>> + Send {
        async {
            if let Some(rcpt_to) = rcpt_to {
                self.rcpt_to.push(rcpt_to.to_string());
                Ok(UserSession::OK)
            } else {
                Err(smtp::SmtpError::FailedCmd("RCTP TO Failed".to_string()))
            }
        }
    }

    #[instrument(skip(self), fields(session = self.session_id.to_string(), peer = self.peer.to_string()))]
    fn start_data_callback(
        &mut self,
    ) -> impl std::future::Future<Output = Result<&[u8], smtp::SmtpError>> + Send {
        async { Ok(UserSession::SEND_DATA) }
    }

    #[instrument(skip(self, data), fields(session = self.session_id.to_string(), peer = self.peer.to_string()))]
    fn recv_data_callback(
        &mut self,
        data: Option<&str>,
    ) -> impl std::future::Future<Output = Result<&[u8], smtp::SmtpError>> + Send {
        async {
            match data {
                Some(d) if self.total_data + d.len() < self.max_data => {
                    self.data += d;
                    Ok(UserSession::OK)
                }
                Some(d) if self.total_data + d.len() >= self.max_data => {
                    Err(smtp::SmtpError::MaxData)
                }
                _ => Err(smtp::SmtpError::Unknown),
            }
        }
    }

    #[instrument(skip(self, _data), fields(session = self.session_id.to_string(), peer = self.peer.to_string()))]
    fn end_data_callback(
        &mut self,
        _data: Option<&str>,
    ) -> impl std::future::Future<Output = Result<&[u8], smtp::SmtpError>> + Send {
        async { Ok(UserSession::OK) }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let app_name = concat!(env!("CARGO_PKG_NAME"), "-", env!("CARGO_PKG_VERSION")).to_string();

    let (non_blocking_writer, _guard) = tracing_appender::non_blocking(std::io::stdout());
    let bunyan_formatting_layer = BunyanFormattingLayer::new(app_name, non_blocking_writer);
    let subscriber = Registry::default()
        .with(EnvFilter::new("INFO"))
        .with(JsonStorageLayer)
        .with(bunyan_formatting_layer);
    tracing::subscriber::set_global_default(subscriber).unwrap();

    let args = Args::parse();
    let listener = TcpListener::bind(format!("{}:{}", args.host, args.port)).await?;

    loop {
        let (stream, _) = listener.accept().await?;
        let domain = args.domain.clone();

        tokio::spawn(timeout_at(
            Instant::now() + Duration::from_millis(args.max_conn_duration_ms),
            async move {
                let peer = stream.peer_addr()?;
                let mut stream = BufReader::new(stream);

                let mut session = UserSession::new(domain.as_str(), peer, args.max_data_bytes);
                session
                    .run(&mut stream, &peer, &domain, &args.max_read_duration_ms)
                    .await?;

                info!("{}", serde_json::to_string(&session)?);
                Ok::<(), anyhow::Error>(())
            },
        ));
    }
}
