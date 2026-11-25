//! `mailserv`: a receive-only SMTP server for hosted domains (with optional
//! submission ports). This file is the entry point; the work is in the
//! modules:
//!
//! - [`config`]: command-line and config-file settings;
//! - [`server`]: startup, listeners, the accept loop, signals, and the
//!   per-connection driver;
//! - [`session`]: the SMTP policy for one connection;
//! - [`address`] and [`headers`]: envelope syntax and the raw header
//!   checks;
//! - [`tls`]: certificates and handshakes;
//! - [`auth`], [`authority`], [`spool`], [`delivery`], [`limit`]: AUTH,
//!   recipient policy, storage, delivery and rate limits.

use anyhow::Result;
use clap::Parser as _;
use tracing_bunyan_formatter::{BunyanFormattingLayer, JsonStorageLayer};
use tracing_subscriber::layer::SubscriberExt as _;
use tracing_subscriber::{EnvFilter, Registry};

mod address;
mod auth;
mod authority;
mod config;
mod delivery;
mod fsutil;
mod hashpw;
mod headers;
mod limit;
mod privdrop;
mod server;
mod session;
mod spool;
#[cfg(test)]
mod testutil;
mod tls;
mod verdict;

/// Parse the command line and run: the `hash-password` utility (see
/// [`hashpw::run`]), or the server. For the server, set up JSON logging
/// (`RUST_LOG` filters; `info` by default), make new files private
/// (umask), resolve the configuration (see [`config::load`]) and hand it
/// to [`server::run`].
///
/// # Errors
///
/// An unreadable or invalid config file, an invalid configuration, or
/// any [`server::run`] startup failure.
#[tokio::main]
async fn main() -> Result<()> {
    let args = config::Args::parse();
    // Utilities run before logging is set up, so stdout carries only
    // their output.
    if let Some(config::Command::HashPassword) = args.command {
        return hashpw::run();
    }

    let app_name = concat!(env!("CARGO_PKG_NAME"), "-", env!("CARGO_PKG_VERSION")).to_string();
    let (non_blocking_writer, _guard) = tracing_appender::non_blocking(std::io::stdout());
    let bunyan_formatting_layer = BunyanFormattingLayer::new(app_name, non_blocking_writer);
    // RUST_LOG wins; INFO is the default (e.g. RUST_LOG=debug,
    // RUST_LOG=mailserv=trace).
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("INFO"));
    let subscriber = Registry::default()
        .with(filter)
        .with(JsonStorageLayer)
        .with(bunyan_formatting_layer);
    tracing::subscriber::set_global_default(subscriber)?;

    // Anything created without an explicit mode is private to the service
    // user. The spool and maildirs also set 0600/0700 explicitly.
    privdrop::restrict_umask();

    let config = config::load(args).await?;
    server::run(config).await
}
