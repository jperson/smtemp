use anyhow::{anyhow, Result};
use std::net::SocketAddr;
use std::str;
use tracing::error;

use std::time::Duration;
use thiserror::Error;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::time::timeout;

#[derive(Error, Debug)]
pub enum SmtpError {
    #[error("command failed")]
    FailedCmd(String),
    #[error("max data size exceeded")]
    MaxData,
    #[error("failed spf check")]
    SpfError,
    #[error("unknown error")]
    Unknown,
}

impl From<anyhow::Error> for SmtpError {
    fn from(_: anyhow::Error) -> Self {
        SmtpError::SpfError
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum SmtpState {
    Idle,
    Ready,
    Data,
    Reset,
    Quit,
}

pub trait SmtpSession {
    const OK: &'static [u8] = b"250 Ok\r\n";
    const SEND_DATA: &'static [u8] = b"354 End data with <CR>.<CR><LF>\n";
    const DATA_END: &'static str = ".\r\n";
    const MAX_DATA: &'static [u8] = b"500 Message exceeds max length\r\n";
    const QUIT: &'static [u8] = b"221 Bye\r\n";
    const CONT: &'static [u8] = &[];
    const UNKNOWN: &'static [u8] = b"500 Unknown\r\n";
    const INVALID_SEQ: &'static [u8] = b"503 5.5.1 Invalid sequence.\r\n";
    const MULTI_MAIL: &'static [u8] = b"503 5.5.1 Multiple MAIL FROM commands not allowed.\r\n";
    const SPF_FAILED: &'static [u8] = b"550 5.7.23 SPF validation failed\r\n";

    //async fn server_greet(&self) -> Result<&[u8], SmtpError>;
    fn server_greet(&self) -> impl std::future::Future<Output = Result<&[u8], SmtpError>> + Send;
    fn helo_callback(
        &mut self,
        helo: Option<&str>,
    ) -> impl std::future::Future<Output = Result<&[u8], SmtpError>> + Send;
    fn mail_from_callback(
        &mut self,
        mail_from: Option<&str>,
    ) -> impl std::future::Future<Output = Result<&[u8], SmtpError>> + Send;
    fn rcpt_to_callback(
        &mut self,
        rcpt_to: Option<&str>,
    ) -> impl std::future::Future<Output = Result<&[u8], SmtpError>> + Send;
    fn start_data_callback(
        &mut self,
    ) -> impl std::future::Future<Output = Result<&[u8], SmtpError>> + Send;
    fn recv_data_callback(
        &mut self,
        data: Option<&str>,
    ) -> impl std::future::Future<Output = Result<&[u8], SmtpError>> + Send;
    fn end_data_callback(
        &mut self,
        data: Option<&str>,
    ) -> impl std::future::Future<Output = Result<&[u8], SmtpError>> + Send;

    fn run(
        &mut self,
        stream: &mut BufReader<TcpStream>,
        _peer: &SocketAddr,
        _domain: &str,
        max_read_duration_ms: &u64,
    ) -> impl std::future::Future<Output = Result<()>> + Send
    where
        Self: Send,
    {
        async {
            let mut state: &SmtpState = &SmtpState::Idle;

            if let Ok(resp) = self.server_greet().await {
                let _ = stream.write(resp).await;
            }

            while let Ok(Ok(_)) = timeout(Duration::from_millis(*max_read_duration_ms), async {
                let mut line = String::new();
                if stream.read_line(&mut line).await? == 0 {
                    return Err(anyhow!("Stream closed"));
                }

                if let Ok((resp, new_state)) = self.handler(state, line.as_str()).await {
                    state = new_state;
                    if !resp.is_empty() {
                        let _ = stream.write(resp).await;
                    }
                }
                Ok(())
            })
            .await
            {
                if *state == SmtpState::Quit {
                    break;
                }
            }
            Ok(())
        }
    }

    fn handler<'s>(
        &mut self,
        state: &'s SmtpState,
        msg: &str,
    ) -> impl std::future::Future<Output = Result<(&[u8], &'s SmtpState), SmtpError>> + Send
    where
        Self: Send,
    {
        async move {
            let cmd: Vec<&str> = msg.splitn(2, ' ').collect();

            match (state, cmd[0].trim_end().to_lowercase().as_str()) {
                (SmtpState::Idle, "helo") | (SmtpState::Idle, "ehlo") => Ok((
                    self.helo_callback(Some(cmd[1].trim_end())).await?,
                    &SmtpState::Ready,
                )),
                (SmtpState::Ready, "rcpt") => {
                    if cmd[1].to_lowercase().starts_with("to:") {
                        Ok((
                            self.rcpt_to_callback(Some(cmd[1][3..].trim_end())).await?,
                            state,
                        ))
                    } else {
                        Ok((Self::UNKNOWN, &SmtpState::Idle))
                    }
                }
                (SmtpState::Ready, "mail") => {
                    if cmd[1].to_lowercase().starts_with("from:") {
                        Ok((
                            self.mail_from_callback(Some(cmd[1][5..].trim_end()))
                                .await?,
                            state,
                        ))
                    } else {
                        Ok((Self::UNKNOWN, &SmtpState::Idle))
                    }
                }
                (SmtpState::Ready, "data") => {
                    Ok((self.start_data_callback().await?, &SmtpState::Data))
                }
                (SmtpState::Data, _) => {
                    if msg == Self::DATA_END {
                        Ok((self.end_data_callback(Some(msg)).await?, &SmtpState::Ready))
                    } else {
                        match self.recv_data_callback(Some(msg)).await {
                            Ok(_) => Ok((Self::CONT, state)),
                            Err(SmtpError::MaxData) => Ok((Self::MAX_DATA, &SmtpState::Ready)),
                            Err(_) => Ok((Self::UNKNOWN, &SmtpState::Idle)),
                        }
                    }
                }
                (SmtpState::Ready, "vrfy") => Ok((Self::OK, state)),
                (SmtpState::Ready, "noop") => Ok((Self::OK, state)),
                (SmtpState::Ready, "help") => Ok((Self::OK, state)),
                (SmtpState::Ready, "expn") => Ok((Self::OK, state)),
                (_, "rset") => Ok((Self::OK, &SmtpState::Idle)),
                (_, "quit") => Ok((Self::QUIT, &SmtpState::Quit)),
                _ => Ok((Self::UNKNOWN, &SmtpState::Idle)),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // #[test]
    // fn basic_session() {
    //     let mut sess = SmtpSession::new(&String::from("example.org"), 10);
    //     assert_eq!(sess.state, SmtpState::Idle);
    //
    //     assert_eq!(
    //         sess.handler("HELO foo.net").unwrap(),
    //         b"250 example.org Hello\n"
    //     );
    //     assert_eq!(sess.to_owned().state, SmtpState::Ready);
    //     assert_eq!(sess.to_owned().helo, Some(String::from("foo.net")));
    //
    //     assert_eq!(
    //         sess.handler("RCPT TO test@example.net").unwrap(),
    //         SmtpSession::OK
    //     );
    //     assert_eq!(sess.to_owned().state, SmtpState::Ready);
    //     assert_eq!(sess.to_owned().rcpt, vec!["test@example.net"]);
    //
    //     assert_eq!(sess.handler("DATA").unwrap(), SmtpSession::SEND_DATA);
    //     assert_eq!(sess.to_owned().state, SmtpState::Data);
    //
    //     assert_eq!(sess.handler("A simple test").unwrap(), SmtpSession::CONT);
    //     assert_eq!(sess.to_owned().data, vec!["A simple test"]);
    //     assert_eq!(sess.to_owned().state, SmtpState::Data);
    //
    //     assert_eq!(sess.handler("with two lines.").unwrap(), SmtpSession::CONT);
    //     assert_eq!(
    //         sess.to_owned().data,
    //         vec!["A simple test", "with two lines."]
    //     );
    //     assert_eq!(sess.to_owned().state, SmtpState::Data);
    //
    //     assert_eq!(sess.handler(".\r\n").unwrap(), SmtpSession::OK);
    //     assert_eq!(sess.to_owned().state, SmtpState::Ready);
    //
    //     assert_eq!(sess.handler("QUIT").unwrap(), SmtpSession::QUIT);
    //     assert_eq!(sess.to_owned().state, SmtpState::Quit);
    // }
}
