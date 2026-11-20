use std::future::Future;
use std::net::SocketAddr;
use std::time::Duration;

use anyhow::{anyhow, Result};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::time::timeout;

/// What the session policy decided about a command: the reply to send to
/// the client, and whether the protocol state machine is allowed to
/// advance.
///
/// This is what makes rejections binding rather than advisory: a rejected
/// HELO leaves the session in [`SmtpState::Idle`], a rejected DATA leaves
/// it in [`SmtpState::Ready`], and so on — a client cannot proceed past a
/// refused command even if it ignores the reply.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Control {
    /// The command succeeded. The state machine advances where the
    /// protocol defines a transition (HELO: Idle→Ready, DATA: Ready→Data).
    Accept(Vec<u8>),
    /// Permanently refused (a 5xx reply). The state does not advance.
    Reject(Vec<u8>),
    /// Temporarily failed (a 4xx reply). The state does not advance; the
    /// client may retry.
    Tempfail(Vec<u8>),
}

impl Control {
    pub fn accept(reply: impl Into<Vec<u8>>) -> Self {
        Control::Accept(reply.into())
    }

    pub fn reject(reply: impl Into<Vec<u8>>) -> Self {
        Control::Reject(reply.into())
    }

    pub fn tempfail(reply: impl Into<Vec<u8>>) -> Self {
        Control::Tempfail(reply.into())
    }

    /// The reply bytes to send to the client.
    pub fn reply(&self) -> &[u8] {
        match self {
            Control::Accept(r) | Control::Reject(r) | Control::Tempfail(r) => r,
        }
    }

    /// The reply bytes, consuming the control.
    pub fn into_reply(self) -> Vec<u8> {
        match self {
            Control::Accept(r) | Control::Reject(r) | Control::Tempfail(r) => r,
        }
    }

    pub fn is_accept(&self) -> bool {
        matches!(self, Control::Accept(_))
    }
}

/// The verdict on a single message-data line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DataControl {
    /// Keep reading message data; nothing is sent to the client.
    Continue,
    /// Abort the transfer: reply now, then discard lines until the "."
    /// terminator (e.g. when the message exceeds the size limit).
    Abort(Vec<u8>),
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum SmtpState {
    /// Waiting for HELO/EHLO.
    Idle,
    /// HELO accepted; envelope commands allowed.
    Ready,
    /// Receiving message data.
    Data,
    /// A data transfer was aborted; discarding lines until the ".".
    Discard,
    /// The client asked to end the session.
    Quit,
}

/// The protocol side of an SMTP session: the state machine, command
/// syntax, and reply framing. The implementor is the policy: it decides
/// every reply and whether a command advances the session.
pub trait SmtpSession {
    const OK: &'static [u8] = b"250 Ok\r\n";
    const SEND_DATA: &'static [u8] = b"354 End data with <CR>.<CR><LF>\r\n";
    const DATA_END: &'static str = ".\r\n";
    const QUIT: &'static [u8] = b"221 Bye\r\n";
    const UNKNOWN: &'static [u8] = b"500 Unknown\r\n";
    const SYNTAX_ERR: &'static [u8] = b"501 5.5.4 Syntax error\r\n";
    const INVALID_SEQ: &'static [u8] = b"503 5.5.1 Invalid sequence.\r\n";
    const MULTI_MAIL: &'static [u8] = b"503 5.5.1 Multiple MAIL FROM commands not allowed.\r\n";

    /// The banner to send when the connection opens.
    fn server_greet(&self) -> impl Future<Output = Vec<u8>> + Send;

    /// HELO/EHLO. `Accept` advances the session to [`SmtpState::Ready`];
    /// anything else leaves it in [`SmtpState::Idle`].
    fn helo(&mut self, arg: &str) -> impl Future<Output = Control> + Send;

    /// MAIL FROM. `Accept` records the envelope sender.
    fn mail_from(&mut self, path: &str) -> impl Future<Output = Control> + Send;

    /// RCPT TO. `Accept` records the recipient.
    fn rcpt_to(&mut self, path: &str) -> impl Future<Output = Control> + Send;

    /// DATA. `Accept` starts message-data mode; a rejection (e.g. no valid
    /// recipients) leaves the session in [`SmtpState::Ready`].
    fn start_data(&mut self) -> impl Future<Output = Control> + Send;

    /// One line of message data (line ending included, as received).
    fn recv_data(&mut self, line: &str) -> impl Future<Output = DataControl> + Send;

    /// The message is complete. The session always returns to
    /// [`SmtpState::Ready`]; the control only carries the reply.
    fn end_data(&mut self) -> impl Future<Output = Control> + Send;

    /// RSET: abandon the current transaction. The policy must clear the
    /// envelope (sender, recipients, data).
    fn reset(&mut self) -> impl Future<Output = Control> + Send;

    /// Serve one connection: read commands, run them through
    /// [`handler`], write replies, until QUIT, an error, or a read
    /// timeout.
    fn run(
        &mut self,
        stream: &mut BufReader<TcpStream>,
        _peer: &SocketAddr,
        _domain: &str,
        max_read_duration_ms: &u64,
    ) -> impl Future<Output = Result<()>> + Send
    where
        Self: Send,
    {
        async {
            let mut state = SmtpState::Idle;

            let _ = stream.write_all(&self.server_greet().await).await;

            loop {
                let line = match timeout(Duration::from_millis(*max_read_duration_ms), async {
                    let mut line = String::new();
                    if stream.read_line(&mut line).await? == 0 {
                        return Err(anyhow!("Stream closed"));
                    }
                    Ok(line)
                })
                .await
                {
                    Ok(Ok(line)) => line,
                    // Read error or timeout: the session ends silently.
                    _ => return Ok(()),
                };

                let (reply, next) = self.handler(&state, line.as_str()).await;
                state = next;
                if !reply.is_empty() {
                    let _ = stream.write_all(&reply).await;
                }

                if state == SmtpState::Quit {
                    break;
                }
            }
            Ok(())
        }
    }

    /// Apply one command line in the given state, returning the reply and
    /// the next state. Every command produces a reply — there is no silent
    /// error path.
    fn handler(
        &mut self,
        state: &SmtpState,
        msg: &str,
    ) -> impl Future<Output = (Vec<u8>, SmtpState)> + Send
    where
        Self: Send,
    {
        async move {
            let cmd: Vec<&str> = msg.splitn(2, ' ').collect();
            let verb = cmd[0].trim_end().to_lowercase();

            match (state, verb.as_str()) {
                // RSET and QUIT are honored in any state. Mid-DATA they are
                // technically client protocol violations, but honoring
                // them is safer than treating them as message lines.
                (_, "rset") => (self.reset().await.into_reply(), SmtpState::Idle),
                (_, "quit") => (Self::QUIT.to_vec(), SmtpState::Quit),

                (SmtpState::Idle, "helo") | (SmtpState::Idle, "ehlo") => {
                    match cmd.get(1).map(|arg| arg.trim_end()) {
                        Some(arg) if !arg.is_empty() => match self.helo(arg).await {
                            Control::Accept(reply) => (reply, SmtpState::Ready),
                            refused => (refused.into_reply(), SmtpState::Idle),
                        },
                        // RFC 5321 Section 4.1.1.1: a domain argument is
                        // required.
                        _ => (Self::SYNTAX_ERR.to_vec(), SmtpState::Idle),
                    }
                }

                (SmtpState::Ready, "mail") => {
                    let Some(&arg) = cmd.get(1) else {
                        return (Self::SYNTAX_ERR.to_vec(), state.clone());
                    };
                    if !arg.to_lowercase().starts_with("from:") {
                        return (Self::UNKNOWN.to_vec(), state.clone());
                    }
                    let path = arg[5..].trim_end();
                    if path.is_empty() {
                        return (Self::SYNTAX_ERR.to_vec(), state.clone());
                    }
                    (self.mail_from(path).await.into_reply(), state.clone())
                }

                (SmtpState::Ready, "rcpt") => {
                    let Some(&arg) = cmd.get(1) else {
                        return (Self::SYNTAX_ERR.to_vec(), state.clone());
                    };
                    if !arg.to_lowercase().starts_with("to:") {
                        return (Self::UNKNOWN.to_vec(), state.clone());
                    }
                    let path = arg[3..].trim_end();
                    if path.is_empty() {
                        return (Self::SYNTAX_ERR.to_vec(), state.clone());
                    }
                    (self.rcpt_to(path).await.into_reply(), state.clone())
                }

                (SmtpState::Ready, "data") => match self.start_data().await {
                    Control::Accept(reply) => (reply, SmtpState::Data),
                    refused => (refused.into_reply(), SmtpState::Ready),
                },

                (SmtpState::Data, _) => {
                    if msg == Self::DATA_END {
                        // The transaction ends either way; the control
                        // only carries the reply.
                        (self.end_data().await.into_reply(), SmtpState::Ready)
                    } else {
                        match self.recv_data(msg).await {
                            DataControl::Continue => (Vec::new(), SmtpState::Data),
                            DataControl::Abort(reply) => (reply, SmtpState::Discard),
                        }
                    }
                }

                (SmtpState::Discard, _) => {
                    // The abort reply was already sent; swallow lines
                    // until the terminator.
                    let done = msg == Self::DATA_END;
                    (Vec::new(), if done { SmtpState::Ready } else { SmtpState::Discard })
                }

                (SmtpState::Ready, "vrfy" | "noop" | "help" | "expn") => {
                    (Self::OK.to_vec(), state.clone())
                }

                _ => (Self::UNKNOWN.to_vec(), SmtpState::Idle),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A configurable SmtpSession that records what the protocol machine
    /// hands to the callbacks. Every test drives `handler()` directly —
    /// the state machine runs entirely in-process.
    #[derive(Default)]
    struct TestSession {
        helo: Option<String>,
        mail_from: Option<String>,
        rcpt_to: Vec<String>,
        data_lines: Vec<String>,
        end_data_calls: usize,
        reset_calls: usize,
        reject_helo: bool,
        reject_start_data: bool,
        reject_end_data: bool,
        /// When set, abort the data transfer once more than this many
        /// bytes have been received.
        data_limit: Option<usize>,
        received_bytes: usize,
    }

    impl SmtpSession for TestSession {
        async fn server_greet(&self) -> Vec<u8> {
            b"220 test ready\r\n".to_vec()
        }

        async fn helo(&mut self, arg: &str) -> Control {
            if self.reject_helo {
                return Control::reject(b"550 nope\r\n");
            }
            self.helo = Some(arg.to_string());
            Control::accept(b"250 hello\r\n")
        }

        async fn mail_from(&mut self, path: &str) -> Control {
            self.mail_from = Some(path.to_string());
            Control::accept(Self::OK)
        }

        async fn rcpt_to(&mut self, path: &str) -> Control {
            self.rcpt_to.push(path.to_string());
            Control::accept(Self::OK)
        }

        async fn start_data(&mut self) -> Control {
            if self.reject_start_data {
                return Control::reject(b"503 5.5.1 No valid recipients\r\n");
            }
            Control::accept(Self::SEND_DATA)
        }

        async fn recv_data(&mut self, line: &str) -> DataControl {
            self.received_bytes += line.len();
            if let Some(limit) = self.data_limit {
                if self.received_bytes > limit {
                    return DataControl::Abort(b"552 5.3.4 too big\r\n".to_vec());
                }
            }
            self.data_lines.push(line.to_string());
            DataControl::Continue
        }

        async fn end_data(&mut self) -> Control {
            self.end_data_calls += 1;
            if self.reject_end_data {
                return Control::reject(b"550 nope\r\n");
            }
            Control::accept(b"250 accepted\r\n")
        }

        async fn reset(&mut self) -> Control {
            self.reset_calls += 1;
            self.mail_from = None;
            self.rcpt_to.clear();
            self.data_lines.clear();
            Control::accept(Self::OK)
        }
    }

    /// Drive one command through the handler and assert the reply and the
    /// resulting state.
    async fn expect(
        session: &mut TestSession,
        state: SmtpState,
        line: &str,
        want_reply: &[u8],
        want_next: SmtpState,
    ) {
        let (reply, next) = session.handler(&state, line).await;
        assert_eq!(reply, want_reply, "reply for {line:?}");
        assert_eq!(next, want_next, "next state for {line:?}");
    }

    #[tokio::test]
    async fn helo_and_ehlo_advance_to_ready() {
        let mut s = TestSession::default();
        expect(&mut s, SmtpState::Idle, "HELO example.org\r\n", b"250 hello\r\n", SmtpState::Ready)
            .await;
        assert_eq!(s.helo.as_deref(), Some("example.org"));

        expect(&mut s, SmtpState::Idle, "EHLO mail.example.net\r\n", b"250 hello\r\n", SmtpState::Ready)
            .await;
        assert_eq!(s.helo.as_deref(), Some("mail.example.net"));
    }

    /// The core of the binding-control design: a rejected HELO leaves the
    /// session in Idle, so a client that ignores the rejection still
    /// cannot proceed to MAIL.
    #[tokio::test]
    async fn rejected_helo_leaves_session_idle() {
        let mut s = TestSession {
            reject_helo: true,
            ..Default::default()
        };
        expect(&mut s, SmtpState::Idle, "HELO example.org\r\n", b"550 nope\r\n", SmtpState::Idle)
            .await;

        // The client ignores the 550 and tries to send mail anyway.
        expect(&mut s, SmtpState::Idle, "MAIL FROM:<a@b>\r\n", TestSession::UNKNOWN, SmtpState::Idle)
            .await;
        expect(&mut s, SmtpState::Idle, "RCPT TO:<c@d>\r\n", TestSession::UNKNOWN, SmtpState::Idle)
            .await;
        expect(&mut s, SmtpState::Idle, "DATA\r\n", TestSession::UNKNOWN, SmtpState::Idle)
            .await;
        assert_eq!(s.mail_from, None, "no envelope may be recorded before an accepted HELO");
    }

    #[tokio::test]
    async fn helo_without_argument_is_a_syntax_error() {
        let mut s = TestSession::default();
        expect(&mut s, SmtpState::Idle, "HELO\r\n", TestSession::SYNTAX_ERR, SmtpState::Idle)
            .await;
        expect(&mut s, SmtpState::Idle, "EHLO\r\n", TestSession::SYNTAX_ERR, SmtpState::Idle)
            .await;
        expect(&mut s, SmtpState::Idle, "HELO \r\n", TestSession::SYNTAX_ERR, SmtpState::Idle)
            .await;
        assert_eq!(s.helo, None, "callback must not run on a syntax error");
    }

    #[tokio::test]
    async fn mail_from_requires_helo_first() {
        let mut s = TestSession::default();
        expect(&mut s, SmtpState::Idle, "MAIL FROM:<a@b>\r\n", TestSession::UNKNOWN, SmtpState::Idle)
            .await;
        assert_eq!(s.mail_from, None);
    }

    #[tokio::test]
    async fn mail_from_passes_the_path_to_the_callback() {
        let mut s = TestSession::default();
        expect(&mut s, SmtpState::Ready, "MAIL FROM:<alice@example.org>\r\n", TestSession::OK, SmtpState::Ready)
            .await;
        assert_eq!(s.mail_from.as_deref(), Some("<alice@example.org>"));

        // The null sender is a valid non-empty path.
        expect(&mut s, SmtpState::Ready, "MAIL FROM:<>\r\n", TestSession::OK, SmtpState::Ready)
            .await;
        assert_eq!(s.mail_from.as_deref(), Some("<>"));
    }

    #[tokio::test]
    async fn mail_argument_errors_keep_the_session_in_ready() {
        let mut s = TestSession::default();
        expect(&mut s, SmtpState::Ready, "MAIL\r\n", TestSession::SYNTAX_ERR, SmtpState::Ready)
            .await;
        expect(&mut s, SmtpState::Ready, "MAIL FROM:\r\n", TestSession::SYNTAX_ERR, SmtpState::Ready)
            .await;
        // A malformed keyword no longer resets the state to Idle.
        expect(&mut s, SmtpState::Ready, "MAIL X:<a@b>\r\n", TestSession::UNKNOWN, SmtpState::Ready)
            .await;
    }

    #[tokio::test]
    async fn rcpt_argument_errors_keep_the_session_in_ready() {
        let mut s = TestSession::default();
        expect(&mut s, SmtpState::Ready, "RCPT\r\n", TestSession::SYNTAX_ERR, SmtpState::Ready)
            .await;
        expect(&mut s, SmtpState::Ready, "RCPT TO:\r\n", TestSession::SYNTAX_ERR, SmtpState::Ready)
            .await;
        expect(&mut s, SmtpState::Ready, "RCPT FROM:<a@b>\r\n", TestSession::UNKNOWN, SmtpState::Ready)
            .await;
    }

    #[tokio::test]
    async fn rcpt_to_passes_the_path_to_the_callback() {
        let mut s = TestSession::default();
        expect(&mut s, SmtpState::Ready, "RCPT TO:<bob@example.net>\r\n", TestSession::OK, SmtpState::Ready)
            .await;
        assert_eq!(s.rcpt_to, vec!["<bob@example.net>".to_string()]);
    }

    #[tokio::test]
    async fn data_requires_ready_state() {
        let mut s = TestSession::default();
        expect(&mut s, SmtpState::Idle, "DATA\r\n", TestSession::UNKNOWN, SmtpState::Idle)
            .await;
    }

    /// A rejected DATA (e.g. no valid recipients) leaves the session in
    /// Ready, able to accept more RCPTs or a new MAIL.
    #[tokio::test]
    async fn rejected_start_data_stays_ready() {
        let mut s = TestSession {
            reject_start_data: true,
            ..Default::default()
        };
        expect(&mut s, SmtpState::Ready, "DATA\r\n", b"503 5.5.1 No valid recipients\r\n", SmtpState::Ready)
            .await;

        // The client adds a recipient and retries DATA successfully.
        s.reject_start_data = false;
        expect(&mut s, SmtpState::Ready, "RCPT TO:<bob@example.net>\r\n", TestSession::OK, SmtpState::Ready)
            .await;
        expect(&mut s, SmtpState::Ready, "DATA\r\n", TestSession::SEND_DATA, SmtpState::Data)
            .await;
    }

    #[tokio::test]
    async fn data_mode_records_lines_until_crlf_dot() {
        let mut s = TestSession::default();
        expect(&mut s, SmtpState::Ready, "DATA\r\n", TestSession::SEND_DATA, SmtpState::Data)
            .await;

        // Message lines yield no reply and stay in Data mode.
        expect(&mut s, SmtpState::Data, "line one\r\n", b"", SmtpState::Data).await;
        expect(&mut s, SmtpState::Data, "line two\r\n", b"", SmtpState::Data).await;
        assert_eq!(s.data_lines, vec!["line one\r\n".to_string(), "line two\r\n".to_string()]);
        assert_eq!(s.end_data_calls, 0);

        expect(&mut s, SmtpState::Data, ".\r\n", b"250 accepted\r\n", SmtpState::Ready).await;
        assert_eq!(s.end_data_calls, 1);
    }

    #[tokio::test]
    async fn lf_only_dot_does_not_terminate_data() {
        let mut s = TestSession::default();
        expect(&mut s, SmtpState::Data, ".\n", b"", SmtpState::Data).await;
        assert_eq!(s.data_lines, vec![".\n".to_string()], "documents known LF-terminator wart");
    }

    /// A size-abort replies once, discards the rest of the message until
    /// the terminator, and returns the session to Ready.
    #[tokio::test]
    async fn data_size_abort_discards_until_dot() {
        let mut s = TestSession {
            data_limit: Some(10),
            ..Default::default()
        };
        expect(&mut s, SmtpState::Ready, "DATA\r\n", TestSession::SEND_DATA, SmtpState::Data)
            .await;

        expect(&mut s, SmtpState::Data, "short\r\n", b"", SmtpState::Data).await;
        // This line crosses the limit.
        expect(&mut s, SmtpState::Data, "this line is too long\r\n", b"552 5.3.4 too big\r\n", SmtpState::Discard)
            .await;

        // Remaining body lines are swallowed without being recorded or
        // mistaken for commands. QUIT still ends the session: it is matched
        // before the discard arm, which is the safe response for a client
        // that aborts and then hangs up.
        expect(&mut s, SmtpState::Discard, "more body\r\n", b"", SmtpState::Discard).await;
        expect(&mut s, SmtpState::Discard, "QUIT\r\n", TestSession::QUIT, SmtpState::Quit).await;
    }

    #[tokio::test]
    async fn discarded_lines_swallowed_until_dot() {
        let mut s = TestSession {
            data_limit: Some(10),
            ..Default::default()
        };
        expect(&mut s, SmtpState::Ready, "DATA\r\n", TestSession::SEND_DATA, SmtpState::Data)
            .await;
        expect(&mut s, SmtpState::Data, "this line is too long\r\n", b"552 5.3.4 too big\r\n", SmtpState::Discard)
            .await;
        expect(&mut s, SmtpState::Discard, "more body\r\n", b"", SmtpState::Discard).await;
        expect(&mut s, SmtpState::Discard, ".\r\n", b"", SmtpState::Ready).await;
        assert_eq!(s.data_lines, Vec::<String>::new());

        // The session is usable again.
        expect(&mut s, SmtpState::Ready, "MAIL FROM:<a@b>\r\n", TestSession::OK, SmtpState::Ready)
            .await;
    }

    #[tokio::test]
    async fn end_data_rejection_still_returns_to_ready() {
        let mut s = TestSession {
            reject_end_data: true,
            ..Default::default()
        };
        expect(&mut s, SmtpState::Data, ".\r\n", b"550 nope\r\n", SmtpState::Ready).await;
        assert_eq!(s.end_data_calls, 1);
    }

    #[tokio::test]
    async fn rset_clears_envelope_and_returns_to_idle() {
        let mut s = TestSession::default();
        expect(&mut s, SmtpState::Ready, "MAIL FROM:<a@b>\r\n", TestSession::OK, SmtpState::Ready)
            .await;
        expect(&mut s, SmtpState::Ready, "RCPT TO:<c@d>\r\n", TestSession::OK, SmtpState::Ready)
            .await;

        expect(&mut s, SmtpState::Ready, "RSET\r\n", TestSession::OK, SmtpState::Idle).await;
        assert_eq!(s.reset_calls, 1);
        assert_eq!(s.mail_from, None, "RSET must clear the envelope");
        assert!(s.rcpt_to.is_empty());
    }

    #[tokio::test]
    async fn rset_and_quit_work_mid_data() {
        let mut s = TestSession::default();
        expect(&mut s, SmtpState::Ready, "DATA\r\n", TestSession::SEND_DATA, SmtpState::Data)
            .await;
        expect(&mut s, SmtpState::Data, "body line\r\n", b"", SmtpState::Data).await;

        // RSET mid-DATA aborts the transfer and clears the envelope.
        expect(&mut s, SmtpState::Data, "RSET\r\n", TestSession::OK, SmtpState::Idle).await;
        assert_eq!(s.reset_calls, 1);
        assert!(s.data_lines.is_empty());

        // QUIT mid-DATA ends the session (via a fresh DATA mode).
        expect(&mut s, SmtpState::Ready, "DATA\r\n", TestSession::SEND_DATA, SmtpState::Data)
            .await;
        expect(&mut s, SmtpState::Data, "QUIT\r\n", TestSession::QUIT, SmtpState::Quit).await;
    }

    #[tokio::test]
    async fn quit_terminates_the_session() {
        let mut s = TestSession::default();
        expect(&mut s, SmtpState::Ready, "QUIT\r\n", TestSession::QUIT, SmtpState::Quit).await;
    }

    #[tokio::test]
    async fn misc_commands_accepted_in_ready_state() {
        let mut s = TestSession::default();
        for cmd in ["NOOP\r\n", "VRFY user\r\n", "HELP\r\n", "EXPN list\r\n"] {
            expect(&mut s, SmtpState::Ready, cmd, TestSession::OK, SmtpState::Ready).await;
        }
    }

    #[tokio::test]
    async fn unknown_command_is_rejected() {
        let mut s = TestSession::default();
        expect(&mut s, SmtpState::Idle, "FROB\r\n", TestSession::UNKNOWN, SmtpState::Idle).await;
    }

    #[tokio::test]
    async fn verbs_are_case_insensitive() {
        let mut s = TestSession::default();
        expect(&mut s, SmtpState::Idle, "helo example.org\r\n", b"250 hello\r\n", SmtpState::Ready)
            .await;
        expect(&mut s, SmtpState::Ready, "MaIl FrOm:<a@b>\r\n", TestSession::OK, SmtpState::Ready)
            .await;
        expect(&mut s, SmtpState::Ready, "rCpT tO:<c@d>\r\n", TestSession::OK, SmtpState::Ready)
            .await;
        expect(&mut s, SmtpState::Ready, "dAta\r\n", TestSession::SEND_DATA, SmtpState::Data)
            .await;
        expect(&mut s, SmtpState::Data, ".\r\n", b"250 accepted\r\n", SmtpState::Ready).await;
        expect(&mut s, SmtpState::Ready, "qUiT\r\n", TestSession::QUIT, SmtpState::Quit).await;
    }

    #[tokio::test]
    async fn full_session_happy_path() {
        let mut s = TestSession::default();
        expect(&mut s, SmtpState::Idle, "HELO client.example\r\n", b"250 hello\r\n", SmtpState::Ready)
            .await;
        expect(&mut s, SmtpState::Ready, "MAIL FROM:<alice@example.org>\r\n", TestSession::OK, SmtpState::Ready)
            .await;
        expect(&mut s, SmtpState::Ready, "RCPT TO:<bob@example.net>\r\n", TestSession::OK, SmtpState::Ready)
            .await;
        expect(&mut s, SmtpState::Ready, "DATA\r\n", TestSession::SEND_DATA, SmtpState::Data)
            .await;
        expect(&mut s, SmtpState::Data, "Subject: hi\r\n", b"", SmtpState::Data).await;
        expect(&mut s, SmtpState::Data, "\r\n", b"", SmtpState::Data).await;
        expect(&mut s, SmtpState::Data, "body\r\n", b"", SmtpState::Data).await;
        expect(&mut s, SmtpState::Data, ".\r\n", b"250 accepted\r\n", SmtpState::Ready).await;
        expect(&mut s, SmtpState::Ready, "QUIT\r\n", TestSession::QUIT, SmtpState::Quit).await;

        assert_eq!(s.helo.as_deref(), Some("client.example"));
        assert_eq!(s.mail_from.as_deref(), Some("<alice@example.org>"));
        assert_eq!(s.rcpt_to, vec!["<bob@example.net>".to_string()]);
        assert_eq!(
            s.data_lines,
            vec!["Subject: hi\r\n".to_string(), "\r\n".to_string(), "body\r\n".to_string()]
        );
        assert_eq!(s.end_data_calls, 1);
    }
}
