//! SMTP wire protocol: state machine, framing, and DATA transparency.
//!
//! This crate owns *what SMTP is* (verbs, states, sequencing, line caps,
//! dot-unstuffing); the [`SmtpSession`] implementor owns *what this server
//! is* (policy: every reply and every accept/reject decision, expressed as
//! [`Control`] verdicts that bind the state machine).
#![warn(missing_docs)]

use std::future::Future;
use std::net::SocketAddr;
use std::time::Duration;

use anyhow::Result;
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
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
    /// Pause the session for a transport upgrade (STARTTLS, RFC 3207): the
    /// reply is written, the read loop returns
    /// [`EndReason::TlsHandshake`], and the caller performs the TLS
    /// handshake before resuming with a fresh `run` call.
    Upgrade(Vec<u8>),
    /// Continue an interactive exchange (the AUTH PLAIN/LOGIN continuation
    /// dance, RFC 4954): the reply (a `334` challenge) is sent, the machine
    /// enters [`SmtpState::Auth`], and further lines go to
    /// [`SmtpSession::auth_line`] until it returns a final verdict.
    Challenge(Vec<u8>),
}

impl Control {
    /// Build an [`Control::Accept`].
    pub fn accept(reply: impl Into<Vec<u8>>) -> Self {
        Control::Accept(reply.into())
    }

    /// Build a [`Control::Reject`].
    pub fn reject(reply: impl Into<Vec<u8>>) -> Self {
        Control::Reject(reply.into())
    }

    /// Build a [`Control::Tempfail`].
    pub fn tempfail(reply: impl Into<Vec<u8>>) -> Self {
        Control::Tempfail(reply.into())
    }

    /// Build a [`Control::Upgrade`] (STARTTLS pause).
    pub fn upgrade(reply: impl Into<Vec<u8>>) -> Self {
        Control::Upgrade(reply.into())
    }

    /// Build a [`Control::Challenge`] (AUTH continuation).
    pub fn challenge(reply: impl Into<Vec<u8>>) -> Self {
        Control::Challenge(reply.into())
    }

    /// Returns the reply bytes to send to the client.
    pub fn reply(&self) -> &[u8] {
        match self {
            Control::Accept(r)
            | Control::Reject(r)
            | Control::Tempfail(r)
            | Control::Upgrade(r)
            | Control::Challenge(r) => r,
        }
    }

    /// Returns the reply bytes, consuming the control.
    pub fn into_reply(self) -> Vec<u8> {
        match self {
            Control::Accept(r)
            | Control::Reject(r)
            | Control::Tempfail(r)
            | Control::Upgrade(r)
            | Control::Challenge(r) => r,
        }
    }

    /// Returns whether this control lets the command through (only
    /// [`Control::Accept`] does).
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

/// The protocol state machine's states.
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
    /// The policy accepted STARTTLS: the `220` reply was written and the
    /// read loop is paused for the caller to perform the TLS handshake.
    /// Never visible to policy; the driver resets to Idle after the
    /// handshake (RFC 3207 Section 4.2: the protocol restarts).
    TlsHandshake,
    /// Mid-authentication (RFC 4954): lines go to
    /// [`SmtpSession::auth_line`] until it returns a final verdict, which
    /// returns the session to the carried state. A client `*` aborts
    /// (RFC 4954 Section 4).
    Auth(Box<SmtpState>),
    /// The client asked to end the session.
    Quit,
}

/// Where the protocol loop stands, owned by the connection driver so the
/// state survives a STARTTLS pause: the driver performs the TLS handshake
/// and calls [`SmtpSession::run`] again with the same session state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionState {
    /// The state-machine state.
    pub state: SmtpState,
    /// The banner has been sent on this connection — exactly once, not
    /// once per `run` call.
    pub greeted: bool,
}

impl Default for SessionState {
    fn default() -> Self {
        SessionState {
            state: SmtpState::Idle,
            greeted: false,
        }
    }
}

/// Why the protocol loop returned.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EndReason {
    /// QUIT, EOF, read timeout, or I/O error: the session is over.
    Closed,
    /// The policy accepted STARTTLS and the `220` reply was written: the
    /// caller must perform the TLS handshake on the raw stream, mark the
    /// session with [`SmtpSession::tls_established`], reset the protocol
    /// state to Idle, and call `run` again over the TLS stream.
    TlsHandshake,
}

/// One read line from the wire.
enum Line {
    /// A full line up to and including its '\n' (or the final unterminated
    /// bytes at EOF).
    Complete(Vec<u8>),
    /// More than the configured cap was read. `terminated` says whether
    /// the newline was reached (and consumed) before the cap was
    /// exceeded — when false, the remainder of the line is still on the
    /// wire and must be drained before any further line is read.
    /// `last` is the last octet read so far (used to tell a CRLF ending
    /// from a bare LF once the line is drained).
    Overflow { terminated: bool, last: Option<u8> },
}

/// Read one line (up to and including '\n') from `reader`, never
/// buffering more than `cap` octets before reporting overflow.
///
/// Returns [`Line::Complete`] (empty at EOF with nothing read) or
/// [`Line::Overflow`].
///
/// # Errors
///
/// Any I/O error from the reader.
async fn read_line_capped<R: AsyncBufRead + Unpin>(
    reader: &mut R,
    cap: usize,
) -> std::io::Result<Line> {
    let mut line = Vec::new();
    loop {
        let buf = reader.fill_buf().await?;
        if buf.is_empty() {
            // EOF: whatever was accumulated (possibly nothing) is the
            // final unterminated line.
            return Ok(Line::Complete(line));
        }
        match buf.iter().position(|&b| b == b'\n') {
            Some(pos) => {
                let overflows = line.len() + pos + 1 > cap;
                line.extend_from_slice(&buf[..=pos]);
                reader.consume(pos + 1);
                return Ok(if overflows {
                    // The octet before the '\n' (CR for a CRLF ending).
                    let last = line.len().checked_sub(2).map(|i| line[i]);
                    Line::Overflow {
                        terminated: true,
                        last,
                    }
                } else {
                    Line::Complete(line)
                });
            }
            None => {
                let n = buf.len();
                line.extend_from_slice(buf);
                reader.consume(n);
                if line.len() > cap {
                    return Ok(Line::Overflow {
                        terminated: false,
                        last: line.last().copied(),
                    });
                }
            }
        }
    }
}

/// Consume bytes from `reader` up to and including the next '\n' (or
/// EOF), discarding them. Used to drain the remainder of an over-long
/// line. `last` is the last octet already consumed before the drain.
///
/// Returns whether the line ended with CRLF (false for a bare LF or EOF).
///
/// # Errors
///
/// Any I/O error from the reader.
async fn drain_line<R: AsyncBufRead + Unpin>(
    reader: &mut R,
    mut last: Option<u8>,
) -> std::io::Result<bool> {
    loop {
        let buf = reader.fill_buf().await?;
        if buf.is_empty() {
            return Ok(false);
        }
        match buf.iter().position(|&b| b == b'\n') {
            Some(pos) => {
                let before = if pos > 0 { Some(buf[pos - 1]) } else { last };
                reader.consume(pos + 1);
                return Ok(before == Some(b'\r'));
            }
            None => {
                let n = buf.len();
                last = buf.last().copied();
                reader.consume(n);
            }
        }
    }
}

/// Returns whether `a` and `b` are equal, ignoring ASCII case.
fn eq_ignore_ascii_case(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len()
        && a.iter()
            .zip(b.iter())
            .all(|(x, y)| x.eq_ignore_ascii_case(y))
}

/// Decode the base64 AUTH token `input` (surrounding whitespace ignored).
/// The special initial response `=` means an empty response (RFC 4954
/// Section 4).
///
/// Returns the decoded bytes, or `None` if `input` is not UTF-8 or not
/// valid standard base64.
pub fn decode_b64(input: &[u8]) -> Option<Vec<u8>> {
    if input == b"=" {
        return Some(Vec::new());
    }
    let text = std::str::from_utf8(input).ok()?;
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD
        .decode(text.trim())
        .ok()
}

/// Decode the RFC 4616 PLAIN message `input`: `authzid NUL authcid NUL
/// passwd`.
///
/// Returns `(authcid, passwd)`, or `None` unless there are exactly three
/// UTF-8 fields and the authorization identity is empty or equal to the
/// authentication identity (the only form this server supports).
pub fn decode_plain(input: &[u8]) -> Option<(String, String)> {
    let parts: Vec<&[u8]> = input.split(|&b| b == 0).collect();
    if parts.len() != 3 {
        return None;
    }
    let authzid = std::str::from_utf8(parts[0]).ok()?;
    let authcid = std::str::from_utf8(parts[1]).ok()?;
    let passwd = std::str::from_utf8(parts[2]).ok()?;
    if !authzid.is_empty() && authzid != authcid {
        return None;
    }
    Some((authcid.to_string(), passwd.to_string()))
}

/// Split the command `content` at its first space.
///
/// Returns the verb and the rest of the line (`None` without a space).
fn split_verb(content: &[u8]) -> (&[u8], Option<&[u8]>) {
    match content.iter().position(|&b| b == b' ') {
        Some(i) => (&content[..i], Some(&content[i + 1..])),
        None => (content, None),
    }
}

/// Returns `bytes` with trailing ASCII whitespace (SP, HTAB, LF, FF, CR)
/// removed.
fn trim_ascii_end(mut bytes: &[u8]) -> &[u8] {
    while let Some((&last, rest)) = bytes.split_last() {
        if last.is_ascii_whitespace() {
            bytes = rest;
        } else {
            break;
        }
    }
    bytes
}

/// The protocol side of an SMTP session: the state machine, command
/// syntax, reply framing, and DATA transparency (dot-unstuffing, bounded
/// line reads). The implementor is the policy: it decides every reply and
/// whether a command advances the session.
pub trait SmtpSession {
    /// `250 Ok` generic positive reply.
    const OK: &'static [u8] = b"250 Ok\r\n";
    /// `354` reply that starts message-data mode.
    const SEND_DATA: &'static [u8] = b"354 End data with <CR>.<CR><LF>\r\n";
    /// `221` reply that closes the session.
    const QUIT: &'static [u8] = b"221 Bye\r\n";
    /// `500` reply for unrecognized commands.
    const UNKNOWN: &'static [u8] = b"500 Unknown\r\n";
    /// `501` reply for malformed arguments.
    const SYNTAX_ERR: &'static [u8] = b"501 5.5.4 Syntax error\r\n";
    /// `503` reply for commands out of sequence (kept for policy use).
    const INVALID_SEQ: &'static [u8] = b"503 5.5.1 Invalid sequence.\r\n";
    /// `503` reply for a repeated MAIL FROM.
    const MULTI_MAIL: &'static [u8] = b"503 5.5.1 Multiple MAIL FROM commands not allowed.\r\n";
    /// Reply when a command line exceeds `MAX_CMD_LINE`.
    const LINE_TOO_LONG: &'static [u8] = b"500 5.5.2 Line too long\r\n";
    /// Reply when a message-data line exceeds `MAX_DATA_LINE`; the rest
    /// of the transfer is discarded.
    const DATA_LINE_TOO_LONG: &'static [u8] =
        b"552 5.3.4 Line exceeds fixed maximum message line size\r\n";
    /// `421` sent when the server shuts down between transactions (RFC
    /// 5321 §3.8): the client must retry later.
    const SHUTTING_DOWN: &'static [u8] = b"421 4.3.2 Service shutting down, try again later\r\n";

    /// Command lines are capped at 512 octets including CRLF (RFC 5321
    /// Section 4.5.3.1.4). An over-long command is answered with
    /// `LINE_TOO_LONG` and the session continues.
    const MAX_CMD_LINE: usize = 512;
    /// Message-data lines are capped at this many octets including the
    /// line ending, so a single line can never exhaust memory regardless
    /// of the message-size policy. RFC 5321 sets 1000 for
    /// interoperability, but real mail regularly carries longer lines, so
    /// the default is generous. An over-long data line aborts the transfer
    /// (`DATA_LINE_TOO_LONG`, then discard-until-dot).
    const MAX_DATA_LINE: usize = 64 * 1024;

    /// Returns the banner to send when the connection opens.
    fn server_greet(&self) -> impl Future<Output = Vec<u8>> + Send;

    /// HELO/EHLO with the non-empty, trailing-whitespace-trimmed domain
    /// argument `arg`. `ehlo` distinguishes the verbs so the reply can
    /// carry the multiline capability list (RFC 5321 Section 3.2).
    /// `Accept` advances the session to [`SmtpState::Ready`]; anything
    /// else leaves it in [`SmtpState::Idle`].
    fn helo(&mut self, ehlo: bool, arg: &str) -> impl Future<Output = Control> + Send;

    /// MAIL FROM. `path` is everything after `FROM:` (the path plus any
    /// ESMTP parameters), trailing whitespace trimmed, never empty.
    /// `Accept` records the envelope sender; the state stays Ready either
    /// way.
    fn mail_from(&mut self, path: &str) -> impl Future<Output = Control> + Send;

    /// RCPT TO. `path` is everything after `TO:`, as for
    /// [`SmtpSession::mail_from`]. `Accept` records the recipient.
    fn rcpt_to(&mut self, path: &str) -> impl Future<Output = Control> + Send;

    /// DATA. `Accept` starts message-data mode; a rejection (e.g. no valid
    /// recipients) leaves the session in [`SmtpState::Ready`].
    fn start_data(&mut self) -> impl Future<Output = Control> + Send;

    /// One line of message data: the (dot-unstuffed) content followed by
    /// the line ending exactly as the client sent it (CRLF, bare LF, or
    /// nothing for an unterminated final line). Raw bytes — the body may
    /// contain any 8-bit content and must be preserved verbatim.
    fn recv_data(&mut self, line: &[u8]) -> impl Future<Output = DataControl> + Send;

    /// The message is complete. The session always returns to
    /// [`SmtpState::Ready`]; the control only carries the reply.
    fn end_data(&mut self) -> impl Future<Output = Control> + Send;

    /// RSET: abandon the current transaction. The policy must clear the
    /// envelope (sender, recipients, data).
    fn reset(&mut self) -> impl Future<Output = Control> + Send;

    /// STARTTLS (RFC 3207). `Upgrade` pauses the session for the TLS
    /// handshake ([`EndReason::TlsHandshake`]); `Reject` keeps the session
    /// in its current state. The policy is responsible for refusing when
    /// TLS is unavailable (454) or already active (503).
    fn starttls(&mut self) -> impl Future<Output = Control> + Send;

    /// Called by the connection driver after the TLS handshake completes.
    /// The policy should discard pre-TLS knowledge (HELO name, SPF
    /// results, envelope): the protocol restarts, and the client must
    /// re-issue EHLO (RFC 3207 Section 4.2).
    fn tls_established(&mut self) -> impl Future<Output = ()> + Send;

    /// AUTH (RFC 4954). `mechanism` is the SASL name (PLAIN, LOGIN, ...);
    /// `initial` is the optional base64 initial response — the special
    /// value `=` means an empty response, per the RFC. A
    /// [`Control::Challenge`] result begins the continuation dance in
    /// [`SmtpState::Auth`].
    fn auth(
        &mut self,
        mechanism: &str,
        initial: Option<&[u8]>,
    ) -> impl Future<Output = Control> + Send;

    /// One continuation `line` of an in-progress AUTH exchange (without
    /// its line ending): the base64 response to the previous challenge. A
    /// client abort (`*`) is intercepted by the protocol layer and never
    /// reaches this method. Only called in [`SmtpState::Auth`].
    fn auth_line(&mut self, line: &[u8]) -> impl Future<Output = Control> + Send;

    /// A message-data line exceeded [`SmtpSession::MAX_DATA_LINE`], so the
    /// transfer is being aborted (the rest is discarded until the
    /// terminator). Returns the reply to send, by default
    /// [`SmtpSession::DATA_LINE_TOO_LONG`]. The line never reaches
    /// [`SmtpSession::recv_data`], so this is the policy's only chance to
    /// record the dropped message (e.g. log it).
    fn data_line_too_long(&mut self) -> impl Future<Output = Vec<u8>> + Send {
        async { Self::DATA_LINE_TOO_LONG.to_vec() }
    }

    /// Resolves once the server has started a graceful shutdown. By
    /// default it never resolves.
    ///
    /// The read loop only waits on this **between transactions** (Idle or
    /// Ready): it then sends [`SmtpSession::SHUTTING_DOWN`] (`421`, RFC 5321
    /// §3.8) and ends the session, so the client retries later. A message
    /// transfer (Data/Discard) or an AUTH exchange in progress is never
    /// interrupted: the session finishes it, sends its reply, and gets the
    /// `421` at its next command.
    fn shutdown_signal(&self) -> impl Future<Output = ()> + Send {
        std::future::pending()
    }

    /// Serve one connection over `stream`: read bounded lines, run them
    /// through `handler`, write replies, until QUIT, EOF, an error, a
    /// read timeout, a graceful shutdown, or a STARTTLS pause.
    ///
    /// Each read (including the drain of an over-long line) may take at
    /// most `max_read_duration_ms`. `session_state` carries the state and
    /// whether the banner was sent, so a call after a STARTTLS pause
    /// resumes where the previous one stopped. `_peer` and `_domain` are
    /// unused by the protocol layer.
    ///
    /// Generic over the stream so sessions can be tested in-process
    /// against an in-memory duplex — and so the driver can hand a
    /// plaintext stream first and a TLS stream after a STARTTLS upgrade.
    ///
    /// Returns why the loop ended. Read errors, timeouts and write
    /// failures end the session as [`EndReason::Closed`]; this never
    /// returns `Err` today.
    fn run<R>(
        &mut self,
        stream: &mut BufReader<R>,
        _peer: &SocketAddr,
        _domain: &str,
        max_read_duration_ms: &u64,
        session_state: &mut SessionState,
    ) -> impl Future<Output = Result<EndReason>> + Send
    where
        R: AsyncRead + AsyncWrite + Unpin + Send,
        Self: Send,
    {
        async move {
            // The banner is sent once per connection, not once per run()
            // call: a STARTTLS resume must not re-greet.
            if !session_state.greeted {
                let _ = stream.write_all(&self.server_greet().await).await;
                session_state.greeted = true;
            }

            // Whether the previous message-data line ended with a bare LF.
            // The DATA terminator is `<CRLF>.<CRLF>`: a `.` line only ends
            // the transfer when the line before it ended with CRLF.
            // Otherwise `<LF>.<CRLF>` would end DATA here while an upstream
            // relay treats it as body text — the SMTP-smuggling parser
            // differential (CVE-2023-51764 class). Such a `.` line is
            // message data; it is handed to the handler dot-stuffed so
            // the ordinary unstuffing delivers it as a literal ".".
            let mut after_bare_lf = false;

            loop {
                let in_data = matches!(session_state.state, SmtpState::Data | SmtpState::Discard);
                if !in_data {
                    after_bare_lf = false;
                }
                let cap = if in_data {
                    Self::MAX_DATA_LINE
                } else {
                    Self::MAX_CMD_LINE
                };

                let read = timeout(
                    Duration::from_millis(*max_read_duration_ms),
                    read_line_capped(stream, cap),
                );
                // Between transactions, a graceful shutdown ends the session
                // with a 421 (see `shutdown_signal`). Checked first
                // (`biased`), so a client that keeps sending commands can't
                // hold the session open through a shutdown. Mid-transfer
                // and mid-AUTH, the read is never raced: those finish first.
                let read = if matches!(session_state.state, SmtpState::Idle | SmtpState::Ready) {
                    tokio::select! {
                        biased;
                        () = self.shutdown_signal() => None,
                        read = read => Some(read),
                    }
                } else {
                    Some(read.await)
                };
                let Some(read) = read else {
                    let _ = stream.write_all(Self::SHUTTING_DOWN).await;
                    return Ok(EndReason::Closed);
                };
                let line = match read {
                    // EOF (empty line) ends the session; a final
                    // unterminated line is still delivered.
                    Ok(Ok(line)) if line.is_complete_and_empty() => return Ok(EndReason::Closed),
                    Ok(Ok(line)) => line,
                    // Read error or timeout: the session ends silently.
                    _ => return Ok(EndReason::Closed),
                };

                match line {
                    Line::Complete(mut line) => {
                        if in_data {
                            if after_bare_lf && line == b".\r\n" {
                                line.insert(0, b'.');
                            }
                            after_bare_lf = line.ends_with(b"\n") && !line.ends_with(b"\r\n");
                        }
                        let (reply, next) = self.handler(&session_state.state, &line).await;
                        session_state.state = next;
                        if !reply.is_empty() {
                            let _ = stream.write_all(&reply).await;
                        }
                        match session_state.state {
                            SmtpState::Quit => break,
                            // The policy accepted STARTTLS; the `220` is
                            // on the wire and the caller takes over for
                            // the handshake.
                            SmtpState::TlsHandshake => return Ok(EndReason::TlsHandshake),
                            _ => {}
                        }
                    }
                    Line::Overflow { terminated, last } => {
                        // Only drain when the line's newline is still on
                        // the wire; a line that arrived fully within one
                        // buffered chunk was already consumed to its end.
                        // The drain is a read and gets the same read
                        // timeout as every other read: a client that goes
                        // silent mid-line must not block the session
                        // forever.
                        let drained = if terminated {
                            Ok(Ok(last == Some(b'\r')))
                        } else {
                            timeout(
                                Duration::from_millis(*max_read_duration_ms),
                                drain_line(stream, last),
                            )
                            .await
                        };
                        let Ok(Ok(ended_crlf)) = drained else {
                            return Ok(EndReason::Closed);
                        };
                        if in_data {
                            after_bare_lf = !ended_crlf;
                        }
                        match session_state.state {
                            SmtpState::Data => {
                                // The line never reached the policy; abort
                                // the transfer the same way a policy size
                                // abort would.
                                let reply = self.data_line_too_long().await;
                                let _ = stream.write_all(&reply).await;
                                session_state.state = SmtpState::Discard;
                            }
                            // Already discarding: keep draining silently.
                            SmtpState::Discard => {}
                            _ => {
                                let _ = stream.write_all(Self::LINE_TOO_LONG).await;
                            }
                        }
                    }
                }
            }
            Ok(EndReason::Closed)
        }
    }

    /// Apply one line `msg` (including its line ending as received) in
    /// `state`.
    ///
    /// Returns the reply to send and the next state. Every command
    /// produces a reply — there is no silent error path; only message
    /// data lines and the end of a discarded transfer produce an empty
    /// reply.
    ///
    /// DATA framing (RFC 5321 Section 4.1.1.4 / 4.5.2): in `Data` and
    /// `Discard` states every line is message data — `RSET`, `QUIT`, and
    /// every other verb are content, never commands, so message text can
    /// never inject SMTP commands (the SMTP-smuggling class,
    /// CVE-2023-51764/51765/51766). The only exit from DATA is a line
    /// whose content is exactly `.` **with a CRLF ending** (the
    /// terminator is `<CRLF>.<CRLF>`); a bare-LF `.` is message data,
    /// never a terminator. Any other line beginning with `.` has that
    /// first dot removed before the line is handed to `recv_data`.
    fn handler(
        &mut self,
        state: &SmtpState,
        msg: &[u8],
    ) -> impl Future<Output = (Vec<u8>, SmtpState)> + Send
    where
        Self: Send,
    {
        async move {
            // Split the line into its content and the original line
            // ending, so data lines preserve the ending as received.
            let (content, ending): (&[u8], &[u8]) = match msg.strip_suffix(b"\n") {
                Some(s) => match s.strip_suffix(b"\r") {
                    Some(s2) => (s2, &b"\r\n"[..]),
                    None => (s, &b"\n"[..]),
                },
                None => (msg, &b""[..]),
            };

            // DATA framing first: in Data and Discard states the line is
            // message content, full stop. Verbs are only verbs outside
            // DATA.
            if matches!(state, SmtpState::Data | SmtpState::Discard) {
                // The one exit: <CRLF>.<CRLF>. A bare-LF `.` is data.
                if content == b"." && ending == b"\r\n" {
                    return match state {
                        SmtpState::Data => (self.end_data().await.into_reply(), SmtpState::Ready),
                        // An aborted transfer has ended: the transaction is
                        // over, so the policy must clear its envelope and
                        // any buffered data, exactly as for RSET (RFC 5321
                        // §4.1.1.4). The abort reply was already sent, so
                        // the reset's own reply is not.
                        _ => {
                            let _ = self.reset().await;
                            (Vec::new(), SmtpState::Ready)
                        }
                    };
                }
                if matches!(state, SmtpState::Data) {
                    // Dot-unstuffing: a data line starting with '.' has
                    // that first dot removed.
                    let unstuffed = content.strip_prefix(b".").unwrap_or(content);
                    let mut line = Vec::with_capacity(unstuffed.len() + ending.len());
                    line.extend_from_slice(unstuffed);
                    line.extend_from_slice(ending);
                    return match self.recv_data(&line).await {
                        DataControl::Continue => (Vec::new(), SmtpState::Data),
                        DataControl::Abort(reply) => (reply, SmtpState::Discard),
                    };
                }
                // Discard: swallow everything until the terminator.
                return (Vec::new(), SmtpState::Discard);
            }

            let (verb, arg) = split_verb(content);

            match (state, verb) {
                // RSET aborts the current transaction but the session stays
                // greeted (RFC 5321 Section 4.1.1.5): the next MAIL needs no
                // new EHLO. Unreachable in Data/Discard (handled above —
                // mid-DATA, RSET is message data).
                (_, v) if eq_ignore_ascii_case(v, b"rset") => {
                    let next = match state {
                        SmtpState::Idle => SmtpState::Idle,
                        SmtpState::Auth(return_to) => (**return_to).clone(),
                        _ => SmtpState::Ready,
                    };
                    (self.reset().await.into_reply(), next)
                }
                (_, v) if eq_ignore_ascii_case(v, b"quit") => {
                    (Self::QUIT.to_vec(), SmtpState::Quit)
                }

                (&SmtpState::Idle | &SmtpState::Ready, v)
                    if eq_ignore_ascii_case(v, b"helo") || eq_ignore_ascii_case(v, b"ehlo") =>
                {
                    match arg
                        .map(trim_ascii_end)
                        .and_then(|a| std::str::from_utf8(a).ok())
                    {
                        // RFC 5321 Section 4.1.1.1: a domain argument is
                        // required. Commands must be ASCII.
                        Some(arg) if !arg.is_empty() => {
                            match self.helo(eq_ignore_ascii_case(v, b"ehlo"), arg).await {
                                Control::Accept(reply) => (reply, SmtpState::Ready),
                                refused => (refused.into_reply(), SmtpState::Idle),
                            }
                        }
                        _ => (Self::SYNTAX_ERR.to_vec(), SmtpState::Idle),
                    }
                }

                // STARTTLS (RFC 3207): only before a transaction — in Data
                // or Discard state the verb is message data, which is the
                // RFC-correct response to a mid-transfer upgrade attempt.
                (&SmtpState::Idle | &SmtpState::Ready, v)
                    if eq_ignore_ascii_case(v, b"starttls") =>
                {
                    match self.starttls().await {
                        Control::Upgrade(reply) => (reply, SmtpState::TlsHandshake),
                        refused => (refused.into_reply(), state.clone()),
                    }
                }

                // AUTH (RFC 4954): the verb carries the SASL mechanism and
                // the optional base64 initial response.
                (&SmtpState::Idle | &SmtpState::Ready, v) if eq_ignore_ascii_case(v, b"auth") => {
                    let (mechanism, initial) = match arg.map(trim_ascii_end) {
                        Some(arg) => match arg.iter().position(|&b| b == b' ') {
                            Some(i) => (
                                &arg[..i],
                                Some(
                                    std::str::from_utf8(trim_ascii_end(&arg[i + 1..]))
                                        .unwrap_or("")
                                        .as_bytes(),
                                ),
                            ),
                            None => (arg, None),
                        },
                        None => {
                            return (Self::SYNTAX_ERR.to_vec(), state.clone());
                        }
                    };
                    let Ok(mechanism) = std::str::from_utf8(mechanism) else {
                        return (Self::SYNTAX_ERR.to_vec(), state.clone());
                    };
                    match self.auth(mechanism, initial).await {
                        Control::Challenge(reply) => {
                            (reply, SmtpState::Auth(Box::new(state.clone())))
                        }
                        refused => (refused.into_reply(), state.clone()),
                    }
                }

                // Mid-authentication lines (RFC 4954 Section 4): the
                // base64 response, or `*` to abort.
                (SmtpState::Auth(return_to), _) => {
                    if content == b"*" {
                        (
                            b"501 5.7.0 Authentication aborted\r\n".to_vec(),
                            (**return_to).clone(),
                        )
                    } else {
                        match self.auth_line(content).await {
                            Control::Challenge(reply) => {
                                (reply, SmtpState::Auth(return_to.clone()))
                            }
                            done => (done.into_reply(), (**return_to).clone()),
                        }
                    }
                }

                (&SmtpState::Ready, v) if eq_ignore_ascii_case(v, b"mail") => {
                    match Self::envelope_arg(arg, b"from:") {
                        Ok(path) => (self.mail_from(path).await.into_reply(), SmtpState::Ready),
                        Err(reply) => (reply, SmtpState::Ready),
                    }
                }

                (&SmtpState::Ready, v) if eq_ignore_ascii_case(v, b"rcpt") => {
                    match Self::envelope_arg(arg, b"to:") {
                        Ok(path) => (self.rcpt_to(path).await.into_reply(), SmtpState::Ready),
                        Err(reply) => (reply, SmtpState::Ready),
                    }
                }

                (&SmtpState::Ready, v) if eq_ignore_ascii_case(v, b"data") => {
                    match self.start_data().await {
                        Control::Accept(reply) => (reply, SmtpState::Data),
                        refused => (refused.into_reply(), SmtpState::Ready),
                    }
                }

                (&SmtpState::Ready, v)
                    if eq_ignore_ascii_case(v, b"vrfy")
                        || eq_ignore_ascii_case(v, b"noop")
                        || eq_ignore_ascii_case(v, b"help")
                        || eq_ignore_ascii_case(v, b"expn") =>
                {
                    (Self::OK.to_vec(), SmtpState::Ready)
                }

                // An unknown or out-of-state verb is refused but the
                // session keeps its state: dropping to Idle would silently
                // discard the envelope (a later MAIL would then see the
                // stale sender) and de-greet the session.
                _ => (Self::UNKNOWN.to_vec(), state.clone()),
            }
        }
    }

    /// Validate the argument `arg` of MAIL FROM / RCPT TO: an ASCII
    /// case-insensitive `prefix` (`from:`/`to:`) and a non-empty, UTF-8
    /// path.
    ///
    /// Returns the path after the prefix, trailing whitespace trimmed.
    ///
    /// # Errors
    ///
    /// The reply to send: [`SmtpSession::UNKNOWN`] when the prefix is
    /// missing, [`SmtpSession::SYNTAX_ERR`] for no argument, a non-UTF-8
    /// path or an empty path. Either way the session stays in Ready.
    fn envelope_arg<'a>(
        arg: Option<&'a [u8]>,
        prefix: &[u8],
    ) -> std::result::Result<&'a str, Vec<u8>> {
        let Some(arg) = arg else {
            return Err(Self::SYNTAX_ERR.to_vec());
        };
        if arg.len() < prefix.len() || !eq_ignore_ascii_case(&arg[..prefix.len()], prefix) {
            return Err(Self::UNKNOWN.to_vec());
        }
        let path = match std::str::from_utf8(trim_ascii_end(&arg[prefix.len()..])) {
            Ok(path) => path,
            Err(_) => return Err(Self::SYNTAX_ERR.to_vec()),
        };
        if path.is_empty() {
            return Err(Self::SYNTAX_ERR.to_vec());
        }
        Ok(path)
    }
}

impl Line {
    /// Whether this is an empty complete line: EOF with nothing read.
    fn is_complete_and_empty(&self) -> bool {
        matches!(self, Line::Complete(line) if line.is_empty())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::duplex;

    /// A configurable SmtpSession that records what the protocol machine
    /// hands to the callbacks. Plain `do_*` methods hold the behavior so
    /// the const overrides ([`SmallSession`]) can reuse it.
    #[derive(Default)]
    struct TestSession {
        helo: Option<String>,
        mail_from: Option<String>,
        rcpt_to: Vec<String>,
        data_lines: Vec<Vec<u8>>,
        end_data_calls: usize,
        reset_calls: usize,
        reject_helo: bool,
        reject_start_data: bool,
        reject_end_data: bool,
        /// When set, abort the data transfer once more than this many
        /// bytes have been received.
        data_limit: Option<usize>,
        received_bytes: usize,
        /// STARTTLS policy: None refuses with 454; Some upgrades.
        offer_tls: Option<Vec<u8>>,
        tls_active: bool,
        tls_established_calls: usize,
        /// AUTH policy: None refuses; Some is the (user, password) pair
        /// accepted by PLAIN and LOGIN, and the challenge replies to
        /// expect.
        auth_users: Option<(String, String)>,
        authenticated: Option<String>,
        /// LOGIN continuation state.
        auth_login_user: Option<String>,
        /// The mechanism of the in-progress continuation.
        auth_pending: Option<&'static str>,
        /// Graceful-shutdown signal (None: never shuts down).
        shutdown: Option<tokio::sync::watch::Receiver<bool>>,
    }

    impl TestSession {
        fn do_helo(&mut self, ehlo: bool, arg: &str) -> Control {
            let _ = ehlo;
            if self.reject_helo {
                return Control::reject(b"550 nope\r\n");
            }
            self.helo = Some(arg.to_string());
            Control::accept(b"250 hello\r\n")
        }

        fn do_starttls(&mut self) -> Control {
            if self.tls_active {
                return Control::reject(b"503 5.5.1 TLS already active\r\n");
            }
            match self.offer_tls.take() {
                Some(reply) => Control::upgrade(reply),
                None => Control::reject(b"454 4.7.0 TLS not available\r\n"),
            }
        }

        fn do_tls_established(&mut self) {
            self.tls_active = true;
            self.tls_established_calls += 1;
            self.helo = None;
            self.mail_from = None;
            self.authenticated = None;
        }

        fn verify(&mut self, user: &str, pass: &str) -> Control {
            match &self.auth_users {
                Some((u, p)) if u == user && p == pass => {
                    self.authenticated = Some(user.to_string());
                    Control::accept(b"235 2.7.0 Authentication successful\r\n")
                }
                _ => Control::reject(b"535 5.7.8 Authentication credentials invalid\r\n"),
            }
        }

        fn do_auth(&mut self, mechanism: &str, initial: Option<&[u8]>) -> Control {
            if !self.tls_active {
                return Control::reject(b"538 5.7.11 Encryption required for authentication\r\n");
            }
            if self.authenticated.is_some() {
                return Control::reject(b"503 5.5.1 Already authenticated\r\n");
            }
            let Some((_, _)) = &self.auth_users else {
                return Control::reject(b"502 5.5.1 Authentication not supported\r\n");
            };
            match mechanism {
                "PLAIN" => {
                    let Some(initial) = initial else {
                        self.auth_pending = Some("PLAIN");
                        return Control::challenge(b"334 \r\n");
                    };
                    match decode_b64(initial).as_deref().and_then(decode_plain) {
                        Some((user, pass)) => self.verify(&user, &pass),
                        None => Control::reject(b"501 5.5.2 Invalid base64 data\r\n"),
                    }
                }
                "LOGIN" => {
                    if let Some(initial) = initial {
                        match decode_b64(initial) {
                            Some(user) => {
                                self.auth_login_user =
                                    Some(String::from_utf8_lossy(&user).into_owned());
                                self.auth_pending = Some("LOGIN");
                                Control::challenge(b"334 UGFzc3dvcmQ6\r\n")
                            }
                            None => Control::reject(b"501 5.5.2 Invalid base64 data\r\n"),
                        }
                    } else {
                        self.auth_pending = Some("LOGIN");
                        Control::challenge(b"334 VXNlcm5hbWU6\r\n")
                    }
                }
                _ => Control::reject(b"504 5.5.4 Unrecognized authentication type\r\n"),
            }
        }

        fn do_auth_line(&mut self, line: &[u8]) -> Control {
            match decode_b64(line) {
                None => Control::reject(b"501 5.5.2 Invalid base64 data\r\n"),
                Some(data) => match self.auth_pending.take() {
                    Some("PLAIN") => match decode_plain(&data) {
                        Some((user, pass)) => self.verify(&user, &pass),
                        None => Control::reject(b"501 5.5.2 Invalid PLAIN response\r\n"),
                    },
                    Some("LOGIN") => {
                        if let Some(user) = self.auth_login_user.take() {
                            let pass = String::from_utf8_lossy(&data).into_owned();
                            self.verify(&user, &pass)
                        } else {
                            self.auth_login_user =
                                Some(String::from_utf8_lossy(&data).into_owned());
                            self.auth_pending = Some("LOGIN");
                            Control::challenge(b"334 UGFzc3dvcmQ6\r\n")
                        }
                    }
                    _ => Control::reject(b"501 5.5.2 No authentication in progress\r\n"),
                },
            }
        }

        fn do_mail_from(&mut self, path: &str) -> Control {
            self.mail_from = Some(path.to_string());
            Control::accept(Self::OK)
        }

        fn do_rcpt_to(&mut self, path: &str) -> Control {
            self.rcpt_to.push(path.to_string());
            Control::accept(Self::OK)
        }

        fn do_start_data(&mut self) -> Control {
            if self.reject_start_data {
                return Control::reject(b"503 5.5.1 No valid recipients\r\n");
            }
            Control::accept(Self::SEND_DATA)
        }

        fn do_recv_data(&mut self, line: &[u8]) -> DataControl {
            self.received_bytes += line.len();
            if let Some(limit) = self.data_limit {
                if self.received_bytes > limit {
                    return DataControl::Abort(b"552 5.3.4 too big\r\n".to_vec());
                }
            }
            self.data_lines.push(line.to_vec());
            DataControl::Continue
        }

        fn do_end_data(&mut self) -> Control {
            self.end_data_calls += 1;
            if self.reject_end_data {
                return Control::reject(b"550 nope\r\n");
            }
            Control::accept(b"250 accepted\r\n")
        }

        fn do_reset(&mut self) -> Control {
            self.reset_calls += 1;
            self.mail_from = None;
            self.rcpt_to.clear();
            self.data_lines.clear();
            Control::accept(Self::OK)
        }
    }

    impl SmtpSession for TestSession {
        async fn server_greet(&self) -> Vec<u8> {
            b"220 test ready\r\n".to_vec()
        }

        async fn shutdown_signal(&self) {
            if let Some(mut rx) = self.shutdown.clone() {
                if rx.wait_for(|&down| down).await.is_ok() {
                    return;
                }
            }
            std::future::pending::<()>().await
        }

        async fn helo(&mut self, ehlo: bool, arg: &str) -> Control {
            self.do_helo(ehlo, arg)
        }

        async fn starttls(&mut self) -> Control {
            self.do_starttls()
        }

        async fn tls_established(&mut self) {
            self.do_tls_established()
        }

        async fn auth(&mut self, mechanism: &str, initial: Option<&[u8]>) -> Control {
            self.do_auth(mechanism, initial)
        }

        async fn auth_line(&mut self, line: &[u8]) -> Control {
            self.do_auth_line(line)
        }

        async fn mail_from(&mut self, path: &str) -> Control {
            self.do_mail_from(path)
        }

        async fn rcpt_to(&mut self, path: &str) -> Control {
            self.do_rcpt_to(path)
        }

        async fn start_data(&mut self) -> Control {
            self.do_start_data()
        }

        async fn recv_data(&mut self, line: &[u8]) -> DataControl {
            self.do_recv_data(line)
        }

        async fn end_data(&mut self) -> Control {
            self.do_end_data()
        }

        async fn reset(&mut self) -> Control {
            self.do_reset()
        }
    }

    /// Same behavior as [`TestSession`] with tiny line caps, so framing
    /// overflow can be tested without moving kilobytes through the duplex.
    #[derive(Default)]
    struct SmallSession(TestSession);

    impl SmtpSession for SmallSession {
        const MAX_CMD_LINE: usize = 16;
        const MAX_DATA_LINE: usize = 32;

        async fn server_greet(&self) -> Vec<u8> {
            b"220 test ready\r\n".to_vec()
        }

        async fn helo(&mut self, ehlo: bool, arg: &str) -> Control {
            self.0.do_helo(ehlo, arg)
        }

        async fn starttls(&mut self) -> Control {
            self.0.do_starttls()
        }

        async fn tls_established(&mut self) {
            self.0.do_tls_established()
        }

        async fn auth(&mut self, mechanism: &str, initial: Option<&[u8]>) -> Control {
            self.0.do_auth(mechanism, initial)
        }

        async fn auth_line(&mut self, line: &[u8]) -> Control {
            self.0.do_auth_line(line)
        }

        async fn mail_from(&mut self, path: &str) -> Control {
            self.0.do_mail_from(path)
        }

        async fn rcpt_to(&mut self, path: &str) -> Control {
            self.0.do_rcpt_to(path)
        }

        async fn start_data(&mut self) -> Control {
            self.0.do_start_data()
        }

        async fn recv_data(&mut self, line: &[u8]) -> DataControl {
            self.0.do_recv_data(line)
        }

        async fn end_data(&mut self) -> Control {
            self.0.do_end_data()
        }

        async fn reset(&mut self) -> Control {
            self.0.do_reset()
        }
    }

    /// Drive one command through the handler and assert the reply and the
    /// resulting state.
    async fn expect(
        session: &mut TestSession,
        state: SmtpState,
        line: &[u8],
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
        expect(
            &mut s,
            SmtpState::Idle,
            b"HELO example.org\r\n",
            b"250 hello\r\n",
            SmtpState::Ready,
        )
        .await;
        assert_eq!(s.helo.as_deref(), Some("example.org"));

        expect(
            &mut s,
            SmtpState::Idle,
            b"EHLO mail.example.net\r\n",
            b"250 hello\r\n",
            SmtpState::Ready,
        )
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
        expect(
            &mut s,
            SmtpState::Idle,
            b"HELO example.org\r\n",
            b"550 nope\r\n",
            SmtpState::Idle,
        )
        .await;

        // The client ignores the 550 and tries to send mail anyway.
        expect(
            &mut s,
            SmtpState::Idle,
            b"MAIL FROM:<a@b>\r\n",
            TestSession::UNKNOWN,
            SmtpState::Idle,
        )
        .await;
        expect(
            &mut s,
            SmtpState::Idle,
            b"RCPT TO:<c@d>\r\n",
            TestSession::UNKNOWN,
            SmtpState::Idle,
        )
        .await;
        expect(
            &mut s,
            SmtpState::Idle,
            b"DATA\r\n",
            TestSession::UNKNOWN,
            SmtpState::Idle,
        )
        .await;
        assert_eq!(
            s.mail_from, None,
            "no envelope may be recorded before an accepted HELO"
        );
    }

    #[tokio::test]
    async fn helo_without_argument_is_a_syntax_error() {
        let mut s = TestSession::default();
        expect(
            &mut s,
            SmtpState::Idle,
            b"HELO\r\n",
            TestSession::SYNTAX_ERR,
            SmtpState::Idle,
        )
        .await;
        expect(
            &mut s,
            SmtpState::Idle,
            b"EHLO\r\n",
            TestSession::SYNTAX_ERR,
            SmtpState::Idle,
        )
        .await;
        expect(
            &mut s,
            SmtpState::Idle,
            b"HELO \r\n",
            TestSession::SYNTAX_ERR,
            SmtpState::Idle,
        )
        .await;
        assert_eq!(s.helo, None, "callback must not run on a syntax error");
    }

    /// A command argument that is not valid UTF-8 is a syntax error, not
    /// a panic or a mojibake path.
    #[tokio::test]
    async fn command_with_invalid_utf8_arg_is_a_syntax_error() {
        let mut s = TestSession::default();
        expect(
            &mut s,
            SmtpState::Idle,
            b"HELO \xff\xfe\xfd\r\n",
            TestSession::SYNTAX_ERR,
            SmtpState::Idle,
        )
        .await;
        assert_eq!(s.helo, None);

        expect(
            &mut s,
            SmtpState::Ready,
            b"MAIL FROM:<a@b>\xff\r\n",
            TestSession::SYNTAX_ERR,
            SmtpState::Ready,
        )
        .await;
        assert_eq!(s.mail_from, None);
    }

    #[tokio::test]
    async fn mail_from_requires_helo_first() {
        let mut s = TestSession::default();
        expect(
            &mut s,
            SmtpState::Idle,
            b"MAIL FROM:<a@b>\r\n",
            TestSession::UNKNOWN,
            SmtpState::Idle,
        )
        .await;
        assert_eq!(s.mail_from, None);
    }

    #[tokio::test]
    async fn mail_from_passes_the_path_to_the_callback() {
        let mut s = TestSession::default();
        expect(
            &mut s,
            SmtpState::Ready,
            b"MAIL FROM:<alice@example.org>\r\n",
            TestSession::OK,
            SmtpState::Ready,
        )
        .await;
        assert_eq!(s.mail_from.as_deref(), Some("<alice@example.org>"));

        // The null sender is a valid non-empty path.
        expect(
            &mut s,
            SmtpState::Ready,
            b"MAIL FROM:<>\r\n",
            TestSession::OK,
            SmtpState::Ready,
        )
        .await;
        assert_eq!(s.mail_from.as_deref(), Some("<>"));
    }

    #[tokio::test]
    async fn mail_argument_errors_keep_the_session_in_ready() {
        let mut s = TestSession::default();
        expect(
            &mut s,
            SmtpState::Ready,
            b"MAIL\r\n",
            TestSession::SYNTAX_ERR,
            SmtpState::Ready,
        )
        .await;
        expect(
            &mut s,
            SmtpState::Ready,
            b"MAIL FROM:\r\n",
            TestSession::SYNTAX_ERR,
            SmtpState::Ready,
        )
        .await;
        // A malformed keyword leaves the state unchanged (still Ready).
        expect(
            &mut s,
            SmtpState::Ready,
            b"MAIL X:<a@b>\r\n",
            TestSession::UNKNOWN,
            SmtpState::Ready,
        )
        .await;
    }

    #[tokio::test]
    async fn rcpt_argument_errors_keep_the_session_in_ready() {
        let mut s = TestSession::default();
        expect(
            &mut s,
            SmtpState::Ready,
            b"RCPT\r\n",
            TestSession::SYNTAX_ERR,
            SmtpState::Ready,
        )
        .await;
        expect(
            &mut s,
            SmtpState::Ready,
            b"RCPT TO:\r\n",
            TestSession::SYNTAX_ERR,
            SmtpState::Ready,
        )
        .await;
        expect(
            &mut s,
            SmtpState::Ready,
            b"RCPT FROM:<a@b>\r\n",
            TestSession::UNKNOWN,
            SmtpState::Ready,
        )
        .await;
    }

    #[tokio::test]
    async fn rcpt_to_passes_the_path_to_the_callback() {
        let mut s = TestSession::default();
        expect(
            &mut s,
            SmtpState::Ready,
            b"RCPT TO:<bob@example.net>\r\n",
            TestSession::OK,
            SmtpState::Ready,
        )
        .await;
        assert_eq!(s.rcpt_to, vec!["<bob@example.net>".to_string()]);
    }

    #[tokio::test]
    async fn data_requires_ready_state() {
        let mut s = TestSession::default();
        expect(
            &mut s,
            SmtpState::Idle,
            b"DATA\r\n",
            TestSession::UNKNOWN,
            SmtpState::Idle,
        )
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
        expect(
            &mut s,
            SmtpState::Ready,
            b"DATA\r\n",
            b"503 5.5.1 No valid recipients\r\n",
            SmtpState::Ready,
        )
        .await;

        // The client adds a recipient and retries DATA successfully.
        s.reject_start_data = false;
        expect(
            &mut s,
            SmtpState::Ready,
            b"RCPT TO:<bob@example.net>\r\n",
            TestSession::OK,
            SmtpState::Ready,
        )
        .await;
        expect(
            &mut s,
            SmtpState::Ready,
            b"DATA\r\n",
            TestSession::SEND_DATA,
            SmtpState::Data,
        )
        .await;
    }

    #[tokio::test]
    async fn data_mode_records_lines_until_crlf_dot() {
        let mut s = TestSession::default();
        expect(
            &mut s,
            SmtpState::Ready,
            b"DATA\r\n",
            TestSession::SEND_DATA,
            SmtpState::Data,
        )
        .await;

        // Message lines yield no reply and stay in Data mode.
        expect(
            &mut s,
            SmtpState::Data,
            b"line one\r\n",
            b"",
            SmtpState::Data,
        )
        .await;
        expect(
            &mut s,
            SmtpState::Data,
            b"line two\r\n",
            b"",
            SmtpState::Data,
        )
        .await;
        assert_eq!(
            s.data_lines,
            vec![b"line one\r\n".to_vec(), b"line two\r\n".to_vec()]
        );
        assert_eq!(s.end_data_calls, 0);

        expect(
            &mut s,
            SmtpState::Data,
            b".\r\n",
            b"250 accepted\r\n",
            SmtpState::Ready,
        )
        .await;
        assert_eq!(s.end_data_calls, 1);
    }

    /// Dot-unstuffing (RFC 5321 Section 4.5.2): a data line beginning with
    /// '.' loses that dot before reaching the policy; ".." becomes ".".
    #[tokio::test]
    async fn dot_unstuffing() {
        let mut s = TestSession::default();
        expect(
            &mut s,
            SmtpState::Data,
            b".hidden\r\n",
            b"",
            SmtpState::Data,
        )
        .await;
        expect(
            &mut s,
            SmtpState::Data,
            b"..two dots\r\n",
            b"",
            SmtpState::Data,
        )
        .await;
        expect(&mut s, SmtpState::Data, b"plain\r\n", b"", SmtpState::Data).await;
        // A bare-LF line is unstuffed and keeps its ending.
        expect(&mut s, SmtpState::Data, b".lf line\n", b"", SmtpState::Data).await;

        assert_eq!(
            s.data_lines,
            vec![
                b"hidden\r\n".to_vec(),
                b".two dots\r\n".to_vec(),
                b"plain\r\n".to_vec(),
                b"lf line\n".to_vec(),
            ]
        );
    }

    /// The terminator is exactly <CRLF>.<CRLF>. A bare-LF `.` is message
    /// data (an empty line), never a terminator — this closes the
    /// SMTP-smuggling parser differential (CVE-2023-51764 class).
    #[tokio::test]
    async fn lf_dot_is_message_data_not_a_terminator() {
        let mut s = TestSession::default();
        // Bare-LF dot: an empty line of data, still in DATA.
        expect(&mut s, SmtpState::Data, b".\n", b"", SmtpState::Data).await;
        assert_eq!(s.data_lines, vec![b"\n".to_vec()]);
        assert_eq!(s.end_data_calls, 0);

        // Only CRLF.CRLF terminates.
        expect(
            &mut s,
            SmtpState::Data,
            b".\r\n",
            b"250 accepted\r\n",
            SmtpState::Ready,
        )
        .await;
        assert_eq!(s.end_data_calls, 1);
    }

    /// Message data is bytes, not text: 8-bit and invalid-UTF-8 content
    /// reaches the policy verbatim.
    #[tokio::test]
    async fn data_lines_are_raw_bytes() {
        let mut s = TestSession::default();
        let raw = b"binary \xFF\xFE\x00 bytes\r\n";
        expect(&mut s, SmtpState::Data, raw, b"", SmtpState::Data).await;
        assert_eq!(s.data_lines, vec![raw.to_vec()]);
    }

    /// A size-abort replies once, discards the rest of the message until
    /// the terminator, and returns the session to Ready.
    #[tokio::test]
    async fn data_size_abort_discards_until_dot() {
        let mut s = TestSession {
            data_limit: Some(10),
            ..Default::default()
        };
        expect(
            &mut s,
            SmtpState::Ready,
            b"DATA\r\n",
            TestSession::SEND_DATA,
            SmtpState::Data,
        )
        .await;

        expect(&mut s, SmtpState::Data, b"short\r\n", b"", SmtpState::Data).await;
        // This line crosses the limit.
        expect(
            &mut s,
            SmtpState::Data,
            b"this line is too long\r\n",
            b"552 5.3.4 too big\r\n",
            SmtpState::Discard,
        )
        .await;

        // Remaining body lines are swallowed without being recorded or
        // mistaken for commands — including QUIT (message content, not a
        // command — the SMTP-smuggling class). The only exit is the
        // CRLF dot terminator.
        expect(
            &mut s,
            SmtpState::Discard,
            b"more body\r\n",
            b"",
            SmtpState::Discard,
        )
        .await;
        expect(
            &mut s,
            SmtpState::Discard,
            b"QUIT\r\n",
            b"",
            SmtpState::Discard,
        )
        .await;
        s.mail_from = Some("a@b".into());
        assert_eq!(s.reset_calls, 0);
        expect(&mut s, SmtpState::Discard, b".\r\n", b"", SmtpState::Ready).await;
        // The aborted transaction is over: the policy was told (reset), so
        // its envelope and buffered data are gone and the next MAIL works.
        assert_eq!(s.reset_calls, 1);
        assert_eq!(s.mail_from, None);
        assert!(s.data_lines.is_empty());
        assert_eq!(s.end_data_calls, 0, "an aborted message is never delivered");
    }

    #[tokio::test]
    async fn discarded_lines_swallowed_until_dot() {
        let mut s = TestSession {
            data_limit: Some(10),
            ..Default::default()
        };
        expect(
            &mut s,
            SmtpState::Ready,
            b"DATA\r\n",
            TestSession::SEND_DATA,
            SmtpState::Data,
        )
        .await;
        expect(
            &mut s,
            SmtpState::Data,
            b"this line is too long\r\n",
            b"552 5.3.4 too big\r\n",
            SmtpState::Discard,
        )
        .await;
        expect(
            &mut s,
            SmtpState::Discard,
            b"more body\r\n",
            b"",
            SmtpState::Discard,
        )
        .await;
        expect(&mut s, SmtpState::Discard, b".\r\n", b"", SmtpState::Ready).await;
        assert_eq!(s.data_lines, Vec::<Vec<u8>>::new());

        // The session is usable again.
        expect(
            &mut s,
            SmtpState::Ready,
            b"MAIL FROM:<a@b>\r\n",
            TestSession::OK,
            SmtpState::Ready,
        )
        .await;
    }

    #[tokio::test]
    async fn end_data_rejection_still_returns_to_ready() {
        let mut s = TestSession {
            reject_end_data: true,
            ..Default::default()
        };
        expect(
            &mut s,
            SmtpState::Data,
            b".\r\n",
            b"550 nope\r\n",
            SmtpState::Ready,
        )
        .await;
        assert_eq!(s.end_data_calls, 1);
    }

    /// RSET aborts the transaction but the session stays greeted
    /// (RFC 5321 Section 4.1.1.5): the next MAIL works without a new
    /// EHLO.
    #[tokio::test]
    async fn rset_clears_envelope_and_keeps_the_session_greeted() {
        let mut s = TestSession::default();
        expect(
            &mut s,
            SmtpState::Ready,
            b"MAIL FROM:<a@b>\r\n",
            TestSession::OK,
            SmtpState::Ready,
        )
        .await;
        expect(
            &mut s,
            SmtpState::Ready,
            b"RCPT TO:<c@d>\r\n",
            TestSession::OK,
            SmtpState::Ready,
        )
        .await;

        expect(
            &mut s,
            SmtpState::Ready,
            b"RSET\r\n",
            TestSession::OK,
            SmtpState::Ready,
        )
        .await;
        assert_eq!(s.reset_calls, 1);
        assert_eq!(s.mail_from, None, "RSET must clear the envelope");
        assert!(s.rcpt_to.is_empty());

        // The session is still greeted: MAIL works without a new EHLO.
        expect(
            &mut s,
            SmtpState::Ready,
            b"MAIL FROM:<e@f>\r\n",
            TestSession::OK,
            SmtpState::Ready,
        )
        .await;
    }

    /// SMTP smuggling (CVE-2023-51764 class): in DATA state, message
    /// lines that look like commands — RSET, QUIT, MAIL, DATA, even a
    /// bare-LF dot — are message content, never commands. The message
    /// continues to its real CRLF.CRLF terminator and nothing inside the
    /// body reaches the command parser.
    #[tokio::test]
    async fn smtp_smuggling_is_prevented() {
        let mut s = TestSession::default();
        expect(
            &mut s,
            SmtpState::Ready,
            b"DATA\r\n",
            TestSession::SEND_DATA,
            SmtpState::Data,
        )
        .await;

        // Every one of these is message data.
        for line in [
            &b"RSET\r\n"[..],
            b"QUIT\r\n".as_slice(),
            b"MAIL FROM:<attacker@evil.example>\r\n".as_slice(),
            b"RCPT TO:<victim@example.org>\r\n".as_slice(),
            b"DATA\r\n".as_slice(),
            b".\n".as_slice(),
        ] {
            expect(&mut s, SmtpState::Data, line, b"", SmtpState::Data).await;
        }
        assert_eq!(s.reset_calls, 0, "nothing mid-DATA may abort the message");
        assert_eq!(s.end_data_calls, 0);
        assert_eq!(s.data_lines.len(), 6);

        // The real terminator ends the transaction; the body lines were
        // never commands.
        expect(
            &mut s,
            SmtpState::Data,
            b".\r\n",
            b"250 accepted\r\n",
            SmtpState::Ready,
        )
        .await;
        assert_eq!(s.end_data_calls, 1);
        assert_eq!(s.mail_from, None, "no smuggled MAIL FROM may be recorded");
    }

    // -- AUTH (RFC 4954) -------------------------------------------------

    fn b64(s: &str) -> Vec<u8> {
        use base64::Engine as _;
        base64::engine::general_purpose::STANDARD
            .encode(s)
            .into_bytes()
    }

    fn tls_session() -> TestSession {
        TestSession {
            tls_active: true,
            auth_users: Some(("alice".to_string(), "secret".to_string())),
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn auth_plain_with_initial_response() {
        let mut s = tls_session();
        // authzid NUL authcid NUL passwd, base64'd.
        let initial = b64("\0alice\0secret");
        expect(
            &mut s,
            SmtpState::Ready,
            [b"AUTH PLAIN ".as_slice(), &initial, b"\r\n"]
                .concat()
                .as_slice(),
            b"235 2.7.0 Authentication successful\r\n",
            SmtpState::Ready,
        )
        .await;
        assert_eq!(s.authenticated.as_deref(), Some("alice"));

        // Bad credentials.
        let mut s = tls_session();
        let initial = b64("\0alice\0wrong");
        expect(
            &mut s,
            SmtpState::Ready,
            [b"AUTH PLAIN ".as_slice(), &initial, b"\r\n"]
                .concat()
                .as_slice(),
            b"535 5.7.8 Authentication credentials invalid\r\n",
            SmtpState::Ready,
        )
        .await;
    }

    #[tokio::test]
    async fn auth_plain_continuation_and_abort() {
        let mut s = tls_session();
        // No initial response: the machine enters the continuation state,
        // remembering where to return (Ready).
        expect(
            &mut s,
            SmtpState::Ready,
            b"AUTH PLAIN\r\n",
            b"334 \r\n",
            SmtpState::Auth(Box::new(SmtpState::Ready)),
        )
        .await;
        // The client completes the exchange.
        expect(
            &mut s,
            SmtpState::Auth(Box::new(SmtpState::Ready)),
            &b64("\0alice\0secret"),
            b"235 2.7.0 Authentication successful\r\n",
            SmtpState::Ready,
        )
        .await;
        assert_eq!(s.authenticated.as_deref(), Some("alice"));

        // A client aborts with `*`: back to the remembered state.
        let mut s = tls_session();
        expect(
            &mut s,
            SmtpState::Ready,
            b"AUTH PLAIN\r\n",
            b"334 \r\n",
            SmtpState::Auth(Box::new(SmtpState::Ready)),
        )
        .await;
        expect(
            &mut s,
            SmtpState::Auth(Box::new(SmtpState::Ready)),
            b"*\r\n",
            b"501 5.7.0 Authentication aborted\r\n",
            SmtpState::Ready,
        )
        .await;
    }

    #[tokio::test]
    async fn auth_login_dance() {
        let mut s = tls_session();
        expect(
            &mut s,
            SmtpState::Ready,
            b"AUTH LOGIN\r\n",
            b"334 VXNlcm5hbWU6\r\n", // base64 "Username:"
            SmtpState::Auth(Box::new(SmtpState::Ready)),
        )
        .await;
        expect(
            &mut s,
            SmtpState::Auth(Box::new(SmtpState::Ready)),
            &b64("alice"),
            b"334 UGFzc3dvcmQ6\r\n", // base64 "Password:"
            SmtpState::Auth(Box::new(SmtpState::Ready)),
        )
        .await;
        expect(
            &mut s,
            SmtpState::Auth(Box::new(SmtpState::Ready)),
            &b64("secret"),
            b"235 2.7.0 Authentication successful\r\n",
            SmtpState::Ready,
        )
        .await;
        assert_eq!(s.authenticated.as_deref(), Some("alice"));
    }

    #[tokio::test]
    async fn auth_policy_gates() {
        // AUTH over a plaintext connection is refused (RFC 8310: the
        // password must not traverse an unencrypted channel).
        let mut s = tls_session();
        s.tls_active = false;
        expect(
            &mut s,
            SmtpState::Ready,
            b"AUTH PLAIN\r\n",
            b"538 5.7.11 Encryption required for authentication\r\n",
            SmtpState::Ready,
        )
        .await;

        // No configured users: not supported.
        let mut s = TestSession {
            tls_active: true,
            ..Default::default()
        };
        expect(
            &mut s,
            SmtpState::Ready,
            b"AUTH PLAIN\r\n",
            b"502 5.5.1 Authentication not supported\r\n",
            SmtpState::Ready,
        )
        .await;

        // Unsupported mechanism.
        let mut s = tls_session();
        expect(
            &mut s,
            SmtpState::Ready,
            b"AUTH CRAM-MD5\r\n",
            b"504 5.5.4 Unrecognized authentication type\r\n",
            SmtpState::Ready,
        )
        .await;

        // AUTH without an argument is a syntax error.
        expect(
            &mut s,
            SmtpState::Ready,
            b"AUTH\r\n",
            TestSession::SYNTAX_ERR,
            SmtpState::Ready,
        )
        .await;

        // Already authenticated.
        let mut s = tls_session();
        s.authenticated = Some("alice".to_string());
        expect(
            &mut s,
            SmtpState::Ready,
            b"AUTH PLAIN\r\n",
            b"503 5.5.1 Already authenticated\r\n",
            SmtpState::Ready,
        )
        .await;
    }

    #[tokio::test]
    async fn quit_terminates_the_session() {
        let mut s = TestSession::default();
        expect(
            &mut s,
            SmtpState::Ready,
            b"QUIT\r\n",
            TestSession::QUIT,
            SmtpState::Quit,
        )
        .await;
    }

    #[tokio::test]
    async fn misc_commands_accepted_in_ready_state() {
        let mut s = TestSession::default();
        for cmd in [
            b"NOOP\r\n".as_slice(),
            b"VRFY user\r\n",
            b"HELP\r\n",
            b"EXPN list\r\n",
        ] {
            expect(
                &mut s,
                SmtpState::Ready,
                cmd,
                TestSession::OK,
                SmtpState::Ready,
            )
            .await;
        }
    }

    #[tokio::test]
    async fn unknown_command_is_rejected() {
        let mut s = TestSession::default();
        expect(
            &mut s,
            SmtpState::Idle,
            b"FROB\r\n",
            TestSession::UNKNOWN,
            SmtpState::Idle,
        )
        .await;
    }

    // -- STARTTLS (RFC 3207) -------------------------------------------

    /// The policy's Upgrade verdict pauses the machine in TlsHandshake; a
    /// refusal keeps the current state.
    #[tokio::test]
    async fn starttls_upgrade_and_refusal() {
        let mut s = TestSession {
            offer_tls: Some(b"220 2.0.0 Ready to start TLS\r\n".to_vec()),
            ..Default::default()
        };
        expect(
            &mut s,
            SmtpState::Ready,
            b"STARTTLS\r\n",
            b"220 2.0.0 Ready to start TLS\r\n",
            SmtpState::TlsHandshake,
        )
        .await;

        // Refused (no TLS available): the session stays where it was.
        let mut s = TestSession::default();
        expect(
            &mut s,
            SmtpState::Ready,
            b"STARTTLS\r\n",
            b"454 4.7.0 TLS not available\r\n",
            SmtpState::Ready,
        )
        .await;
        // Also valid from Idle (before HELO).
        expect(
            &mut s,
            SmtpState::Idle,
            b"STARTTLS\r\n",
            b"454 4.7.0 TLS not available\r\n",
            SmtpState::Idle,
        )
        .await;
    }

    /// STARTTLS mid-transaction is message data, not a command (RFC 3207
    /// Section 4: the command must not be issued during a transfer).
    #[tokio::test]
    async fn starttls_during_data_is_message_data() {
        let mut s = TestSession {
            offer_tls: Some(b"220 2.0.0 Ready to start TLS\r\n".to_vec()),
            ..Default::default()
        };
        expect(
            &mut s,
            SmtpState::Data,
            b"STARTTLS\r\n",
            b"",
            SmtpState::Data,
        )
        .await;
        assert_eq!(s.data_lines, vec![b"STARTTLS\r\n".to_vec()]);
    }

    /// The driver contract: run writes the 220, returns TlsHandshake; the
    /// resumed run does not re-greet and continues from the reset state.
    #[tokio::test]
    async fn starttls_pause_and_resume_over_duplex() {
        let (client, server) = duplex(1024);
        let peer: SocketAddr = "127.0.0.1:2525".parse().unwrap();

        let task = tokio::spawn(async move {
            let mut session = TestSession {
                offer_tls: Some(b"220 2.0.0 Ready to start TLS\r\n".to_vec()),
                ..Default::default()
            };
            let mut stream = BufReader::new(server);
            let mut state = SessionState::default();
            let first = session
                .run(&mut stream, &peer, "example.org", &2000, &mut state)
                .await;

            // The driver: handshake goes here (abstracted away in this
            // test); the protocol restarts in Idle with no new greeting.
            session.do_tls_established();
            state.state = SmtpState::Idle;
            state.greeted = true;

            let second = session
                .run(&mut stream, &peer, "example.org", &2000, &mut state)
                .await;
            (session, first, second)
        });

        let mut client = BufReader::new(client);
        let mut greet = String::new();
        client.read_line(&mut greet).await.unwrap();
        assert_eq!(greet, "220 test ready\r\n");

        client.write_all(b"EHLO client.test\r\n").await.unwrap();
        assert_eq!(read_reply(&mut client).await, "250 hello\r\n");

        client.write_all(b"STARTTLS\r\n").await.unwrap();
        assert_eq!(
            read_reply(&mut client).await,
            "220 2.0.0 Ready to start TLS\r\n"
        );

        // (TLS would be negotiated here.)

        // After the handshake the client re-issues EHLO; the server must
        // not re-send the banner.
        client.write_all(b"EHLO client.test\r\n").await.unwrap();
        assert_eq!(read_reply(&mut client).await, "250 hello\r\n");

        client.write_all(b"QUIT\r\n").await.unwrap();
        assert_eq!(read_reply(&mut client).await, "221 Bye\r\n");
        drop(client);

        let (session, first, second) = task.await.unwrap();
        assert_eq!(first.unwrap(), EndReason::TlsHandshake);
        assert_eq!(second.unwrap(), EndReason::Closed);
        assert!(session.tls_active);
        // The pre-TLS HELO knowledge was discarded at the upgrade, then
        // legitimately re-established by the client's post-TLS EHLO.
        assert_eq!(session.tls_established_calls, 1);
        assert_eq!(session.helo.as_deref(), Some("client.test"));
    }

    #[tokio::test]
    async fn verbs_are_case_insensitive() {
        let mut s = TestSession::default();
        expect(
            &mut s,
            SmtpState::Idle,
            b"helo example.org\r\n",
            b"250 hello\r\n",
            SmtpState::Ready,
        )
        .await;
        expect(
            &mut s,
            SmtpState::Ready,
            b"MaIl FrOm:<a@b>\r\n",
            TestSession::OK,
            SmtpState::Ready,
        )
        .await;
        expect(
            &mut s,
            SmtpState::Ready,
            b"rCpT tO:<c@d>\r\n",
            TestSession::OK,
            SmtpState::Ready,
        )
        .await;
        expect(
            &mut s,
            SmtpState::Ready,
            b"dAta\r\n",
            TestSession::SEND_DATA,
            SmtpState::Data,
        )
        .await;
        expect(
            &mut s,
            SmtpState::Data,
            b".\r\n",
            b"250 accepted\r\n",
            SmtpState::Ready,
        )
        .await;
        expect(
            &mut s,
            SmtpState::Ready,
            b"qUiT\r\n",
            TestSession::QUIT,
            SmtpState::Quit,
        )
        .await;
    }

    #[tokio::test]
    async fn full_session_happy_path() {
        let mut s = TestSession::default();
        expect(
            &mut s,
            SmtpState::Idle,
            b"HELO client.example\r\n",
            b"250 hello\r\n",
            SmtpState::Ready,
        )
        .await;
        expect(
            &mut s,
            SmtpState::Ready,
            b"MAIL FROM:<alice@example.org>\r\n",
            TestSession::OK,
            SmtpState::Ready,
        )
        .await;
        expect(
            &mut s,
            SmtpState::Ready,
            b"RCPT TO:<bob@example.net>\r\n",
            TestSession::OK,
            SmtpState::Ready,
        )
        .await;
        expect(
            &mut s,
            SmtpState::Ready,
            b"DATA\r\n",
            TestSession::SEND_DATA,
            SmtpState::Data,
        )
        .await;
        expect(
            &mut s,
            SmtpState::Data,
            b"Subject: hi\r\n",
            b"",
            SmtpState::Data,
        )
        .await;
        expect(&mut s, SmtpState::Data, b"\r\n", b"", SmtpState::Data).await;
        expect(&mut s, SmtpState::Data, b"body\r\n", b"", SmtpState::Data).await;
        expect(
            &mut s,
            SmtpState::Data,
            b".\r\n",
            b"250 accepted\r\n",
            SmtpState::Ready,
        )
        .await;
        expect(
            &mut s,
            SmtpState::Ready,
            b"QUIT\r\n",
            TestSession::QUIT,
            SmtpState::Quit,
        )
        .await;

        assert_eq!(s.helo.as_deref(), Some("client.example"));
        assert_eq!(s.mail_from.as_deref(), Some("<alice@example.org>"));
        assert_eq!(s.rcpt_to, vec!["<bob@example.net>".to_string()]);
        assert_eq!(
            s.data_lines,
            vec![
                b"Subject: hi\r\n".to_vec(),
                b"\r\n".to_vec(),
                b"body\r\n".to_vec()
            ]
        );
        assert_eq!(s.end_data_calls, 1);
    }

    // -- Framing tests over an in-memory duplex (exercise `run`, the read
    //    caps, and the greet/reply wire loop) -------------------------------

    /// Read one reply line from the client side of the duplex.
    async fn read_reply(client: &mut BufReader<tokio::io::DuplexStream>) -> String {
        let mut buf = String::new();
        client.read_line(&mut buf).await.unwrap();
        buf
    }

    #[tokio::test]
    async fn full_session_over_duplex() {
        let (client, server) = duplex(1024);
        let peer: SocketAddr = "127.0.0.1:2525".parse().unwrap();

        let task = tokio::spawn(async move {
            let mut session = TestSession::default();
            let mut stream = BufReader::new(server);
            let result = session
                .run(
                    &mut stream,
                    &peer,
                    "example.org",
                    &2000,
                    &mut SessionState::default(),
                )
                .await;
            (session, result)
        });

        let mut client = BufReader::new(client);
        let mut greet = String::new();
        client.read_line(&mut greet).await.unwrap();
        assert_eq!(greet, "220 test ready\r\n");

        client.write_all(b"HELO client.example\r\n").await.unwrap();
        assert_eq!(read_reply(&mut client).await, "250 hello\r\n");

        client.write_all(b"MAIL FROM:<a@b>\r\n").await.unwrap();
        assert_eq!(read_reply(&mut client).await, "250 Ok\r\n");

        client.write_all(b"RCPT TO:<c@d>\r\n").await.unwrap();
        assert_eq!(read_reply(&mut client).await, "250 Ok\r\n");

        client.write_all(b"DATA\r\n").await.unwrap();
        assert_eq!(
            read_reply(&mut client).await,
            "354 End data with <CR>.<CR><LF>\r\n"
        );

        // Stuffed lines arrive on the wire and reach the policy unstuffed.
        client
            .write_all(b".stuffed\r\n..dots\r\nplain\r\n.\r\n")
            .await
            .unwrap();
        assert_eq!(read_reply(&mut client).await, "250 accepted\r\n");

        client.write_all(b"QUIT\r\n").await.unwrap();
        assert_eq!(read_reply(&mut client).await, "221 Bye\r\n");
        drop(client);

        let (session, result) = task.await.unwrap();
        result.unwrap();
        assert_eq!(
            session.data_lines,
            vec![
                b"stuffed\r\n".to_vec(),
                b".dots\r\n".to_vec(),
                b"plain\r\n".to_vec()
            ]
        );
        assert_eq!(session.end_data_calls, 1);
        assert_eq!(session.helo.as_deref(), Some("client.example"));
    }

    /// Start `run` over a duplex with a TestSession wired to a shutdown
    /// signal; returns the client side, the shutdown sender, and the task.
    #[allow(clippy::type_complexity)]
    fn spawn_with_shutdown() -> (
        BufReader<tokio::io::DuplexStream>,
        tokio::sync::watch::Sender<bool>,
        tokio::task::JoinHandle<(TestSession, Result<EndReason>)>,
    ) {
        let (client, server) = duplex(4096);
        let (tx, rx) = tokio::sync::watch::channel(false);
        let peer: SocketAddr = "127.0.0.1:2525".parse().unwrap();
        let task = tokio::spawn(async move {
            let mut session = TestSession {
                shutdown: Some(rx),
                ..Default::default()
            };
            let mut stream = BufReader::new(server);
            let result = session
                .run(
                    &mut stream,
                    &peer,
                    "example.org",
                    &5000,
                    &mut SessionState::default(),
                )
                .await;
            (session, result)
        });
        (BufReader::new(client), tx, task)
    }

    /// Graceful shutdown between transactions: an idle session is told
    /// `421` (RFC 5321 §3.8) and closed at once, without waiting for the
    /// client's next command or the read timeout.
    #[tokio::test]
    async fn shutdown_ends_an_idle_session_with_421() {
        let (mut client, shutdown, task) = spawn_with_shutdown();
        let mut greet = String::new();
        client.read_line(&mut greet).await.unwrap();
        client.write_all(b"HELO client.example\r\n").await.unwrap();
        assert_eq!(read_reply(&mut client).await, "250 hello\r\n");

        shutdown.send(true).unwrap();
        assert_eq!(
            read_reply(&mut client).await,
            "421 4.3.2 Service shutting down, try again later\r\n"
        );
        let (_, result) = tokio::time::timeout(Duration::from_secs(2), task)
            .await
            .expect("session ends promptly")
            .unwrap();
        assert_eq!(result.unwrap(), EndReason::Closed);
    }

    /// Graceful shutdown during a transfer: the message in progress is
    /// finished and answered normally; the `421` comes after its reply.
    #[tokio::test]
    async fn shutdown_lets_a_transfer_in_progress_finish() {
        let (mut client, shutdown, task) = spawn_with_shutdown();
        let mut greet = String::new();
        client.read_line(&mut greet).await.unwrap();
        for (cmd, reply) in [
            (&b"HELO client.example\r\n"[..], "250 hello\r\n"),
            (b"MAIL FROM:<a@b>\r\n", "250 Ok\r\n"),
            (b"RCPT TO:<c@d>\r\n", "250 Ok\r\n"),
            (b"DATA\r\n", "354 End data with <CR>.<CR><LF>\r\n"),
        ] {
            client.write_all(cmd).await.unwrap();
            assert_eq!(read_reply(&mut client).await, reply);
        }
        client.write_all(b"first line\r\n").await.unwrap();
        // Let the session read that line, then start shutting down.
        tokio::time::sleep(Duration::from_millis(50)).await;
        shutdown.send(true).unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
        client.write_all(b"second line\r\n.\r\n").await.unwrap();

        assert_eq!(read_reply(&mut client).await, "250 accepted\r\n");
        assert_eq!(
            read_reply(&mut client).await,
            "421 4.3.2 Service shutting down, try again later\r\n"
        );
        let (session, result) = task.await.unwrap();
        assert_eq!(result.unwrap(), EndReason::Closed);
        assert_eq!(session.end_data_calls, 1, "the message was completed");
        assert_eq!(session.data_lines.len(), 2);
    }

    /// SMTP smuggling, `<LF>.<CRLF>` variant (CVE-2023-51764): a `.` line
    /// only terminates DATA when the line before it ended with CRLF.
    /// After a bare-LF line, `.<CRLF>` is message data, so the smuggled
    /// commands that follow stay in the body and never reach the
    /// command parser.
    #[tokio::test]
    async fn lf_dot_crlf_does_not_terminate_data() {
        let (client, server) = duplex(4096);
        let peer: SocketAddr = "127.0.0.1:2525".parse().unwrap();
        let task = tokio::spawn(async move {
            let mut session = TestSession::default();
            let mut stream = BufReader::new(server);
            let result = session
                .run(
                    &mut stream,
                    &peer,
                    "example.org",
                    &2000,
                    &mut SessionState::default(),
                )
                .await;
            (session, result)
        });

        let mut client = BufReader::new(client);
        let mut greet = String::new();
        client.read_line(&mut greet).await.unwrap();
        client.write_all(b"HELO client.example\r\n").await.unwrap();
        read_reply(&mut client).await;
        client.write_all(b"MAIL FROM:<a@b>\r\n").await.unwrap();
        read_reply(&mut client).await;
        client.write_all(b"RCPT TO:<c@d>\r\n").await.unwrap();
        read_reply(&mut client).await;
        client.write_all(b"DATA\r\n").await.unwrap();
        read_reply(&mut client).await;

        client
            .write_all(b"first\n.\r\nMAIL FROM:<evil@x>\r\nlast\r\n.\r\n")
            .await
            .unwrap();
        // Exactly one end-of-data reply: the real terminator.
        assert_eq!(read_reply(&mut client).await, "250 accepted\r\n");
        client.write_all(b"QUIT\r\n").await.unwrap();
        assert_eq!(read_reply(&mut client).await, "221 Bye\r\n");
        drop(client);

        let (session, result) = task.await.unwrap();
        result.unwrap();
        assert_eq!(session.end_data_calls, 1);
        assert_eq!(
            session.data_lines,
            vec![
                b"first\n".to_vec(),
                b".\r\n".to_vec(),
                b"MAIL FROM:<evil@x>\r\n".to_vec(),
                b"last\r\n".to_vec(),
            ]
        );
        assert_eq!(session.mail_from.as_deref(), Some("<a@b>"));
    }

    /// An over-long command line is answered with 500 and the session
    /// continues with the next (valid) command.
    #[tokio::test]
    async fn oversized_command_line_is_rejected_and_session_continues() {
        let (client, server) = duplex(1024);
        let peer: SocketAddr = "127.0.0.1:2525".parse().unwrap();

        let task = tokio::spawn(async move {
            let mut session = SmallSession::default();
            let mut stream = BufReader::new(server);
            let result = session
                .run(
                    &mut stream,
                    &peer,
                    "example.org",
                    &2000,
                    &mut SessionState::default(),
                )
                .await;
            (session, result)
        });

        let mut client = BufReader::new(client);
        let mut greet = String::new();
        client.read_line(&mut greet).await.unwrap();

        // MAX_CMD_LINE is 16 for SmallSession; this line is 22 octets.
        client.write_all(b"AAAAAAAAAAAAAAAAAAAA\r\n").await.unwrap();
        assert_eq!(read_reply(&mut client).await, "500 5.5.2 Line too long\r\n");

        // The session is unaffected.
        client.write_all(b"HELO x\r\n").await.unwrap();
        assert_eq!(read_reply(&mut client).await, "250 hello\r\n");

        client.write_all(b"QUIT\r\n").await.unwrap();
        drop(client);
        let (_, result) = task.await.unwrap();
        result.unwrap();
    }

    /// An over-long data line aborts the transfer with 552, the rest of
    /// the message is discarded until the terminator, and the session
    /// returns to Ready.
    #[tokio::test]
    async fn oversized_data_line_aborts_and_discards() {
        let (client, server) = duplex(1024);
        let peer: SocketAddr = "127.0.0.1:2525".parse().unwrap();

        let task = tokio::spawn(async move {
            let mut session = SmallSession::default();
            let mut stream = BufReader::new(server);
            let result = session
                .run(
                    &mut stream,
                    &peer,
                    "example.org",
                    &2000,
                    &mut SessionState::default(),
                )
                .await;
            (session, result)
        });

        let mut client = BufReader::new(client);
        let mut greet = String::new();
        client.read_line(&mut greet).await.unwrap();

        for cmd in [
            &b"HELO x\r\n"[..],
            &b"MAIL FROM:<a@b>\r\n"[..],
            &b"RCPT TO:<c@d>\r\n"[..],
            &b"DATA\r\n"[..],
        ] {
            client.write_all(cmd).await.unwrap();
            read_reply(&mut client).await;
        }

        // MAX_DATA_LINE is 32 for SmallSession; this line is 41 octets.
        client.write_all(&[b'X'; 40]).await.unwrap();
        client.write_all(b"\r\n").await.unwrap();
        assert_eq!(
            read_reply(&mut client).await,
            "552 5.3.4 Line exceeds fixed maximum message line size\r\n"
        );

        // Subsequent body lines are swallowed silently.
        client.write_all(b"more body\r\n").await.unwrap();
        // The "." terminator ends the discard — with no reply.
        client.write_all(b".\r\n").await.unwrap();

        // The session is usable again, in Ready. SmallSession's 16-octet
        // command cap limits the command length; MAIL FROM:<a> is 15
        // octets and valid in Ready.
        client.write_all(b"MAIL FROM:<a>\r\n").await.unwrap();
        assert_eq!(read_reply(&mut client).await, "250 Ok\r\n");

        client.write_all(b"QUIT\r\n").await.unwrap();
        drop(client);
        let (session, result) = task.await.unwrap();
        result.unwrap();
        // The oversized line never reached the policy.
        assert_eq!(session.0.data_lines, Vec::<Vec<u8>>::new());
    }

    /// A client that sends an over-long line and then goes silent must
    /// not block the session forever: the drain of the unterminated line
    /// is subject to the same read timeout as every other read.
    #[tokio::test]
    async fn silent_client_mid_overflow_line_ends_the_session() {
        let (client, server) = duplex(1024);
        let peer: SocketAddr = "127.0.0.1:2525".parse().unwrap();

        let task = tokio::spawn(async move {
            let mut session = SmallSession::default();
            let mut stream = BufReader::new(server);
            // Short read timeout: the drain must give up on this clock.
            let result = session
                .run(
                    &mut stream,
                    &peer,
                    "example.org",
                    &100,
                    &mut SessionState::default(),
                )
                .await;
            (session, result)
        });

        let mut client = BufReader::new(client);
        let mut greet = String::new();
        client.read_line(&mut greet).await.unwrap();

        // 40 octets, no newline, then silence. MAX_DATA_LINE is 32 for
        // SmallSession, but this arrives in command (Idle) state, capped
        // at MAX_CMD_LINE = 16.
        client.write_all(&[b'X'; 40]).await.unwrap();

        // The run task must terminate on its own (drain read timeout);
        // awaiting it here is the assertion.
        let (session, result) = tokio::time::timeout(std::time::Duration::from_secs(5), task)
            .await
            .expect("session must end after the read timeout, not hang")
            .unwrap();
        result.unwrap();

        // The session ended before any reply was produced, and nothing
        // reached the policy.
        assert_eq!(session.0.data_lines, Vec::<Vec<u8>>::new());
        assert_eq!(session.0.end_data_calls, 0);
    }

    /// The client closing the connection ends the session cleanly.
    #[tokio::test]
    async fn eof_ends_the_session() {
        let (client, server) = duplex(1024);
        let peer: SocketAddr = "127.0.0.1:2525".parse().unwrap();

        let task = tokio::spawn(async move {
            let mut session = TestSession::default();
            let mut stream = BufReader::new(server);
            let result = session
                .run(
                    &mut stream,
                    &peer,
                    "example.org",
                    &2000,
                    &mut SessionState::default(),
                )
                .await;
            (session, result)
        });

        let mut client = BufReader::new(client);
        let mut greet = String::new();
        client.read_line(&mut greet).await.unwrap();
        assert_eq!(greet, "220 test ready\r\n");

        drop(client);
        let (session, result) = task.await.unwrap();
        result.unwrap();
        assert_eq!(session.end_data_calls, 0);
    }
}
