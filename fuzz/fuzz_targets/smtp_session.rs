//! SMTP framing and the state machine: any byte stream a client sends
//! (commands, DATA, the terminator, smuggling attempts, overlong lines,
//! AUTH exchanges) must end the session without a panic or a hang.
#![no_main]

use libfuzzer_sys::fuzz_target;
use smtp::{Control, DataControl, SessionState, SmtpSession};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _, BufReader};

/// A policy that accepts everything, so every protocol path is reachable,
/// and offers AUTH with a challenge so the continuation state is too.
struct AcceptAll;

impl SmtpSession for AcceptAll {
    async fn server_greet(&self) -> Vec<u8> {
        b"220 fuzz\r\n".to_vec()
    }
    async fn helo(&mut self, _ehlo: bool, _arg: &str) -> Control {
        Control::accept(Self::OK)
    }
    async fn mail_from(&mut self, _path: &str) -> Control {
        Control::accept(Self::OK)
    }
    async fn rcpt_to(&mut self, path: &str) -> Control {
        // Reach the Close path too.
        if path.contains("close") {
            Control::close(b"421 bye\r\n")
        } else {
            Control::accept(Self::OK)
        }
    }
    async fn start_data(&mut self) -> Control {
        Control::accept(Self::SEND_DATA)
    }
    async fn recv_data(&mut self, line: &[u8]) -> DataControl {
        if line.len() > 1000 {
            DataControl::Abort(b"552 too big\r\n".to_vec())
        } else {
            DataControl::Continue
        }
    }
    async fn end_data(&mut self) -> Control {
        Control::accept(Self::OK)
    }
    async fn reset(&mut self) -> Control {
        Control::accept(Self::OK)
    }
    async fn starttls(&mut self) -> Control {
        // An upgrade would pause the loop; refuse it so the input keeps
        // flowing through one run.
        Control::tempfail(b"454 no\r\n")
    }
    async fn tls_established(&mut self) {}
    async fn auth(&mut self, _mechanism: &str, _initial: Option<&[u8]>) -> Control {
        Control::challenge(b"334 \r\n")
    }
    async fn auth_line(&mut self, line: &[u8]) -> Control {
        if line.is_empty() {
            Control::challenge(b"334 \r\n")
        } else {
            Control::accept(b"235 ok\r\n")
        }
    }
}

fuzz_target!(|input: &[u8]| {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .unwrap();
    runtime.block_on(async {
        let (mut client, server) = tokio::io::duplex(64 * 1024);
        let session = tokio::spawn(async move {
            let mut stream = BufReader::new(server);
            let peer = "127.0.0.1:25".parse().unwrap();
            AcceptAll
                .run(
                    &mut stream,
                    &peer,
                    "fuzz",
                    &1000,
                    &mut SessionState::default(),
                )
                .await
        });
        // Write the input, then EOF; drain the replies so the server never
        // blocks on a full pipe.
        let _ = client.write_all(input).await;
        let _ = client.shutdown().await;
        let mut replies = Vec::new();
        let _ = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            client.read_to_end(&mut replies),
        )
        .await;
        let ended = tokio::time::timeout(std::time::Duration::from_secs(5), session).await;
        assert!(ended.is_ok(), "the session must end after EOF");
    });
});
