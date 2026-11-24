//! `mailserv hash-password`: turn a password into the argon2id hash
//! string that `--auth-users-file` expects, without the password ever
//! appearing in argv, shell history or on screen.

use std::io::{BufRead, Write};

use anyhow::{bail, Context, Result};

use crate::auth;

/// Read a password from stdin and print its argon2id hash
/// ([`auth::hash_password`]) to stdout, followed by a newline.
///
/// When stdin is a terminal, the password is read twice with echo turned
/// off (prompts go to stderr) and must match. Otherwise one line is read,
/// so `mailserv hash-password < file` and pipes work. The trailing line
/// ending is removed; everything else, including spaces, is part of the
/// password.
///
/// # Errors
///
/// stdin can't be read, the password is empty, the two entries differ,
/// the terminal can't be configured, or hashing fails.
pub fn run() -> Result<()> {
    let password = if is_terminal() {
        let first = prompt_hidden("Password: ")?;
        let second = prompt_hidden("Confirm password: ")?;
        if first != second {
            bail!("the passwords don't match");
        }
        first
    } else {
        read_line()?
    };
    if password.is_empty() {
        bail!("refusing to hash an empty password");
    }
    let hash = auth::hash_password(&password)?;
    println!("{hash}");
    Ok(())
}

/// Returns whether stdin is a terminal.
fn is_terminal() -> bool {
    // SAFETY: isatty only inspects the descriptor.
    unsafe { libc::isatty(libc::STDIN_FILENO) == 1 }
}

/// Write `prompt` to stderr and read one line from the terminal with echo
/// turned off; echo is restored before returning (even on error).
///
/// Returns the line without its line ending.
///
/// # Errors
///
/// The terminal attributes can't be read or set, or reading fails.
fn prompt_hidden(prompt: &str) -> Result<String> {
    let mut stderr = std::io::stderr();
    write!(stderr, "{prompt}")?;
    stderr.flush()?;
    let line = {
        let _echo_off = EchoOff::new()?;
        read_line()
    };
    // The user's Enter wasn't echoed either.
    writeln!(stderr)?;
    line
}

/// Read one line from stdin.
///
/// Returns it without the trailing `\n` or `\r\n`.
///
/// # Errors
///
/// Reading fails, or the line is not UTF-8.
fn read_line() -> Result<String> {
    let mut line = String::new();
    std::io::stdin()
        .lock()
        .read_line(&mut line)
        .context("cannot read the password from stdin")?;
    let trimmed = line
        .strip_suffix('\n')
        .map(|l| l.strip_suffix('\r').unwrap_or(l))
        .unwrap_or(&line);
    Ok(trimmed.to_string())
}

/// Terminal echo turned off on stdin for as long as this guard lives.
struct EchoOff {
    /// The attributes to restore.
    saved: libc::termios,
}

impl EchoOff {
    /// Turn echo off on stdin.
    ///
    /// # Errors
    ///
    /// The terminal attributes can't be read or set.
    fn new() -> Result<Self> {
        // SAFETY: termios is plain data; tcgetattr fills it in, and is
        // only called on stdin, which the caller checked is a terminal.
        unsafe {
            let mut saved: libc::termios = std::mem::zeroed();
            if libc::tcgetattr(libc::STDIN_FILENO, &mut saved) != 0 {
                return Err(std::io::Error::last_os_error()).context("tcgetattr failed");
            }
            let mut quiet = saved;
            quiet.c_lflag &= !libc::ECHO;
            if libc::tcsetattr(libc::STDIN_FILENO, libc::TCSANOW, &quiet) != 0 {
                return Err(std::io::Error::last_os_error()).context("tcsetattr failed");
            }
            Ok(EchoOff { saved })
        }
    }
}

impl Drop for EchoOff {
    fn drop(&mut self) {
        // SAFETY: restores attributes previously read from the same fd.
        unsafe {
            libc::tcsetattr(libc::STDIN_FILENO, libc::TCSANOW, &self.saved);
        }
    }
}
