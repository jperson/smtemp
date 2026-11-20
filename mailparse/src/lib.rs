use std::collections::HashMap;

use pest::Parser;
use pest::iterators::{Pair, Pairs};
use pest_derive::Parser;
use thiserror::Error;

use jiff::Zoned;
use jiff::fmt::rfc2822;

#[derive(Parser)]
#[grammar = "../grammar/mail.pest"]
struct MailParser;

#[derive(Error, Debug)]
pub enum MailHeaderError {
    #[error("Invalid header")]
    InvalidHeader,

    #[error("InvalidDate")]
    InvalidDate,

    #[error("InvalidMailbox")]
    InvalidMailbox,

    #[error("Unknown")]
    Unknown,

    #[error("Missing header/body separator")]
    MissingSeparator,

    #[error("Header block is not valid UTF-8")]
    InvalidUtf8,
}

// ---------------------------------------------------------------------------
// Public parsing API
// ---------------------------------------------------------------------------

/// A single message header with its raw, unparsed bytes preserved.
///
/// Order and duplicates are retained in [`ParsedMessage::headers`]; this is
/// the representation to use for byte-exact operations such as DKIM
/// canonicalization.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawHeader<'m> {
    /// Field name without the trailing colon, exactly as it appeared.
    pub name: &'m [u8],
    /// Everything after the colon up to the end of the last (folded) line,
    /// excluding the final line terminator. Embedded CRLF/LF of folded
    /// continuation lines and all whitespace are preserved verbatim.
    pub raw_value: &'m [u8],
}

impl RawHeader<'_> {
    /// ASCII case-insensitive comparison of this header's name against
    /// `name` (header field names are case-insensitive per RFC 5322).
    pub fn name_eq(&self, name: &str) -> bool {
        self.name.eq_ignore_ascii_case(name.as_bytes())
    }
}

/// A fully parsed message: ordered raw headers, the typed header view, and
/// the raw body.
#[derive(Debug)]
pub struct ParsedMessage<'m> {
    /// All headers in their original order, duplicates preserved.
    pub headers: Vec<RawHeader<'m>>,
    /// Best-effort typed (RFC 5322/MIME) view. Headers that fail typed
    /// parsing are still available in `headers`.
    pub typed: MailHeaders<'m>,
    /// Raw body bytes: everything after the blank line separating headers
    /// from the body. Line terminators are preserved verbatim (CRLF or LF).
    pub body: &'m [u8],
}

/// Parse a complete RFC 5322 message: header block, blank-line separator, and
/// body.
///
/// The header block must be valid UTF-8 (typical for mail headers). For
/// byte-level access on messages with non-UTF-8 headers, use
/// [`split_message`] and [`extract_raw_headers`] directly.
///
/// # Example
///
/// ```
/// let raw = b"From: Alice <alice@example.com>\r\nSubject: Hi\r\n\r\nHello\r\n";
/// let msg = mailparse::parse_message(raw).unwrap();
///
/// assert_eq!(msg.headers.len(), 2);
/// assert!(msg.headers[0].name_eq("from"));
/// assert_eq!(msg.headers[1].raw_value, b" Hi");
/// assert_eq!(msg.body, b"Hello\r\n");
/// assert_eq!(msg.typed.from.as_ref().unwrap()[0].local_part, "alice");
/// ```
pub fn parse_message(raw: &[u8]) -> Result<ParsedMessage<'_>, MailHeaderError> {
    let (header_block, body) = split_message(raw)?;
    let headers = extract_raw_headers(header_block);
    let header_str =
        std::str::from_utf8(header_block).map_err(|_| MailHeaderError::InvalidUtf8)?;
    let typed = parse_headers(header_str)?;
    Ok(ParsedMessage {
        headers,
        typed,
        body,
    })
}

/// Parse a header block (each header terminated by CRLF or LF) into the
/// typed [`MailHeaders`] view.
///
/// Lenient: unknown or malformed headers fall back to `optional_field` or are
/// skipped, so a best-effort typed view is returned for most inputs.
pub fn parse_headers(src: &str) -> Result<MailHeaders<'_>, MailHeaderError> {
    let pairs = MailParser::parse(Rule::fields, src).map_err(|_| MailHeaderError::InvalidHeader)?;
    pairs.try_into()
}

/// Split a raw message at the first blank line into `(header_block, body)`.
///
/// The header block retains the line terminator of its final header (each
/// header grammar rule consumes its own terminator). Accepts CRLF, LF, or
/// mixed line endings. An empty input yields empty headers and body; an
/// input beginning with a blank line yields an empty header block. An input
/// with no blank line is rejected with [`MailHeaderError::MissingSeparator`].
pub fn split_message(raw: &[u8]) -> Result<(&[u8], &[u8]), MailHeaderError> {
    if raw.is_empty() {
        return Ok((&[], &[]));
    }
    if let Some(body) = raw.strip_prefix(b"\r\n") {
        return Ok((&[], body));
    }
    if let Some(body) = raw.strip_prefix(b"\n") {
        return Ok((&[], body));
    }

    for i in 0..raw.len() {
        if raw[i] != b'\n' {
            continue;
        }
        match raw.get(i + 1) {
            // Last header ended with LF; the blank line is a bare LF.
            Some(b'\n') => return Ok((&raw[..i + 1], &raw[i + 2..])),
            // Last header ended with CRLF (or LF); the blank line is CRLF.
            Some(b'\r') if raw.get(i + 2) == Some(&b'\n') => {
                return Ok((&raw[..i + 1], &raw[i + 3..]))
            }
            _ => {}
        }
    }

    Err(MailHeaderError::MissingSeparator)
}

/// Split a header block into [`RawHeader`]s, preserving order, duplicates,
/// folding, and exact bytes.
///
/// Lines that neither contain a colon nor continue a previous header are
/// malformed and skipped.
pub fn extract_raw_headers(header_block: &[u8]) -> Vec<RawHeader<'_>> {
    struct HeaderAcc<'a> {
        name: &'a [u8],
        value_start: usize,
        value_end: usize,
    }

    let mut acc: Vec<HeaderAcc> = Vec::new();
    let mut line_start = 0usize;

    for (i, &b) in header_block.iter().enumerate() {
        if b != b'\n' {
            continue;
        }
        let content_end = if i > line_start && header_block[i - 1] == b'\r' {
            i - 1
        } else {
            i
        };
        let line = &header_block[line_start..content_end];

        if line.first() == Some(&b' ') || line.first() == Some(&b'\t') {
            // Folded continuation: extend the previous header's raw value.
            if let Some(last) = acc.last_mut() {
                last.value_end = content_end;
            }
        } else if let Some(colon) = line.iter().position(|&c| c == b':') {
            acc.push(HeaderAcc {
                name: &header_block[line_start..line_start + colon],
                value_start: line_start + colon + 1,
                value_end: content_end,
            });
        }

        line_start = i + 1;
    }

    // Tolerate a final header line without a line terminator.
    if line_start < header_block.len() {
        let line = &header_block[line_start..];
        if line.first() == Some(&b' ') || line.first() == Some(&b'\t') {
            if let Some(last) = acc.last_mut() {
                last.value_end = header_block.len();
            }
        } else if let Some(colon) = line.iter().position(|&c| c == b':') {
            acc.push(HeaderAcc {
                name: &header_block[line_start..line_start + colon],
                value_start: line_start + colon + 1,
                value_end: header_block.len(),
            });
        }
    }

    acc.into_iter()
        .map(|h| RawHeader {
            name: h.name,
            raw_value: &header_block[h.value_start..h.value_end],
        })
        .collect()
}

#[derive(Debug, Default)]
pub struct DateZoned;

#[derive(Debug, Default, Clone, Eq, PartialEq)]
pub struct Mailbox<'p> {
    pub display_name: &'p str,
    pub local_part: &'p str,
    pub domain: &'p str,
}

#[derive(Debug, Default, Eq, PartialEq)]
pub struct MsgId<'p> {
    pub id_left: &'p str,
    pub id_right: &'p str,
}

#[derive(Debug, Default, Eq, PartialEq)]
pub struct Trace<'p> {
    pub return_path: Option<&'p str>,
    pub received_tokens: Vec<&'p str>,
    pub date_time: Zoned,
}

/// A parsed `DKIM-Signature` header. The raw tag list is retained verbatim
/// (with folding); consumers parse the individual tags per RFC 6376.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct DkimHeader<'p> {
    /// Everything after the `DKIM-Signature:` colon, trimmed of surrounding
    /// whitespace. Folded lines are preserved.
    pub raw: &'p str,
}

#[derive(Debug, Default)]
pub struct MimeVersion<'p> {
    pub major: &'p str,
    pub minor: &'p str,
}

#[derive(Debug, Default)]
pub struct ContentType<'p> {
    pub content_type: &'p str,
    pub content_subtype: &'p str,
    /// Last-seen parameter's attribute and value.
    pub attribute: &'p str,
    pub value: &'p str,
    /// All parameters in order of appearance.
    pub parameters: Vec<(&'p str, &'p str)>,
}

#[derive(Debug, Default)]
pub struct ContentEncoding<'p> {
    pub mechanism: &'p str,
}

#[derive(Debug, Default)]
pub struct ContentDescription<'p> {
    pub description: &'p str,
}

#[derive(Debug, Default)]
pub struct ContentDisposition<'p> {
    pub disposition: &'p str,
}

#[derive(Debug, Default)]
pub struct MimeHeader<'p> {
    pub mime_version: Option<MimeVersion<'p>>,
    pub content_type: Option<ContentType<'p>>,
    pub content_encoding: Option<ContentEncoding<'p>>,
    pub content_id: Option<MsgId<'p>>,
    pub content_description: Option<ContentDescription<'p>>,
    pub content_disposition: Option<ContentDisposition<'p>>,
}

#[derive(Debug, Default)]
pub struct MailHeaders<'h> {
    //pub trace: Vec<Trace<'h>>,
    pub trace: Vec<Trace<'h>>,

    pub resent_date: Vec<Zoned>,
    pub resent_from: Vec<Mailbox<'h>>,
    pub resent_sender: Vec<Mailbox<'h>>,
    pub resent_to: Vec<Mailbox<'h>>,
    pub resent_cc: Vec<Mailbox<'h>>,
    pub resent_bcc: Vec<Mailbox<'h>>,
    pub resent_msg_id: Vec<MsgId<'h>>,

    pub dkim: Vec<DkimHeader<'h>>,

    pub orig_date: Option<Zoned>,
    pub from: Option<Vec<Mailbox<'h>>>,
    pub sender: Option<Mailbox<'h>>,
    pub reply_to: Option<Vec<Mailbox<'h>>>,
    pub to: Option<Vec<Mailbox<'h>>>,
    pub cc: Option<Vec<Mailbox<'h>>>,
    pub bcc: Option<Vec<Mailbox<'h>>>,
    pub message_id: Option<MsgId<'h>>,
    pub in_reply_to: Option<Vec<MsgId<'h>>>,
    pub references: Option<Vec<MsgId<'h>>>,
    pub subject: Option<&'h str>,
    pub comments: Vec<&'h str>,
    pub keywords: Vec<&'h str>,

    pub mime_header: Option<MimeHeader<'h>>,

    pub optional_field: HashMap<&'h str, &'h str>,
}

/// Collect every mailbox (local_part/domain pair) reachable in `pairs`,
/// skipping display names, comments, folding whitespace, and other noise
/// pairs. `display_name` pairs attach to the next mailbox. Groups are
/// recursed into, yielding their member mailboxes.
macro_rules! mailboxes {
    ($rules:ident) => {{
        fn walk<'p, I>(pairs: I, out: &mut Vec<Mailbox<'p>>)
        where
            I: IntoIterator<Item = Pair<'p, Rule>>,
        {
            let mut pending_display: Option<&'p str> = None;
            let mut current: Option<Mailbox<'p>> = None;

            for p in pairs {
                match p.as_rule() {
                    Rule::display_name => pending_display = Some(p.as_str().trim()),
                    Rule::local_part => {
                        current = Some(Mailbox {
                            display_name: pending_display.take().unwrap_or(""),
                            local_part: p.as_str().trim(),
                            domain: "",
                        });
                    }
                    Rule::domain => {
                        if let Some(mut m) = current.take() {
                            m.domain = p.as_str().trim();
                            out.push(m);
                        }
                    }
                    _ => walk(p.into_inner(), out),
                }
            }
        }

        let mut out: Vec<Mailbox> = Vec::new();
        walk($rules, &mut out);
        out
    }};
}

/// Collect every msg-id (`id_left`/`id_right` pair) reachable in `pairs`,
/// skipping comments, folding whitespace, and other noise pairs.
macro_rules! msg_ids {
    ($rules:ident) => {{
        fn walk<'p, I>(pairs: I, out: &mut Vec<MsgId<'p>>)
        where
            I: IntoIterator<Item = Pair<'p, Rule>>,
        {
            let mut current: Option<MsgId<'p>> = None;

            for p in pairs {
                match p.as_rule() {
                    Rule::id_left => {
                        current = Some(MsgId {
                            id_left: p.as_str().trim(),
                            id_right: "",
                        })
                    }
                    Rule::id_right => {
                        if let Some(mut m) = current.take() {
                            m.id_right = p.as_str().trim();
                            out.push(m);
                        }
                    }
                    _ => walk(p.into_inner(), out),
                }
            }
        }

        let mut out: Vec<MsgId> = Vec::new();
        walk($rules, &mut out);
        out
    }};
}

impl<'p> TryFrom<Pairs<'p, Rule>> for MailHeaders<'p> {
    type Error = MailHeaderError;
    fn try_from(pairs: Pairs<'p, Rule>) -> Result<Self, Self::Error> {
        let mut mh = MailHeaders::default();

        for item in pairs.into_iter() {
            match item.as_rule() {
                // Trace fields
                Rule::trace => trace(&mut mh, item)?,
                Rule::return_path => return_path(&mut mh, item)?,
                Rule::received => received(&mut mh, item)?,

                Rule::resent_date => resent_date(&mut mh, item)?,
                Rule::resent_from => resent_from(&mut mh, item)?,
                Rule::resent_sender => resent_sender(&mut mh, item)?,
                Rule::resent_to => resent_to(&mut mh, item)?,
                Rule::resent_cc => resent_cc(&mut mh, item)?,
                Rule::resent_bcc => resent_bcc(&mut mh, item)?,
                Rule::resent_msg_id => resent_msg_id(&mut mh, item)?,
                Rule::dkim_header => dkim_header(&mut mh, item)?,

                // Originator fields
                Rule::orig_date => orig_date(&mut mh, item)?,
                Rule::from => from(&mut mh, item)?,
                Rule::sender => sender(&mut mh, item)?,
                Rule::reply_to => reply_to(&mut mh, item)?,

                //Destination fields
                Rule::to => to(&mut mh, item)?,
                Rule::cc => cc(&mut mh, item)?,
                Rule::bcc => bcc(&mut mh, item)?,

                //Identification fields
                Rule::message_id => message_id(&mut mh, item)?,
                Rule::in_reply_to => in_reply_to(&mut mh, item)?,
                Rule::references => references(&mut mh, item)?,

                //Informational fields
                Rule::subject => subject(&mut mh, item)?,
                Rule::comments => comments(&mut mh, item)?,
                Rule::keywords => keywords(&mut mh, item)?,

                //Mime
                Rule::mime_header => mime_header(&mut mh, item)?,

                //Optional fields
                Rule::optional_field => optional_field(&mut mh, item)?,

                // The `fields` grammar only produces the rules above;
                // new grammar rules must be handled here.
                _ => {}
            }
        }

        Ok(mh)
    }
}

fn trace<'p>(mh: &mut MailHeaders<'p>, item: Pair<'p, Rule>) -> Result<(), MailHeaderError> {
    let mut return_path: Option<&'p str> = None;
    let mut receiveds: Vec<Pair<'p, Rule>> = Vec::new();

    for rule in item.into_inner() {
        match rule.as_rule() {
            Rule::return_path => {
                return_path = Some(
                    rule.as_str()
                        .split_once(':')
                        .map(|(_, v)| v)
                        .unwrap_or("")
                        .trim(),
                )
            }
            Rule::received => receiveds.push(rule),
            _ => continue,
        }
    }

    // Each Received line is its own trace entry, as in real messages.
    let no_receiveds = receiveds.is_empty();
    for received in receiveds {
        let mut th = Trace {
            return_path,
            ..Default::default()
        };
        for token in received.into_inner() {
            match token.as_rule() {
                Rule::received_token => th.received_tokens.push(token.as_str().trim()),
                Rule::received_date => {
                    th.date_time = rfc2822::parse(token.as_str().trim())
                        .map_err(|_| MailHeaderError::InvalidDate)?
                }
                _ => continue,
            }
        }
        mh.trace.push(th);
    }

    // A trace block may be just a Return-Path with no Received lines.
    if no_receiveds && return_path.is_some() {
        mh.trace.push(Trace {
            return_path,
            ..Default::default()
        });
    }

    Ok(())
}

/// Standalone `Return-Path` header (not part of a trace block).
fn return_path<'p>(mh: &mut MailHeaders<'p>, item: Pair<'p, Rule>) -> Result<(), MailHeaderError> {
    let value = item
        .as_str()
        .split_once(':')
        .map(|(_, v)| v)
        .unwrap_or("")
        .trim();
    mh.trace.push(Trace {
        return_path: Some(value),
        ..Default::default()
    });
    Ok(())
}

/// Standalone `Received` header (not part of a trace block).
fn received<'p>(mh: &mut MailHeaders<'p>, item: Pair<'p, Rule>) -> Result<(), MailHeaderError> {
    let mut th = Trace::default();
    for token in item.into_inner() {
        match token.as_rule() {
            Rule::received_token => th.received_tokens.push(token.as_str().trim()),
            Rule::received_date => {
                th.date_time =
                    rfc2822::parse(token.as_str().trim()).map_err(|_| MailHeaderError::InvalidDate)?
            }
            _ => continue,
        }
    }
    mh.trace.push(th);
    Ok(())
}

fn resent_date<'p>(mh: &mut MailHeaders<'p>, item: Pair<'p, Rule>) -> Result<(), MailHeaderError> {
    mh.resent_date.push(
        rfc2822::parse(&item.as_str().trim()[13..]).map_err(|_| MailHeaderError::InvalidHeader)?,
    );

    Ok(())
}

fn resent_from<'p>(mh: &mut MailHeaders<'p>, item: Pair<'p, Rule>) -> Result<(), MailHeaderError> {
    let rules = item.into_inner();
    mh.resent_from.extend(mailboxes!(rules));
    Ok(())
}

fn resent_to<'p>(mh: &mut MailHeaders<'p>, item: Pair<'p, Rule>) -> Result<(), MailHeaderError> {
    let rules = item.into_inner();
    mh.resent_to.extend(mailboxes!(rules));
    Ok(())
}

fn resent_cc<'p>(mh: &mut MailHeaders<'p>, item: Pair<'p, Rule>) -> Result<(), MailHeaderError> {
    let rules = item.into_inner();
    mh.resent_cc.extend(mailboxes!(rules));
    Ok(())
}

fn resent_bcc<'p>(mh: &mut MailHeaders<'p>, item: Pair<'p, Rule>) -> Result<(), MailHeaderError> {
    let rules = item.into_inner();
    mh.resent_bcc.extend(mailboxes!(rules));
    Ok(())
}

fn resent_msg_id<'p>(
    mh: &mut MailHeaders<'p>,
    item: Pair<'p, Rule>,
) -> Result<(), MailHeaderError> {
    let rules = item.into_inner();
    mh.resent_msg_id.extend(msg_ids!(rules));
    Ok(())
}

fn dkim_header<'p>(mh: &mut MailHeaders<'p>, item: Pair<'p, Rule>) -> Result<(), MailHeaderError> {
    let raw = item
        .as_str()
        .split_once(':')
        .map(|(_, v)| v)
        .unwrap_or("")
        .trim();
    mh.dkim.push(DkimHeader { raw });
    Ok(())
}

fn resent_sender<'p>(mh: &mut MailHeaders<'p>, item: Pair<'p, Rule>) -> Result<(), MailHeaderError> {
    let rules = item.into_inner();
    let m = mailboxes!(rules)
        .into_iter()
        .next()
        .ok_or(MailHeaderError::InvalidMailbox)?;
    mh.resent_sender.push(m);
    Ok(())
}

//Originator fields
fn orig_date<'p>(mh: &mut MailHeaders<'p>, item: Pair<'p, Rule>) -> Result<(), MailHeaderError> {
    if mh.orig_date.is_none() {
        mh.orig_date = Some(
            rfc2822::parse(&item.as_str().trim()[6..])
                .map_err(|_| MailHeaderError::InvalidHeader)?,
        )
    }
    Ok(())
}

fn from<'p>(mh: &mut MailHeaders<'p>, item: Pair<'p, Rule>) -> Result<(), MailHeaderError> {
    if mh.from.is_none() {
        let rules = item.into_inner();
        mh.from = Some(mailboxes!(rules));
    } else {
        return Err(MailHeaderError::InvalidMailbox);
    }

    Ok(())
}

fn sender<'p>(mh: &mut MailHeaders<'p>, item: Pair<'p, Rule>) -> Result<(), MailHeaderError> {
    if mh.sender.is_none() {
        let rules = item.into_inner();
        let m = mailboxes!(rules)
            .into_iter()
            .next()
            .ok_or(MailHeaderError::InvalidMailbox)?;
        mh.sender = Some(m);
    } else {
        return Err(MailHeaderError::InvalidHeader);
    }
    Ok(())
}

fn reply_to<'p>(mh: &mut MailHeaders<'p>, item: Pair<'p, Rule>) -> Result<(), MailHeaderError> {
    if mh.reply_to.is_none() {
        let rules = item.into_inner();
        mh.reply_to = Some(mailboxes!(rules));
    } else {
        return Err(MailHeaderError::InvalidHeader);
    }
    Ok(())
}

//Destination fields
fn to<'p>(mh: &mut MailHeaders<'p>, item: Pair<'p, Rule>) -> Result<(), MailHeaderError> {
    if mh.to.is_none() {
        let rules = item.into_inner();
        mh.to = Some(mailboxes!(rules));
    } else {
        return Err(MailHeaderError::InvalidHeader);
    }

    Ok(())
}

fn cc<'p>(mh: &mut MailHeaders<'p>, item: Pair<'p, Rule>) -> Result<(), MailHeaderError> {
    if mh.cc.is_none() {
        let rules = item.into_inner();
        mh.cc = Some(mailboxes!(rules));
    } else {
        return Err(MailHeaderError::InvalidHeader);
    }

    Ok(())
}

fn bcc<'p>(mh: &mut MailHeaders<'p>, item: Pair<'p, Rule>) -> Result<(), MailHeaderError> {
    if mh.bcc.is_none() {
        let rules = item.into_inner();
        mh.bcc = Some(mailboxes!(rules));
    } else {
        return Err(MailHeaderError::InvalidHeader);
    }

    Ok(())
}

//Identification fields
fn message_id<'p>(mh: &mut MailHeaders<'p>, item: Pair<'p, Rule>) -> Result<(), MailHeaderError> {
    if mh.message_id.is_none() {
        let rules = item.into_inner();
        let m = msg_ids!(rules)
            .into_iter()
            .next()
            .ok_or(MailHeaderError::InvalidHeader)?;
        mh.message_id = Some(m);
    } else {
        return Err(MailHeaderError::InvalidHeader);
    }

    Ok(())
}

fn in_reply_to<'p>(mh: &mut MailHeaders<'p>, item: Pair<'p, Rule>) -> Result<(), MailHeaderError> {
    if mh.in_reply_to.is_none() {
        let rules = item.into_inner();
        mh.in_reply_to = Some(msg_ids!(rules));
    } else {
        return Err(MailHeaderError::InvalidHeader);
    }

    Ok(())
}

fn references<'p>(mh: &mut MailHeaders<'p>, item: Pair<'p, Rule>) -> Result<(), MailHeaderError> {
    if mh.references.is_none() {
        let rules = item.into_inner();
        mh.references = Some(msg_ids!(rules));
    } else {
        return Err(MailHeaderError::InvalidHeader);
    }

    Ok(())
}

//Informational fields
fn subject<'p>(mh: &mut MailHeaders<'p>, item: Pair<'p, Rule>) -> Result<(), MailHeaderError> {
    if mh.subject.is_none() {
        mh.subject = Some(item.as_str()[9..].trim());
    } else {
        return Err(MailHeaderError::InvalidHeader);
    }

    Ok(())
}

fn comments<'p>(mh: &mut MailHeaders<'p>, item: Pair<'p, Rule>) -> Result<(), MailHeaderError> {
    mh.comments.push(item.as_str()[9..].trim());
    Ok(())
}

fn keywords<'p>(mh: &mut MailHeaders<'p>, item: Pair<'p, Rule>) -> Result<(), MailHeaderError> {
    mh.keywords.push(item.as_str()[10..].trim());
    Ok(())
}

//MIME
fn mime_header<'p>(mh: &mut MailHeaders<'p>, item: Pair<'p, Rule>) -> Result<(), MailHeaderError> {
    let rules = item.into_inner();

    if mh.mime_header.is_none() {
        mh.mime_header = Some(MimeHeader::default());
    }

    for rule in rules {
        match rule.as_rule() {
            Rule::mime_version => mime_version(mh, rule)?,
            Rule::content_type => content_type(mh, rule)?,
            Rule::content_encoding => content_encoding(mh, rule)?,
            Rule::content_id => content_id(mh, rule)?,
            Rule::content_description => content_description(mh, rule)?,
            Rule::content_disposition => content_disposition(mh, rule)?,
            _ => continue,
        }
    }
    Ok(())
}

fn mime_version<'p>(mh: &mut MailHeaders<'p>, item: Pair<'p, Rule>) -> Result<(), MailHeaderError> {
    let rules = item.into_inner();
    let mut ver = MimeVersion::default();

    for rule in rules {
        match rule.as_rule() {
            Rule::major => ver.major = rule.as_str().trim(),
            Rule::minor => ver.minor = rule.as_str().trim(),
            _ => continue,
        }
    }

    if let Some(mh) = &mut mh.mime_header {
        mh.mime_version = Some(ver);
    }

    Ok(())
}

fn content_type<'p>(mh: &mut MailHeaders<'p>, item: Pair<'p, Rule>) -> Result<(), MailHeaderError> {
    let rules = item.into_inner();
    let mut ctype = ContentType::default();

    for rule in rules {
        match rule.as_rule() {
            Rule::r#type => ctype.content_type = rule.as_str().trim(),
            Rule::subtype => ctype.content_subtype = rule.as_str().trim(),
            Rule::parameter => {
                let mut attr = "";
                let mut val = "";
                for rule in rule.into_inner() {
                    match rule.as_rule() {
                        Rule::attribute => attr = rule.as_str().trim(),
                        Rule::value => val = rule.as_str().trim(),
                        _ => continue,
                    }
                }
                ctype.attribute = attr;
                ctype.value = val;
                ctype.parameters.push((attr, val));
            }
            _ => continue,
        }
    }

    if let Some(mh) = &mut mh.mime_header {
        mh.content_type = Some(ctype);
    }
    Ok(())
}

fn content_encoding<'p>(
    mh: &mut MailHeaders<'p>,
    item: Pair<'p, Rule>,
) -> Result<(), MailHeaderError> {
    let rules = item.into_inner();
    let mut enc = ContentEncoding::default();

    for rule in rules {
        match rule.as_rule() {
            Rule::mechanism => enc.mechanism = rule.as_str().trim(),
            _ => continue,
        }
    }

    if let Some(mh) = &mut mh.mime_header {
        mh.content_encoding = Some(enc);
    }
    Ok(())
}

fn content_id<'p>(mh: &mut MailHeaders<'p>, item: Pair<'p, Rule>) -> Result<(), MailHeaderError> {
    if let Some(mh) = &mut mh.mime_header {
        let rules = item.into_inner();
        let m = msg_ids!(rules)
            .into_iter()
            .next()
            .ok_or(MailHeaderError::InvalidHeader)?;
        mh.content_id = Some(m);
    } else {
        return Err(MailHeaderError::InvalidHeader);
    }

    Ok(())
}

fn content_description<'p>(
    mh: &mut MailHeaders<'p>,
    item: Pair<'p, Rule>,
) -> Result<(), MailHeaderError> {
    let rules = item.into_inner();

    if let Some(mh) = &mut mh.mime_header {
        for rule in rules {
            match rule.as_rule() {
                Rule::description => {
                    mh.content_description = Some(ContentDescription {
                        description: rule.as_str().trim(),
                    })
                }
                _ => continue,
            }
        }
    }

    Ok(())
}

fn content_disposition<'p>(
    mh: &mut MailHeaders<'p>,
    item: Pair<'p, Rule>,
) -> Result<(), MailHeaderError> {
    // TODO: parse disposition type and parameters
    let _ = (mh, item);
    Ok(())
}

fn optional_field<'p>(
    mh: &mut MailHeaders<'p>,
    item: Pair<'p, Rule>,
) -> Result<(), MailHeaderError> {
    let mut rules = item.into_inner();
    let name = rules
        .next()
        .ok_or(MailHeaderError::InvalidHeader)?
        .as_str()
        .trim();
    let value = rules
        .next()
        .ok_or(MailHeaderError::InvalidHeader)?
        .as_str()
        .trim();

    mh.optional_field.insert(name, value);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // #[test]
    // fn test_token() {
    //     let src = include_str!("../test/headers");
    //     let pairs = MailParser::parse(Rule::headers, src).unwrap();
    //
    //     for item in pairs {
    //         println!(
    //             "rule: {:?},  value: {:?}",
    //             item.as_rule(),
    //             item.into_inner().as_str().trim()
    //         );
    //     }
    // }

    #[test]
    fn trace_headers() {
        let src = include_str!("../test/trace");
        let mut mh = MailHeaders::default();

        let pairs = MailParser::parse(Rule::trace, src).unwrap();
        let item = pairs.into_iter().next().unwrap();

        let expected_tokens: Vec<&str> = vec![
            "from",
            "x.y.test",
            "by",
            "example.net",
            "via",
            "TCP",
            "with",
            "ESMTP",
            "id",
            "ABC12345",
            "for",
            "<mary@example.net>",
        ];

        trace(&mut mh, item).unwrap();
        assert_eq!(mh.trace.len(), 1);
        assert_eq!(mh.trace[0].return_path, Some("<foo@example.net>"));
        assert_eq!(mh.trace[0].received_tokens, expected_tokens);
    }

    #[test]
    fn resent_date_parser() {
        let src: &str = "Resent-Date: Mon, 24 Nov 1997 14:22:01 -0800\n";
        let mut mh = MailHeaders::default();

        let pairs = MailParser::parse(Rule::resent_date, src).unwrap();
        let item = pairs.into_iter().next().unwrap();

        resent_date(&mut mh, item).unwrap();
        assert_eq!(mh.resent_date.len(), 1);
        assert_eq!(
            mh.resent_date[0].to_string(),
            String::from("1997-11-24T14:22:01-08:00[-08:00]")
        );
    }

    #[test]
    fn resent_from_parser() {
        let src: &str = "Resent-From: Mary Smith <mary@example.net>\n";
        let mut mh = MailHeaders::default();

        let pairs = MailParser::parse(Rule::resent_from, src).unwrap();
        let item = pairs.into_iter().next().unwrap();

        resent_from(&mut mh, item).unwrap();

        let expected = Mailbox {
            display_name: "Mary Smith",
            local_part: "mary",
            domain: "example.net",
        };

        assert_eq!(mh.resent_from.len(), 1);
        assert_eq!(mh.resent_from[0], expected);
    }

    #[test]
    fn resent_to_parser() {
        let src: &str = "Resent-To: Jane Brown <j-brown@other.example>\n";
        let mut mh = MailHeaders::default();

        let pairs = MailParser::parse(Rule::resent_to, src).unwrap();
        let item = pairs.into_iter().next().unwrap();

        resent_to(&mut mh, item).unwrap();

        let expected = Mailbox {
            display_name: "Jane Brown",
            local_part: "j-brown",
            domain: "other.example",
        };

        assert_eq!(mh.resent_to.len(), 1);
        assert_eq!(mh.resent_to[0], expected);
    }

    #[test]
    fn resent_cc_parser() {
        let src: &str = "Resent-Cc: Jane Brown <j-brown@other.example>\n";
        let mut mh = MailHeaders::default();

        let pairs = MailParser::parse(Rule::resent_cc, src).unwrap();
        let item = pairs.into_iter().next().unwrap();

        resent_cc(&mut mh, item).unwrap();

        let expected = Mailbox {
            display_name: "Jane Brown",
            local_part: "j-brown",
            domain: "other.example",
        };

        assert_eq!(mh.resent_cc.len(), 1);
        assert_eq!(mh.resent_cc[0], expected);
    }

    #[test]
    fn resent_bcc_parser() {
        let src: &str = "Resent-Bcc: Jane Brown <j-brown@other.example>\n";
        let mut mh = MailHeaders::default();

        let pairs = MailParser::parse(Rule::resent_bcc, src).unwrap();
        let item = pairs.into_iter().next().unwrap();

        resent_bcc(&mut mh, item).unwrap();

        let expected = Mailbox {
            display_name: "Jane Brown",
            local_part: "j-brown",
            domain: "other.example",
        };

        assert_eq!(mh.resent_bcc.len(), 1);
        assert_eq!(mh.resent_bcc[0], expected);
    }

    #[test]
    fn resent_msg_id_parser() {
        let src: &str = "Resent-Message-ID: <950124.162336@example.com>\n";
        let mut mh = MailHeaders::default();

        let pairs = MailParser::parse(Rule::resent_msg_id, src).unwrap();
        let item = pairs.into_iter().next().unwrap();

        resent_msg_id(&mut mh, item).unwrap();

        let expected = MsgId {
            id_left: "950124.162336",
            id_right: "example.com",
        };

        assert_eq!(mh.resent_msg_id.len(), 1);
        assert_eq!(mh.resent_msg_id[0], expected);
    }

    #[test]
    fn orig_date_parser() {
        let src: &str = "Date: Fri, 21 Nov 1997 11:00:00 -0600\n";
        let mut mh = MailHeaders::default();

        let pairs = MailParser::parse(Rule::orig_date, src).unwrap();
        let item = pairs.into_iter().next().unwrap();

        orig_date(&mut mh, item).unwrap();

        assert!(mh.orig_date.is_some());
        assert_eq!(
            mh.orig_date.unwrap().to_string(),
            String::from("1997-11-21T11:00:00-06:00[-06:00]")
        );
    }

    #[test]
    fn from_field_parser() {
        let src: &str = "From: John Doe <jdoe@machine.example>\n";
        let mut mh = MailHeaders::default();

        let pairs = MailParser::parse(Rule::from, src).unwrap();
        let item = pairs.into_iter().next().unwrap();

        from(&mut mh, item).unwrap();

        let expected = Mailbox {
            display_name: "John Doe",
            local_part: "jdoe",
            domain: "machine.example",
        };

        assert!(mh.from.is_some_and(|x| x[0] == expected));
    }

    #[test]
    fn sender_field_parser() {
        let src: &str = "Sender: Michael Jones <mjones@machine.example>\n";
        let mut mh = MailHeaders::default();

        let pairs = MailParser::parse(Rule::sender, src).unwrap();
        let item = pairs.into_iter().next().unwrap();

        sender(&mut mh, item).unwrap();

        let expected = Mailbox {
            display_name: "Michael Jones",
            local_part: "mjones",
            domain: "machine.example",
        };

        assert!(mh.sender.is_some_and(|x| x == expected));
    }

    #[test]
    fn in_reply_to_parser() {
        let src: &str = "In-Reply-To: <1234@local.machine.example>\n";
        let mut mh = MailHeaders::default();

        let pairs = MailParser::parse(Rule::in_reply_to, src).unwrap();
        let item = pairs.into_iter().next().unwrap();

        in_reply_to(&mut mh, item).unwrap();

        let expected = MsgId {
            id_left: "1234",
            id_right: "local.machine.example",
        };

        assert!(mh.in_reply_to.is_some_and(|x| x[0] == expected));
    }

    #[test]
    fn to_parser() {
        let src: &str = "To: John Doe <jdoe@machine.example>\n";
        let mut mh = MailHeaders::default();

        let pairs = MailParser::parse(Rule::to, src).unwrap();
        let item = pairs.into_iter().next().unwrap();

        to(&mut mh, item).unwrap();

        let expected = Mailbox {
            display_name: "John Doe",
            local_part: "jdoe",
            domain: "machine.example",
        };

        assert!(mh.to.is_some_and(|x| x[0] == expected));
    }

    #[test]
    fn cc_parser() {
        let src: &str = "Cc: John Doe <jdoe@machine.example>\n";
        let mut mh = MailHeaders::default();

        let pairs = MailParser::parse(Rule::cc, src).unwrap();
        let item = pairs.into_iter().next().unwrap();

        cc(&mut mh, item).unwrap();

        let expected = Mailbox {
            display_name: "John Doe",
            local_part: "jdoe",
            domain: "machine.example",
        };

        assert!(mh.cc.is_some_and(|x| x[0] == expected));
    }

    #[test]
    fn bcc_parser() {
        let src: &str = "Bcc: John Doe <jdoe@machine.example>\n";
        let mut mh = MailHeaders::default();

        let pairs = MailParser::parse(Rule::bcc, src).unwrap();
        let item = pairs.into_iter().next().unwrap();

        bcc(&mut mh, item).unwrap();

        let expected = Mailbox {
            display_name: "John Doe",
            local_part: "jdoe",
            domain: "machine.example",
        };

        assert!(mh.bcc.is_some_and(|x| x[0] == expected));
    }

    #[test]
    fn message_id_parser() {
        let src: &str = "Message-ID: <3456@example.net>\n";
        let mut mh = MailHeaders::default();

        let pairs = MailParser::parse(Rule::message_id, src).unwrap();
        let item = pairs.into_iter().next().unwrap();

        message_id(&mut mh, item).unwrap();

        let expected = MsgId {
            id_left: "3456",
            id_right: "example.net",
        };

        assert!(mh.message_id.is_some_and(|x| x == expected));
    }

    #[test]
    fn references_parser() {
        let src: &str = "References: <3456@example.net>\n";
        let mut mh = MailHeaders::default();

        let pairs = MailParser::parse(Rule::references, src).unwrap();
        let item = pairs.into_iter().next().unwrap();

        references(&mut mh, item).unwrap();

        let expected = MsgId {
            id_left: "3456",
            id_right: "example.net",
        };

        assert!(mh.references.is_some_and(|x| x[0] == expected));
    }

    #[test]
    fn subject_parser() {
        let src: &str = "Subject: Saying Hello\n";
        let mut mh = MailHeaders::default();

        let pairs = MailParser::parse(Rule::subject, src).unwrap();
        let item = pairs.into_iter().next().unwrap();

        subject(&mut mh, item).unwrap();
        assert!(mh.subject.is_some_and(|x| x == "Saying Hello"));
    }

    #[test]
    fn comments_parser() {
        let src: &str = "Comments: Saying Hello\n";
        let mut mh = MailHeaders::default();

        let pairs = MailParser::parse(Rule::comments, src).unwrap();
        let item = pairs.into_iter().next().unwrap();

        comments(&mut mh, item).unwrap();
        assert_eq!(mh.comments[0], "Saying Hello");
    }

    #[test]
    fn keywords_parser() {
        let src: &str = "Keywords: test, foo\n";
        let mut mh = MailHeaders::default();

        let pairs = MailParser::parse(Rule::keywords, src).unwrap();
        let item = pairs.into_iter().next().unwrap();

        keywords(&mut mh, item).unwrap();
        assert_eq!(mh.keywords[0], "test, foo");
    }

    #[test]
    fn mime_header_parser() {
        let src: &str = "Mime-Version: 1.0\n";
        let mut mh = MailHeaders::default();

        let pairs = MailParser::parse(Rule::mime_header, src).unwrap();
        let item = pairs.into_iter().next().unwrap();

        mime_header(&mut mh, item).unwrap();
        assert!(mh.mime_header.is_some());

        let h = mh.mime_header.unwrap();
        assert!(h.mime_version.is_some());

        let v = h.mime_version.unwrap();
        assert_eq!(v.major, "1");
        assert_eq!(v.minor, "0");
    }

    #[test]
    fn mime_content_type_parser() {
        let src: &str = "Content-Type: text/plain; charset=us-ascii (Plain Text)\n";
        let mut mh = MailHeaders::default();

        let pairs = MailParser::parse(Rule::mime_header, src).unwrap();
        let item = pairs.into_iter().next().unwrap();

        mime_header(&mut mh, item).unwrap();
        assert!(mh.mime_header.is_some());

        let h = mh.mime_header.unwrap();
        let ct = h.content_type.expect("content_type should be parsed");
        assert_eq!(ct.content_type, "text");
        assert_eq!(ct.content_subtype, "plain");
        assert_eq!(ct.attribute, "charset");
        assert_eq!(ct.value, "us-ascii");
        assert_eq!(ct.parameters.len(), 1);
        assert_eq!(ct.parameters[0], ("charset", "us-ascii"));
    }

    #[test]
    fn mime_content_encoding_parser() {
        let src: &str = "Content-Transfer-Encoding: base64\n";
        let mut mh = MailHeaders::default();

        let pairs = MailParser::parse(Rule::mime_header, src).unwrap();
        let item = pairs.into_iter().next().unwrap();

        mime_header(&mut mh, item).unwrap();
        assert!(mh.mime_header.is_some());

        let h = mh.mime_header.unwrap();
        assert!(h.content_encoding.is_some());
        assert_eq!(h.content_encoding.unwrap().mechanism, "base64");
    }

    #[test]
    fn mime_content_id_parser() {
        let src: &str = "Content-Id: <foo@example.net>\n";
        let mut mh = MailHeaders::default();

        let pairs = MailParser::parse(Rule::mime_header, src).unwrap();
        let item = pairs.into_iter().next().unwrap();

        mime_header(&mut mh, item).unwrap();
        assert!(mh.mime_header.is_some());

        let h = mh.mime_header.unwrap();
        assert!(h.content_id.is_some());

        let cid = h.content_id.unwrap();
        assert_eq!(cid.id_left, "foo");
        assert_eq!(cid.id_right, "example.net");
    }

    #[test]
    fn mime_content_description_parser() {
        let src: &str = "Content-Description: test description\n";
        let mut mh = MailHeaders::default();

        let pairs = MailParser::parse(Rule::mime_header, src).unwrap();
        let item = pairs.into_iter().next().unwrap();

        mime_header(&mut mh, item).unwrap();
        assert!(mh.mime_header.is_some());

        let h = mh.mime_header.unwrap();
        assert!(h.content_description.is_some());

        let des = h.content_description.unwrap().description;
        assert_eq!(des, "test description");
    }

    #[test]
    fn mime_content_disposition_parser() {
        let src: &str = "Content-Disposition: attachment; filename=genome.jpeg; modification-date=\"Wed, 12 Feb 1997 16:29:51 -0500\"\n";
        let mut mh = MailHeaders::default();

        let pairs = MailParser::parse(Rule::mime_header, src).unwrap();
        let item = pairs.into_iter().next().unwrap();

        mime_header(&mut mh, item).unwrap();
        // assert!(mh.mime_header.is_some());
        //
        // let h = mh.mime_header.unwrap();
        // assert!(h.content_description.is_some());
        //
        // let des = h.content_description.unwrap().description;
        // assert_eq!(des, "test description");
    }

    #[test]
    fn optional_field_parser() {
        let src: &str = "Optional: test\n";
        let mut mh = MailHeaders::default();

        let pairs = MailParser::parse(Rule::optional_field, src).unwrap();
        let item = pairs.into_iter().next().unwrap();

        optional_field(&mut mh, item).unwrap();
        assert_eq!(mh.optional_field[&"Optional"], "test");
    }

    // A realistic message: folded DKIM-Signature, trace headers interleaved
    // with optional fields, duplicates, MIME headers, and a multipart body.
    const TEST_MESSAGE: &str = r#"Delivered-To: jrperson@gmail.com
Received: by mx.google.com with SMTP id mh7csp748466nlc;
        Fri, 1 Nov 2024 18:16:08 -0700 (PDT)
Authentication-Results: mx.google.com;
       dkim=pass header.i=@protonmail.com;
       spf=pass smtp.mailfrom=jason.person@protonmail.com
Return-Path: <jason.person@protonmail.ch>
Received: from mail-40140.protonmail.ch by mx.google.com with ESMTPS id abc123;
        Fri, 01 Nov 2024 18:16:08 -0700 (PDT)
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=protonmail.com; s=protonmail3; t=1730510168; x=1730769368; bh=evU+ZAhaA7uoDunwy9tpxgyXQlVvxX0ZJTSDyRIcuew=; h=Date:To:From:Subject:Message-ID:Feedback-ID:From:To:Cc:Date:
 Subject:Reply-To:Feedback-ID:Message-ID:
 List-Unsubscribe:List-Unsubscribe-Post; b=OcGMbHQ7D6awrQVpP/eSLuPPz8cUpAuPS+IegdH602vdGJcgEHHGGG2VSghVbIX
 9R51b1Jcuf23BFIClp/mpdaGQSNOJ2YLiS9iE0MG+NeO2nMTDui8mObGj5g0ZmSlCV
 dXMlV6KdvNXpA==
Date: Sat, 02 Nov 2024 01:16:06 +0000
To: "jrperson@gmail.com" <jrperson@gmail.com>
From: Jason Person <jason.person@protonmail.com>
Subject: Test
Message-ID: <zuZRjJOl1NxzLHjkiYvxLU6XuKH9KZ2UnlMXEZmWnFTHP9Qyh5XX71DDO9WerlL4O2@protonmail.com>
MIME-Version: 1.0
Content-Type: multipart/alternative; boundary="b1=_DAe4ebKwgsZsACinmSR6tfFOA3greGoFYImur3b4"

--b1=_DAe4ebKwgsZsACinmSR6tfFOA3greGoFYImur3b4
Content-Type: text/plain; charset=utf-8
Content-Transfer-Encoding: base64

VGVzdA==
--b1=_DAe4ebKwgsZsACinmSR6tfFOA3greGoFYImur3b4--
"#;

    #[test]
    fn parse_message_full() {
        let raw = TEST_MESSAGE.replace('\n', "\r\n").into_bytes();

        let msg = parse_message(&raw).unwrap();

        // Raw headers: order and duplicates preserved.
        assert_eq!(msg.headers.len(), 13);
        assert!(msg.headers[0].name_eq("delivered-to"));
        assert_eq!(
            msg.headers.iter().filter(|h| h.name_eq("received")).count(),
            2
        );

        // Raw values preserve folding whitespace verbatim.
        let dkim = msg
            .headers
            .iter()
            .find(|h| h.name_eq("dkim-signature"))
            .unwrap();
        let dkim_val = String::from_utf8_lossy(dkim.raw_value);
        assert!(dkim_val.starts_with(" v=1; a=rsa-sha256"));
        assert!(dkim_val.ends_with("dXMlV6KdvNXpA=="));
        assert!(dkim_val.contains("\r\n 9R51b1")); // fold preserved

        let subject = msg
            .headers
            .iter()
            .find(|h| h.name_eq("subject"))
            .unwrap();
        assert_eq!(subject.raw_value, b" Test");

        // Typed view: DKIM-Signature retained with its raw tag list.
        assert_eq!(msg.typed.dkim.len(), 1);
        assert!(msg.typed.dkim[0].raw.starts_with("v=1; a=rsa-sha256"));

        let from = msg.typed.from.as_ref().unwrap();
        assert_eq!(from[0].local_part, "jason.person");
        assert_eq!(from[0].domain, "protonmail.com");

        assert!(msg.typed.subject.is_some_and(|s| s == "Test"));

        // Trace: one entry per Received, with Return-Path attached to its block.
        assert_eq!(msg.typed.trace.len(), 2);
        assert_eq!(msg.typed.trace[0].return_path, None);
        assert_eq!(
            msg.typed.trace[1].return_path,
            Some("<jason.person@protonmail.ch>")
        );
        assert!(!msg.typed.trace[1].received_tokens.is_empty());

        // MIME headers.
        let mh = msg.typed.mime_header.as_ref().unwrap();
        assert!(mh.mime_version.is_some());
        let ct = mh.content_type.as_ref().unwrap();
        assert_eq!(ct.content_type, "multipart");
        assert_eq!(ct.content_subtype, "alternative");
        assert_eq!(ct.parameters[0].0, "boundary");

        // Body: raw bytes after the blank line, verbatim.
        assert!(msg
            .body
            .starts_with(b"--b1=_DAe4ebKwgsZsACinmSR6tfFOA3greGoFYImur3b4\r\n"));
        assert!(msg
            .body
            .ends_with(b"--b1=_DAe4ebKwgsZsACinmSR6tfFOA3greGoFYImur3b4--\r\n"));
        assert!(msg.body.windows(7).any(|w| w == b"VGVzdA="));
    }

    #[test]
    fn parse_message_lf_only() {
        let raw =
            b"From: foo@bar.com\nSubject: Hi\nX-Folded: one\n two\n\nbody line\nstill body\n";
        let msg = parse_message(raw).unwrap();

        assert_eq!(msg.headers.len(), 3);
        let folded = msg
            .headers
            .iter()
            .find(|h| h.name_eq("x-folded"))
            .unwrap();
        assert_eq!(folded.raw_value, b" one\n two");

        assert_eq!(msg.body, b"body line\nstill body\n");
    }

    #[test]
    fn test_split_message() {
        // CRLF throughout
        let (h, b) = split_message(b"A: 1\r\nB: 2\r\n\r\nbody").unwrap();
        assert_eq!(h, b"A: 1\r\nB: 2\r\n");
        assert_eq!(b, b"body");

        // LF throughout
        let (h, b) = split_message(b"A: 1\nB: 2\n\nbody").unwrap();
        assert_eq!(h, b"A: 1\nB: 2\n");
        assert_eq!(b, b"body");

        // CRLF headers, LF-only separator
        let (h, b) = split_message(b"A: 1\r\n\nbody").unwrap();
        assert_eq!(h, b"A: 1\r\n");
        assert_eq!(b, b"body");

        // Empty body
        let (h, b) = split_message(b"A: 1\r\n\r\n").unwrap();
        assert_eq!(h, b"A: 1\r\n");
        assert!(b.is_empty());

        // Empty header block
        let (h, b) = split_message(b"\r\nbody").unwrap();
        assert!(h.is_empty());
        assert_eq!(b, b"body");

        // Empty message
        let (h, b) = split_message(b"").unwrap();
        assert!(h.is_empty());
        assert!(b.is_empty());

        // No separator
        assert!(split_message(b"A: 1\r\nB: 2\r\n").is_err());
    }
}


