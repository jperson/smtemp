use anyhow::{anyhow, Result};
use deku::prelude::*;
use ipnet::Ipv4Net;
use serde::Serialize;
use std::io::BufReader;
use std::io::Write;
use std::net::Ipv4Addr;

/// The EDNS0 payload size we advertise in queries (bytes): the DNS flag
/// day 2020 recommendation — large enough for realistic responses, small
/// enough that responses never need IP fragmentation.
pub const EDNS0_PAYLOAD_SIZE: u16 = 1232;

/// The EDNS0 OPT pseudo-RR parsed from a response (RFC 6891).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Edns0 {
    /// The responder's advertised UDP payload size (the OPT class). On
    /// stream transports this is informational only.
    pub payload_size: u16,
    /// The upper 8 bits of the OPT TTL: extended RCODE (combined with
    /// the header RCODE for modern response codes).
    pub extended_rcode: u8,
    /// EDNS0 version implemented by the responder (must be 0 when we
    /// queried with version 0).
    pub version: u8,
    /// DNSSEC OK flag (TTL bit 15).
    pub dnssec_ok: bool,
}

impl Edns0 {
    /// Decode the OPT pseudo-RR fields from a record's owner name,
    /// type, class, and TTL. The OPT name must be the root (RFC 6891
    /// §6.1.2); options in `rdata` carry no semantics for this client
    /// and are ignored.
    fn from_fields(name: &str, record_type: u16, record_class: u16, ttl: u32) -> Result<Self> {
        if record_type != 0x29 {
            return Err(anyhow!("not an OPT record (type {record_type})"));
        }
        if !name.is_empty() {
            return Err(anyhow!("EDNS0 OPT record name is not the root"));
        }
        Ok(Edns0 {
            payload_size: record_class,
            extended_rcode: ((ttl >> 24) & 0xff) as u8,
            version: ((ttl >> 16) & 0xff) as u8,
            dnssec_ok: (ttl >> 15) & 0x1 == 0x1,
        })
    }
}

#[allow(dead_code)]
/// A DNS message: header, question section, and the three answer
/// sections. Parsed from (or written to) the wire format.
#[derive(Debug, Clone, Serialize)]
pub struct DnsMessage {
    /// The 12-octet header (flags, counts, rcode).
    pub header: DnsHeader,
    /// The question section (normally one entry).
    pub questions: Vec<DnsQuestion>,
    /// Answer records.
    pub answers: Vec<DnsResourceRecord>,
    /// Authority records.
    pub authorities: Vec<DnsResourceRecord>,
    /// Additional records (contains the EDNS0 OPT pseudo-RR).
    pub additionals: Vec<DnsResourceRecord>,
}

/// Bounds-checked read helpers for hostile input. DNS responses come from
/// the configured resolver, which may be buggy, spoofed, or compromised —
/// every parse failure must be a returned Err, never a panic.
fn read_u8(data: &[u8], offset: usize) -> Result<u8> {
    data.get(offset)
        .copied()
        .ok_or_else(|| anyhow!("truncated DNS message at offset {offset}"))
}

fn read_u16(data: &[u8], offset: usize) -> Result<u16> {
    let end = offset
        .checked_add(2)
        .ok_or_else(|| anyhow!("DNS offset overflow at {offset}"))?;
    match data.get(offset..end) {
        Some(b) => Ok(u16::from_be_bytes([b[0], b[1]])),
        None => Err(anyhow!("truncated DNS message at offset {offset}")),
    }
}

fn read_u32(data: &[u8], offset: usize) -> Result<u32> {
    let end = offset
        .checked_add(4)
        .ok_or_else(|| anyhow!("DNS offset overflow at {offset}"))?;
    match data.get(offset..end) {
        Some(b) => Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]])),
        None => Err(anyhow!("truncated DNS message at offset {offset}")),
    }
}

/// A checked subslice `[offset..end]`: errors on reversal or overrun
/// instead of panicking.
fn slice(data: &[u8], offset: usize, end: usize) -> Result<&[u8]> {
    if offset > end {
        return Err(anyhow!("DNS rdata length underflow ({offset} > {end})"));
    }
    data.get(offset..end)
        .ok_or_else(|| anyhow!("DNS rdata overruns message ({end} > {}) ", data.len()))
}

impl DnsMessage {
    /// Build a standard query with an EDNS0 OPT pseudo-RR in the
    /// additional section, advertising a 1232-byte payload size (the
    /// DNS flag-day 2020 recommendation: large enough for modern
    /// responses, small enough to avoid IP fragmentation).
    pub fn new(id: u16, questions: Vec<DnsQuestion>) -> Self {
        let header = DnsHeader {
            transaction_id: id,
            qr: 0x00,
            opcode: 0x00,
            aa: 0x00,
            tc: 0x00,
            rd: 0x01,
            ra: 0x00,
            z: 0x00,
            ad: 0x00,
            cd: 0x00,
            rcode: 0x00,
            question_count: questions.len() as u16,
            answer_count: 0x00,
            authority_resource_records: 0x00,
            additional_resource_records_count: 0x01,
        };

        let opt_rr = DnsResourceRecord {
            name: Label(String::from("")),
            record_type: 0x29,
            record_class: EDNS0_PAYLOAD_SIZE,
            ttl: 0x00,
            rdlength: 0x00,
            rdata: QType::EMPTY,
        };

        DnsMessage {
            header,
            questions,
            answers: vec![],
            authorities: vec![],
            additionals: vec![opt_rr],
        }
    }

    /// Extract and validate the EDNS0 OPT pseudo-RR from the additional
    /// section (RFC 6891).
    ///
    /// Returns `Ok(None)` when the responder sent no OPT record (it may
    /// not support EDNS0 even though we queried with it). Returns `Err`
    /// on conformance violations: more than one OPT record, or an OPT
    /// with a non-root owner name, or an OPT version greater than the 0
    /// we requested — each means the responder is misbehaving, and the
    /// answer is not trustworthy.
    pub fn edns0(&self) -> Result<Option<Edns0>> {
        let mut found: Option<Edns0> = None;
        for rr in &self.additionals {
            if rr.record_type != 0x29 {
                continue;
            }
            if found.is_some() {
                return Err(anyhow!("EDNS0 violation: more than one OPT record"));
            }
            found = Some(Edns0::from_fields(
                &rr.name.0,
                rr.record_type,
                rr.record_class,
                rr.ttl,
            )?);
        }
        if let Some(edns) = &found {
            if edns.version > 0 {
                return Err(anyhow!(
                    "EDNS0 violation: responder answered with version {} (we requested 0)",
                    edns.version
                ));
            }
        }
        Ok(found)
    }

    /// Parse a full DNS message (header, questions, records) from raw
    /// bytes. Total: every malformed input is an `Err`, never a panic.
    pub fn from_bytes(data: &[u8]) -> Result<(usize, Self)> {
        let cursor = std::io::Cursor::new(data);
        let mut buf = BufReader::new(cursor);
        let (offset, header) = DnsHeader::from_reader((&mut buf, 0))?;
        let mut offset = offset / 8; //bits to bytes

        let mut questions: Vec<DnsQuestion> = vec![];
        for _ in 0..header.question_count {
            let q: DnsQuestion;
            (offset, q) = DnsQuestion::from_bytes(data, offset)?;
            questions.push(q);
        }

        let mut answers: Vec<DnsResourceRecord> = vec![];
        for _ in 0..header.answer_count {
            let rr: DnsResourceRecord;
            (offset, rr) = DnsResourceRecord::from_bytes(data, offset)?;
            answers.push(rr);
        }

        let mut authorities: Vec<DnsResourceRecord> = vec![];
        for _ in 0..header.authority_resource_records {
            let rr: DnsResourceRecord;
            (offset, rr) = DnsResourceRecord::from_bytes(data, offset)?;
            authorities.push(rr);
        }

        let mut additionals: Vec<DnsResourceRecord> = vec![];
        for _ in 0..header.additional_resource_records_count {
            let rr: DnsResourceRecord;
            (offset, rr) = DnsResourceRecord::from_bytes(data, offset)?;
            additionals.push(rr);
        }

        let msg = DnsMessage {
            header,
            questions,
            answers,
            authorities,
            additionals,
        };

        Ok((offset, msg))
    }

    /// Serialize the full message (header, questions, records).
    /// Serialize to wire format. The header counts are synchronized
    /// with the actual section lengths here — a message that carries
    /// records but advertises fewer of them in its header is malformed
    /// on the wire, and forgetting to bump the counts by hand is an
    /// easy way to produce exactly that.
    pub fn to_vec(&self) -> Result<Vec<u8>> {
        let mut header = self.header.clone();
        header.question_count = self.questions.len() as u16;
        header.answer_count = self.answers.len() as u16;
        header.authority_resource_records = self.authorities.len() as u16;
        header.additional_resource_records_count = self.additionals.len() as u16;

        let mut data = Vec::new();
        let _ = data.write_all(header.to_bytes()?.as_slice());

        for q in &self.questions {
            let _ = data.write_all(q.to_bytes()?.as_slice());
        }

        for a in &self.answers {
            let _ = data.write_all(a.to_bytes()?.as_slice());
        }

        for a in &self.authorities {
            let _ = data.write_all(a.to_bytes()?.as_slice());
        }

        for a in &self.additionals {
            let _ = data.write_all(a.to_bytes()?.as_slice());
        }

        Ok(data)
    }
}

/// The DNS message header (RFC 1035 Section 4.1.1).
#[derive(Debug, PartialEq, DekuRead, DekuWrite, Clone, Serialize)]
#[deku(endian = "big")]
pub struct DnsHeader {
    /// The transaction ID echoed from the query.
    pub transaction_id: u16,
    /// Query (0) or response (1).
    #[deku(bits = 1)]
    pub qr: u8,
    /// Operation (0 = standard query).
    #[deku(bits = 4)]
    pub opcode: u8,
    /// Authoritative answer.
    #[deku(bits = 1)]
    pub aa: u8,
    /// Truncated.
    #[deku(bits = 1)]
    pub tc: u8,
    /// Recursion desired (query side).
    #[deku(bits = 1)]
    pub rd: u8,
    /// Recursion available (response side).
    #[deku(bits = 1)]
    pub ra: u8,
    /// Reserved; must be zero.
    #[deku(bits = 1)]
    pub z: u8,
    /// Authentic data (DNSSEC).
    #[deku(bits = 1)]
    pub ad: u8,
    /// Checking disabled (DNSSEC).
    #[deku(bits = 1)]
    pub cd: u8,
    /// Response code (0 = NOERROR, 3 = NXDOMAIN).
    #[deku(bits = 4)]
    pub rcode: u8,

    /// Number of question entries.
    pub question_count: u16,
    /// Number of answer records.
    pub answer_count: u16,
    /// Number of authority records.
    pub authority_resource_records: u16,
    /// Number of additional records (includes the OPT pseudo-RR).
    pub additional_resource_records_count: u16,
}

#[allow(dead_code)]
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
/// One entry of the question section: a name plus type and class.
pub struct DnsQuestion {
    /// The queried domain name.
    pub name: Label,
    /// The queried record type (1 = A, 16 = TXT, ...).
    pub record_type: u16,
    /// The queried class (1 = IN).
    pub record_class: u16,
}

impl DnsQuestion {
    /// Parse a question entry at `offset`; returns the offset past it.
    /// Every read is bounds-checked.
    pub fn from_bytes(data: &[u8], mut offset: usize) -> Result<(usize, Self)> {
        let label: Label;
        (offset, label) = Label::from_bytes(data, offset, 0)?;

        let record_type = read_u16(data, offset)?;
        let record_class = read_u16(data, offset + 2)?;

        Ok((
            offset + 4,
            DnsQuestion {
                name: label,
                record_type,
                record_class,
            },
        ))
    }

    /// Serialize the question entry.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let mut data: Vec<u8> = vec![];
        let _ = data.write_all(self.name.to_bytes()?.as_slice());
        let _ = data.write_all(&self.record_type.to_be_bytes());
        let _ = data.write_all(&self.record_class.to_be_bytes());
        Ok(data)
    }
}

#[allow(dead_code)]
#[derive(Debug, PartialEq, Eq, Clone, Serialize)]
/// One resource record from any answer section.
pub struct DnsResourceRecord {
    /// The record's owner name (possibly compression-decoded).
    pub name: Label,
    /// The record type (1 = A, 15 = MX, 16 = TXT, ...).
    pub record_type: u16,
    /// The record class (1 = IN).
    pub record_class: u16,
    /// Time-to-live in seconds.
    pub ttl: u32,
    /// The rdata length as claimed on the wire; the parsed rdata is
    /// bounded by it (see [`QType::try_from`]).
    pub rdlength: u16,
    /// The parsed record data.
    pub rdata: QType,
}

impl DnsResourceRecord {
    /// Parse one resource record at `offset`; returns the offset past its
    /// rdata. Every read is bounds-checked, and the parsed rdata is
    /// bounded by the record's own `rdlength`.
    pub fn from_bytes(data: &[u8], mut offset: usize) -> Result<(usize, Self)> {
        let label: Label;
        (offset, label) = Label::from_bytes(data, offset, 0)?;
        let record_type = read_u16(data, offset)?;
        let record_class = read_u16(data, offset + 2)?;
        let ttl = read_u32(data, offset + 4)?;
        let rdlength = read_u16(data, offset + 8)?;
        let rdata_start = offset + 10;
        let rdata_end = rdata_start
            .checked_add(rdlength as usize)
            .ok_or_else(|| anyhow!("DNS rdata offset overflow"))?;

        let rr = DnsResourceRecord {
            name: label,
            record_type,
            record_class,
            ttl,
            rdlength,
            rdata: QType::try_from(record_type, data, rdata_start, rdata_end)?,
        };

        Ok((rdata_end, rr))
    }

    /// Serialize the record; `rdlength` is recomputed from the rdata so
    /// it can never disagree with the encoded bytes.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let mut data: Vec<u8> = vec![];
        let _ = data.write_all(self.name.to_bytes()?.as_slice());
        let _ = data.write_all(&self.record_type.to_be_bytes());
        let _ = data.write_all(&self.record_class.to_be_bytes());
        let _ = data.write_all(&self.ttl.to_be_bytes());
        let rdata = self.rdata.to_bytes()?;
        let _ = data.write_all(&(rdata.len() as u16).to_be_bytes());
        let _ = data.write_all(rdata.as_slice());

        Ok(data)
    }
}

/// A domain name, stored as the joined human-readable form
/// (`"example.com"`) with compression pointers decoded during parsing.
#[derive(Debug, PartialEq, Eq, Clone, Serialize)]
pub struct Label(String);

impl Label {
    /// Build a label from its human-readable dotted form.
    pub fn new(s: String) -> Self {
        Label(s)
    }

    /// Parse a (possibly compression-pointer) name at `offset`, returning
    /// the offset just past it in the *original* message. `depth` bounds
    /// pointer-chain recursion; every read is bounds-checked, so hostile
    /// pointers (self-referential, out-of-range) yield `Err`.
    pub fn from_bytes(data: &[u8], mut offset: usize, depth: usize) -> Result<(usize, Self)> {
        if depth > 20 {
            return Err(anyhow!("Max recursion reached"));
        }

        let mut labels: Vec<String> = vec![];

        loop {
            match read_u8(data, offset)? {
                0x00 => {
                    let l = Label(labels.join("."));
                    return Ok((offset + 1, l));
                }
                first if first & 0xC0 == 0xC0 => {
                    let hi = read_u16(data, offset)?;
                    let ptr = (hi & 0x3FFF) as usize;
                    if ptr >= data.len() {
                        return Err(anyhow!("compression pointer out of range"));
                    }

                    let (_, label_cont) = Label::from_bytes(data, ptr, depth + 1)?;
                    labels.push(label_cont.0);

                    let l = Label(labels.join("."));
                    return Ok((offset + 2, l));
                }
                len => {
                    let start = offset + 1;
                    let end = start
                        .checked_add(len as usize)
                        .ok_or_else(|| anyhow!("DNS label offset overflow"))?;
                    let bytes = slice(data, start, end)?;
                    labels.push(String::from_utf8(bytes.to_vec())?);
                    offset = end;
                }
            }
        }
    }

    /// Serialize the name as uncompressed wire labels plus the root
    /// terminator.
    ///
    /// Returns `Err` ([`InvalidName`]) for a name that has no valid wire
    /// form (see [`check_name`]). Previously such names were written
    /// anyway: a label's length was cast to one octet, so a 64-255 octet
    /// label set the top bits that mark a compression pointer or an
    /// extended label type, a longer one wrapped around, and an empty
    /// label ended the name early (L1/D3 in REPORT.md and DEPLOYMENT.md).
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        check_name(&self.0)?;
        let mut data: Vec<u8> = vec![];

        if !self.0.is_empty() {
            for part in self.0.split(".") {
                data.push(part.len() as u8);
                let _ = data.write_all(part.as_bytes());
            }
        }

        data.push(0x00);
        Ok(data)
    }
}

/// The longest label: 63 octets (RFC 1035 §2.3.4). The two top bits of
/// the length octet are reserved for compression pointers (`0xC0`) and
/// extended label types (`0x40`).
pub const MAX_LABEL_OCTETS: usize = 63;

/// The longest name in text form, without a trailing dot: 253 octets,
/// which is 255 on the wire (a length octet per label plus the root
/// terminator; RFC 1035 §2.3.4).
pub const MAX_NAME_OCTETS: usize = 253;

/// A name that can't be sent as a DNS query: an empty label (`a..b`,
/// `.a`), a label over [`MAX_LABEL_OCTETS`], or a name over
/// [`MAX_NAME_OCTETS`]. RFC 7208 §4.3 treats such a name like one that
/// does not exist, which is how SPF handles this error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvalidName {
    /// The offending name.
    pub name: String,
    /// What is wrong with it.
    pub reason: &'static str,
}

impl std::fmt::Display for InvalidName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Bounded: the name may be attacker-supplied and arbitrarily long.
        let shown: String = self.name.chars().take(80).collect();
        let more = if self.name.chars().count() > 80 {
            "..."
        } else {
            ""
        };
        write!(f, "invalid DNS name {shown:?}{more}: {}", self.reason)
    }
}

impl std::error::Error for InvalidName {}

/// Check that `name` (text form, no trailing dot) has a valid wire
/// encoding. The empty string is the root name and is valid.
///
/// Returns `Err` describing the first problem found.
pub fn check_name(name: &str) -> Result<(), InvalidName> {
    let invalid = |reason| InvalidName {
        name: name.to_string(),
        reason,
    };
    if name.is_empty() {
        return Ok(());
    }
    if name.len() > MAX_NAME_OCTETS {
        return Err(invalid("name longer than 253 octets"));
    }
    for label in name.split('.') {
        if label.is_empty() {
            return Err(invalid("empty label"));
        }
        if label.len() > MAX_LABEL_OCTETS {
            return Err(invalid("label longer than 63 octets"));
        }
    }
    Ok(())
}

/// Normalize a name for querying: trim surrounding whitespace, drop one
/// trailing dot (`example.com.` is the same name as `example.com`), then
/// [`check_name`]. The root name is refused here: nothing in the mail
/// checks has a reason to query it.
///
/// Returns the normalized name (a sub-slice of `name`) or the error.
pub fn normalize_name(name: &str) -> Result<&str, InvalidName> {
    let trimmed = name.trim();
    let trimmed = trimmed.strip_suffix('.').unwrap_or(trimmed);
    if trimmed.is_empty() {
        return Err(InvalidName {
            name: name.to_string(),
            reason: "empty name",
        });
    }
    check_name(trimmed)?;
    Ok(trimmed)
}

impl From<&Label> for String {
    fn from(l: &Label) -> Self {
        let Label(s) = l;
        s.to_owned()
    }
}

impl TryFrom<&Label> for Ipv4Net {
    type Error = anyhow::Error;
    fn try_from(l: &Label) -> Result<Self> {
        let Label(s) = l;
        let ip4 = s.parse::<Ipv4Addr>()?;
        Ok(Ipv4Net::from(ip4))
    }
}

/// Parsed record data, typed by record type. Types the verifier needs
/// (A, MX, PTR, TXT) carry parsed values; the rest carry enough to round-
/// trip. Parsing never panics on malformed rdata (see [`QType::try_from`]).
#[derive(PartialEq, Eq, Debug, Clone, Serialize)]
pub enum QType {
    /// IPv4 address record.
    A(Ipv4Addr),
    /// Name server.
    NS(Label),
    /// Obsolete mail destination.
    MD(Label),
    /// Obsolete mail forwarder.
    MF(Label),
    /// Canonical name alias.
    CNAME(Label),
    /// Start of authority: mname, rname, serial, refresh, retry, expire,
    /// minimum.
    SOA(Label, Label, u32, u32, u32, u32, u32),
    /// Mailbox (obsolete).
    MB(Label),
    /// Mail group (obsolete).
    MG(Label),
    /// Mail rename (obsolete).
    MR(Label),
    /// Raw bytes (any rdata).
    NULL(Vec<u8>),
    /// Well-known service.
    WKS(Ipv4Addr, u8, Vec<u8>),
    /// Reverse-lookup pointer.
    PTR(Label),
    /// Host information.
    HINFO(String),
    /// Mailbox info (obsolete).
    MINFO(Label, Label),
    /// Mail exchange: preference, exchange domain.
    MX(u16, Label),
    /// Text record: all character-strings concatenated (DKIM keys and
    /// SPF records span multiple strings).
    TXT(String),
    /// Unrecognized record type: rdata not parsed.
    EMPTY,
}

impl QType {
    /// Parse rdata of `rtype` from `data[offset..end]`. `end` is the
    /// attacker-controlled `rdlength` bound, so it is validated against
    /// the message before anything is sliced; every fixed-width field
    /// read is additionally checked against the record's own rdata bounds
    /// so a lying `rdlength` cannot cross into the next record.
    pub fn try_from(rtype: u16, data: &[u8], mut offset: usize, end: usize) -> Result<Self> {
        if end > data.len() {
            return Err(anyhow!("DNS rdata overruns message"));
        }
        if offset > end {
            return Err(anyhow!("DNS rdata length underflow"));
        }
        Ok(match rtype {
            1 => {
                if offset + 4 > end {
                    return Err(anyhow!("A rdata truncated"));
                }
                QType::A(Ipv4Addr::from_bits(read_u32(data, offset)?))
            }
            2 => {
                let (_, name) = Label::from_bytes(data, offset, 0)?;
                QType::NS(name)
            }
            3 => {
                let (_, name) = Label::from_bytes(data, offset, 0)?;
                QType::MD(name)
            }
            4 => {
                let (_, name) = Label::from_bytes(data, offset, 0)?;
                QType::MF(name)
            }
            5 => {
                let (_, name) = Label::from_bytes(data, offset, 0)?;
                QType::CNAME(name)
            }
            6 => {
                let mname: Label;
                (offset, mname) = Label::from_bytes(data, offset, 0)?;

                let rname: Label;
                (offset, rname) = Label::from_bytes(data, offset, 0)?;

                if offset + 20 > end {
                    return Err(anyhow!("SOA fixed fields truncated"));
                }
                let serial = read_u32(data, offset)?;
                let refresh = read_u32(data, offset + 4)?;
                let retry = read_u32(data, offset + 8)?;
                let expire = read_u32(data, offset + 12)?;
                let minimum = read_u32(data, offset + 16)?;

                QType::SOA(mname, rname, serial, refresh, retry, expire, minimum)
            }
            7 => {
                let (_, name) = Label::from_bytes(data, offset, 0)?;
                QType::MB(name)
            }
            8 => {
                let (_, name) = Label::from_bytes(data, offset, 0)?;
                QType::MG(name)
            }
            9 => {
                let (_, name) = Label::from_bytes(data, offset, 0)?;
                QType::MR(name)
            }
            10 => QType::NULL(slice(data, offset, end)?.to_vec()),
            11 => {
                if offset + 5 > end {
                    return Err(anyhow!("WKS rdata truncated"));
                }
                let ipv4 = Ipv4Addr::from_bits(read_u32(data, offset)?);
                let proto = read_u8(data, offset + 4)?;
                let bitmap = slice(data, offset + 5, end)?.to_vec();

                QType::WKS(ipv4, proto, bitmap)
            }
            12 => {
                let (_, name) = Label::from_bytes(data, offset, 0)?;
                QType::PTR(name)
            }
            13 => {
                let s: String = String::from_utf8(slice(data, offset, end)?.to_vec())?;
                QType::HINFO(s)
            }
            14 => {
                let rmailbx: Label;
                (offset, rmailbx) = Label::from_bytes(data, offset, 0)?;

                let emailbx: Label;
                (_, emailbx) = Label::from_bytes(data, offset, 0)?;

                QType::MINFO(rmailbx, emailbx)
            }
            15 => {
                if offset + 2 > end {
                    return Err(anyhow!("MX rdata truncated"));
                }
                let preference = read_u16(data, offset)?;
                let (_, name) = Label::from_bytes(data, offset + 2, 0)?;
                QType::MX(preference, name)
            }
            16 => {
                // TXT rdata is one or more character-strings, each a
                // one-byte length followed by that many bytes (RFC 1035
                // Section 3.3.14). Long values (DKIM keys, long SPF records)
                // are split across multiple strings and must be
                // concatenated.
                let mut value = String::new();
                let mut pos = offset;
                while pos < end {
                    let Some(&len_byte) = data.get(pos) else {
                        return Err(anyhow!("TXT rdata truncated"));
                    };
                    let len = len_byte as usize;
                    if pos + 1 + len > end {
                        return Err(anyhow!("TXT character-string overruns rdata"));
                    }
                    value.push_str(&String::from_utf8_lossy(&data[pos + 1..pos + 1 + len]));
                    pos += 1 + len;
                }
                QType::TXT(value)
            }
            _ => QType::EMPTY,
        })
    }

    /// Serialize the rdata.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        Ok(match self {
            QType::A(ipv4) => ipv4.to_bits().to_be_bytes().to_vec(),
            QType::NS(label) => label.to_bytes()?,
            QType::MD(label) => label.to_bytes()?,
            QType::MF(label) => label.to_bytes()?,
            QType::CNAME(label) => label.to_bytes()?,
            QType::SOA(mname, rname, serial, refresh, retry, expire, minimum) => {
                let mut data: Vec<u8> = vec![];
                let _ = data.write_all(mname.to_bytes()?.as_slice());
                let _ = data.write_all(rname.to_bytes()?.as_slice());
                let _ = data.write_all(serial.to_be_bytes().as_slice());
                let _ = data.write_all(refresh.to_be_bytes().as_slice());
                let _ = data.write_all(retry.to_be_bytes().as_slice());
                let _ = data.write_all(expire.to_be_bytes().as_slice());
                let _ = data.write_all(minimum.to_be_bytes().as_slice());
                data
            }
            QType::MB(label) => label.to_bytes()?,
            QType::MG(label) => label.to_bytes()?,
            QType::MR(label) => label.to_bytes()?,
            QType::NULL(v) => v.to_vec(),
            QType::WKS(ipv4, proto, bitmap) => {
                let mut data: Vec<u8> = vec![];
                let _ = data.write_all(ipv4.to_bits().to_be_bytes().as_ref());
                let _ = data.write(&[*proto]);
                let _ = data.write_all(bitmap);
                data
            }
            QType::PTR(label) => label.to_bytes()?,
            QType::HINFO(s) => s.as_bytes().to_vec(),
            QType::MINFO(rmailbx, emailbx) => {
                let mut data: Vec<u8> = vec![];
                let _ = data.write_all(rmailbx.to_bytes()?.as_slice());
                let _ = data.write_all(emailbx.to_bytes()?.as_slice());
                data
            }
            QType::MX(p, label) => {
                let mut data: Vec<u8> = vec![];
                let _ = data.write_all(p.to_be_bytes().as_slice());
                let _ = data.write_all(label.to_bytes()?.as_slice());
                data
            }
            QType::TXT(s) => {
                let mut data: Vec<u8> = vec![];
                for chunk in s.as_bytes().chunks(255) {
                    data.push(chunk.len() as u8);
                    let _ = data.write_all(chunk);
                }
                data
            }
            _ => vec![],
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A real reddit.com TXT response (with compression pointers and an
    /// OPT additional record) — the base fixture for the hostile-input
    /// systematic tests below.
    pub(crate) const RESPONSE_FIXTURE: &[u8] = &[
        0x10, 0x32, 0x81, 0x90, 0x00, 0x01, 0x00, 0x10, 0x00, 0x00, 0x00, 0x01, 0x06, 0x72, 0x65,
        0x64, 0x64, 0x69, 0x74, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x10, 0x00, 0x01, 0xc0, 0x0c,
        0x00, 0x10, 0x00, 0x01, 0x00, 0x00, 0x0d, 0xc3, 0x00, 0x25, 0x24, 0x36, 0x31, 0x34, 0x61,
        0x63, 0x34, 0x62, 0x65, 0x2d, 0x38, 0x36, 0x36, 0x34, 0x2d, 0x34, 0x63, 0x65, 0x61, 0x2d,
        0x38, 0x65, 0x32, 0x39, 0x2d, 0x66, 0x38, 0x34, 0x64, 0x30, 0x38, 0x61, 0x64, 0x38, 0x37,
        0x35, 0x63, 0xc0, 0x0c, 0x00, 0x10, 0x00, 0x01, 0x00, 0x00, 0x0d, 0xc3, 0x00, 0x0e, 0x0d,
        0x4d, 0x53, 0x3d, 0x6d, 0x73, 0x37, 0x31, 0x30, 0x34, 0x31, 0x39, 0x30, 0x32, 0xc0, 0x0c,
        0x00, 0x10, 0x00, 0x01, 0x00, 0x00, 0x0d, 0xc3, 0x00, 0x2b, 0x2a, 0x61, 0x70, 0x70, 0x6c,
        0x65, 0x2d, 0x64, 0x6f, 0x6d, 0x61, 0x69, 0x6e, 0x2d, 0x76, 0x65, 0x72, 0x69, 0x66, 0x69,
        0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x3d, 0x71, 0x43, 0x33, 0x72, 0x53, 0x53, 0x4b, 0x72,
        0x68, 0x31, 0x30, 0x44, 0x6f, 0x4d, 0x49, 0x37, 0xc0, 0x0c, 0x00, 0x10, 0x00, 0x01, 0x00,
        0x00, 0x0d, 0xc3, 0x00, 0x5f, 0x5e, 0x61, 0x74, 0x6c, 0x61, 0x73, 0x73, 0x69, 0x61, 0x6e,
        0x2d, 0x64, 0x6f, 0x6d, 0x61, 0x69, 0x6e, 0x2d, 0x76, 0x65, 0x72, 0x69, 0x66, 0x69, 0x63,
        0x61, 0x74, 0x69, 0x6f, 0x6e, 0x3d, 0x61, 0x47, 0x57, 0x44, 0x78, 0x47, 0x76, 0x74, 0x2b,
        0x6f, 0x59, 0x33, 0x70, 0x37, 0x71, 0x54, 0x57, 0x74, 0x35, 0x76, 0x32, 0x75, 0x4a, 0x44,
        0x56, 0x4a, 0x6b, 0x6f, 0x4a, 0x41, 0x65, 0x48, 0x78, 0x77, 0x47, 0x71, 0x4b, 0x6d, 0x47,
        0x51, 0x4c, 0x4d, 0x45, 0x73, 0x55, 0x58, 0x55, 0x4a, 0x4a, 0x65, 0x2f, 0x50, 0x6d, 0x2f,
        0x6b, 0x2b, 0x47, 0x47, 0x4e, 0x50, 0x70, 0x6e, 0x36, 0x4d, 0xc0, 0x0c, 0x00, 0x10, 0x00,
        0x01, 0x00, 0x00, 0x0d, 0xc3, 0x00, 0x5f, 0x5e, 0x61, 0x74, 0x6c, 0x61, 0x73, 0x73, 0x69,
        0x61, 0x6e, 0x2d, 0x64, 0x6f, 0x6d, 0x61, 0x69, 0x6e, 0x2d, 0x76, 0x65, 0x72, 0x69, 0x66,
        0x69, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x3d, 0x76, 0x42, 0x61, 0x56, 0x36, 0x50, 0x58,
        0x79, 0x79, 0x75, 0x34, 0x4f, 0x41, 0x50, 0x4c, 0x69, 0x51, 0x46, 0x62, 0x78, 0x46, 0x4d,
        0x43, 0x62, 0x6f, 0x53, 0x54, 0x6a, 0x6f, 0x52, 0x2f, 0x71, 0x78, 0x4b, 0x4a, 0x32, 0x4f,
        0x6c, 0x70, 0x49, 0x34, 0x36, 0x5a, 0x45, 0x70, 0x5a, 0x4c, 0x2f, 0x46, 0x56, 0x54, 0x49,
        0x66, 0x4d, 0x6c, 0x67, 0x6f, 0x4d, 0x35, 0x48, 0x79, 0x39, 0x65, 0x59, 0xc0, 0x0c, 0x00,
        0x10, 0x00, 0x01, 0x00, 0x00, 0x0d, 0xc3, 0x00, 0x59, 0x58, 0x62, 0x6f, 0x78, 0x2d, 0x64,
        0x6f, 0x6d, 0x61, 0x69, 0x6e, 0x2d, 0x76, 0x65, 0x72, 0x69, 0x66, 0x69, 0x63, 0x61, 0x74,
        0x69, 0x6f, 0x6e, 0x3d, 0x39, 0x35, 0x63, 0x33, 0x33, 0x66, 0x34, 0x65, 0x65, 0x34, 0x62,
        0x31, 0x31, 0x64, 0x38, 0x38, 0x32, 0x37, 0x31, 0x39, 0x30, 0x64, 0x62, 0x63, 0x35, 0x33,
        0x37, 0x31, 0x63, 0x61, 0x37, 0x64, 0x66, 0x32, 0x35, 0x62, 0x39, 0x36, 0x31, 0x30, 0x31,
        0x39, 0x31, 0x31, 0x36, 0x65, 0x35, 0x35, 0x36, 0x35, 0x63, 0x65, 0x34, 0x61, 0x61, 0x33,
        0x36, 0x64, 0x65, 0x39, 0x62, 0x65, 0x33, 0x61, 0xc0, 0x0c, 0x00, 0x10, 0x00, 0x01, 0x00,
        0x00, 0x0d, 0xc3, 0x00, 0x2e, 0x2d, 0x64, 0x6f, 0x63, 0x75, 0x73, 0x69, 0x67, 0x6e, 0x3d,
        0x36, 0x62, 0x61, 0x30, 0x63, 0x35, 0x61, 0x39, 0x2d, 0x35, 0x61, 0x35, 0x65, 0x2d, 0x34,
        0x31, 0x66, 0x38, 0x2d, 0x61, 0x37, 0x63, 0x38, 0x2d, 0x38, 0x62, 0x34, 0x63, 0x36, 0x65,
        0x33, 0x35, 0x63, 0x31, 0x30, 0x63, 0xc0, 0x0c, 0x00, 0x10, 0x00, 0x01, 0x00, 0x00, 0x0d,
        0xc3, 0x00, 0x45, 0x44, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2d, 0x73, 0x69, 0x74, 0x65,
        0x2d, 0x76, 0x65, 0x72, 0x69, 0x66, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x3d, 0x30,
        0x75, 0x76, 0x31, 0x33, 0x2d, 0x77, 0x78, 0x6c, 0x48, 0x4b, 0x38, 0x46, 0x46, 0x4b, 0x61,
        0x55, 0x70, 0x67, 0x7a, 0x79, 0x72, 0x56, 0x6d, 0x4c, 0x31, 0x59, 0x64, 0x4e, 0x59, 0x57,
        0x36, 0x76, 0x33, 0x50, 0x75, 0x70, 0x4c, 0x64, 0x77, 0x33, 0x4a, 0x49, 0xc0, 0x0c, 0x00,
        0x10, 0x00, 0x01, 0x00, 0x00, 0x0d, 0xc3, 0x00, 0x45, 0x44, 0x67, 0x6f, 0x6f, 0x67, 0x6c,
        0x65, 0x2d, 0x73, 0x69, 0x74, 0x65, 0x2d, 0x76, 0x65, 0x72, 0x69, 0x66, 0x69, 0x63, 0x61,
        0x74, 0x69, 0x6f, 0x6e, 0x3d, 0x6f, 0x68, 0x5f, 0x59, 0x4a, 0x45, 0x35, 0x36, 0x30, 0x79,
        0x30, 0x65, 0x36, 0x46, 0x48, 0x50, 0x31, 0x52, 0x54, 0x37, 0x4e, 0x49, 0x6a, 0x79, 0x54,
        0x6c, 0x42, 0x68, 0x41, 0x43, 0x4e, 0x4d, 0x76, 0x44, 0x32, 0x45, 0x67, 0x53, 0x73, 0x73,
        0x30, 0x73, 0x63, 0xc0, 0x0c, 0x00, 0x10, 0x00, 0x01, 0x00, 0x00, 0x0d, 0xc3, 0x00, 0x45,
        0x44, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2d, 0x73, 0x69, 0x74, 0x65, 0x2d, 0x76, 0x65,
        0x72, 0x69, 0x66, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x3d, 0x7a, 0x5a, 0x48, 0x6f,
        0x7a, 0x59, 0x62, 0x41, 0x4a, 0x6d, 0x53, 0x4c, 0x4f, 0x4d, 0x47, 0x34, 0x4f, 0x6a, 0x51,
        0x46, 0x6f, 0x48, 0x69, 0x56, 0x71, 0x6b, 0x78, 0x74, 0x64, 0x67, 0x76, 0x79, 0x42, 0x7a,
        0x73, 0x45, 0x37, 0x77, 0x55, 0x47, 0x46, 0x69, 0x77, 0xc0, 0x0c, 0x00, 0x10, 0x00, 0x01,
        0x00, 0x00, 0x0d, 0xc3, 0x00, 0x3f, 0x3e, 0x6c, 0x6f, 0x67, 0x6d, 0x65, 0x69, 0x6e, 0x2d,
        0x76, 0x65, 0x72, 0x69, 0x66, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x2d, 0x63, 0x6f,
        0x64, 0x65, 0x3d, 0x31, 0x65, 0x33, 0x30, 0x37, 0x66, 0x63, 0x38, 0x2d, 0x33, 0x36, 0x31,
        0x61, 0x2d, 0x34, 0x65, 0x33, 0x39, 0x2d, 0x38, 0x30, 0x31, 0x32, 0x2d, 0x65, 0x64, 0x30,
        0x38, 0x37, 0x33, 0x62, 0x30, 0x36, 0x36, 0x36, 0x38, 0xc0, 0x0c, 0x00, 0x10, 0x00, 0x01,
        0x00, 0x00, 0x0d, 0xc3, 0x00, 0x3e, 0x3d, 0x6f, 0x6e, 0x65, 0x74, 0x72, 0x75, 0x73, 0x74,
        0x2d, 0x64, 0x6f, 0x6d, 0x61, 0x69, 0x6e, 0x2d, 0x76, 0x65, 0x72, 0x69, 0x66, 0x69, 0x63,
        0x61, 0x74, 0x69, 0x6f, 0x6e, 0x3d, 0x36, 0x62, 0x39, 0x38, 0x62, 0x61, 0x33, 0x64, 0x64,
        0x30, 0x38, 0x37, 0x34, 0x30, 0x35, 0x33, 0x39, 0x39, 0x62, 0x62, 0x66, 0x34, 0x35, 0x62,
        0x36, 0x63, 0x62, 0x64, 0x63, 0x64, 0x33, 0x37, 0xc0, 0x0c, 0x00, 0x10, 0x00, 0x01, 0x00,
        0x00, 0x0d, 0xc3, 0x00, 0x55, 0x54, 0x73, 0x74, 0x72, 0x69, 0x70, 0x65, 0x2d, 0x76, 0x65,
        0x72, 0x69, 0x66, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x3d, 0x38, 0x30, 0x61, 0x61,
        0x37, 0x65, 0x32, 0x63, 0x39, 0x37, 0x37, 0x35, 0x66, 0x65, 0x65, 0x32, 0x36, 0x35, 0x33,
        0x66, 0x36, 0x31, 0x62, 0x30, 0x34, 0x62, 0x34, 0x36, 0x64, 0x61, 0x36, 0x66, 0x64, 0x32,
        0x32, 0x37, 0x62, 0x35, 0x36, 0x66, 0x65, 0x63, 0x64, 0x39, 0x34, 0x39, 0x39, 0x65, 0x35,
        0x66, 0x36, 0x33, 0x63, 0x64, 0x30, 0x64, 0x63, 0x66, 0x35, 0x36, 0x33, 0x39, 0x38, 0x34,
        0xc0, 0x0c, 0x00, 0x10, 0x00, 0x01, 0x00, 0x00, 0x0d, 0xc3, 0x00, 0x55, 0x54, 0x73, 0x74,
        0x72, 0x69, 0x70, 0x65, 0x2d, 0x76, 0x65, 0x72, 0x69, 0x66, 0x69, 0x63, 0x61, 0x74, 0x69,
        0x6f, 0x6e, 0x3d, 0x39, 0x62, 0x64, 0x37, 0x30, 0x64, 0x64, 0x31, 0x38, 0x38, 0x34, 0x34,
        0x32, 0x31, 0x62, 0x34, 0x37, 0x66, 0x35, 0x39, 0x36, 0x66, 0x65, 0x61, 0x33, 0x30, 0x31,
        0x65, 0x31, 0x34, 0x38, 0x33, 0x38, 0x63, 0x39, 0x38, 0x32, 0x35, 0x63, 0x64, 0x62, 0x61,
        0x35, 0x62, 0x32, 0x30, 0x39, 0x39, 0x39, 0x30, 0x39, 0x36, 0x38, 0x66, 0x64, 0x63, 0x36,
        0x66, 0x38, 0x30, 0x31, 0x30, 0x63, 0x37, 0xc0, 0x0c, 0x00, 0x10, 0x00, 0x01, 0x00, 0x00,
        0x0d, 0xc3, 0x00, 0x3c, 0x3b, 0x74, 0x77, 0x69, 0x6c, 0x69, 0x6f, 0x2d, 0x64, 0x6f, 0x6d,
        0x61, 0x69, 0x6e, 0x2d, 0x76, 0x65, 0x72, 0x69, 0x66, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6f,
        0x6e, 0x3d, 0x35, 0x65, 0x33, 0x37, 0x38, 0x35, 0x35, 0x64, 0x37, 0x63, 0x39, 0x34, 0x34,
        0x35, 0x65, 0x39, 0x36, 0x37, 0x62, 0x33, 0x31, 0x63, 0x35, 0x65, 0x30, 0x33, 0x37, 0x31,
        0x65, 0x62, 0x62, 0x35, 0xc0, 0x0c, 0x00, 0x10, 0x00, 0x01, 0x00, 0x00, 0x0d, 0xc3, 0x00,
        0xf0, 0xef, 0x76, 0x3d, 0x73, 0x70, 0x66, 0x31, 0x20, 0x69, 0x6e, 0x63, 0x6c, 0x75, 0x64,
        0x65, 0x3a, 0x61, 0x6d, 0x61, 0x7a, 0x6f, 0x6e, 0x73, 0x65, 0x73, 0x2e, 0x63, 0x6f, 0x6d,
        0x20, 0x69, 0x6e, 0x63, 0x6c, 0x75, 0x64, 0x65, 0x3a, 0x5f, 0x73, 0x70, 0x66, 0x2e, 0x67,
        0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d, 0x20, 0x69, 0x6e, 0x63, 0x6c, 0x75,
        0x64, 0x65, 0x3a, 0x6d, 0x61, 0x69, 0x6c, 0x67, 0x75, 0x6e, 0x2e, 0x6f, 0x72, 0x67, 0x20,
        0x69, 0x6e, 0x63, 0x6c, 0x75, 0x64, 0x65, 0x3a, 0x31, 0x39, 0x39, 0x32, 0x32, 0x38, 0x36,
        0x32, 0x2e, 0x73, 0x70, 0x66, 0x30, 0x31, 0x2e, 0x68, 0x75, 0x62, 0x73, 0x70, 0x6f, 0x74,
        0x65, 0x6d, 0x61, 0x69, 0x6c, 0x2e, 0x6e, 0x65, 0x74, 0x20, 0x69, 0x6e, 0x63, 0x6c, 0x75,
        0x64, 0x65, 0x3a, 0x68, 0x73, 0x2e, 0x72, 0x65, 0x64, 0x64, 0x69, 0x74, 0x2e, 0x63, 0x6f,
        0x6d, 0x20, 0x69, 0x6e, 0x63, 0x6c, 0x75, 0x64, 0x65, 0x3a, 0x5f, 0x73, 0x70, 0x66, 0x2e,
        0x73, 0x61, 0x6c, 0x65, 0x73, 0x66, 0x6f, 0x72, 0x63, 0x65, 0x2e, 0x63, 0x6f, 0x6d, 0x20,
        0x69, 0x70, 0x34, 0x3a, 0x31, 0x37, 0x34, 0x2e, 0x31, 0x32, 0x39, 0x2e, 0x32, 0x30, 0x33,
        0x2e, 0x31, 0x38, 0x39, 0x20, 0x69, 0x70, 0x34, 0x3a, 0x35, 0x32, 0x2e, 0x32, 0x30, 0x35,
        0x2e, 0x36, 0x31, 0x2e, 0x37, 0x39, 0x20, 0x69, 0x70, 0x34, 0x3a, 0x35, 0x34, 0x2e, 0x31,
        0x37, 0x32, 0x2e, 0x39, 0x37, 0x2e, 0x32, 0x34, 0x37, 0x20, 0x69, 0x70, 0x34, 0x3a, 0x35,
        0x32, 0x2e, 0x35, 0x30, 0x2e, 0x32, 0x34, 0x2e, 0x32, 0x30, 0x38, 0x20, 0x7e, 0x61, 0x6c,
        0x6c, 0x00, 0x00, 0x29, 0x04, 0xd0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    #[test]
    fn test_txt() {
        let question = DnsQuestion {
            name: Label::new("google.com".to_string()),
            record_type: 0x10,
            record_class: 0x01,
        };

        // Header: id=0x1032, flags=0x0100 (rd=1), 1 question, 1 additional
        // (the EDNS0 OPT pseudo-RR), then the question, then the OPT RR:
        // root name, type 41, class 1232 (payload size), ttl 0, rdlength 0.
        let expected: Vec<u8> = vec![
            0x10, 0x32, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x06, 0x67,
            0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x10, 0x00, 0x01,
            0x00, 0x00, 0x29, 0x04, 0xd0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];

        let data = DnsMessage::new(0x1032, vec![question]).to_vec().unwrap();
        assert_eq!(expected, data);
    }

    #[test]
    fn test_txt_multistring_roundtrip() {
        // A DKIM-sized TXT value (SPKI keys are regularly > 255 bytes) must
        // survive serialization as multiple character-strings and parse back
        // as the concatenated value.
        let long = format!("v=DKIM1; k=rsa; p={}", "ABCD".repeat(200)); // 823 bytes

        let rr = DnsResourceRecord {
            name: Label::new("sel1._domainkey.example.org".to_string()),
            record_type: 0x10,
            record_class: 0x01,
            ttl: 300,
            rdlength: 0, // recomputed by to_bytes
            rdata: QType::TXT(long.clone()),
        };

        let mut msg = DnsMessage::new(0x0102, vec![]);
        msg.header.answer_count = 1;
        msg.answers = vec![rr];

        let bytes = msg.to_vec().unwrap();
        let (_, parsed) = DnsMessage::from_bytes(&bytes).unwrap();

        assert_eq!(parsed.answers.len(), 1);
        match &parsed.answers[0].rdata {
            QType::TXT(txt) => assert_eq!(txt, &long),
            other => panic!("expected TXT rdata, got {:?}", other),
        }
    }

    #[test]
    fn test_txt_response() {
        let data = RESPONSE_FIXTURE.to_vec();

        let (_, dq) = DnsMessage::from_bytes(&data).unwrap();
        println!("{:?}", dq);
    }

    /// Queries advertise the flag-day-2020 payload size, and a parsed
    /// roundtrip preserves a conformant OPT record.
    #[test]
    fn edns0_query_advertises_1232_and_roundtrips() {
        let q = DnsMessage::new(
            0x1234,
            vec![DnsQuestion {
                name: Label::new("example.test".into()),
                record_type: 0x10,
                record_class: 0x01,
            }],
        );
        assert_eq!(q.additionals.len(), 1);
        assert_eq!(q.additionals[0].record_class, EDNS0_PAYLOAD_SIZE);
        assert_eq!(q.additionals[0].record_type, 0x29);

        // Roundtrip: the response's OPT decodes to version 0, no DO bit,
        // and the payload size it was built with.
        let resp = DnsMessage::new(0x1234, vec![]);
        let bytes = resp.to_vec().unwrap();
        let (_, parsed) = DnsMessage::from_bytes(&bytes).unwrap();
        let edns = parsed.edns0().unwrap().expect("OPT must be found");
        assert_eq!(edns.payload_size, EDNS0_PAYLOAD_SIZE);
        assert_eq!(edns.version, 0);
        assert_eq!(edns.extended_rcode, 0);
        assert!(!edns.dnssec_ok);
    }

    /// A response without an OPT record is allowed (the responder may
    /// not support EDNS0): edns0() returns Ok(None).
    #[test]
    fn edns0_absent_opt_is_ok() {
        let mut resp = DnsMessage::new(1, vec![]);
        resp.additionals.clear();
        assert!(resp.edns0().unwrap().is_none());
    }

    /// EDNS0 conformance violations are hard errors: two OPT records,
    /// a non-root owner name, and a version above the requested 0.
    #[test]
    fn edns0_violations_are_errors() {
        let base = || DnsMessage::new(1, vec![]);

        // Two OPTs.
        let mut resp = base();
        resp.additionals.push(resp.additionals[0].clone());
        assert!(resp.edns0().is_err());

        // Non-root owner name (RFC 6891 §6.1.2).
        let mut resp = base();
        resp.additionals[0].name = Label::new("evil.test".into());
        assert!(resp.edns0().is_err());

        // Version above 0.
        let mut resp = base();
        resp.additionals[0].ttl = 1 << 16; // version = 1
        assert!(resp.edns0().is_err());
    }

    /// The DO bit and extended RCODE decode from their TTL positions.
    #[test]
    fn edns0_decodes_ttl_fields() {
        let mut resp = DnsMessage::new(1, vec![]);
        // ext-rcode = 5, version = 0, DO = 1, class = 1232.
        resp.additionals[0].ttl = (5 << 24) | (1 << 15);
        resp.additionals[0].record_class = 1232;
        let edns = resp.edns0().unwrap().unwrap();
        assert_eq!(edns.extended_rcode, 5);
        assert_eq!(edns.version, 0);
        assert!(edns.dnssec_ok);
        assert_eq!(edns.payload_size, 1232);
    }
}

/// Hostile-input tests: DNS responses come from the configured resolver,
/// which may be buggy, spoofed, or compromised — parsing must be total
/// (Ok or Err, never a panic) for every possible input.
#[cfg(test)]
mod hostile {
    use super::tests::RESPONSE_FIXTURE;
    use super::*;

    #[test]
    fn truncated_responses_never_panic() {
        let data = RESPONSE_FIXTURE.to_vec();
        for len in 0..=data.len() {
            let _ = DnsMessage::from_bytes(&data[..len]);
        }
    }

    /// Flip bits systematically across the message: every single-byte
    /// corruption must parse without panicking.
    #[test]
    fn bitflip_responses_never_panic() {
        let base = RESPONSE_FIXTURE.to_vec();
        for i in 0..base.len() {
            for mask in [0x01u8, 0x40, 0x80, 0xFF] {
                let mut corrupted = base.clone();
                corrupted[i] ^= mask;
                let _ = DnsMessage::from_bytes(&corrupted);
            }
        }
    }

    /// Compression pointers that point at themselves or past the end of
    /// the message must error out (bounded by the depth limit and the
    /// range check), never loop or panic.
    #[test]
    fn hostile_compression_pointers_error() {
        // Self-referential pointer in the question name: the name at
        // offset 12 points at offset 12.
        let mut self_ptr = vec![0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0];
        self_ptr.extend([0xC0, 0x0C]); // name: pointer to itself
        self_ptr.extend([0, 16, 0, 1]); // TXT IN
        assert!(DnsMessage::from_bytes(&self_ptr).is_err());

        // Pointer past the end of the message: 0x3FFF is 4095.
        let mut past_end = vec![0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0];
        past_end.extend([0xC0, 0xFF]);
        past_end.extend([0, 16, 0, 1]);
        assert!(DnsMessage::from_bytes(&past_end).is_err());
    }

    /// An answer whose rdlength claims more rdata than the message
    /// contains must error, not panic or read into unrelated memory.
    #[test]
    fn rdlength_overrun_errors() {
        let mut d = vec![0, 1, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0];
        d.extend([1, b'a', 0]); // question name "a"
        d.extend([0, 16, 0, 1]); // TXT IN
        d.extend([0xC0, 0x0C]); // answer name: pointer to the question
        d.extend([0, 16, 0, 1]); // TXT IN
        d.extend([0, 0, 0, 0]); // ttl 0
        d.extend([0xFF, 0xFF]); // rdlength 65535 — overruns everything
        assert!(DnsMessage::from_bytes(&d).is_err());
    }

    /// A TXT character-string that overruns its own rdlength must error.
    #[test]
    fn txt_string_overrun_errors() {
        let mut d = vec![0, 1, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0];
        d.extend([1, b'a', 0, 0, 16, 0, 1]);
        d.extend([0xC0, 0x0C, 0, 16, 0, 1, 0, 0, 0, 0]);
        d.extend([0, 3]); // rdlength 3
        d.extend([10, b'a', b'b']); // string claims 10 bytes, rdata has 2 left
        assert!(DnsMessage::from_bytes(&d).is_err());
    }

    /// Section counts far exceeding the data must fail fast instead of
    /// panicking (each parse runs out of bytes and returns Err).
    #[test]
    fn counts_exceeding_data_error_without_panic() {
        let mut d = vec![0, 1, 0x81, 0x80, 0, 50, 0, 0, 0, 0, 0, 0];
        d.extend([1, b'a', 0, 0, 16, 0, 1]);
        assert!(DnsMessage::from_bytes(&d).is_err());
    }

    /// An A record whose rdlength is too small must not read fixed-width
    /// fields across into the next record's data.
    #[test]
    fn a_record_with_short_rdlength_errors() {
        let mut d = vec![0, 1, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0];
        d.extend([1, b'a', 0, 0, 1, 0, 1]);
        d.extend([0xC0, 0x0C, 0, 1, 0, 1, 0, 0, 0, 0]);
        d.extend([0, 2]); // rdlength 2 — an A record needs 4
        d.extend([10, 0, 0, 1]); // would-be A bytes, beyond the rdata
        assert!(DnsMessage::from_bytes(&d).is_err());
    }
}
