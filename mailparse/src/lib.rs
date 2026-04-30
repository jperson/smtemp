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
}

#[derive(Debug, Default)]
pub struct DateZoned;

#[derive(Debug, Default, Clone, Eq, PartialEq)]
pub struct Mailbox<'p> {
    display_name: &'p str,
    local_part: &'p str,
    domain: &'p str,
}

#[derive(Debug, Default, Eq, PartialEq)]
pub struct MsgId<'p> {
    id_left: &'p str,
    id_right: &'p str,
}

#[derive(Debug, Default, Eq, PartialEq)]
pub struct Trace<'p> {
    return_path: Option<&'p str>,
    received_tokens: Vec<&'p str>,
    date_time: Zoned,
}

#[derive(Debug, Default)]
pub struct DkimHeader;

#[derive(Debug, Default)]
pub struct MimeVersion<'p> {
    major: &'p str,
    minor: &'p str,
}

#[derive(Debug, Default)]
pub struct ContentType<'p> {
    content_type: &'p str,
    content_subtype: &'p str,
    attribute: &'p str,
    value: &'p str,
}

#[derive(Debug, Default)]
pub struct ContentEncoding<'p> {
    mechanism: &'p str,
}

#[derive(Debug, Default)]
pub struct ContentDescription<'p> {
    description: &'p str,
}

#[derive(Debug, Default)]
pub struct ContentDisposition<'p> {
    disposition: &'p str,
}

#[derive(Debug, Default)]
pub struct MimeHeader<'p> {
    mime_version: Option<MimeVersion<'p>>,
    content_type: Option<ContentType<'p>>,
    content_encoding: Option<ContentEncoding<'p>>,
    content_id: Option<MsgId<'p>>,
    content_description: Option<ContentDescription<'p>>,
    content_disposition: Option<ContentDisposition<'p>>,
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

    pub dkim: Option<DkimHeader>,

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

macro_rules! mailbox {
    ($rules:ident) => {
        Mailbox {
            display_name: $rules
                .next()
                .ok_or(MailHeaderError::InvalidMailbox)?
                .as_str()
                .trim(),
            local_part: $rules
                .next()
                .ok_or(MailHeaderError::InvalidMailbox)?
                .as_str()
                .trim(),
            domain: $rules
                .next()
                .ok_or(MailHeaderError::InvalidMailbox)?
                .as_str()
                .trim(),
        }
    };
}

macro_rules! msg_id {
    ($rules:ident) => {
        MsgId {
            id_left: $rules
                .next()
                .ok_or(MailHeaderError::InvalidHeader)?
                .as_str()
                .trim(),
            id_right: $rules
                .next()
                .ok_or(MailHeaderError::InvalidHeader)?
                .as_str()
                .trim(),
        }
    };
}

impl<'p> TryFrom<Pairs<'p, Rule>> for MailHeaders<'p> {
    type Error = MailHeaderError;
    fn try_from(pairs: Pairs<'p, Rule>) -> Result<Self, Self::Error> {
        let mut mh = MailHeaders::default();

        for item in pairs.into_iter() {
            match item.as_rule() {
                // Trace fields
                // Rule::trace => trace(&mut mh)?,
                Rule::resent_date => resent_date(&mut mh, item)?,
                Rule::resent_from => resent_from(&mut mh, item)?,
                Rule::resent_to => resent_to(&mut mh, item)?,
                Rule::resent_cc => resent_cc(&mut mh, item)?,
                Rule::resent_bcc => resent_bcc(&mut mh, item)?,
                Rule::resent_msg_id => resent_msg_id(&mut mh, item)?,
                // Rule::dkim_header => dkim_header(&mut mh)?,

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

                _ => println!("none"),
            }
        }

        Ok(mh)
    }
}

fn trace<'p>(mh: &mut MailHeaders<'p>, item: Pair<'p, Rule>) -> Result<(), MailHeaderError> {
    let mut th = Trace::default();

    for rule in item.into_inner() {
        match rule.as_rule() {
            Rule::received => {
                for token in rule.into_inner() {
                    match token.as_rule() {
                        Rule::received_token => th.received_tokens.push(token.as_str().trim()),
                        Rule::received_date => {
                            th.date_time = rfc2822::parse(token.as_str().trim())
                                .map_err(|_| MailHeaderError::InvalidHeader)?
                        }
                        _ => continue,
                    }
                }
            }
            Rule::return_path => th.return_path = Some(rule.as_str()[13..].trim()),
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
    let mut rules = item.into_inner();
    while rules.peek().is_some() {
        mh.resent_from.push(mailbox!(rules));
    }
    Ok(())
}

fn resent_to<'p>(mh: &mut MailHeaders<'p>, item: Pair<'p, Rule>) -> Result<(), MailHeaderError> {
    let mut rules = item.into_inner();
    while rules.peek().is_some() {
        mh.resent_to.push(mailbox!(rules));
    }
    Ok(())
}

fn resent_cc<'p>(mh: &mut MailHeaders<'p>, item: Pair<'p, Rule>) -> Result<(), MailHeaderError> {
    let mut rules = item.into_inner();
    while rules.peek().is_some() {
        mh.resent_cc.push(mailbox!(rules));
    }
    Ok(())
}

fn resent_bcc<'p>(mh: &mut MailHeaders<'p>, item: Pair<'p, Rule>) -> Result<(), MailHeaderError> {
    let mut rules = item.into_inner();
    while rules.peek().is_some() {
        mh.resent_bcc.push(mailbox!(rules));
    }
    Ok(())
}

fn resent_msg_id<'p>(
    mh: &mut MailHeaders<'p>,
    item: Pair<'p, Rule>,
) -> Result<(), MailHeaderError> {
    let mut rules = item.into_inner();
    while rules.peek().is_some() {
        mh.resent_msg_id.push(msg_id!(rules));
    }
    Ok(())
}

fn dkim_header(_mh: &mut MailHeaders) -> Result<(), MailHeaderError> {
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
        let mut rules = item.into_inner();
        let mut vs: Vec<Mailbox> = Vec::new();

        while rules.peek().is_some() {
            vs.push(mailbox!(rules));
        }

        mh.from = Some(vs);
    } else {
        return Err(MailHeaderError::InvalidMailbox);
    }

    Ok(())
}

fn sender<'p>(mh: &mut MailHeaders<'p>, item: Pair<'p, Rule>) -> Result<(), MailHeaderError> {
    if mh.sender.is_none() {
        let mut rules = item.into_inner();
        mh.sender = Some(mailbox!(rules));
    } else {
        return Err(MailHeaderError::InvalidHeader);
    }
    Ok(())
}

fn reply_to<'p>(mh: &mut MailHeaders<'p>, item: Pair<'p, Rule>) -> Result<(), MailHeaderError> {
    if mh.reply_to.is_none() {
        let mut rules = item.into_inner();
        let mut vs: Vec<Mailbox<'p>> = Vec::new();

        while rules.peek().is_some() {
            vs.push(mailbox!(rules));
        }
        mh.reply_to = Some(vs);
    } else {
        return Err(MailHeaderError::InvalidHeader);
    }
    Ok(())
}

//Destination fields
fn to<'p>(mh: &mut MailHeaders<'p>, item: Pair<'p, Rule>) -> Result<(), MailHeaderError> {
    if mh.to.is_none() {
        let mut rules = item.into_inner();
        let mut vs: Vec<Mailbox<'p>> = Vec::new();

        while rules.peek().is_some() {
            vs.push(mailbox!(rules));
        }
        mh.to = Some(vs);
    } else {
        return Err(MailHeaderError::InvalidHeader);
    }

    Ok(())
}

fn cc<'p>(mh: &mut MailHeaders<'p>, item: Pair<'p, Rule>) -> Result<(), MailHeaderError> {
    if mh.cc.is_none() {
        let mut rules = item.into_inner();
        let mut vs: Vec<Mailbox<'p>> = Vec::new();

        while rules.peek().is_some() {
            vs.push(mailbox!(rules));
        }
        mh.cc = Some(vs);
    } else {
        return Err(MailHeaderError::InvalidHeader);
    }

    Ok(())
}

fn bcc<'p>(mh: &mut MailHeaders<'p>, item: Pair<'p, Rule>) -> Result<(), MailHeaderError> {
    if mh.bcc.is_none() {
        let mut rules = item.into_inner();
        let mut vs: Vec<Mailbox<'p>> = Vec::new();

        while rules.peek().is_some() {
            vs.push(mailbox!(rules));
        }
        mh.bcc = Some(vs);
    } else {
        return Err(MailHeaderError::InvalidHeader);
    }

    Ok(())
}

//Identification fields
fn message_id<'p>(mh: &mut MailHeaders<'p>, item: Pair<'p, Rule>) -> Result<(), MailHeaderError> {
    if mh.message_id.is_none() {
        let mut rules = item.into_inner();
        mh.message_id = Some(msg_id!(rules));
    } else {
        return Err(MailHeaderError::InvalidHeader);
    }

    Ok(())
}

fn in_reply_to<'p>(mh: &mut MailHeaders<'p>, item: Pair<'p, Rule>) -> Result<(), MailHeaderError> {
    if mh.in_reply_to.is_none() {
        let mut rules = item.into_inner();
        let mut vs: Vec<MsgId<'p>> = Vec::new();

        while rules.peek().is_some() {
            vs.push(msg_id!(rules));
        }
        mh.in_reply_to = Some(vs);
    } else {
        return Err(MailHeaderError::InvalidHeader);
    }

    Ok(())
}

fn references<'p>(mh: &mut MailHeaders<'p>, item: Pair<'p, Rule>) -> Result<(), MailHeaderError> {
    if mh.references.is_none() {
        let mut rules = item.into_inner();
        let mut vs: Vec<MsgId<'p>> = Vec::new();

        while rules.peek().is_some() {
            vs.push(msg_id!(rules));
        }
        mh.references = Some(vs);
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
    let mut rules = item.into_inner();

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
                let rules = rule.into_inner();

                for rule in rules {
                    match rule.as_rule() {
                        Rule::attribute => ctype.attribute = rule.as_str().trim(),
                        Rule::value => ctype.value = rule.as_str().trim(),
                        _ => continue,
                    };
                }
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
    let mut rules = item.into_inner();

    if let Some(mh) = &mut mh.mime_header {
        mh.content_id = Some(msg_id!(rules));
    } else {
        return Err(MailHeaderError::InvalidHeader);
    }

    Ok(())
}

fn content_description<'p>(
    mh: &mut MailHeaders<'p>,
    item: Pair<'p, Rule>,
) -> Result<(), MailHeaderError> {
    let mut rules = item.into_inner();

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
    let mut rules = item.into_inner();
    let mut dis = ContentDisposition::default();

    println!("{:#?}", rules);

    // if let Some(mh) = &mut mh.mime_header {
    //     for rule in rules {
    //         match rule.as_rule() {
    //             Rule::disposition_type => continue,
    //             _ => continue,
    //         }
    //     }
    // }
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
        assert!(h.content_type.is_some());
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
}
