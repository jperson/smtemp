use std::collections::HashMap;

use anyhow::{anyhow, Error};
use pest::iterators::Pairs;
use pest::Parser;
use pest_derive::Parser;

use jiff::fmt::rfc2822;
use jiff::Zoned;

#[derive(Parser)]
#[grammar = "../grammar/rfc5322.pest"]
struct ImfParser;

#[derive(Debug)]
pub struct Mailbox<'p> {
    display_name: &'p str,
    local_part: &'p str,
    domain: &'p str,
}

#[derive(Debug)]
pub struct MsgId<'p> {
    id_left: &'p str,
    id_right: &'p str,
}

#[derive(Debug)]
pub struct Trace<'p> {
    return_path: Option<&'p str>,
    received: Vec<&'p str>,
}

#[derive(Debug, Default)]
pub struct ImfHeaders<'h> {
    //pub trace: Vec<Trace<'h>>,
    pub trace: Vec<&'h str>,
    pub orig_date: Option<Zoned>,
    pub from: Option<Vec<Mailbox<'h>>>,
    pub sender: Option<Mailbox<'h>>,

    pub resent_date: Vec<Zoned>,
    pub resent_from: Vec<Mailbox<'h>>,
    pub resent_sender: Vec<Mailbox<'h>>,
    pub resent_to: Vec<Mailbox<'h>>,
    pub resent_cc: Vec<Mailbox<'h>>,
    pub resent_bcc: Vec<Mailbox<'h>>,
    pub resent_msg_id: Vec<MsgId<'h>>,

    pub reply_to: Option<Vec<Mailbox<'h>>>,
    pub to: Option<Vec<Mailbox<'h>>>,
    pub cc: Option<Vec<Mailbox<'h>>>,
    pub bcc: Option<Vec<Mailbox<'h>>>,
    pub msg_id: Option<MsgId<'h>>,

    pub in_reply_to: Option<Vec<MsgId<'h>>>,
    pub references: Option<Vec<MsgId<'h>>>,

    pub subject: Option<&'h str>,
    pub comments: Vec<&'h str>,
    pub keywords: Vec<&'h str>,
    pub optional_field: HashMap<&'h str, &'h str>,

    pub received: Vec<&'h str>,
}

macro_rules! mailbox {
    ($rules:ident) => {
        Mailbox {
            display_name: $rules
                .next()
                .ok_or(anyhow!("missing mailbox"))?
                .as_str()
                .trim(),
            local_part: $rules
                .next()
                .ok_or(anyhow!("missing local part"))?
                .as_str()
                .trim(),
            domain: $rules
                .next()
                .ok_or(anyhow!("missing domain"))?
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
                .ok_or(anyhow!("missing id_left"))?
                .as_str()
                .trim(),
            id_right: $rules
                .next()
                .ok_or(anyhow!("missing id_right"))?
                .as_str()
                .trim(),
        }
    };
}

pub fn parse_headers(src: &str) -> Result<ImfHeaders, Error> {
    let pairs = ImfParser::parse(Rule::fields, src.trim_start())?;
    let hdrs: ImfHeaders = pairs.try_into()?;

    if hdrs.from.is_none() {
        Err(anyhow!("Missing from field"))
    } else if hdrs.orig_date.is_none() {
        Err(anyhow!("Missing orig_date field"))
    } else {
        Ok(hdrs)
    }
}

impl<'p> TryFrom<Pairs<'p, Rule>> for ImfHeaders<'p> {
    type Error = Error;
    fn try_from(pairs: Pairs<'p, Rule>) -> Result<Self, Self::Error> {
        let mut ret: ImfHeaders = Default::default();

        for item in pairs {
            match item.as_rule() {
                Rule::orig_date => {
                    if ret.orig_date.is_none() {
                        let mut rules = item.into_inner();
                        ret.orig_date = Some(rfc2822::parse(
                            rules
                                .next()
                                .ok_or(anyhow!("missing date_time"))?
                                .as_str()
                                .trim(),
                        )?);
                    } else {
                        return Err(anyhow!("Found multiple orig_date fields"));
                    }
                }
                Rule::from => {
                    if ret.from.is_none() {
                        let mut rules = item.into_inner();
                        let mut vs: Vec<Mailbox<'p>> = Vec::new();
                        while rules.peek().is_some() {
                            vs.push(mailbox!(rules));
                        }
                        ret.from = Some(vs);
                    } else {
                        return Err(anyhow!("Found multiple from fields"));
                    }
                }
                Rule::resent_from => {
                    let mut rules = item.into_inner();
                    while rules.peek().is_some() {
                        ret.resent_from.push(mailbox!(rules));
                    }
                }
                Rule::sender => {
                    if ret.sender.is_none() {
                        let mut rules = item.into_inner();
                        ret.sender = Some(mailbox!(rules));
                    } else {
                        return Err(anyhow!("Found multiple sender fields"));
                    }
                }
                Rule::resent_sender => {
                    let mut rules = item.into_inner();
                    while rules.peek().is_some() {
                        ret.resent_sender.push(mailbox!(rules));
                    }
                }
                Rule::reply_to => {
                    if ret.reply_to.is_none() {
                        let mut rules = item.into_inner();
                        let mut vs: Vec<Mailbox<'p>> = Vec::new();

                        while rules.peek().is_some() {
                            vs.push(mailbox!(rules));
                        }
                        ret.reply_to = Some(vs);
                    } else {
                        return Err(anyhow!("Found multiple reply-to fields"));
                    }
                }
                Rule::to => {
                    if ret.to.is_none() {
                        let mut rules = item.into_inner();
                        let mut vs: Vec<Mailbox<'p>> = Vec::new();

                        while rules.peek().is_some() {
                            vs.push(mailbox!(rules));
                        }
                        ret.to = Some(vs);
                    } else {
                        return Err(anyhow!("Found multiple reply-to fields"));
                    }
                }
                Rule::resent_to => {
                    let mut rules = item.into_inner();
                    while rules.peek().is_some() {
                        ret.resent_to.push(mailbox!(rules));
                    }
                }
                Rule::cc => {
                    if ret.cc.is_none() {
                        let mut rules = item.into_inner();
                        let mut vs: Vec<Mailbox<'p>> = Vec::new();

                        while rules.peek().is_some() {
                            vs.push(mailbox!(rules));
                        }
                        ret.cc = Some(vs);
                    } else {
                        return Err(anyhow!("Found multiple reply-to fields"));
                    }
                }
                Rule::resent_cc => {
                    let mut rules = item.into_inner();
                    while rules.peek().is_some() {
                        ret.resent_cc.push(mailbox!(rules));
                    }
                }
                Rule::bcc => {
                    if ret.bcc.is_none() {
                        let mut rules = item.into_inner();
                        let mut vs: Vec<Mailbox<'p>> = Vec::new();
                        while rules.peek().is_some() {
                            vs.push(mailbox!(rules));
                        }
                        ret.bcc = Some(vs);
                    } else {
                        return Err(anyhow!("Found multiple reply-to fields"));
                    }
                }
                Rule::resent_bcc => {
                    let mut rules = item.into_inner();
                    while rules.peek().is_some() {
                        ret.resent_bcc.push(mailbox!(rules));
                    }
                }
                Rule::message_id => {
                    if ret.msg_id.is_none() {
                        let mut rules = item.into_inner();
                        ret.msg_id = Some(msg_id!(rules));
                    } else {
                        return Err(anyhow!("Found multiple reply-to fields"));
                    }
                }
                Rule::resent_msg_id => {
                    let mut rules = item.into_inner();
                    while rules.peek().is_some() {
                        ret.resent_msg_id.push(msg_id!(rules));
                    }
                }
                Rule::in_reply_to => {
                    if ret.in_reply_to.is_none() {
                        let mut rules = item.into_inner();
                        let mut vs: Vec<MsgId<'p>> = Vec::new();

                        while rules.peek().is_some() {
                            vs.push(msg_id!(rules));
                        }
                        ret.in_reply_to = Some(vs);
                    } else {
                        return Err(anyhow!("Found multiple in-reply-to fields"));
                    }
                }
                Rule::references => {
                    if ret.references.is_none() {
                        let mut rules = item.into_inner();
                        let mut vs: Vec<MsgId<'p>> = Vec::new();

                        while rules.peek().is_some() {
                            vs.push(msg_id!(rules));
                        }
                        ret.references = Some(vs);
                    } else {
                        return Err(anyhow!("Found multiple in-reply-to fields"));
                    }
                }
                Rule::subject => {
                    if ret.subject.is_none() {
                        ret.subject = Some(item.as_str().trim());
                    } else {
                        return Err(anyhow!("Found multiple subject fields"));
                    }
                }
                Rule::comments => {
                    ret.comments.push(item.as_str().trim());
                }
                Rule::keywords => {
                    ret.keywords.push(item.as_str().trim());
                }
                Rule::resent_date => {
                    let mut rules = item.into_inner();
                    ret.resent_date.push(rfc2822::parse(
                        rules
                            .next()
                            .ok_or(anyhow!("missing date_time"))?
                            .as_str()
                            .trim(),
                    )?);
                }
                Rule::trace => {
                    //TODO
                    ret.trace.push(item.as_str());
                }
                Rule::optional_field => {
                    let mut rules = item.into_inner();
                    let name = rules
                        .next()
                        .ok_or(anyhow!("missing field name"))?
                        .as_str()
                        .trim();
                    let value = rules
                        .next()
                        .ok_or(anyhow!("missing field value"))?
                        .as_str()
                        .trim();

                    ret.optional_field.insert(name, value);
                }
                _ => {
                    unreachable!();
                }
            }
        }

        Ok(ret)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fields() {
        let src = "\
            Date: Mon, 01 Jan 2024 12:01:33 +0000\r\n\
            From: Test User <foo@test.com>\r\n\
            Sender: Foo User <bar@test.com>\r\n\
            Reply-To: Test User <test@user.com>,Bar Foo <foo@test.com>\r\n\
            To: Test User <test@user.com>,Bar Foo <foo@test.com>\r\n\
            Cc: Test User <test@user.com>,Bar Foo <foo@test.com>\r\n\
            Bcc: Test User <test@user.com>,Bar Foo <foo@test.com>\r\n\
            Message-ID:<foobar.baz@test.com>\r\n\
            Subject: This is a test\r\n\
            Comments: A comment\r\n\
            Comments: Another comment\r\n\
            Keywords: test,foo,bar\r\n\
            Keywords: blah\r\n\
            Resent-Date: Mon, 01 Jan 2024 12:01:33 +0000\r\n\
            Resent-Date: Mon, 01 Jan 2024 12:01:33 +0000\r\n\
            Resent-Date: Mon, 01 Jan 2024 12:01:33 +0000\r\n\
            Resent-Date: Mon, 01 Jan 2024 12:01:33 +0000\r\n\
            Resent-Sender: Foo User <bar@test.com>\r\n\
            Resent-Sender: Bar User <foo@test.com>\r\n\
            Return-Path: <foo@foo.com>\r\n\
            Received:foo.com;Mon, 01 Jan 2024 12:00:00 +0000\r\n\
            Foo:bar,baz,foo\r\n\
            Bar:fkjadf,asdkjasf;asdfkjlj\r\n\
            ";
        let pairs = ImfParser::parse(Rule::fields, src.trim_start()).unwrap();
        let hdrs: ImfHeaders = pairs.try_into().unwrap();
        println!("{:?}", hdrs);
    }

    #[test]
    fn test_from() {
        let src = "From: Test User <test@user.com>\r\n";
        let pairs = ImfParser::parse(Rule::from, src).unwrap();
        println!("from: {:?}", pairs);
    }

    #[test]
    fn test_sender() {
        let src = "Sender:Test User <test@user.com>\r\n";
        let pairs = ImfParser::parse(Rule::sender, src).unwrap();
        println!("from: {:?}", pairs);
    }

    #[test]
    fn test_bcc() {
        let src = "Bcc: Test User <test@user.com>,Bar Foo <foo@test.com>\r\n";
        let pairs = ImfParser::parse(Rule::bcc, src).unwrap();
        println!("bcc: {:?}", pairs);
    }

    #[test]
    fn test_reply_to() {
        let src = "Reply-To:Test User <test@user.com>,Bar Foo <foo@test.com>\r\n";
        let pairs = ImfParser::parse(Rule::reply_to, src).unwrap();
        println!("from: {:?}", pairs);
    }

    #[test]
    fn test_orig_date() {
        let src = "Date: Mon, 01 Jan 2024 12:01:33 +0000\r\n";
        let mut pairs = ImfParser::parse(Rule::orig_date, src).unwrap();
        println!("orig_date: {:?}", pairs.next().unwrap().as_str().trim());
    }

    #[test]
    fn test_resent_date() {
        let src = "Resent-Date: Mon, 01 Jan 2024 12:01:33 +0000\r\n";
        let mut pairs = ImfParser::parse(Rule::resent_date, src).unwrap();
        println!("resent_date: {:?}", pairs.next().unwrap().as_str().trim());
    }

    #[test]
    fn test_message_id() {
        let src = "Message-ID:<foobar.baz@test.com>\r\n";
        let pairs = ImfParser::parse(Rule::message_id, src).unwrap();
        println!("message_id: {:?}", pairs);
    }

    #[test]
    fn test_in_reply_to() {
        let src = "In-Reply-To:<foobar.baz@test.com>\r\n";
        let pairs = ImfParser::parse(Rule::in_reply_to, src).unwrap();
        println!("in_reply_to: {:?}", pairs);
    }

    #[test]
    fn test_references() {
        let src = "References:<foobar.baz@test.com>\r\n";
        let pairs = ImfParser::parse(Rule::references, src).unwrap();
        println!("references: {:?}", pairs);
    }

    #[test]
    fn test_subject() {
        let src = "Subject: this is a test\r\n";
        let pairs = ImfParser::parse(Rule::subject_field, src).unwrap();
        println!("subject: {:?}", pairs);
    }

    #[test]
    fn test_trace() {
        let src =
            "Return-Path:<foo@test.com>\r\nReceived:foo.com;Mon, 01 Jan 2024 12:00:00 +0000\r\n";
        let pairs = ImfParser::parse(Rule::trace, src).unwrap();
        println!("trace: {:?}", pairs);
    }

    #[test]
    fn test_return_path() {
        let src = "Received:foo.com;Mon, 01 Jan 2024 12:00:00 +0000\r\n";
        let pairs = ImfParser::parse(Rule::trace, src).unwrap();
        println!("return_path: {:?}", pairs);
    }

    #[test]
    fn test_dot_atom() {
        let src = "foo.com;Mon, 01 Jan 2024 12:01:22 +0000\r\n";
        let pairs = ImfParser::parse(Rule::dot_atom, src).unwrap();
        println!("dot_atom: {:?}", pairs);
    }

    #[test]
    fn test_optional_field() {
        let src = "Foo:somefield;foo\r\n";
        let pairs = ImfParser::parse(Rule::optional_field, src).unwrap();
        println!("optional_field: {:?}", pairs);
    }
}
