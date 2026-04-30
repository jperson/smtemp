use pest::Parser;
use pest::iterators::Pairs;
use pest_derive::Parser;
use thiserror::Error;

#[derive(Parser)]
#[grammar = "../grammar/rfc2045.pest"]
struct MimeParser;

#[derive(Debug, Error, PartialEq)]
pub enum MimeParserError {
    #[error("Failed parsing version header")]
    InvalidHeader,

    #[error("Failed parsing version header")]
    InvalidHeader2,
}

#[derive(Debug, Default, PartialEq)]
pub struct MimeHeaderVersion {
    pub major: u8,
    pub minor: u8,
}

impl<'p> TryFrom<Pairs<'p, Rule>> for MimeHeaderVersion {
    type Error = MimeParsreError;
    fn try_from(pairs: Pairs<'p, Rule>) -> Result<Self, Self::Error> {
        let mut ret: MimeHeaderVersion = Default::default();

        for item in pairs {
            match item.as_rule() {
                Rule::major => {
                    ret.major = item
                        .as_str()
                        .trim()
                        .parse::<u8>()
                        .map_err(|_| MimeParserError::InvalidHeader)?
                }
                Rule::minor => {
                    ret.minor = item
                        .as_str()
                        .trim()
                        .parse::<u8>()
                        .map_err(|_| MimeParserError::InvalidHeader2)?
                }
                _ => unreachable!(),
            }
        }

        Ok(ret)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_token() {
        let src = "atoken";
        let pairs = MimeParser::parse(Rule::token, src).unwrap();
        println!("{:?}", pairs);
    }

    #[test]
    fn test_version() {
        let src = "MIME-Version: 1.0";
        let pairs = MimeParser::parse(Rule::version_header, src).unwrap();
        let version: Result<MimeHeaderVersion, MimeParserError> = pairs.try_into();
        assert_eq!(Ok(MimeHeaderVersion { major: 1, minor: 0 }), version);

        let src = "MIME-Version:1.0";
        let pairs = MimeParser::parse(Rule::version_header, src).unwrap();
        let version: Result<MimeHeaderVersion, MimeParserError> = pairs.try_into();
        assert_eq!(Ok(MimeHeaderVersion { major: 1, minor: 0 }), version);

        let src = "MIME-Version:    1.0";
        let pairs = MimeParser::parse(Rule::version_header, src).unwrap();
        let version: Result<MimeHeaderVersion, MimeParserError> = pairs.try_into();
        assert_eq!(Ok(MimeHeaderVersion { major: 1, minor: 0 }), version);

        let src = "MIME-Version: 1.0 (produced by MetaSend Vx.x)";
        let pairs = MimeParser::parse(Rule::version_header, src).unwrap();
        let version: Result<MimeHeaderVersion, MimeParserError> = pairs.try_into();
        assert_eq!(Ok(MimeHeaderVersion { major: 1, minor: 0 }), version);

        let src = "MIME-Version: (produced by MetaSend Vx.x) 1.0";
        let pairs = MimeParser::parse(Rule::version_header, src).unwrap();
        let version: Result<MimeHeaderVersion, MimeParserError> = pairs.try_into();
        assert_eq!(Ok(MimeHeaderVersion { major: 1, minor: 0 }), version);

        let src = "MIME-Version: 1.(produced by MetaSend Vx.x)0";
        let pairs = MimeParser::parse(Rule::version_header, src).unwrap();
        let version: Result<MimeHeaderVersion, MimeParserError> = pairs.try_into();
        assert_eq!(Ok(MimeHeaderVersion { major: 1, minor: 0 }), version);
    }

    #[test]
    fn test_comment() {
        let src = "(produced by MetaSend Vx.x)";
        let pairs = MimeParser::parse(Rule::comment, src).unwrap();
        println!("{:?}", pairs);
    }
}
