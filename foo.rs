//use std::iter::Enumerate;
//use std::iter::Peekable;
use std::str::CharIndices;

// use winnow::prelude::*;
// use winnow::{
//     //ascii::float,
//     //combinator::alt,
//     //combinator::cut_err,
//     //combinator::{delimited, preceded, separated_pair, terminated},
//     //combinator::{repeat, separated},
//     combinator::{alt, seq},
//     error::IResult,
//     token::{literal, take_while},
// };
//use logos::{Lexer, Logos, Span};

// #[derive(Debug, Logos)]
// enum Token {
//     //quoted-pair     =   ("\" (VCHAR / WSP)) / obs-qp
//     #[regex(r#"\\([ \t]|[\x21-\x7E])"#, |lex| lex.slice().to_owned())]
//     QuotedPair(String),
//
//     //FWS  =   ([*WSP CRLF] 1*WSP) /  obs-FWS ; Folding white space
//     #[regex("[ \t]*\r\n[ \t]+", |lex| lex.slice().to_owned())]
//     FWS(String),
//
//     /*
//     * ctext = %d33-39 /  ; Printable US-ASCII
//               %d42-91 /  ;  characters not including
//               %d93-126 / ;  "(", ")", or "\"
//               obs-ctext
//     */
//     #[regex("([\x21-\x27]|[\x2a-\x5b]|[\x5d-\x7e])", |lex| lex.slice().to_owned())]
//     CText(String),
// }

// fn ctext<'i>(input: &mut &'i str) -> IResult<&'i str, &'i str> {
//     take_while(0.., ('!'..='\'', '*'..='[', ']'..='~')).parse_peek(input)
// }
//
// fn wsp<'i>(input: &mut &'i str) -> IResult<&'i str, &'i str> {
//     alt((literal(" "), literal("\t"))).parse_peek(input)
// }
//
// fn quoted_pair<'i>(input: &mut &'i str) -> IResult<&'i str, (&'i str, &'i str)> {
//     ("\\", alt((ctext, wsp))).parse_next(input)
// }
#[derive(Debug)]
struct Stream<'s> {
    source: &'s str,
    pos: usize,
}

impl<'s> Stream<'s> {
    pub fn new(source: &'s str) -> Self {
        Stream { source, pos: 0 }
    }

    pub fn peek(&self) -> Option<char> {
        self.source[self.pos..].chars().next()
    }

    pub fn take_while<P>(&mut self, mut predicate: P) -> Option<&'s str>
    where
        P: FnMut(&char) -> bool,
    {
        let start = self.pos;
        let mut offset = 0;
        let mut last;
        let mut source_iter = self.source[self.pos..].char_indices();

        loop {
            if let Some((i, c)) = source_iter.next() {
                if !predicate(&c) {
                    last = i;
                    break;
                }
                offset = i;
            } else {
                last = self.source.len() - self.pos;
                break;
            }
        }

        if offset == 0 {
            None
        } else {
            self.pos += last;
            Some(&self.source[start..=start + offset])
        }
    }
}

#[derive(Debug)]
enum Token<'s> {
    WSP,
    CText(&'s str),
}

//addr-spec = local-part "@" domain
fn addr_spec() {}

//local-part = dot-atom / quoted-string / obs-local-part
fn local_part() {}

//dot-atom = [CFWS] dot-atom-text [CFWS]
fn dot_atom() {}

//CFWS = (1*([FWS] comment) [FWS]) / FWS
fn cfws() {}

//FWS = ([*WSP CRLF] 1*WSP) /  obs-FWS ; Folding white space
fn fws() {}

//WSP = SP / HTAB ; white space
fn wsp<'s>(s: &mut Stream) -> Token<'s> {
    match s.peek() {
        Some(' ') | Some('\t') => {
            s.pos += 1;
            Token::WSP
        }
        _ => panic!("Failed to parse WSP"),
    }
}

//obs-FWS = 1*([CRLF] WSP) ; As amended in erratum #1908
fn obs_fws() {}

/*
ctext =  %d33-39 /   ; Printable US-ASCII
         %d42-91 /   ;  characters not including
         %d93-126 /  ;  "(", ")", or "\"
         obs-ctext
*/
fn ctext<'s>(s: &mut Stream) -> Token<'s> {
    // let r = s.source.by_ref().take_while(|c| match c {
    //     '!'..='\'' | '*'..='[' | ']'..='~' => true,
    //     _ => false,
    // });
    //
    // println!("{:?}", r
    Token::WSP
}

//obs-ctext = obs-NO-WS-CTL
fn obs_ctext() {}

//ccontent = ctext / quoted-pair / comment
fn ccontent() {}

//comment = "(" *([FWS] ccontent) [FWS] ")"
fn comment() {}

//dot-atom-text = 1*atext *("." 1*atext)
fn dot_atom_text() {}

/*
atext =  ALPHA / DIGIT /   ; Printable US-ASCII
        "!" / "#" /        ;  characters not including
        "$" / "%" /        ;  specials.  Used for atoms.
        "&" / "'" /
        "*" / "+" /
        "-" / "/" /
        "=" / "?" /
        "^" / "_" /
        "`" / "{" /
        "|" / "}" /
        "~"
*/
fn atext() {}

/*
specials =  "(" / ")" /  ; Special characters that do
            "<" / ">" /  ;  not appear in atext
            "[" / "]" /
            ":" / ";" /
            "@" / "\" /
            "," / "." /
            DQUOTE
*/
fn specials() {}

//quoted-string = [CFWS] DQUOTE *([FWS] qcontent) [FWS] DQUOTE [CFWS]
fn quoted_string() {}

//qcontent = qtext / quoted-pair
fn qcontent() {}

/*
qtext =  %d33 /       ; Printable US-ASCII
         %d35-91 /    ;  characters not including
         %d93-126 /   ;  "\" or the quote character
         obs-qtext
*/
fn qtext() {}

//obs-qtext = obs-NO-WS-CTL
fn obs_qtext() {}

/*
obs-NO-WS-CTL =  %d1-8 /     ; US-ASCII control
                 %d11 /      ;  characters that do not
                 %d12 /      ;  include the carriage
                 %d14-31 /   ;  return, line feed, and
                 %d127       ;  white space characters
*/
fn obs_no_ws_ctl() {}

//quoted-pair = ("\" (VCHAR / WSP)) / obs-qp
fn quoted_pair() {}

//VCHAR = %x21-7E            ; visible (printing) characters
fn vchar() {}

//obs-qp = "\" (%d0 / obs-NO-WS-CTL / LF / CR)
fn obs_qp() {}

//obs-local-part = word *("." word)
fn obs_local_part() {}

//word = atom / quoted-string
fn word() {}

//atom = [CFWS] 1*atext [CFWS]
fn atom() {}

//domain = dot-atom / domain-literal / obs-domain
fn domain() {}

//domain-literal = [CFWS] "[" *([FWS] dtext) [FWS] "]" [CFWS]
fn domain_literal() {}

/*
dtext =  %d33-90 /     ; Printable US-ASCII
         %d94-126 /    ;  characters not including
         obs-dtext     ;  "[", "]", or "\"
*/
fn dtext() {}

//obs-dtext = obs-NO-WS-CTL / quoted-pair
fn obs_dtext() {}

//obs-domain = atom *("." atom)
fn obs_domain() {}

//NB For SMTP mail, the domain-literal is restricted by RFC5321 as follows:

//Mailbox = Local-part "@" ( Domain / address-literal )
fn mailbox() {}

/*
address-literal  = "[" ( IPv4-address-literal /
                IPv6-address-literal /
                General-address-literal ) "]"
*/
fn address_literal() {}

//IPv4-address-literal = Snum 3("."  Snum)
fn ipv4_address_literal() {}

//IPv6-address-literal  = "IPv6:" IPv6-addr
fn ipv6_address_literal() {}

/*
Snum  = 1*3DIGIT
     ; representing a decimal integer
     ; value in the range 0 through 255
*/
fn snum() {}

//IPv6-addr = IPv6-full / IPv6-comp / IPv6v4-full / IPv6v4-comp
fn ipv6_addr() {}

//IPv6-hex = 1*4HEXDIG
fn ipv6_hex() {}

//IPv6-full = IPv6-hex 7(":" IPv6-hex)
fn ipv6_full() {}

/*
IPv6-comp  = [IPv6-hex *5(":" IPv6-hex)] "::" [IPv6-hex *5(":" IPv6-hex)]
          ; The "::" represents at least 2 16-bit groups of
          ; zeros.  No more than 6 groups in addition to the
          ; "::" may be present.
*/
fn ipv6_comp() {}

//IPv6v4-full = IPv6-hex 5(":" IPv6-hex) ":" IPv4-address-literal
fn ipv6v4_full() {}

/*
IPv6v4-comp  = [IPv6-hex *3(":" IPv6-hex)] "::"
            [IPv6-hex *3(":" IPv6-hex) ":"]
            IPv4-address-literal
            ; The "::" represents at least 2 16-bit groups of
            ; zeros.  No more than 4 groups in addition to the
            ; "::" and IPv4-address-literal may be present.
*/
fn ipv6v4_comp() {}

#[cfg(test)]
mod tests {
    use super::*;

    //#[test]
    // fn test_lexer() {
    //     let src = "\\a   \r\n \\x!!";
    //     let mut lexer = Token::lexer(src);
    //     println!("{:?}", lexer.spanned().collect::<Vec<_>>());
    // }
    #[test]
    fn test_wsp_parser() {
        let src = "\tabc";
        let mut scanner = Stream::new(src);
        let r = wsp(&mut scanner);
        println!("{:?}, {:?}", scanner, r);
    }

    #[test]
    fn test_ctext_parser() {
        let src = "!abcd()";
        let mut scanner = Stream::new(src);
        let r = ctext(&mut scanner);
        println!("{:?}", scanner);
    }

    #[test]
    fn test_scanner() {
        let src = "abcÿd!!";
        let mut scanner = Stream::new(src);
        let r = scanner.take_while(|c| c.is_ascii_alphabetic());
        println!("r: {:?}", r);
        println!("peek: {:?}", scanner.peek());

        let r = scanner.take_while(|c| c.is_ascii());
        println!("r: {:?}", r);
        println!("peek: {:?}", scanner.peek());
        // println!("{:?}", scanner);
        // let x = scanner
        //     .source
        //     .clone()
        //     .take_while(|c| c.is_ascii_alphabetic())
        //     .collect::<Vec<_>>();
        // println!("{:?}", x.last());
        // println!("{:?}", scanner);
    }

    #[test]
    fn test_foo() {
        let src = "abÿÿc12";
        let cs = src[0..].char_indices();
        println!(
            "{:?}",
            cs.take_while(|(_, c)| c.is_ascii()).collect::<Vec<_>>()
        );
        println!("{:?}", src.get(4..));
    }
}
