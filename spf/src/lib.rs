#![feature(addr_parse_ascii)]
use anyhow::{anyhow, Result};
use async_recursion::async_recursion;
use fqdn::FQDN;
use ipnet::{Ipv4Net, Ipv6Net};
use serde::Serialize;
use std::net::{IpAddr, Ipv4Addr};

use dns::{proto::QType, query_tls};

pub mod parser;
use crate::parser::parser::{
    parse, Spf, SpfDirective, SpfMacroSubs, SpfMechanism, SpfModifier, SpfQualifier, SpfTerm,
};

#[derive(Debug, Eq, PartialEq, Clone, Serialize)]
pub enum SpfResult {
    None,
    Neutral,
    Pass,
    Fail,
    SoftFail,
    TempError,
    PermError,
}

pub async fn query_spf_record(dest: &Ipv4Addr, domain: &str, subs: &SpfMacroSubs) -> Result<Spf> {
    let fqdn = if !domain.ends_with(".") {
        domain.to_string() + "."
    } else {
        domain.to_string()
    };
    let _ = fqdn.parse::<FQDN>()?;
    let spf_record = query_tls(dest, domain, 0x10, 0x01).await?;

    if !(spf_record.header.rcode == 0x00 || spf_record.header.rcode == 0x03) {
        return Err(anyhow!("Invalid rcode for dns record"));
    }

    for ans in spf_record.answers {
        if let QType::TXT(spf) = &ans.rdata {
            if spf.starts_with("v=spf1") {
                let spf = parse(subs, spf.as_str())?;
                return Ok(spf);
            }
        }
    }

    Err(anyhow!("Failed to find SPF record"))
}

#[async_recursion]
pub async fn check_host(
    server: &Ipv4Addr,
    peer: IpAddr,
    sender: &String,
    domain: String,
    helo: &Option<String>,
) -> Result<SpfResult> {
    let mut result: Option<SpfResult> = None;
    let mut redirect: Option<&SpfModifier> = None;
    let mut exp: Option<&SpfModifier> = None;

    let subs = SpfMacroSubs::new(peer, sender, &domain, helo);
    let spf = query_spf_record(server, domain.as_str(), &subs).await?;

    for term in spf.terms.iter() {
        match term {
            SpfTerm::Modifier(m) if m.name == "redirect" => {
                if redirect.is_some() {
                    return Ok(SpfResult::PermError);
                }
                redirect = Some(m);
            }
            SpfTerm::Modifier(m) if m.name == "exp" => {
                if exp.is_some() {
                    return Ok(SpfResult::PermError);
                }
                exp = Some(m);
            }
            SpfTerm::Modifier(_) => continue,
            SpfTerm::Directive(d) => {
                result = check_directive(server, peer, sender, helo, d).await;
                if result.is_some() {
                    break;
                }
            }
        }
    }

    if result.is_none() {
        if let Some(m) = redirect {
            result = check_host(server, peer, sender, m.value.clone(), helo)
                .await
                .ok();
        }
    }

    match result {
        Some(SpfResult::Fail) if exp.is_some() => {
            if let Some(d) = exp {
                check_host(server, peer, sender, d.value.clone(), helo).await
            } else {
                Err(anyhow!("check_host failed"))
            }
        }
        Some(r) => Ok(r.clone()),
        None => Ok(SpfResult::Neutral),
    }
}

fn check_ipv4(peer: IpAddr, ip: &Ipv4Net, pass: &SpfResult) -> Option<SpfResult> {
    match peer {
        IpAddr::V4(ip4) if ip.contains(&ip4) => Some(pass.clone()),
        _ => None,
    }
}

fn check_ipv6(peer: IpAddr, ip: &Ipv6Net, pass: &SpfResult) -> Option<SpfResult> {
    match peer {
        IpAddr::V6(ip6) if ip.contains(&ip6) => Some(pass.clone()),
        _ => None,
    }
}

async fn check_a_record(
    server: &Ipv4Addr,
    peer: IpAddr,
    d: &str,
    m: &SpfResult,
) -> Option<SpfResult> {
    let dns = query_tls(server, d, 0x16, 0x01).await.ok()?;
    if dns.header.rcode != 0x00 || dns.header.rcode != 0x03 {
        return Some(SpfResult::TempError);
    }

    for ans in dns.answers.iter() {
        if let QType::A(ip) = ans.rdata {
            let ipn = Ipv4Net::from(ip);
            if let Some(r) = check_ipv4(peer, &ipn, m) {
                return Some(r);
            }
        }
    }

    None
}

async fn check_mx_record(
    server: &Ipv4Addr,
    peer: IpAddr,
    d: &str,
    m: &SpfResult,
) -> Option<SpfResult> {
    let mut nlookups = 0;
    let dns = query_tls(server, d, 0xF, 0x01).await.ok()?;
    if dns.header.rcode != 0x00 || dns.header.rcode != 0x03 {
        return Some(SpfResult::TempError);
    }

    for ans in dns.answers.iter() {
        if nlookups < 10 {
            if let QType::MX(_, ip) = &ans.rdata {
                let ipn = Ipv4Net::try_from(ip).ok()?;
                if let Some(r) = check_ipv4(peer, &ipn, m) {
                    return Some(r);
                }
                nlookups += 1;
            }
        } else {
            return None;
        }
    }

    None
}

async fn check_ptr_record(
    server: &Ipv4Addr,
    peer: IpAddr,
    d: &String,
    m: &SpfResult,
) -> Option<SpfResult> {
    let mut nlookups = 0;
    let d = d.to_owned() + ".in-addr.arpa";

    let dns = query_tls(server, &d, 0x0C, 0x01).await.ok()?;
    if dns.header.rcode != 0x00 || dns.header.rcode != 0x03 {
        return Some(SpfResult::TempError);
    }

    for ans in dns.answers.iter() {
        if nlookups >= 10 {
            return None;
        }

        if let QType::PTR(label) = &ans.rdata {
            let domain = String::from(label);
            if let Some(r) = check_a_record(server, peer, &domain, m).await {
                return Some(r);
            }
            nlookups += 1;
        }
    }

    None
}

async fn check_directive(
    server: &Ipv4Addr,
    peer: IpAddr,
    sender: &String,
    helo: &Option<String>,
    SpfDirective {
        qualifier: q,
        mechanism: m,
    }: &SpfDirective,
) -> Option<SpfResult> {
    match (q, m) {
        (SpfQualifier::Plus, SpfMechanism::All) => Some(SpfResult::Pass),
        (SpfQualifier::Dash, SpfMechanism::All) => Some(SpfResult::Fail),
        (SpfQualifier::Question, SpfMechanism::All) => Some(SpfResult::Neutral),
        (SpfQualifier::Tilde, SpfMechanism::All) => Some(SpfResult::SoftFail),

        //TODO need to check qualifier for each branch
        (SpfQualifier::Plus, SpfMechanism::Include(s)) => {
            match check_host(server, peer, sender, s.to_string(), helo)
                .await
                .ok()?
            {
                SpfResult::Pass => Some(SpfResult::Pass),
                SpfResult::Fail => None,
                SpfResult::SoftFail => None,
                SpfResult::Neutral => None,
                SpfResult::TempError => Some(SpfResult::TempError),
                SpfResult::PermError => Some(SpfResult::PermError),
                SpfResult::None => Some(SpfResult::PermError),
            }
        }
        (SpfQualifier::Dash, SpfMechanism::Include(s)) => {
            match check_host(server, peer, sender, s.to_string(), helo)
                .await
                .ok()?
            {
                SpfResult::Pass => Some(SpfResult::Fail),
                SpfResult::Fail => None,
                SpfResult::SoftFail => None,
                SpfResult::Neutral => None,
                SpfResult::TempError => Some(SpfResult::TempError),
                SpfResult::PermError => Some(SpfResult::PermError),
                SpfResult::None => Some(SpfResult::PermError),
            }
        }
        (SpfQualifier::Question, SpfMechanism::Include(s)) => {
            match check_host(server, peer, sender, s.to_string(), helo)
                .await
                .ok()?
            {
                SpfResult::Pass => Some(SpfResult::Neutral),
                SpfResult::Fail => None,
                SpfResult::SoftFail => None,
                SpfResult::Neutral => None,
                SpfResult::TempError => Some(SpfResult::TempError),
                SpfResult::PermError => Some(SpfResult::PermError),
                SpfResult::None => Some(SpfResult::PermError),
            }
        }
        (SpfQualifier::Tilde, SpfMechanism::Include(s)) => {
            match check_host(server, peer, sender, s.to_string(), helo)
                .await
                .ok()?
            {
                SpfResult::Pass => Some(SpfResult::SoftFail),
                SpfResult::Fail => None,
                SpfResult::SoftFail => None,
                SpfResult::Neutral => None,
                SpfResult::TempError => Some(SpfResult::TempError),
                SpfResult::PermError => Some(SpfResult::PermError),
                SpfResult::None => Some(SpfResult::PermError),
            }
        }

        (SpfQualifier::Plus, SpfMechanism::A(s)) => {
            check_a_record(server, peer, s, &SpfResult::Pass).await
        }
        (SpfQualifier::Dash, SpfMechanism::A(s)) => {
            check_a_record(server, peer, s, &SpfResult::Fail).await
        }
        (SpfQualifier::Question, SpfMechanism::A(s)) => {
            check_a_record(server, peer, s, &SpfResult::Neutral).await
        }
        (SpfQualifier::Tilde, SpfMechanism::A(s)) => {
            check_a_record(server, peer, s, &SpfResult::SoftFail).await
        }
        //
        (SpfQualifier::Plus, SpfMechanism::Mx(s)) => {
            check_mx_record(server, peer, s, &SpfResult::Pass).await
        }
        (SpfQualifier::Dash, SpfMechanism::Mx(s)) => {
            check_mx_record(server, peer, s, &SpfResult::Fail).await
        }
        (SpfQualifier::Question, SpfMechanism::Mx(s)) => {
            check_mx_record(server, peer, s, &SpfResult::Neutral).await
        }
        (SpfQualifier::Tilde, SpfMechanism::Mx(s)) => {
            check_mx_record(server, peer, s, &SpfResult::SoftFail).await
        }

        (SpfQualifier::Plus, SpfMechanism::Ptr(s)) => {
            check_ptr_record(server, peer, s, &SpfResult::Pass).await
        }
        (SpfQualifier::Dash, SpfMechanism::Ptr(s)) => {
            check_ptr_record(server, peer, s, &SpfResult::Fail).await
        }
        (SpfQualifier::Question, SpfMechanism::Ptr(s)) => {
            check_ptr_record(server, peer, s, &SpfResult::Neutral).await
        }
        (SpfQualifier::Tilde, SpfMechanism::Ptr(s)) => {
            check_ptr_record(server, peer, s, &SpfResult::SoftFail).await
        }

        (SpfQualifier::Plus, SpfMechanism::Ip4(ip)) => check_ipv4(peer, ip, &SpfResult::Pass),
        (SpfQualifier::Dash, SpfMechanism::Ip4(ip)) => check_ipv4(peer, ip, &SpfResult::Fail),
        (SpfQualifier::Question, SpfMechanism::Ip4(ip)) => {
            check_ipv4(peer, ip, &SpfResult::Neutral)
        }
        (SpfQualifier::Tilde, SpfMechanism::Ip4(ip)) => check_ipv4(peer, ip, &SpfResult::SoftFail),

        (SpfQualifier::Plus, SpfMechanism::Ip6(ip)) => check_ipv6(peer, ip, &SpfResult::Pass),
        (SpfQualifier::Dash, SpfMechanism::Ip6(ip)) => check_ipv6(peer, ip, &SpfResult::Fail),
        (SpfQualifier::Question, SpfMechanism::Ip6(ip)) => {
            check_ipv6(peer, ip, &SpfResult::Neutral)
        }
        (SpfQualifier::Tilde, SpfMechanism::Ip6(ip)) => check_ipv6(peer, ip, &SpfResult::SoftFail),

        (SpfQualifier::Plus, SpfMechanism::Exists(s)) => {
            check_a_record(server, peer, s, &SpfResult::Pass).await
        }
        (SpfQualifier::Dash, SpfMechanism::Exists(s)) => {
            check_a_record(server, peer, s, &SpfResult::Fail).await
        }
        (SpfQualifier::Question, SpfMechanism::Exists(s)) => {
            check_a_record(server, peer, s, &SpfResult::Neutral).await
        }
        (SpfQualifier::Tilde, SpfMechanism::Exists(s)) => {
            check_a_record(server, peer, s, &SpfResult::SoftFail).await
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_check_host_google() {
        let result = check_host(
            &"1.1.1.1".parse::<Ipv4Addr>().unwrap(),
            "10.0.0.1".parse::<IpAddr>().unwrap(),
            &"foo@test.com".to_string(),
            String::from("google.com"),
            &Some(String::from("google.com")),
        )
        .await
        .unwrap();

        assert_eq!(SpfResult::SoftFail, result);
    }

    #[tokio::test]
    async fn test_check_host_reddit() {
        let result = check_host(
            &"1.1.1.1".parse::<Ipv4Addr>().unwrap(),
            "52.50.24.208".parse::<IpAddr>().unwrap(),
            &"foo@test.com".to_string(),
            String::from("reddit.com"),
            &Some(String::from("reddit.com")),
        )
        .await
        .unwrap();

        assert_eq!(SpfResult::Pass, result);
    }

    #[tokio::test]
    async fn test_check_host_bing() {
        let result = check_host(
            &"1.1.1.1".parse::<Ipv4Addr>().unwrap(),
            "52.50.24.208".parse::<IpAddr>().unwrap(),
            &"foo@test.com".to_string(),
            String::from("bing.com"),
            &Some(String::from("bing.com")),
        )
        .await
        .unwrap();

        assert_eq!(SpfResult::Fail, result);
    }

    #[test]
    fn it_works() {
        let s = String::from(
            "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890.foo.",
        );
        let f = s.parse::<FQDN>();
        println!("{:?}", f);
    }
}
