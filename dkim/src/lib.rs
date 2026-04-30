use regex::Regex;
use std::collections::{HashMap, HashSet};

use base64::prelude::*;
use mail_parser::{HeaderValue, Message, MessageParser};
use serde::{Deserialize, Serialize};
use serde_json;
use sha2::{Digest, Sha256};

pub async fn verify_dkim<'msg>(msg: Message<'msg>) -> bool {
    false
}

pub async fn hash_body<'msg>(msg: Message<'msg>) -> String {
    "".to_string()
}

pub async fn hash_headers<'msg>(msg: Message<'msg>, hdrs: &'msg str) -> String {
    for h in hdrs.split(':') {
        println!("{h}");
    }
    "".to_string()
}

pub fn dkim_headers(hdrs: Option<&str>) -> HashMap<&str, String> {
    let mut dkim_hs: HashMap<&str, String> = HashMap::new();
    if let Some(hs) = hdrs {
        for h in hs.split(';').map(|s| s.trim()) {
            if let Some((k, v)) = h.split_once('=') {
                let _ = dkim_hs.insert(k, v.replace("\n\t ", ""));
            }
        }
    }
    dkim_hs
}

pub fn relaxed_canonicalization(key: &str, value: &str) -> String {
    let wsp = Regex::new(r"\s+").unwrap();
    let value = Regex::replace_all(&wsp, value.trim(), " ");

    let re = Regex::new(r"\n|\r").unwrap();
    let value = Regex::replace_all(&re, &value, "");
    format!("{}:{}", key.trim().to_lowercase(), value)
}

pub fn relaxed_body(val: &str) -> String {
    let re = Regex::new(r"\s+").unwrap();
    let re2 = Regex::new(r"(\s*\r\n)+").unwrap();

    re2.replace_all(val, "\r\n")
        .split("\r\n")
        .map(|s| re.replace_all(s, " "))
        .collect::<Vec<_>>()
        .join("\r\n")
}

pub fn add(left: u64, right: u64) -> u64 {
    left + right
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_hash_headers() {
        let m = br#"Delivered-To: jrperson@gmail.com
Received: by 2002:a05:6841:8607:b0:18c1:ca90:59ae with SMTP id mh7csp748466nlc;
        Fri, 1 Nov 2024 18:16:08 -0700 (PDT)
X-Google-Smtp-Source: AGHT+IGph4b780K6bzqs0somuX0rlM8hoZDKRyBPchA9EK9SbNOnO+Dqy6Bau9OHetjdJ2hH/yuu
X-Received: by 2002:a05:6000:401f:b0:37c:ccba:8c93 with SMTP id ffacd0b85a97d-381c145e818mr6820003f8f.11.1730510168623;
        Fri, 01 Nov 2024 18:16:08 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1730510168; cv=none;
        d=google.com; s=arc-20240605;
        b=ghrOi9dVHbUFywlzlUz8OPzUNLzAeucok+R/sRX7iQgsPPIznucGFc13DaVeAZ09Ph
         x6VoogeU41GtvKQpzx5Ls64XMpMbIaR2w6/5lVUiOftVVV3YqhKQkCWdowqZkJbJvU0j
         g1RDZ0/ywKkPZc48YBp7XkM74B3Oeo2M1Y15wWFQzCSi4AhJ8vRji3vIAvRRsArgLN7O
         YVCa6VDMOlEH6MQMdjs6pyY07CYH5n27Xq5SKZgLa+Ke0CNguUsZjcN9rryfLf/FAX3L
         TDcr0rouKvq+vOW9dXrnPo39bZk4rZiouKyLU4U+SmhZ59yf9JtjgYsgTdFs+gClIK2d
         uegg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:feedback-id:message-id:subject:from:to:date
         :dkim-signature;
        bh=evU+ZAhaA7uoDunwy9tpxgyXQlVvxX0ZJTSDyRIcuew=;
        fh=EYxO0cFyL1O3hdDp8JXP7rFJJ7s3DfcCwr7oCM8FnXY=;
        b=gh8KSrG7SeGF7x29ulVIcXVdGi1+vPkKRoMPC1ZvmWxDeoi1MzoiY1aXTF/KdbuGfn
         WXjx8bUne/yirOvvPAqNdGSFrq5QQYFEzK5Fo2HM3q10zIS8XYBG9z/oEcsUKl6dk2yd
         On5EuvQ90jjMPsAVtVuiagN/qAQ8kN3ntLr3ANDda64QGwYz+km5qDJhsS9wsRa5qigq
         SbYSRNfkUUfqctKMG4Zde+RtYSAQ19fYQt+3eip+CEQw+etCx5E7JoU+ABhasyfDmLrm
         pGElzoQ61vkT/39cL4WGTogfUvy9wbWOjp8C4xKe/CfVatP6Fr6fupBoPPbqRlxqY1Oz
         cIYA==;
        dara=google.com
ARC-Authentication-Results: i=1; mx.google.com;
       dkim=pass header.i=@protonmail.com header.s=protonmail3 header.b=OcGMbHQ7;
       spf=pass (google.com: domain of jason.person@protonmail.com designates 185.70.40.140 as permitted sender) smtp.mailfrom=jason.person@protonmail.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=protonmail.com
Return-Path: <jason.person@protonmail.com>
Received: from mail-40140.protonmail.ch (mail-40140.protonmail.ch. [185.70.40.140])
        by mx.google.com with ESMTPS id ffacd0b85a97d-381c10cd3cbsi3282451f8f.50.2024.11.01.18.16.08
        for <jrperson@gmail.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 01 Nov 2024 18:16:08 -0700 (PDT)
Received-SPF: pass (google.com: domain of jason.person@protonmail.com designates 185.70.40.140 as permitted sender) client-ip=185.70.40.140;
Authentication-Results: mx.google.com;
       dkim=pass header.i=@protonmail.com header.s=protonmail3 header.b=OcGMbHQ7;
       spf=pass (google.com: domain of jason.person@protonmail.com designates 185.70.40.140 as permitted sender) smtp.mailfrom=jason.person@protonmail.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=protonmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=protonmail.com; s=protonmail3; t=1730510168; x=1730769368; bh=evU+ZAhaA7uoDunwy9tpxgyXQlVvxX0ZJTSDyRIcuew=; h=Date:To:From:Subject:Message-ID:Feedback-ID:From:To:Cc:Date:
	 Subject:Reply-To:Feedback-ID:Message-ID:BIMI-Selector:
	 List-Unsubscribe:List-Unsubscribe-Post; b=OcGMbHQ7D6awrQVpPwEp/eSLuPPz8cUpAuPS+IegdH602vdGJcgEHHGG2VSghVbIX
	 9R51b1Jcuf23BFIClp/mpdaGQSNOJ2YLiS9iE0MG+NeO2nMTDui8mObGj5g0ZmSlCV
	 WsYVfRq5lCAwxex4p7F3OUZ5YukOLITuliCUTtDB8lxwwbvEKy81X5d4qGwTMI7BNg
	 3YkjP36j3e1Pqsgptx/kMtT6VcsuMHiKyh2jjMs29oAXaGbDLN4SU+fnEExWehbpxV
	 eky5GkuOiL/crJq2iq2EWuZKCoLeq1SITnvEJjYoPOn5lK9Y9e32JHm1xUllYKnRD8
	 dXMlV6KdvNXkA==
Date: Sat, 02 Nov 2024 01:16:06 +0000
To: "jrperson@gmail.com" <jrperson@gmail.com>
From: Jason Person <jason.person@protonmail.com>
Subject: Test
Message-ID: <zuZRjJOl1NxzLHjkiYvxLU6XuKH9KZ2UnlMXEZmWnFQTHP9Qyh5XX71DDO9WerlL4O2_feN8gF1oJ5wq3K6pZWq_7d2GZ7F8UNZOgq0Dr8g=@protonmail.com>
Feedback-ID: 3806480:user:proton
X-Pm-Message-ID: 5fe347cca1a4a7d19512d22789519abebb39badd
MIME-Version: 1.0
Content-Type: multipart/alternative; boundary="b1=_DAe4ebKwgsZsACinmSR6tfFOA3greGoFYImur3b4"

--b1=_DAe4ebKwgsZsACinmSR6tfFOA3greGoFYImur3b4
Content-Type: text/plain; charset=utf-8
Content-Transfer-Encoding: base64

VGVzdA==
--b1=_DAe4ebKwgsZsACinmSR6tfFOA3greGoFYImur3b4
Content-Type: text/html; charset=utf-8
Content-Transfer-Encoding: base64

PGh0bWw+PGhlYWQ+PC9oZWFkPjxib2R5PjxkaXYgZGlyPSJhdXRvIj5UZXN0PC9kaXY+PC9ib2R5
PjwvaHRtbD4=
--b1=_DAe4ebKwgsZsACinmSR6tfFOA3greGoFYImur3b4--
"#;

        let msg = MessageParser::default().parse(m).unwrap();
        //println!("{:?}", msg.headers_raw().collect::<Vec<_>>());
        //println!("{}", serde_json::to_string_pretty(&msg).unwrap());
        let dkim_hs = dkim_headers(msg.header("DKIM-Signature").unwrap().as_text());

        let body = msg.html_bodies().collect::<Vec<_>>();
        println!("body: {:?}", body);

        // println!(
        //     "DKIM-Signature: {:?}, {:?}",
        //     msg.header("DKIM-Signature").unwrap().as_text().unwrap(),
        //     dkim_hs
        // );

        // let mut header_hash_buf: Vec<String> = Vec::new();
        //
        // println!("h: {:?}\n", dkim_hs.get("h"));
        // if let Some(hash_hdrs) = dkim_hs.get("h") {
        //     let mut header_set: HashSet<&str> = HashSet::new();
        //     for hh in hash_hdrs.split(':') {
        //         if let Some(hval) = msg.header_raw(hh.trim()) {
        //             if !header_set.contains(hval) {
        //                 //println!("hh: {}, hval: {}", hh, hval);
        //                 header_hash_buf.push(relaxed_canonicalization(hh, hval));
        //                 header_set.insert(hval);
        //             }
        //         }
        //     }
        // }
        //
        // let dkim_hdr_value = msg.header("DKIM-Signature").unwrap().as_text().unwrap();
        //
        // let re = Regex::new(r"\n|\r").unwrap();
        // let dkim_hdr_value = Regex::replace_all(&re, dkim_hdr_value, "");
        //
        // let re = Regex::new(r"\s+").unwrap();
        // let dkim_hdr_value = Regex::replace_all(&re, &dkim_hdr_value, " ");
        //
        // let re = Regex::new(r"b=[\w0-9\s/+=]+").unwrap();
        // let dkim_hdr_value = Regex::replace_all(&re, &dkim_hdr_value, "b=");
        //
        // header_hash_buf.push(format!("dkim-signature:{}\r\n", dkim_hdr_value));
        // let input = header_hash_buf.join("\r\n");
        // println!("{}", header_hash_buf.join("\r\n"));
        //
        // let mut hasher = Sha256::new();
        // hasher.update(input.as_bytes());
        // let result = hasher.finalize();
        //
        // println!("hash: {:x}, h: {}", result, dkim_hs.get("bh").unwrap());
        // println!("{}", BASE64_STANDARD.encode(result));
    }

    #[test]
    fn test_body_hash() {
        let m = br#"
--b1=_DAe4ebKwgsZsACinmSR6tfFOA3greGoFYImur3b4
Content-Type: text/plain; charset=utf-8
Content-Transfer-Encoding: base64

VGVzdA==
--b1=_DAe4ebKwgsZsACinmSR6tfFOA3greGoFYImur3b4
Content-Type: text/html; charset=utf-8
Content-Transfer-Encoding: base64

PGh0bWw+PGhlYWQ+PC9oZWFkPjxib2R5PjxkaXYgZGlyPSJhdXRvIj5UZXN0PC9kaXY+PC9ib2R5
PjwvaHRtbD4=
--b1=_DAe4ebKwgsZsACinmSR6tfFOA3greGoFYImur3b4--
"#;
    }

    #[test]
    fn test_relaxed_body_canonicalization() {
        let body = " C \r\nD \t E\r\n\r\n\r\n";
        let expected = " C\r\nD E\r\n";

        assert_eq!(relaxed_body(body), expected.to_string());
    }

    #[test]
    fn test_relaxed_headers_canonicalization() {
        let headers = "A: X\r\nB : Y \t\r\n\t Z  \r\n";
        let expected = "a:X\r\nb:Y Z\r\n";
        assert_eq!(relaxed_canonicalization(headers), expected.to_string());
    }
}
