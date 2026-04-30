use anyhow::Result;
use clap::Parser;
use std::str;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;

#[derive(Parser, Debug, Clone)]
#[command(version, about, long_about = None)]
struct Args {
    #[arg(long)]
    host: String,

    #[arg(long, default_value_t = 2525)]
    port: u16,
}

const MESSAGE: &str = r#"
HELO foo.com
MAIL FROM:foo@foo.com
RCPT TO:test@foo.com
RCPT TO:test1@foo.com
DATA
"#;

const DATA: &str = r#"
From: Art Vandelay <art@vandelay.com> (Vandelay Industries)
To: "Colleagues": "James Smythe" <james@vandelay.com>; Friends:
   jane@example.com, =?UTF-8?Q?John_Sm=C3=AEth?= <john@example.com>;
Date: Sat, 20 Nov 2021 14:22:01 -0800
Subject: Why not both importing AND exporting? =?utf-8?b?4pi6?=
Content-Type: multipart/mixed; boundary="festivus";

--festivus
Content-Type: text/html; charset="us-ascii"
Content-Transfer-Encoding: base64

PGh0bWw+PHA+SSB3YXMgdGhpbmtpbmcgYWJvdXQgcXVpdHRpbmcgdGhlICZsZHF1bztle
HBvcnRpbmcmcmRxdW87IHRvIGZvY3VzIGp1c3Qgb24gdGhlICZsZHF1bztpbXBvcnRpbm
cmcmRxdW87LDwvcD48cD5idXQgdGhlbiBJIHRob3VnaHQsIHdoeSBub3QgZG8gYm90aD8
gJiN4MjYzQTs8L3A+PC9odG1sPg==
--festivus
Content-Type: message/rfc822

From: "Cosmo Kramer" <kramer@kramerica.com>
Subject: Exporting my book about coffee tables
Content-Type: multipart/mixed; boundary="giddyup";

--giddyup
Content-Type: text/plain; charset="utf-16"
Content-Transfer-Encoding: quoted-printable

=FF=FE=0C!5=D8"=DD5=D8)=DD5=D8-=DD =005=D8*=DD5=D8"=DD =005=D8"=
=DD5=D85=DD5=D8-=DD5=D8,=DD5=D8/=DD5=D81=DD =005=D8*=DD5=D86=DD =
=005=D8=1F=DD5=D8,=DD5=D8,=DD5=D8(=DD =005=D8-=DD5=D8)=DD5=D8"=
=DD5=D8=1E=DD5=D80=DD5=D8"=DD!=00
--giddyup
Content-Type: image/gif; name*1="about "; name*0="Book ";
             name*2*=utf-8''%e2%98%95 tables.gif
Content-Transfer-Encoding: Base64
Content-Disposition: attachment

R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7
--giddyup--
--festivus--
.
"#;

const DATA_END: &[u8] = b".\r\n";
const QUIT: &str = "QUIT\n";

async fn write_line(stream: &mut BufReader<TcpStream>, l: String) -> Result<()> {
    let l = l.to_string() + "\n";
    stream.write_all(l.as_bytes()).await?;
    Ok(())
}

async fn read_line(stream: &mut BufReader<TcpStream>) -> Result<String> {
    let mut resp: String = String::new();
    let _ = stream.read_line(&mut resp).await?;
    Ok(resp.trim().to_string())
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    let stream = TcpStream::connect(format!("{}:{}", args.host, args.port)).await?;
    let mut stream = BufReader::new(stream);

    for l in MESSAGE.trim().split("\n") {
        write_line(&mut stream, l.to_string()).await?;
        println!("{}", read_line(&mut stream).await?);
    }

    for l in DATA.trim_start().split("\n") {
        write_line(&mut stream, l.to_string()).await?;
    }

    stream.write_all(DATA_END).await?;
    println!("{}", read_line(&mut stream).await?);

    stream.write_all(QUIT.as_bytes()).await?;
    println!("{}", read_line(&mut stream).await?);

    Ok(())
}
