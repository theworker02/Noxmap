//! Bounded TCP diagnostic client for authorized Noxmap workflows.

use noxmap::ScanPolicy;
use std::env;
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

const MAX_REPLY_BYTES: usize = 8_192;

fn main() {
    if let Err(error) = run() {
        eprintln!("error: {error}");
        std::process::exit(2);
    }
}

fn run() -> Result<(), String> {
    let mut arguments = env::args().skip(1);
    let target = arguments.next().ok_or_else(help)?;
    if matches!(target.as_str(), "help" | "--help" | "-h") {
        print_help();
        return Ok(());
    }
    let port = arguments
        .next()
        .ok_or("a TCP port is required")?
        .parse::<u16>()
        .map_err(|_| "port must be a number between 1 and 65535")?;
    if port == 0 {
        return Err("port must be between 1 and 65535".into());
    }
    let options = parse_options(arguments)?;
    let policy = ScanPolicy {
        allow_public: options.allow_public,
        ..ScanPolicy::default()
    };
    policy.validate(&target, 1, 1)?;
    let address = format!("{target}:{port}")
        .to_socket_addrs()
        .map_err(|error| format!("could not resolve target: {error}"))?
        .next()
        .ok_or("target resolved to no addresses")?;
    policy.validate_resolved(address.ip())?;
    let mut stream = TcpStream::connect_timeout(&address, options.timeout)
        .map_err(|error| format!("could not connect to {address}: {error}"))?;
    stream
        .set_read_timeout(Some(options.timeout))
        .map_err(|error| format!("could not configure read timeout: {error}"))?;
    stream
        .set_write_timeout(Some(options.timeout))
        .map_err(|error| format!("could not configure write timeout: {error}"))?;
    if let Some(message) = options.message {
        stream
            .write_all(message.as_bytes())
            .map_err(|error| format!("could not write request: {error}"))?;
    }
    if options.no_read {
        return Ok(());
    }
    let mut reply = vec![0_u8; MAX_REPLY_BYTES];
    match stream.read(&mut reply) {
        Ok(read) => print!("{}", String::from_utf8_lossy(&reply[..read])),
        Err(error)
            if matches!(
                error.kind(),
                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
            ) => {}
        Err(error) => return Err(format!("could not read reply: {error}")),
    }
    Ok(())
}

struct Options {
    allow_public: bool,
    message: Option<String>,
    no_read: bool,
    timeout: Duration,
}

fn parse_options(arguments: impl Iterator<Item = String>) -> Result<Options, String> {
    let mut options = Options {
        allow_public: false,
        message: None,
        no_read: false,
        timeout: Duration::from_millis(800),
    };
    let mut arguments = arguments;
    while let Some(flag) = arguments.next() {
        match flag.as_str() {
            "--allow-public" => options.allow_public = true,
            "--send" => options.message = Some(arguments.next().ok_or("--send requires text")?),
            "--no-read" => options.no_read = true,
            "--timeout-ms" => {
                options.timeout = Duration::from_millis(
                    arguments
                        .next()
                        .ok_or("--timeout-ms requires a number")?
                        .parse()
                        .map_err(|_| "--timeout-ms must be a number")?,
                );
            }
            _ => return Err(format!("unknown option: {flag}")),
        }
    }
    Ok(options)
}

fn print_help() {
    println!(
        "Noxcat — bounded TCP diagnostic client\n\nUSAGE:\n  noxcat <target> <port> [--send <text>] [--no-read] [--timeout-ms 800] [--allow-public]\n\nOnly connect to systems you own or are explicitly authorized to assess. Replies are limited to 8192 bytes."
    );
}

fn help() -> String {
    "run `noxcat --help` for usage".into()
}

#[cfg(test)]
mod tests {
    use super::parse_options;

    #[test]
    fn parses_bounded_client_options() {
        let options = parse_options(
            vec![
                "--send".into(),
                "PING\r\n".into(),
                "--timeout-ms".into(),
                "250".into(),
                "--allow-public".into(),
            ]
            .into_iter(),
        )
        .expect("options should parse");
        assert_eq!(options.message.as_deref(), Some("PING\r\n"));
        assert!(options.allow_public);
        assert_eq!(options.timeout.as_millis(), 250);
    }
}

