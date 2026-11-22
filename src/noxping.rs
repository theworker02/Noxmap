//! Bounded TCP reachability and timing utility for authorized diagnostics.

use noxmap::ScanPolicy;
use std::env;
use std::net::{TcpStream, ToSocketAddrs};
use std::thread;
use std::time::{Duration, Instant};

const MAX_PROBES: u16 = 20;

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

    let mut replies = Vec::new();
    for sequence in 1..=options.count {
        let started = Instant::now();
        let outcome = TcpStream::connect_timeout(&address, options.timeout);
        let elapsed = started.elapsed();
        match outcome {
            Ok(_) => {
                replies.push(elapsed);
                println!(
                    "{sequence}: tcp/{port} reachable time={} ms",
                    elapsed.as_millis()
                );
            }
            Err(error) if is_response(&error) => {
                replies.push(elapsed);
                println!(
                    "{sequence}: tcp/{port} refused (host responded) time={} ms",
                    elapsed.as_millis()
                );
            }
            Err(error) => println!("{sequence}: tcp/{port} no response ({error})"),
        }
        if sequence != options.count {
            thread::sleep(options.interval);
        }
    }
    print_summary(options.count, &replies);
    Ok(())
}

struct Options {
    allow_public: bool,
    count: u16,
    interval: Duration,
    timeout: Duration,
}

fn parse_options(arguments: impl Iterator<Item = String>) -> Result<Options, String> {
    let mut options = Options {
        allow_public: false,
        count: 4,
        interval: Duration::from_millis(250),
        timeout: Duration::from_millis(800),
    };
    let mut arguments = arguments;
    while let Some(flag) = arguments.next() {
        match flag.as_str() {
            "--allow-public" => options.allow_public = true,
            "--count" => {
                options.count = arguments
                    .next()
                    .ok_or("--count requires a number")?
                    .parse()
                    .map_err(|_| "--count must be a number")?;
                if options.count == 0 || options.count > MAX_PROBES {
                    return Err(format!("--count must be between 1 and {MAX_PROBES}"));
                }
            }
            "--interval-ms" => {
                options.interval = Duration::from_millis(
                    arguments
                        .next()
                        .ok_or("--interval-ms requires a number")?
                        .parse()
                        .map_err(|_| "--interval-ms must be a number")?,
                );
            }
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

fn is_response(error: &std::io::Error) -> bool {
    matches!(error.raw_os_error(), Some(10061 | 111))
        || matches!(error.kind(), std::io::ErrorKind::ConnectionRefused)
}

fn print_summary(sent: u16, replies: &[Duration]) {
    let received = u16::try_from(replies.len()).unwrap_or(u16::MAX);
    let loss = f64::from(sent.saturating_sub(received)) / f64::from(sent) * 100.0;
    println!("--- noxping TCP summary ---");
    println!("{sent} probes sent, {received} responses, {loss:.0}% loss");
    if let (Some(min), Some(max)) = (replies.iter().min(), replies.iter().max()) {
        let total = replies.iter().map(Duration::as_micros).sum::<u128>();
        let average = total / replies.len() as u128;
        println!(
            "round-trip min/avg/max = {}/{}/{} ms",
            min.as_millis(),
            average / 1_000,
            max.as_millis()
        );
    }
}

fn print_help() {
    println!(
        "Noxping — bounded TCP reachability and timing utility\n\nUSAGE:\n  noxping <target> <port> [--count 4] [--interval-ms 250] [--timeout-ms 800] [--allow-public]\n\nThis is TCP connection timing, not ICMP or raw-packet probing. Only assess systems you own or are explicitly authorized to test."
    );
}

fn help() -> String {
    "run `noxping --help` for usage".into()
}

#[cfg(test)]
mod tests {
    use super::parse_options;

    #[test]
    fn parses_bounded_probe_options() {
        let options = parse_options(
            vec![
                "--count".into(),
                "2".into(),
                "--interval-ms".into(),
                "10".into(),
            ]
            .into_iter(),
        )
        .expect("options should parse");
        assert_eq!(options.count, 2);
        assert_eq!(options.interval.as_millis(), 10);
    }

    #[test]
    fn rejects_unbounded_probe_counts() {
        assert!(parse_options(vec!["--count".into(), "21".into()].into_iter()).is_err());
    }
}

