use noxmap::api::serve_loopback;
use noxmap::discovery::{HostStatus, discover};
use noxmap::fingerprint::infer_from_services;
use noxmap::monitoring::diff;
use noxmap::report;
use noxmap::scanner::{PortState, parse_ports};
use noxmap::scripting::{parse_script, run_script};
use noxmap::storage::SnapshotStore;
use noxmap::targets::expand_cidr;
use noxmap::topology::{SystemTopologyProvider, TopologyProvider};
use noxmap::{ScanOptions, ScanPolicy, Scanner};
use std::env;
use std::thread;
use std::time::Duration;

fn main() {
    if let Err(error) = run() {
        eprintln!("error: {error}");
        std::process::exit(2);
    }
}

fn run() -> Result<(), String> {
    let mut args = env::args().skip(1);
    let command = args.next().unwrap_or_else(|| "help".into());
    if matches!(command.as_str(), "help" | "--help" | "-h") {
        print_help();
        return Ok(());
    }
    match command.as_str() {
        "scan" | "watch" => {
            let target = args.next().ok_or("a target is required")?;
            let (options, policy, state_dir, json, interval) = scan_arguments(args)?;
            scan_or_watch(
                &command, &target, &options, policy, state_dir, json, interval,
            )
        }
        "fingerprint" => {
            let target = args.next().ok_or("a target is required")?;
            let (options, policy, ..) = scan_arguments(args)?;
            let result = infer_from_services(&Scanner::new(policy).scan(&target, &options)?);
            println!(
                "{}",
                result
                    .guess
                    .unwrap_or_else(|| "No conservative OS identification available".into())
            );
            for evidence in result.evidence {
                println!(
                    "  [{}%] {}",
                    evidence.confidence_percent, evidence.observation
                );
            }
            Ok(())
        }
        "topology" => {
            let target = args.next().ok_or("a target is required")?;
            let path = SystemTopologyProvider::default().trace(&target)?;
            println!("topology: {}", path.target);
            for hop in path.hops {
                println!(
                    "  {:>2}  {}",
                    hop.ttl,
                    hop.address.unwrap_or_else(|| "*".into())
                );
            }
            Ok(())
        }
        "discover" => {
            let target = args.next().ok_or("a target or IPv4 CIDR is required")?;
            let (options, policy, ..) = scan_arguments(args)?;
            for target in expand_cidr(&target, 256)? {
                let result = discover(&Scanner::new(policy), &target, options.ports.clone())?;
                let status = match result.status {
                    HostStatus::Responsive => "up",
                    HostStatus::NoResponse => "no-response",
                    HostStatus::Unknown => "unknown",
                };
                println!("{:<15} {:<12} {}", result.target, status, result.evidence);
            }
            Ok(())
        }
        "script" => {
            let script_path = args.next().ok_or("a .nox script path is required")?;
            let target = args.next().ok_or("a target is required")?;
            let (options, policy, ..) = scan_arguments(args)?;
            let source = std::fs::read_to_string(script_path)
                .map_err(|error| format!("could not read script: {error}"))?;
            let script = parse_script(&source)?;
            let finding = run_script(&script, &Scanner::new(policy).scan(&target, &options)?);
            println!(
                "{}: {} — {}",
                finding.script_id,
                if finding.passed { "passed" } else { "failed" },
                finding.message
            );
            Ok(())
        }
        "api" => {
            let port = args.next().map_or(Ok(8421), |value| {
                value.parse().map_err(|_| "API port must be a number")
            })?;
            let store = SnapshotStore::open(".noxmap")?;
            serve_loopback(port, ScanPolicy::default(), &store)
        }
        _ => compat_scan(command, args.collect()),
    }
}

fn compat_scan(first: String, rest: Vec<String>) -> Result<(), String> {
    let mut tokens = vec![first];
    tokens.extend(rest);
    let mut target = None;
    let mut options = ScanOptions::default();
    let mut policy = ScanPolicy::default();
    let mut output = None;
    let mut index = 0;
    while index < tokens.len() {
        match tokens[index].as_str() {
            "-sT" | "--connect" | "-sV" | "--service-version" => {}
            "-p" | "--ports" => {
                index += 1;
                options.ports = parse_ports(tokens.get(index).ok_or("-p requires a value")?)?;
            }
            "-oN" => {
                index += 1;
                output = Some((
                    tokens.get(index).ok_or("-oN requires a file path")?.clone(),
                    false,
                ));
            }
            "-oX" => {
                index += 1;
                output = Some((
                    tokens.get(index).ok_or("-oX requires a file path")?.clone(),
                    true,
                ));
            }
            "--allow-public" => policy.allow_public = true,
            "-sS" | "-sU" | "-O" | "-A" | "-Pn" => {
                return Err(format!(
                    "{} is not implemented by Noxmap yet; it is never silently substituted with another scan type",
                    tokens[index]
                ));
            }
            value if value.starts_with('-') => {
                return Err(format!("unsupported compatibility option: {value}"));
            }
            value => {
                if target.replace(value.to_string()).is_some() {
                    return Err(
                        "exactly one target is supported per compatibility invocation".into(),
                    );
                }
            }
        }
        index += 1;
    }
    let target = target.ok_or("a target is required")?;
    let snapshot = Scanner::new(policy).scan(&target, &options)?;
    let rendered = if output.as_ref().is_some_and(|(_, xml)| *xml) {
        report::xml(&snapshot)
    } else {
        report::normal(&snapshot)
    };
    if let Some((path, _)) = output {
        std::fs::write(&path, rendered)
            .map_err(|error| format!("could not write report: {error}"))?;
    } else {
        print!("{rendered}");
    }
    Ok(())
}

fn scan_arguments(
    arguments: impl Iterator<Item = String>,
) -> Result<(ScanOptions, ScanPolicy, String, bool, u64), String> {
    let mut options = ScanOptions::default();
    let mut policy = ScanPolicy::default();
    let mut state_dir = ".noxmap".into();
    let mut json = false;
    let mut interval = 60;
    let mut args = arguments;
    while let Some(flag) = args.next() {
        match flag.as_str() {
            "--ports" => {
                options.ports = parse_ports(&args.next().ok_or("--ports requires a value")?)?;
            }
            "--timeout-ms" => {
                options.timeout = Duration::from_millis(
                    args.next()
                        .ok_or("--timeout-ms requires a value")?
                        .parse()
                        .map_err(|_| "timeout must be a number")?,
                );
            }
            "--concurrency" => {
                options.concurrency = args
                    .next()
                    .ok_or("--concurrency requires a value")?
                    .parse()
                    .map_err(|_| "concurrency must be a number")?;
            }
            "--interval-secs" => {
                interval = args
                    .next()
                    .ok_or("--interval-secs requires a value")?
                    .parse()
                    .map_err(|_| "interval must be a number")?;
            }
            "--state-dir" => state_dir = args.next().ok_or("--state-dir requires a value")?,
            "--allow-public" => policy.allow_public = true,
            "--json" => json = true,
            _ => return Err(format!("unknown option: {flag}")),
        }
    }
    Ok((options, policy, state_dir, json, interval))
}

fn scan_or_watch(
    command: &str,
    target: &str,
    options: &ScanOptions,
    policy: ScanPolicy,
    state_dir: String,
    json: bool,
    interval: u64,
) -> Result<(), String> {
    let scanner = Scanner::new(policy);
    let store = SnapshotStore::open(state_dir)?;
    loop {
        let previous = store.latest(target)?;
        let result = scanner.scan(target, options)?;
        if json {
            println!("{}", to_json(&result));
        } else {
            print_human(&result);
        }
        if let Some(before) = &previous {
            for change in diff(before, &result) {
                println!("change: port {} {:?}", change.port, change.kind);
            }
        }
        store.append(&result)?;
        if command == "scan" {
            return Ok(());
        }
        thread::sleep(Duration::from_secs(interval));
    }
}

fn print_help() {
    println!(
        "Noxmap — local-first network inventory\n\nUSAGE:\n  noxmap scan <target> [scan options]\n  noxmap watch <target> [scan options] [--interval-secs 60]\n  noxmap fingerprint <target> [scan options]\n  noxmap topology <target>\n  noxmap script <file.nox> <target> [scan options]\n  noxmap api [loopback-port]\n\nSCAN OPTIONS: --ports 22,80,443 --timeout-ms 800 --concurrency 32 --state-dir .noxmap --json --allow-public"
    );
}
fn print_human(snapshot: &noxmap::ScanSnapshot) {
    println!(
        "{} ({})",
        snapshot.target,
        snapshot
            .resolved_address
            .map_or_else(|| "unresolved".into(), |address| address.ip().to_string())
    );
    for port in &snapshot.ports {
        if port.state == PortState::Open {
            let service = port
                .service
                .as_ref()
                .map_or("unknown", |item| item.name.as_str());
            println!(
                "  {}/tcp open  {}  {} ms",
                port.port,
                service,
                port.latency_ms.unwrap_or_default()
            );
        }
    }
}
fn to_json(snapshot: &noxmap::ScanSnapshot) -> String {
    let ports = snapshot
        .ports
        .iter()
        .map(|port| {
            let state = match port.state {
                PortState::Open => "open",
                PortState::Closed => "closed",
                PortState::Filtered => "filtered",
                PortState::Unreachable => "unreachable",
                PortState::Unresolved => "unresolved",
            };
            format!("{{\"port\":{},\"state\":\"{}\"}}", port.port, state)
        })
        .collect::<Vec<_>>()
        .join(",");
    format!(
        "{{\"target\":\"{}\",\"scanned_at_unix_ms\":{},\"ports\":[{}]}}",
        snapshot.target.replace('"', ""),
        snapshot.scanned_at_unix_ms,
        ports
    )
}

