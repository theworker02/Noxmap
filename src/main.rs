use noxmap::api::serve_loopback;
use noxmap::discovery::{HostStatus, discover};
use noxmap::fingerprint::infer_from_services;
use noxmap::monitoring::diff;
use noxmap::report;
use noxmap::scanner::{PortState, parse_ports, top_tcp_ports};
use noxmap::scripting::{parse_script, run_script};
use noxmap::storage::SnapshotStore;
use noxmap::targets::{apply_exclusions, exclusions_from_file, expand_cidr, targets_from_file};
use noxmap::topology::{SystemTopologyProvider, TopologyProvider};
use noxmap::{ScanOptions, ScanPolicy, Scanner};
use std::env;
use std::fmt::Write as _;
use std::thread;
use std::time::Duration;

#[derive(Clone, Copy, PartialEq, Eq)]
enum ReportFormat {
    Normal,
    Xml,
    Grepable,
    Json,
}

#[derive(Default)]
struct CompatConfig {
    target: Option<String>,
    inventory: Option<String>,
    options: ScanOptions,
    policy: ScanPolicy,
    output: Option<(String, ReportFormat)>,
    exclusions: Vec<String>,
    host_discovery: bool,
}

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
    execute_command(command, args.collect())
}

fn execute_command(command: String, command_args: Vec<String>) -> Result<(), String> {
    let mut args = command_args.into_iter();
    match command.as_str() {
        "scan" | "watch" => {
            let command_args = args.collect::<Vec<_>>();
            let (targets, scan_args) = command_targets(&command_args)?;
            if command == "watch" && targets.len() != 1 {
                return Err(
                    "watch accepts exactly one resolved target; run a separate watch per host"
                        .into(),
                );
            }
            let (options, policy, state_dir, json, interval) =
                scan_arguments(scan_args.into_iter())?;
            for target in targets {
                scan_or_watch(
                    &command,
                    &target,
                    &options,
                    policy,
                    state_dir.clone(),
                    json,
                    interval,
                )?;
            }
            Ok(())
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
        "diff" => handle_diff(args),
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

fn handle_diff(arguments: impl Iterator<Item = String>) -> Result<(), String> {
    let mut arguments = arguments;
    let target = arguments.next().ok_or("a target is required")?;
    let state_dir = diff_arguments(arguments)?;
    let history = SnapshotStore::open(state_dir)?.history(&target)?;
    if history.len() < 2 {
        return Err("diff requires at least two saved snapshots for the target".into());
    }
    let previous = &history[history.len() - 2];
    let current = &history[history.len() - 1];
    let changes = diff(previous, current);
    if changes.is_empty() {
        println!("no port changes between the two latest snapshots for {target}");
    } else {
        println!("Noxmap snapshot diff for {target}");
        for change in changes {
            println!("  {}/tcp {:?}", change.port, change.kind);
        }
    }
    Ok(())
}

fn diff_arguments(arguments: impl Iterator<Item = String>) -> Result<String, String> {
    let mut state_dir = ".noxmap".to_string();
    let mut arguments = arguments;
    while let Some(flag) = arguments.next() {
        match flag.as_str() {
            "--state-dir" => state_dir = arguments.next().ok_or("--state-dir requires a value")?,
            _ => return Err(format!("unknown diff option: {flag}")),
        }
    }
    Ok(state_dir)
}

/// Splits scan options from one target, a bounded IPv4 CIDR, or a Nmap-style
/// newline-delimited inventory supplied by `-iL`.
fn command_targets(tokens: &[String]) -> Result<(Vec<String>, Vec<String>), String> {
    let mut positional = Vec::new();
    let mut list_file = None;
    let mut exclusions = Vec::new();
    let mut scan_args = Vec::new();
    let mut index = 0;
    while index < tokens.len() {
        match tokens[index].as_str() {
            "-iL" | "--input-list" => {
                index += 1;
                let path = tokens.get(index).ok_or("-iL requires a file path")?;
                if list_file.replace(path.clone()).is_some() {
                    return Err("only one -iL inventory is supported per invocation".into());
                }
            }
            "--exclude" => {
                index += 1;
                exclusions.push(
                    tokens
                        .get(index)
                        .ok_or("--exclude requires an expression")?
                        .clone(),
                );
            }
            "--excludefile" => {
                index += 1;
                exclusions.extend(exclusions_from_file(std::path::Path::new(
                    tokens
                        .get(index)
                        .ok_or("--excludefile requires a file path")?,
                ))?);
            }
            "--ports" | "--top-ports" | "--timeout-ms" | "--concurrency" | "--interval-secs"
            | "--state-dir" => {
                scan_args.push(tokens[index].clone());
                index += 1;
                scan_args.push(
                    tokens
                        .get(index)
                        .ok_or("scan option requires a value")?
                        .clone(),
                );
            }
            value if value.starts_with('-') => scan_args.push(value.to_string()),
            value => positional.push(value.to_string()),
        }
        index += 1;
    }
    if list_file.is_some() && !positional.is_empty() {
        return Err("provide either a target or -iL inventory, not both".into());
    }
    if positional.len() > 1 {
        return Err(
            "exactly one target is supported; put multiple targets in an -iL inventory".into(),
        );
    }
    let targets = if let Some(path) = list_file {
        targets_from_file(std::path::Path::new(&path), 256)?
    } else {
        let target = positional
            .into_iter()
            .next()
            .ok_or("a target or -iL inventory is required")?;
        expand_cidr(&target, 256)?
    };
    Ok((apply_exclusions(targets, &exclusions)?, scan_args))
}

fn compat_scan(first: String, rest: Vec<String>) -> Result<(), String> {
    let mut tokens = vec![first];
    tokens.extend(rest);
    let config = parse_compat_config(&tokens)?;
    let targets = compat_targets(&config)?;
    let rendered = if config.host_discovery {
        render_discovery_reports(&config, &targets)?
    } else {
        render_compat_reports(&config, &targets)?
    };
    if let Some((path, _)) = config.output {
        std::fs::write(&path, rendered)
            .map_err(|error| format!("could not write report: {error}"))?;
    } else {
        print!("{rendered}");
    }
    Ok(())
}

fn parse_compat_config(tokens: &[String]) -> Result<CompatConfig, String> {
    let mut config = CompatConfig::default();
    config.options.identify_services = false;
    let mut index = 0;
    while index < tokens.len() {
        match tokens[index].as_str() {
            "-sT" | "--connect" => {}
            "-sn" | "--host-discovery" => config.host_discovery = true,
            "-sV" | "--service-version" => config.options.identify_services = true,
            "-F" | "--fast" => config.options.ports = top_tcp_ports(100)?,
            "--top-ports" => {
                index += 1;
                let count = tokens
                    .get(index)
                    .ok_or("--top-ports requires a count")?
                    .parse()
                    .map_err(|_| "--top-ports must be a number")?;
                config.options.ports = top_tcp_ports(count)?;
            }
            "-p" | "--ports" => {
                index += 1;
                config.options.ports =
                    parse_ports(tokens.get(index).ok_or("-p requires a value")?)?;
            }
            "-oN" => {
                index += 1;
                config.output = Some((
                    tokens.get(index).ok_or("-oN requires a file path")?.clone(),
                    ReportFormat::Normal,
                ));
            }
            "-oX" => {
                index += 1;
                config.output = Some((
                    tokens.get(index).ok_or("-oX requires a file path")?.clone(),
                    ReportFormat::Xml,
                ));
            }
            "-oG" => {
                index += 1;
                config.output = Some((
                    tokens.get(index).ok_or("-oG requires a file path")?.clone(),
                    ReportFormat::Grepable,
                ));
            }
            "-oJ" => {
                index += 1;
                config.output = Some((
                    tokens.get(index).ok_or("-oJ requires a file path")?.clone(),
                    ReportFormat::Json,
                ));
            }
            "-iL" => {
                index += 1;
                config.inventory =
                    Some(tokens.get(index).ok_or("-iL requires a file path")?.clone());
            }
            "--exclude" => {
                index += 1;
                config.exclusions.push(
                    tokens
                        .get(index)
                        .ok_or("--exclude requires an expression")?
                        .clone(),
                );
            }
            "--excludefile" => {
                index += 1;
                config
                    .exclusions
                    .extend(exclusions_from_file(std::path::Path::new(
                        tokens
                            .get(index)
                            .ok_or("--excludefile requires a file path")?,
                    ))?);
            }
            "--allow-public" => config.policy.allow_public = true,
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
                if config.target.replace(value.to_string()).is_some() {
                    return Err(
                        "exactly one target is supported per compatibility invocation".into(),
                    );
                }
            }
        }
        index += 1;
    }
    Ok(config)
}

fn compat_targets(config: &CompatConfig) -> Result<Vec<String>, String> {
    if config.inventory.is_some() && config.target.is_some() {
        return Err("provide either a target or -iL inventory, not both".into());
    }
    let targets = if let Some(path) = &config.inventory {
        targets_from_file(std::path::Path::new(&path), 256)?
    } else {
        expand_cidr(config.target.as_deref().ok_or("a target is required")?, 256)?
    };
    let targets = apply_exclusions(targets, &config.exclusions)?;
    if config
        .output
        .as_ref()
        .is_some_and(|(_, format)| *format == ReportFormat::Xml)
        && targets.len() != 1
    {
        return Err("-oX currently accepts exactly one resolved target".into());
    }
    Ok(targets)
}

fn render_compat_reports(config: &CompatConfig, targets: &[String]) -> Result<String, String> {
    if config
        .output
        .as_ref()
        .is_some_and(|(_, format)| *format == ReportFormat::Json)
    {
        let snapshots = targets
            .iter()
            .map(|target| Scanner::new(config.policy).scan(target, &config.options))
            .collect::<Result<Vec<_>, _>>()?;
        return Ok(format!(
            "[{}]\n",
            snapshots
                .iter()
                .map(report::json)
                .collect::<Vec<_>>()
                .join(",")
        ));
    }
    let mut rendered = String::new();
    for target in targets {
        let snapshot = Scanner::new(config.policy).scan(target, &config.options)?;
        let report = match config.output.as_ref().map(|(_, format)| format) {
            Some(ReportFormat::Xml) => report::xml(&snapshot),
            Some(ReportFormat::Grepable) => report::grepable(&snapshot),
            Some(ReportFormat::Json) => unreachable!("JSON reports return above"),
            _ => report::normal(&snapshot),
        };
        rendered.push_str(&report);
    }
    Ok(rendered)
}

fn render_discovery_reports(config: &CompatConfig, targets: &[String]) -> Result<String, String> {
    if config
        .output
        .as_ref()
        .is_some_and(|(_, format)| *format == ReportFormat::Xml)
    {
        return Err("-oX is not available for -sn yet; use -oN or -oG".into());
    }
    let scanner = Scanner::new(config.policy);
    let mut rendered = String::new();
    for target in targets {
        let result = discover(&scanner, target, config.options.ports.clone())?;
        let status = match result.status {
            HostStatus::Responsive => "up",
            HostStatus::NoResponse => "no-response",
            HostStatus::Unknown => "unknown",
        };
        if config
            .output
            .as_ref()
            .is_some_and(|(_, format)| *format == ReportFormat::Grepable)
        {
            let _ = writeln!(
                rendered,
                "Host: {}\tStatus: {status}\tEvidence: {}",
                result.target, result.evidence
            );
        } else {
            let _ = writeln!(
                rendered,
                "Noxmap host discovery for {}: {status} ({})",
                result.target, result.evidence
            );
        }
    }
    Ok(rendered)
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
            "--top-ports" => {
                let count = args
                    .next()
                    .ok_or("--top-ports requires a count")?
                    .parse()
                    .map_err(|_| "--top-ports must be a number")?;
                options.ports = top_tcp_ports(count)?;
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
            println!("{}", report::json(&result));
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
        "Noxmap — local-first network inventory\n\nUSAGE:\n  noxmap scan <target|ipv4-cidr> [scan options]\n  noxmap scan -iL <inventory.txt> [scan options]\n  noxmap watch <target> [scan options] [--interval-secs 60]\n  noxmap diff <target> [--state-dir .noxmap]\n  noxmap fingerprint <target> [scan options]\n  noxmap topology <target>\n  noxmap script <file.nox> <target> [scan options]\n  noxmap api [loopback-port]\n  noxmap -sT <target> [-p <ports>] [-oN|-oX|-oG|-oJ <file>]\n\nSCAN OPTIONS: --ports 22,80,443 --timeout-ms 800 --concurrency 32 --state-dir .noxmap --json --allow-public\nTARGET INPUT: IPv4 CIDR and -iL inventories are bounded to 256 targets. Use --exclude <host-or-cidr> or --excludefile <path> to remove authorized inventory entries."
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
#[cfg(test)]
mod tests {
    use super::{command_targets, parse_compat_config};

    #[test]
    fn accepts_bounded_cidr_as_a_scan_target() {
        let arguments = vec!["192.0.2.0/30".into(), "--ports".into(), "80,443".into()];
        let (targets, options) = command_targets(&arguments).expect("CIDR target should parse");
        assert_eq!(targets.len(), 4);
        assert_eq!(options, vec!["--ports", "80,443"]);
    }

    #[test]
    fn reads_nmap_style_input_list_without_mixing_targets() {
        let path = std::env::temp_dir().join(format!(
            "noxmap-input-{}-{}.txt",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("system clock should be after Unix epoch")
                .as_nanos()
        ));
        std::fs::write(&path, "# authorized inventory\n192.0.2.10\n192.0.2.12\n")
            .expect("test inventory should be writable");
        let input = path.to_string_lossy().into_owned();
        let arguments = vec!["-iL".into(), input];
        let result = command_targets(&arguments);
        let _ = std::fs::remove_file(&path);
        assert_eq!(
            result.expect("inventory should parse").0,
            vec!["192.0.2.10", "192.0.2.12"]
        );
    }

    #[test]
    fn compatibility_version_detection_is_explicit_and_fast_profile_is_bounded() {
        let plain = parse_compat_config(&["-sT".into(), "127.0.0.1".into()])
            .expect("TCP connect command should parse");
        assert!(!plain.options.identify_services);

        let versioned =
            parse_compat_config(&["-sT".into(), "-sV".into(), "-F".into(), "127.0.0.1".into()])
                .expect("versioned fast command should parse");
        assert!(versioned.options.identify_services);
        assert_eq!(versioned.options.ports.len(), 100);
    }

    #[test]
    fn compatibility_host_discovery_is_explicit() {
        let config = parse_compat_config(&[
            "-sn".into(),
            "-oG".into(),
            "discovery.grep".into(),
            "127.0.0.1".into(),
        ])
        .expect("host-discovery command should parse");
        assert!(config.host_discovery);
        assert_eq!(
            config.output.expect("output should be present").0,
            "discovery.grep"
        );
    }
}

