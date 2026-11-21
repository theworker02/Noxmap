/// Expands one IPv4 CIDR target into individual host addresses.
///
/// Noxmap deliberately bounds expansion so a mistyped prefix cannot trigger an
/// uncontrolled scan. Callers may raise the limit only with explicit policy.
///
/// # Errors
///
/// Returns an error for invalid IPv4 CIDR syntax or a range larger than `max_hosts`.
pub fn expand_cidr(input: &str, max_hosts: usize) -> Result<Vec<String>, String> {
    let Some((address, prefix)) = input.split_once('/') else {
        return Ok(vec![input.to_string()]);
    };
    let ip = address
        .parse::<std::net::Ipv4Addr>()
        .map_err(|_| "only IPv4 CIDR targets are currently supported")?;
    let prefix = prefix
        .parse::<u8>()
        .map_err(|_| "CIDR prefix must be a number")?;
    if prefix > 32 {
        return Err("CIDR prefix must be between 0 and 32".into());
    }
    let size = 1_u64 << (32 - prefix);
    if size > max_hosts as u64 {
        return Err(format!(
            "CIDR expands to {size} hosts, exceeding the Noxmap limit of {max_hosts}"
        ));
    }
    let base = u32::from(ip) & (!0_u32 << (32 - prefix));
    (0..size)
        .map(|offset| {
            let offset =
                u32::try_from(offset).map_err(|_| "CIDR range is too large for IPv4 expansion")?;
            Ok(std::net::Ipv4Addr::from(base + offset).to_string())
        })
        .collect()
}

/// Reads a newline-delimited inventory. Empty lines and `#` comments are ignored.
///
/// # Errors
///
/// Returns an error if the file cannot be read or its combined expansions exceed the limit.
pub fn targets_from_file(path: &std::path::Path, max_hosts: usize) -> Result<Vec<String>, String> {
    let source = std::fs::read_to_string(path)
        .map_err(|error| format!("could not read target list: {error}"))?;
    let mut targets = Vec::new();
    for item in source
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
    {
        let remaining = max_hosts
            .checked_sub(targets.len())
            .ok_or_else(|| format!("target list exceeds the Noxmap limit of {max_hosts}"))?;
        targets.extend(expand_cidr(item, remaining)?);
    }
    if targets.is_empty() {
        return Err("target list contains no usable targets".into());
    }
    Ok(targets)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn expands_small_cidr() {
        assert_eq!(
            expand_cidr("192.0.2.0/30", 4).unwrap(),
            vec!["192.0.2.0", "192.0.2.1", "192.0.2.2", "192.0.2.3"]
        );
    }
    #[test]
    fn bounds_large_cidr() {
        assert!(expand_cidr("192.0.2.0/24", 8).is_err());
    }
}

