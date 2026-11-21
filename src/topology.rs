#[derive(Debug, Clone)]
pub struct Hop {
    pub ttl: u8,
    pub address: Option<String>,
    pub latency_ms: Option<u128>,
}
#[derive(Debug, Clone)]
pub struct TopologyPath {
    pub target: String,
    pub hops: Vec<Hop>,
    pub collection_available: bool,
}
pub trait TopologyProvider: Send + Sync {
    /// Collects a path to the requested target.
    ///
    /// # Errors
    ///
    /// Returns an error when a provider cannot obtain the path.
    fn trace(&self, target: &str) -> Result<TopologyPath, String>;
}

/// A user-invoked platform command adapter. Targets are strictly constrained and
/// supplied as a separate process argument, never interpolated into a shell.
pub struct SystemTopologyProvider {
    pub max_hops: u8,
}

impl Default for SystemTopologyProvider {
    fn default() -> Self {
        Self { max_hops: 12 }
    }
}

impl TopologyProvider for SystemTopologyProvider {
    fn trace(&self, target: &str) -> Result<TopologyPath, String> {
        if target.is_empty()
            || !target.chars().all(|character| {
                character.is_ascii_alphanumeric() || matches!(character, '.' | '-' | ':')
            })
        {
            return Err("topology target contains unsupported characters".into());
        }
        let output = if cfg!(target_os = "windows") {
            std::process::Command::new("tracert")
                .args(["-d", "-h", &self.max_hops.to_string(), target])
                .output()
        } else {
            std::process::Command::new("traceroute")
                .args(["-n", "-m", &self.max_hops.to_string(), target])
                .output()
        }
        .map_err(|error| format!("could not start platform traceroute: {error}"))?;
        let text = String::from_utf8_lossy(&output.stdout);
        let hops = text.lines().filter_map(parse_hop).collect();
        Ok(TopologyPath {
            target: target.into(),
            hops,
            collection_available: output.status.success(),
        })
    }
}

fn parse_hop(line: &str) -> Option<Hop> {
    let mut parts = line.split_whitespace();
    let ttl = parts.next()?.parse::<u8>().ok()?;
    let address = parts
        .find(|value| value.parse::<std::net::IpAddr>().is_ok())
        .map(str::to_string);
    Some(Hop {
        ttl,
        address,
        latency_ms: None,
    })
}

