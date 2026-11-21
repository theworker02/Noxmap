use std::net::IpAddr;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TargetScope {
    Loopback,
    Private,
    LinkLocal,
    Public,
    Hostname,
}

#[derive(Debug, Clone, Copy)]
pub struct ScanPolicy {
    pub allow_public: bool,
    pub max_ports: usize,
    pub max_concurrency: usize,
}

impl Default for ScanPolicy {
    fn default() -> Self {
        Self {
            allow_public: false,
            max_ports: 1_024,
            max_concurrency: 256,
        }
    }
}

impl ScanPolicy {
    /// Validates the request against Noxmap's bounded, consent-first policy.
    ///
    /// # Errors
    ///
    /// Returns an error for empty targets, invalid resource limits, or public targets
    /// that lack an explicit acknowledgement.
    pub fn validate(
        &self,
        target: &str,
        port_count: usize,
        concurrency: usize,
    ) -> Result<TargetScope, String> {
        if target.trim().is_empty() {
            return Err("target must not be empty".into());
        }
        if port_count == 0 {
            return Err("at least one port is required".into());
        }
        if port_count > self.max_ports {
            return Err(format!(
                "port count exceeds policy limit of {}",
                self.max_ports
            ));
        }
        if concurrency == 0 || concurrency > self.max_concurrency {
            return Err(format!(
                "concurrency must be between 1 and {}",
                self.max_concurrency
            ));
        }
        let scope = classify_target(target);
        if scope == TargetScope::Public && !self.allow_public {
            return Err("public targets require --allow-public and explicit authorization".into());
        }
        Ok(scope)
    }

    /// Enforces the public-target acknowledgement after hostname resolution.
    ///
    /// # Errors
    ///
    /// Returns an error when a resolved public address lacks explicit authorization.
    pub fn validate_resolved(&self, address: IpAddr) -> Result<TargetScope, String> {
        let scope = classify_ip(address);
        if scope == TargetScope::Public && !self.allow_public {
            return Err(
                "target resolves to a public address; use --allow-public only with authorization"
                    .into(),
            );
        }
        Ok(scope)
    }
}

#[must_use]
pub fn classify_target(target: &str) -> TargetScope {
    let Ok(ip) = target.parse::<IpAddr>() else {
        return TargetScope::Hostname;
    };
    classify_ip(ip)
}

#[must_use]
pub fn classify_ip(ip: IpAddr) -> TargetScope {
    match ip {
        IpAddr::V4(v4) if v4.is_loopback() => TargetScope::Loopback,
        IpAddr::V6(v6) if v6.is_loopback() => TargetScope::Loopback,
        IpAddr::V4(v4) if v4.is_private() => TargetScope::Private,
        IpAddr::V6(v6) if v6.is_unique_local() => TargetScope::Private,
        IpAddr::V4(v4) if v4.is_link_local() => TargetScope::LinkLocal,
        IpAddr::V6(v6) if v6.is_unicast_link_local() => TargetScope::LinkLocal,
        _ => TargetScope::Public,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn classifies_local_ranges() {
        assert_eq!(classify_target("127.0.0.1"), TargetScope::Loopback);
        assert_eq!(classify_target("192.168.1.5"), TargetScope::Private);
    }
    #[test]
    fn protects_public_targets() {
        assert!(ScanPolicy::default().validate("8.8.8.8", 1, 1).is_err());
    }
    #[test]
    fn protects_resolved_public_targets() {
        assert!(
            ScanPolicy::default()
                .validate_resolved("8.8.8.8".parse().unwrap())
                .is_err()
        );
    }
}

