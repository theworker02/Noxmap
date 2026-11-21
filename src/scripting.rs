#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScriptCapability {
    ReadServiceBanner,
    MakeTcpConnection,
    StoreFinding,
}
#[derive(Debug, Clone)]
pub struct ScriptManifest {
    pub id: String,
    pub version: String,
    pub capabilities: Vec<ScriptCapability>,
}
impl ScriptManifest {
    /// Validates that a data-only script manifest is minimally complete.
    ///
    /// # Errors
    ///
    /// Returns an error when an identifier, version, or capability declaration is missing.
    pub fn validate(&self) -> Result<(), String> {
        if self.id.trim().is_empty() {
            return Err("script id is required".into());
        }
        if self.version.trim().is_empty() {
            return Err("script version is required".into());
        }
        if self.capabilities.is_empty() {
            return Err("script must declare at least one capability".into());
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScriptAction {
    RequireOpenPort(u16),
    RequireService(String),
    CaptureBanner(u16),
}
#[derive(Debug, Clone)]
pub struct Script {
    pub manifest: ScriptManifest,
    pub action: ScriptAction,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScriptFinding {
    pub script_id: String,
    pub passed: bool,
    pub message: String,
}

/// Parses a deliberately small, data-only `.nox` script format. Example:
/// `id=web-check\nversion=1\ncapabilities=MakeTcpConnection\naction=service:http`
/// Parses a data-only script manifest.
///
/// # Errors
///
/// Returns an error for missing fields, undeclared capabilities, or unsupported actions.
pub fn parse_script(input: &str) -> Result<Script, String> {
    let mut id = None;
    let mut version = None;
    let mut capabilities = Vec::new();
    let mut action = None;
    for line in input
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
    {
        let (key, value) = line
            .split_once('=')
            .ok_or_else(|| format!("invalid script line: {line}"))?;
        match key.trim() {
            "id" => id = Some(value.trim().to_string()),
            "version" => version = Some(value.trim().to_string()),
            "capabilities" => {
                for capability in value.split(',').map(str::trim) {
                    capabilities.push(match capability {
                        "ReadServiceBanner" => ScriptCapability::ReadServiceBanner,
                        "MakeTcpConnection" => ScriptCapability::MakeTcpConnection,
                        "StoreFinding" => ScriptCapability::StoreFinding,
                        _ => return Err(format!("unsupported capability: {capability}")),
                    });
                }
            }
            "action" => action = Some(parse_action(value.trim())?),
            _ => return Err(format!("unsupported script field: {key}")),
        }
    }
    let manifest = ScriptManifest {
        id: id.unwrap_or_default(),
        version: version.unwrap_or_default(),
        capabilities,
    };
    manifest.validate()?;
    Ok(Script {
        manifest,
        action: action.ok_or("script action is required")?,
    })
}

fn parse_action(value: &str) -> Result<ScriptAction, String> {
    let (kind, argument) = value.split_once(':').ok_or("action must use kind:value")?;
    match kind {
        "open-port" => Ok(ScriptAction::RequireOpenPort(
            argument
                .parse()
                .map_err(|_| "action port must be a number")?,
        )),
        "banner" => Ok(ScriptAction::CaptureBanner(
            argument
                .parse()
                .map_err(|_| "action port must be a number")?,
        )),
        "service" if !argument.is_empty() => Ok(ScriptAction::RequireService(argument.to_string())),
        _ => Err(format!("unsupported action: {value}")),
    }
}

#[must_use]
pub fn run_script(script: &Script, snapshot: &crate::scanner::ScanSnapshot) -> ScriptFinding {
    let open = |port: u16| {
        snapshot
            .ports
            .iter()
            .any(|item| item.port == port && item.state == crate::scanner::PortState::Open)
    };
    let (passed, message) = match &script.action {
        ScriptAction::RequireOpenPort(port) => (open(*port), format!("tcp/{port} must be open")),
        ScriptAction::CaptureBanner(port) => {
            let banner = snapshot
                .ports
                .iter()
                .find(|item| item.port == *port)
                .and_then(|item| item.service.as_ref())
                .map(|item| item.evidence.clone());
            (
                banner.is_some(),
                banner.map_or_else(
                    || format!("no banner on tcp/{port}"),
                    |value| format!("tcp/{port}: {value}"),
                ),
            )
        }
        ScriptAction::RequireService(name) => (
            snapshot.ports.iter().any(|item| {
                item.service
                    .as_ref()
                    .is_some_and(|service| service.name == *name)
            }),
            format!("service {name} must be identified"),
        ),
    };
    ScriptFinding {
        script_id: script.manifest.id.clone(),
        passed,
        message,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn parses_data_only_script() {
        let script = parse_script(
            "id=check\nversion=1\ncapabilities=MakeTcpConnection\naction=open-port:443",
        )
        .unwrap();
        assert_eq!(script.action, ScriptAction::RequireOpenPort(443));
    }
}

