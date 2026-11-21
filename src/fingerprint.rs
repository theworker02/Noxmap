#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FingerprintAvailability {
    Unavailable,
    Available,
}
#[derive(Debug, Clone)]
pub struct OsEvidence {
    pub source: String,
    pub observation: String,
    pub confidence_percent: u8,
}
#[derive(Debug, Clone)]
pub struct OsFingerprint {
    pub availability: FingerprintAvailability,
    pub guess: Option<String>,
    pub evidence: Vec<OsEvidence>,
}

pub trait OsFingerprintProvider: Send + Sync {
    /// Collects non-invasive fingerprint evidence for a target.
    ///
    /// # Errors
    ///
    /// Returns an error when a provider cannot collect its required evidence.
    fn fingerprint(&self, target: &str) -> Result<OsFingerprint, String>;
}

pub struct UnavailableFingerprintProvider;
impl OsFingerprintProvider for UnavailableFingerprintProvider {
    fn fingerprint(&self, _target: &str) -> Result<OsFingerprint, String> {
        Ok(OsFingerprint {
            availability: FingerprintAvailability::Unavailable,
            guess: None,
            evidence: vec![],
        })
    }
}

/// A conservative classifier that only uses service evidence already collected
/// during a TCP inventory scan. It does not send OS-specific probe packets.
#[must_use]
pub fn infer_from_services(snapshot: &crate::scanner::ScanSnapshot) -> OsFingerprint {
    let mut evidence = Vec::new();
    for port in &snapshot.ports {
        let Some(service) = &port.service else {
            continue;
        };
        let banner = service.evidence.to_ascii_lowercase();
        if banner.contains("microsoft") || port.port == 445 || port.port == 3389 {
            evidence.push(OsEvidence {
                source: format!("tcp/{}", port.port),
                observation: service.evidence.clone(),
                confidence_percent: 35,
            });
            return OsFingerprint {
                availability: FingerprintAvailability::Available,
                guess: Some("Windows-family host (low confidence)".into()),
                evidence,
            };
        }
        if banner.contains("ubuntu") || banner.contains("debian") || banner.contains("openssh") {
            evidence.push(OsEvidence {
                source: format!("tcp/{}", port.port),
                observation: service.evidence.clone(),
                confidence_percent: 30,
            });
            return OsFingerprint {
                availability: FingerprintAvailability::Available,
                guess: Some("Unix-like host (low confidence)".into()),
                evidence,
            };
        }
    }
    OsFingerprint {
        availability: FingerprintAvailability::Unavailable,
        guess: None,
        evidence,
    }
}

