//! Data model: severities, findings, and reports.
//!
//! Design constraints:
//! - Every finding must be serializable (JSON / SARIF) and readable by humans.
//! - Severity expresses impact only; false-positive likelihood is expressed separately by `Confidence`.

use serde::{Deserialize, Serialize};
use std::fmt;

/// Severity. Declaration order is the sort order (Info lightest, Critical heaviest).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
            Severity::Critical => "critical",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Severity::Info => "Info",
            Severity::Low => "Low",
            Severity::Medium => "Medium",
            Severity::High => "High",
            Severity::Critical => "Critical",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "info" | "informational" | "i" => Some(Severity::Info),
            "low" | "l" => Some(Severity::Low),
            "medium" | "med" | "m" => Some(Severity::Medium),
            "high" | "h" => Some(Severity::High),
            "critical" | "crit" | "c" => Some(Severity::Critical),
            _ => None,
        }
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Confidence in a finding. Heuristics always produce some false positives, so label them honestly.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Confidence {
    /// String/path heuristics; requires human review
    Heuristic,
    /// Strongly supported by structured facts; usually true
    Likely,
    /// Factual (e.g. non-empty ld.so.preload, duplicate UID 0)
    Certain,
}

impl Confidence {
    pub fn label(self) -> &'static str {
        match self {
            Confidence::Heuristic => "Heuristic",
            Confidence::Likely => "Likely",
            Confidence::Certain => "Certain",
        }
    }
}

/// Operating system family targeted by a check.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Os {
    Linux,
    MacOs,
}

impl Os {
    pub fn as_str(self) -> &'static str {
        match self {
            Os::Linux => "linux",
            Os::MacOs => "macos",
        }
    }
}

impl fmt::Display for Os {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A single finding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    /// Check id, e.g. `persist.cron`
    pub check: String,
    pub severity: Severity,
    pub confidence: Confidence,
    pub title: String,
    pub message: String,
    /// Logical path (`--root` is stripped so baselines and image scans stay comparable)
    pub path: Option<String>,
    pub line: Option<usize>,
    /// Raw evidence that triggered the finding (command line, config line, hash, ...)
    pub evidence: Option<String>,
    pub remediation: Option<String>,
    /// MITRE ATT&CK technique ids
    pub mitre: Vec<String>,
}

impl Finding {
    pub fn new(
        check: &str,
        severity: Severity,
        title: impl Into<String>,
        message: impl Into<String>,
    ) -> Self {
        Finding {
            check: check.to_string(),
            severity,
            confidence: Confidence::Heuristic,
            title: title.into(),
            message: message.into(),
            path: None,
            line: None,
            evidence: None,
            remediation: None,
            mitre: Vec::new(),
        }
    }

    pub fn at(mut self, path: impl Into<String>, line: Option<usize>) -> Self {
        self.path = Some(path.into());
        self.line = line;
        self
    }

    pub fn evidence(mut self, e: impl Into<String>) -> Self {
        self.evidence = Some(e.into());
        self
    }

    pub fn fix(mut self, r: impl Into<String>) -> Self {
        self.remediation = Some(r.into());
        self
    }

    pub fn mitre(mut self, m: &str) -> Self {
        if !self.mitre.iter().any(|x| x == m) {
            self.mitre.push(m.to_string());
        }
        self
    }

    pub fn confidence(mut self, c: Confidence) -> Self {
        self.confidence = c;
        self
    }

    /// Stable fingerprint used for allowlist matching and de-duplication.
    pub fn fingerprint(&self) -> String {
        format!(
            "{}|{}|{}",
            self.check,
            self.path.as_deref().unwrap_or("-"),
            self.evidence.as_deref().unwrap_or("-")
        )
    }
}

/// One baseline entry. `key` must be stable (no timestamps or ephemeral paths).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotItem {
    pub key: String,
    /// cron / systemd / launchd / shell_rc / suid / listener
    pub kind: String,
    pub path: String,
    pub detail: String,
}

/// Coverage for one check: a scanner must report what it did not inspect and why.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckCoverage {
    pub id: String,
    pub title: String,
    /// What the check inspects (one sentence, from the check itself).
    #[serde(default)]
    pub description: String,
    /// Platforms the check applies to.
    #[serde(default)]
    pub platforms: Vec<Os>,
    /// ran / skipped / failed
    pub status: String,
    pub detail: Option<String>,
    pub findings: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostInfo {
    pub hostname: String,
    pub os: String,
    pub kernel: Option<String>,
    pub privileged: bool,
    pub root: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BaselineSummary {
    pub file: String,
    pub created_at: Option<String>,
    pub added: usize,
    pub removed: usize,
    pub total: usize,
}

/// Complete result of one scan.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Report {
    pub tool: String,
    pub version: String,
    pub host: HostInfo,
    pub started_at: String,
    pub duration_ms: u64,
    pub findings: Vec<Finding>,
    /// Findings suppressed by the allowlist
    pub suppressed: usize,
    /// Allowlist rules ignored because they expired
    pub allowlist_expired: usize,
    pub checks: Vec<CheckCoverage>,
    pub baseline: Option<BaselineSummary>,
    pub scanned_paths: Vec<String>,
}

impl Report {
    pub fn count(&self, sev: Severity) -> usize {
        self.findings.iter().filter(|f| f.severity == sev).count()
    }

    pub fn max_severity(&self) -> Option<Severity> {
        self.findings.iter().map(|f| f.severity).max()
    }
}
