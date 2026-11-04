//! Package-manager file integrity (dpkg / rpm / pacman).
//!
//! This is opt-in (`--verify-packages`): a full verification walks every
//! package-owned file and can take a while. Config files are skipped on
//! purpose; legitimate edits would otherwise drown the signal.

use crate::checks::Check;
use crate::ctx::ScanContext;
use crate::model::{Confidence, Finding, Severity};
use crate::util;
use anyhow::Result;
use std::path::Path;
use std::time::Duration;

const TIMEOUT: Duration = Duration::from_secs(120);
const MAX_FINDINGS: usize = 200;

#[derive(Debug, Clone, PartialEq, Eq)]
struct PkgIssue {
    path: String,
    status: String,
    missing: bool,
    package: Option<String>,
}

pub struct PackageIntegrityCheck;

impl Check for PackageIntegrityCheck {
    fn id(&self) -> &'static str {
        "pkg.integrity"
    }
    fn title(&self) -> &'static str {
        "Package file integrity"
    }
    fn description(&self) -> &'static str {
        "dpkg/rpm/pacman verification of package-owned files (opt-in)."
    }

    fn skip_reason(&self, ctx: &ScanContext) -> Option<String> {
        if !ctx.cfg.verify_packages {
            return Some("package verification disabled (pass --verify-packages)".into());
        }
        if !ctx.is_local() {
            return Some(
                "package verification only runs on the live host (not --root images)".into(),
            );
        }
        if manager().is_none() {
            return Some("no supported package manager (dpkg/rpm/pacman)".into());
        }
        None
    }

    fn run(&self, _ctx: &ScanContext) -> Result<Vec<Finding>> {
        let (name, args) = match manager() {
            Some(v) => v,
            None => return Ok(Vec::new()),
        };
        let out = match util::run_timeout(name, &args, TIMEOUT) {
            Some(o) => o,
            None => {
                return Ok(vec![Finding::new(
                    self.id(),
                    Severity::Info,
                    "Package verification timed out",
                    format!(
                        "`{name} {}` exceeded {} seconds",
                        args.join(" "),
                        TIMEOUT.as_secs()
                    ),
                )
                .confidence(Confidence::Certain)])
            }
        };

        let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
        let issues = match name {
            "dpkg" => parse_dpkg(&stdout),
            "rpm" => parse_rpm(&stdout),
            "pacman" => parse_pacman(&stdout),
            _ => Vec::new(),
        };

        if issues.is_empty() {
            let mut info = format!("`{name}` reported no modified package files");
            if !out.status.success() && !stderr.trim().is_empty() {
                info.push_str(&format!(
                    " (exit {:?}: {})",
                    out.status.code(),
                    stderr.trim()
                ));
            }
            return Ok(vec![Finding::new(
                self.id(),
                Severity::Info,
                "Package verification ran",
                info,
            )
            .confidence(Confidence::Certain)]);
        }

        let mut findings = Vec::new();
        for issue in issues.iter().take(MAX_FINDINGS) {
            let severity = severity_for(&issue.path);
            let title = if issue.missing {
                "Package-managed file is missing"
            } else if severity == Severity::High {
                "Package-managed binary/library was modified"
            } else {
                "Package-managed file was modified"
            };
            let mut f = Finding::new(
                self.id(),
                severity,
                title,
                "The file does not match the package manager's recorded checksums",
            )
            .at(&issue.path, None)
            .evidence(format!("manager={name} status={}", issue.status))
            .fix("Reinstall the package and investigate how the file was changed")
            .confidence(Confidence::Certain)
            .mitre("T1554");
            if let Some(pkg) = &issue.package {
                f.evidence = Some(format!(
                    "manager={name} package={pkg} status={}",
                    issue.status
                ));
            }
            findings.push(f);
        }

        if issues.len() > MAX_FINDINGS {
            findings.push(
                Finding::new(
                    self.id(),
                    Severity::Info,
                    "Package findings truncated",
                    format!(
                        "{} modified files; only the first {MAX_FINDINGS} are reported",
                        issues.len()
                    ),
                )
                .confidence(Confidence::Certain),
            );
        }
        Ok(findings)
    }
}

fn manager() -> Option<(&'static str, Vec<&'static str>)> {
    // Prefer the package database that actually exists: distro tooling is
    // sometimes installed alongside other managers.
    if Path::new("/var/lib/dpkg/status").exists() && util::command_exists("dpkg") {
        return Some(("dpkg", vec!["--verify"]));
    }
    if Path::new("/var/lib/rpm").exists() && util::command_exists("rpm") {
        return Some(("rpm", vec!["-Va"]));
    }
    if Path::new("/var/lib/pacman/local").exists() && util::command_exists("pacman") {
        return Some(("pacman", vec!["-Qkk"]));
    }
    if util::command_exists("dpkg") {
        return Some(("dpkg", vec!["--verify"]));
    }
    if util::command_exists("rpm") {
        return Some(("rpm", vec!["-Va"]));
    }
    if util::command_exists("pacman") {
        return Some(("pacman", vec!["-Qkk"]));
    }
    None
}

fn severity_for(path: &str) -> Severity {
    const BIN_PREFIXES: &[&str] = &[
        "/usr/bin/",
        "/usr/sbin/",
        "/bin/",
        "/sbin/",
        "/usr/lib/",
        "/usr/lib64/",
        "/lib/",
        "/lib64/",
        "/usr/libexec/",
    ];
    if BIN_PREFIXES.iter().any(|p| path.starts_with(p)) {
        Severity::High
    } else {
        Severity::Low
    }
}

fn skip_path(path: &str) -> bool {
    path.starts_with("/etc/")
        || path.starts_with("/usr/share/doc/")
        || path.starts_with("/usr/share/man/")
        || path.starts_with("/usr/share/locale/")
}

fn parse_dpkg(text: &str) -> Vec<PkgIssue> {
    let mut out = Vec::new();
    for line in text.lines() {
        let tokens: Vec<&str> = line.split_whitespace().collect();
        let path = match tokens.iter().find(|t| t.starts_with('/')) {
            Some(p) => *p,
            None => continue,
        };
        if skip_path(path) || tokens.contains(&"c") {
            continue;
        }
        let missing = tokens.contains(&"missing");
        let status = tokens
            .first()
            .copied()
            .unwrap_or(if missing { "missing" } else { "modified" })
            .to_string();
        out.push(PkgIssue {
            path: path.to_string(),
            status,
            missing,
            package: None,
        });
    }
    out
}

fn parse_rpm(text: &str) -> Vec<PkgIssue> {
    let mut out = Vec::new();
    for line in text.lines() {
        let tokens: Vec<&str> = line.split_whitespace().collect();
        let path = match tokens.iter().find(|t| t.starts_with('/')) {
            Some(p) => *p,
            None => continue,
        };
        if skip_path(path) || tokens.contains(&"c") {
            continue;
        }
        let missing = tokens.contains(&"missing");
        let status = tokens
            .first()
            .copied()
            .unwrap_or(if missing { "missing" } else { "modified" })
            .to_string();
        out.push(PkgIssue {
            path: path.to_string(),
            status,
            missing,
            package: None,
        });
    }
    out
}

fn parse_pacman(text: &str) -> Vec<PkgIssue> {
    let mut out = Vec::new();
    for line in text.lines() {
        if !line.contains("warning:") || line.contains("backup file") {
            continue;
        }
        let after = match line.split_once("warning: ") {
            Some((_, rest)) => rest,
            None => continue,
        };
        let (pkg, rest) = match after.split_once(": ") {
            Some(v) => v,
            None => continue,
        };
        let path = match rest.split_once(" (") {
            Some((p, _)) => p.trim(),
            None => continue,
        };
        if !path.starts_with('/') || skip_path(path) {
            continue;
        }
        let missing = rest.to_ascii_lowercase().contains("missing");
        out.push(PkgIssue {
            path: path.to_string(),
            status: if missing {
                "missing".into()
            } else {
                "modified".into()
            },
            missing,
            package: Some(pkg.to_string()),
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dpkg_skips_conffiles_and_flags_binaries() {
        let text = "\
??5??????   /usr/bin/foo
missing     /usr/bin/bar
??5?????? c /etc/ssh/sshd_config
??5??????   /usr/share/doc/x/readme
";
        let issues = parse_dpkg(text);
        assert_eq!(issues.len(), 2);
        assert!(issues.iter().any(|i| i.missing && i.path == "/usr/bin/bar"));
        assert_eq!(severity_for("/usr/bin/foo"), Severity::High);
    }

    #[test]
    fn rpm_and_pacman_parsing() {
        let rpm = "S.5....T.  c /etc/foo\nmissing     /usr/sbin/bar\n";
        let issues = parse_rpm(rpm);
        assert_eq!(issues.len(), 1);
        assert_eq!(issues[0].path, "/usr/sbin/bar");

        let pacman = "\
warning: coreutils: /usr/bin/ls (Checksum mismatch)
warning: bash: /etc/bash.bashrc (Configuration file, backup file: /etc/bash.bashrc)
";
        let issues = parse_pacman(pacman);
        assert_eq!(issues.len(), 1);
        assert_eq!(issues[0].path, "/usr/bin/ls");
        assert_eq!(issues[0].package.as_deref(), Some("coreutils"));
    }
}
