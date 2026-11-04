//! Known-malicious package check backed by `ossf/malicious-packages`.

use crate::checks::Check;
use crate::ctx::ScanContext;
use crate::malicious::{self, Dataset};
use crate::model::{Confidence, Finding, Severity};
use anyhow::Result;
use std::collections::HashSet;

const MAX_FINDINGS: usize = 500;

pub struct MaliciousCheck;

impl Check for MaliciousCheck {
    fn id(&self) -> &'static str {
        "pkg.malicious"
    }
    fn title(&self) -> &'static str {
        "Known-malicious packages"
    }
    fn description(&self) -> &'static str {
        "Known-malicious npm/PyPI/crates.io packages from ossf/malicious-packages."
    }

    fn skip_reason(&self, ctx: &ScanContext) -> Option<String> {
        if ctx.cfg.malicious.is_none() {
            Some(
                "no --malicious dataset directory (clone ossf/malicious-packages to ~/.config/warden/malicious)"
                    .into(),
            )
        } else {
            None
        }
    }

    fn run(&self, ctx: &ScanContext) -> Result<Vec<Finding>> {
        let dir = ctx
            .cfg
            .malicious
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("no --malicious dataset directory"))?;
        let dataset = Dataset::load(dir)?;
        if dataset.is_empty() {
            return Ok(vec![Finding::new(
                self.id(),
                Severity::Info,
                "Malicious-package dataset is empty",
                format!("{} contains no usable OSV records", dir.display()),
            )
            .confidence(Confidence::Certain)]);
        }

        let roots: Vec<_> = ctx.cfg.paths.iter().map(|p| ctx.abs(p)).collect();
        let installed = malicious::installed_packages(&roots, ctx.is_local());

        let mut findings = Vec::new();
        let mut seen = HashSet::new();
        for pkg in &installed {
            let hit = match dataset.matches(pkg) {
                Some(h) => h,
                None => continue,
            };
            let key = format!("{}|{}|{}|{}", pkg.ecosystem, pkg.name, pkg.version, hit.id);
            if !seen.insert(key) {
                continue;
            }
            let title = if hit.summary.is_empty() {
                format!("Known-malicious package: {} {}", pkg.name, pkg.version)
            } else {
                format!(
                    "Known-malicious package: {} {} — {}",
                    pkg.name, pkg.version, hit.summary
                )
            };
            let mut f = Finding::new(
                self.id(),
                Severity::Critical,
                title,
                if hit.details.is_empty() {
                    "Package matches an entry in the malicious-packages dataset".to_string()
                } else {
                    hit.details.clone()
                },
            )
            .evidence(format!(
                "id={} ecosystem={} package={} version={} aliases={}",
                hit.id,
                pkg.ecosystem,
                pkg.name,
                pkg.version,
                hit.aliases.join(",")
            ))
            .fix("Uninstall the package, rotate credentials, and audit install scripts and lockfiles")
            .confidence(Confidence::Certain)
            .mitre("T1195.001");
            if !hit.aliases.is_empty() {
                f.message = format!("{}\nAliases: {}", f.message, hit.aliases.join(", "));
            }
            findings.push(f);
            if findings.len() >= MAX_FINDINGS {
                break;
            }
        }

        findings.push(
            Finding::new(
                self.id(),
                Severity::Info,
                "Malicious-package scan completed",
                format!(
                    "{} installed package(s) checked against {} record(s) from {} file(s); {} finding(s)",
                    installed.len(),
                    dataset.records,
                    dataset.files,
                    findings.len()
                ),
            )
            .confidence(Confidence::Certain),
        );
        Ok(findings)
    }
}
