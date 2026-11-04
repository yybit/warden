//! OSV supply-chain check. Opt-in (`--osv`) because it sends package names to
//! osv.dev and requires network access.

use crate::checks::Check;
use crate::ctx::ScanContext;
use crate::model::{Confidence, Finding, Os, Severity};
use crate::osv::{self, OsvConfig};
use anyhow::Result;
use std::collections::HashSet;

const MAX_FINDINGS: usize = 500;

pub struct OsvCheck;

impl Check for OsvCheck {
    fn id(&self) -> &'static str {
        "pkg.osv"
    }
    fn title(&self) -> &'static str {
        "OSV supply-chain vulnerabilities"
    }
    fn description(&self) -> &'static str {
        "OSV vulnerability lookup for installed packages (opt-in network query, cached)."
    }
    fn platforms(&self) -> &'static [Os] {
        &[Os::Linux]
    }

    fn skip_reason(&self, ctx: &ScanContext) -> Option<String> {
        if !ctx.cfg.osv {
            return Some("OSV checks disabled (pass --osv)".into());
        }
        if !ctx.is_local() {
            return Some("OSV checks only run on the live host".into());
        }
        if osv::detect_ecosystem().is_none() {
            return Some("no OSV ecosystem for this distribution".into());
        }
        None
    }

    fn run(&self, ctx: &ScanContext) -> Result<Vec<Finding>> {
        let ecosystem = osv::detect_ecosystem()
            .ok_or_else(|| anyhow::anyhow!("no OSV ecosystem for this distribution"))?;
        let packages = osv::installed_packages(ecosystem)?;
        if packages.is_empty() {
            return Ok(vec![Finding::new(
                self.id(),
                Severity::Info,
                "OSV found no installed packages",
                format!("ecosystem {ecosystem}; nothing to query"),
            )
            .confidence(Confidence::Certain)]);
        }

        let cfg = OsvConfig {
            base_url: ctx.cfg.osv_url.clone(),
            max_age_hours: ctx.cfg.osv_max_age_hours,
            ..Default::default()
        };
        let (hits, cached) = osv::query(&packages, &cfg)?;

        let mut findings = Vec::new();
        let mut seen = HashSet::new();
        for hit in hits.iter().take(MAX_FINDINGS) {
            let key = format!(
                "{}|{}|{}",
                hit.package.name, hit.package.version, hit.vuln.id
            );
            if !seen.insert(key) {
                continue;
            }
            let title = if hit.vuln.summary.is_empty() {
                format!(
                    "Vulnerable package: {} {}",
                    hit.package.name, hit.package.version
                )
            } else {
                format!(
                    "Vulnerable package: {} {} — {}",
                    hit.package.name, hit.package.version, hit.vuln.summary
                )
            };
            let message = if hit.vuln.details.is_empty() {
                hit.vuln.summary.clone()
            } else {
                hit.vuln.details.clone()
            };
            let mut f = Finding::new(self.id(), hit.vuln.severity, title, message)
                .evidence(format!(
                    "id={} ecosystem={} package={} version={} aliases={} fixed={}",
                    hit.vuln.id,
                    hit.package.ecosystem,
                    hit.package.name,
                    hit.package.version,
                    hit.vuln.aliases.join(","),
                    hit.vuln.fixed.join(",")
                ))
                .fix(if hit.vuln.fixed.is_empty() {
                    "Upgrade the package to a supported version and review the advisory".into()
                } else {
                    format!("Upgrade to {}", hit.vuln.fixed.join(" or "))
                })
                .confidence(Confidence::Likely)
                .mitre("T1195.001");
            if !hit.vuln.aliases.is_empty() {
                f.message = format!("{}\nAliases: {}", f.message, hit.vuln.aliases.join(", "));
            }
            findings.push(f);
        }

        findings.push(
            Finding::new(
                self.id(),
                Severity::Info,
                "OSV query completed",
                format!(
                    "{} package(s) in {}{}; {} finding(s)",
                    packages.len(),
                    ecosystem,
                    if cached { " (cache)" } else { "" },
                    findings.len()
                ),
            )
            .confidence(Confidence::Certain),
        );
        Ok(findings)
    }
}
