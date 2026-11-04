//! Optional ClamAV check. Disabled unless `--clamav` is passed.

use crate::checks::{targets, Check};
use crate::clamav::ClamAv;
use crate::ctx::ScanContext;
use crate::model::{Confidence, Finding, Severity};
use anyhow::Result;
use std::time::Duration;

const SCAN_TIMEOUT: Duration = Duration::from_secs(120);
const MAX_FINDINGS: usize = 1_000;

pub struct ClamavCheck;

impl Check for ClamavCheck {
    fn id(&self) -> &'static str {
        "clamav.scan"
    }
    fn title(&self) -> &'static str {
        "ClamAV known-malware scan"
    }
    fn description(&self) -> &'static str {
        "Optional ClamAV subprocess scanning the same high-value targets."
    }

    fn skip_reason(&self, ctx: &ScanContext) -> Option<String> {
        if !ctx.cfg.clamav {
            Some("ClamAV backend disabled (pass --clamav)".into())
        } else if ClamAv::discover().is_none() {
            Some("clamscan not found in PATH".into())
        } else {
            None
        }
    }

    fn run(&self, ctx: &ScanContext) -> Result<Vec<Finding>> {
        let av = ClamAv::discover().ok_or_else(|| anyhow::anyhow!("clamscan not found in PATH"))?;
        let files = targets::high_value_targets(ctx);
        let scan = av.scan(&files, ctx.cfg.clamav_db.as_deref(), SCAN_TIMEOUT)?;

        if scan.exit_code.is_some_and(|c| c > 1) && scan.hits.is_empty() {
            anyhow::bail!(
                "clamscan exited with code {}; verify the signature database (freshclam) and --clamav-db",
                scan.exit_code.unwrap_or(-1)
            );
        }

        let mut findings = Vec::new();
        let total = scan.hits.len();
        for hit in scan.hits.iter().take(MAX_FINDINGS) {
            findings.push(
                Finding::new(
                    self.id(),
                    Severity::High,
                    format!("ClamAV detected {}", hit.signature),
                    "The file matches a known-malware signature in the local ClamAV database",
                )
                .at(ctx.disp(&hit.path), None)
                .evidence(format!("signature={}", hit.signature))
                .fix("Quarantine the file, preserve the sample, and verify its origin")
                .confidence(Confidence::Certain)
                .mitre("T1204.002"),
            );
        }
        if total > MAX_FINDINGS {
            findings.push(
                Finding::new(
                    self.id(),
                    Severity::Info,
                    "ClamAV results truncated",
                    format!("{total} hits; only the first {MAX_FINDINGS} are reported"),
                )
                .confidence(Confidence::Certain),
            );
        }

        let age = av.db_age_days();
        findings.push(
            Finding::new(
                self.id(),
                Severity::Info,
                "ClamAV backend active",
                format!(
                    "{}; database age {}; {} target file(s); exit={:?}",
                    av.version(),
                    age.map(|d| format!("{d} day(s)"))
                        .unwrap_or_else(|| "unknown".into()),
                    scan.targets,
                    scan.exit_code
                ),
            )
            .confidence(Confidence::Certain),
        );

        if ctx.cfg.clamav_max_db_age_days > 0 {
            match age {
                Some(days) if days > ctx.cfg.clamav_max_db_age_days => findings.push(
                    Finding::new(
                        self.id(),
                        Severity::Medium,
                        "ClamAV signature database is stale",
                        format!(
                            "database is {days} days old (limit {} days); known malware may be missed",
                            ctx.cfg.clamav_max_db_age_days
                        ),
                    )
                    .at("/var/lib/clamav", None)
                    .evidence(av.version())
                    .fix("Run freshclam (or the distribution's ClamAV update service)")
                    .confidence(Confidence::Certain)
                    .mitre("T1562.001"),
                ),
                Some(_) => {}
                None => findings.push(
                    Finding::new(
                        self.id(),
                        Severity::Info,
                        "Cannot determine ClamAV database age",
                        "The version string did not contain a parseable database date",
                    )
                    .evidence(av.version())
                    .confidence(Confidence::Certain),
                ),
            }
        }

        if scan.timed_out {
            findings.push(
                Finding::new(
                    self.id(),
                    Severity::Low,
                    "ClamAV scan timed out",
                    "Results are incomplete; increase the time budget or scan fewer files",
                )
                .confidence(Confidence::Certain),
            );
        }

        Ok(findings)
    }
}
