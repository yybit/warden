//! YARA rule scanning over high-value files.
//!
//! Target selection is shared with the ClamAV backend (`checks::targets`).

use crate::checks::{targets, Check};
use crate::ctx::ScanContext;
use crate::model::{Confidence, Finding, Severity};
use crate::signatures::SignatureEngine;
use anyhow::Result;
use std::time::Duration;

const SCAN_TIMEOUT: Duration = Duration::from_secs(10);

pub struct YaraCheck;

impl Check for YaraCheck {
    fn id(&self) -> &'static str {
        "yara.rules"
    }
    fn title(&self) -> &'static str {
        "YARA rule matches"
    }
    fn description(&self) -> &'static str {
        "YARA-X rule matches over persistence configs, temp dirs, web roots, and --path roots."
    }

    fn skip_reason(&self, ctx: &ScanContext) -> Option<String> {
        if ctx.cfg.yara.is_empty() {
            Some("no --yara rule file or directory provided".into())
        } else {
            None
        }
    }

    fn run(&self, ctx: &ScanContext) -> Result<Vec<Finding>> {
        let engine = SignatureEngine::load(&ctx.cfg.yara)?;
        let files = targets::high_value_targets(ctx);
        let matched = engine.scan_paths(&files, ctx.cfg.max_file_size as usize, SCAN_TIMEOUT);

        let mut findings = Vec::new();
        for (host, matches) in matched {
            let logical = ctx.disp(&host);
            for m in matches {
                findings.push(engine.to_finding(&m, self.id(), &logical));
            }
        }

        // Rule-pack provenance is useful in JSON/verbose output but is not a risk.
        findings.push(
            Finding::new(
                self.id(),
                Severity::Info,
                "YARA rule pack loaded",
                format!(
                    "{} rule(s) from {} file(s); {} target file(s) scanned{}",
                    engine.rule_count,
                    engine.sources.len(),
                    files.len(),
                    if engine.cached {
                        " (compiled-rule cache)"
                    } else {
                        ""
                    }
                ),
            )
            .confidence(Confidence::Certain),
        );

        if !engine.warnings.is_empty() {
            let detail: String = engine.warnings.join("; ").chars().take(1200).collect();
            findings.push(
                Finding::new(
                    self.id(),
                    Severity::Info,
                    "Some YARA rules failed to compile",
                    detail,
                )
                .confidence(Confidence::Certain),
            );
        }

        Ok(findings)
    }
}
