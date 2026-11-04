//! udev rule checks.
//!
//! udev `RUN+=`/`PROGRAM=` execute commands on device events and are a known
//! persistence trigger. Rules are only reported when the command itself looks
//! suspicious, plus when a rule file is writable by non-root.

use crate::checks::{combined_finding, Check};
use crate::ctx::ScanContext;
use crate::heuristics::{command_signals, path_signals};
use crate::model::{Confidence, Finding, Severity};
use crate::util;
use anyhow::Result;

const MAX_CONFIG: u64 = 2 * util::MB;
const DIRS: &[&str] = &[
    "/etc/udev/rules.d",
    "/run/udev/rules.d",
    "/usr/lib/udev/rules.d",
    "/lib/udev/rules.d",
];

pub struct UdevCheck;

impl Check for UdevCheck {
    fn id(&self) -> &'static str {
        "persist.udev"
    }
    fn title(&self) -> &'static str {
        "udev rule execution"
    }
    fn description(&self) -> &'static str {
        "udev rules executing commands via RUN+=/PROGRAM=, plus writable rule files."
    }

    fn run(&self, ctx: &ScanContext) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        for dir in DIRS {
            for file in util::files_in(&ctx.abs(dir)) {
                let logical = ctx.disp(&file);
                if let Some(mode) = util::mode_of(&file) {
                    if util::is_world_writable(mode) {
                        findings.push(
                            Finding::new(
                                self.id(),
                                Severity::High,
                                "udev rule file is world-writable",
                                "Any user can add a device-triggered command",
                            )
                            .at(&logical, None)
                            .fix("chmod o-w and verify the rule contents")
                            .confidence(Confidence::Certain)
                            .mitre("T1546"),
                        );
                    }
                }

                for (line_no, text) in util::read_lines(&file, MAX_CONFIG) {
                    let t = text.trim();
                    if t.is_empty() || t.starts_with('#') {
                        continue;
                    }
                    let cmd = match extract_command(t) {
                        Some(c) => c,
                        None => continue,
                    };
                    let mut hits = command_signals(&cmd);
                    for token in cmd.split_whitespace() {
                        let path = token.trim_matches(|c| matches!(c, '"' | '\'' | ';' | ','));
                        if path.starts_with('/') {
                            hits.extend(path_signals(path));
                        }
                    }
                    if let Some(f) = combined_finding(
                        self.id(),
                        "udev rule runs a suspicious command",
                        &logical,
                        Some(line_no),
                        &format!("RUN/PROGRAM: {cmd}"),
                        &hits,
                        "T1546",
                    ) {
                        findings.push(f);
                    }
                }
            }
        }
        Ok(findings)
    }
}

/// Extract the quoted value of `RUN+=`, `RUN{...}+=`, or `PROGRAM=`.
fn extract_command(line: &str) -> Option<String> {
    for key in ["RUN+=", "PROGRAM="] {
        if let Some(pos) = line.find(key) {
            return quoted(&line[pos + key.len()..]);
        }
    }
    if let Some(pos) = line.find("RUN{") {
        if let Some(eq) = line[pos..].find("}+=") {
            return quoted(&line[pos + eq + 3..]);
        }
    }
    None
}

fn quoted(s: &str) -> Option<String> {
    let start = s.find('"')?;
    let rest = &s[start + 1..];
    let end = rest.find('"')?;
    Some(rest[..end].to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_run_forms() {
        assert_eq!(
            extract_command(r#"ACTION=="add", RUN+="/bin/sh -c 'id'""#).as_deref(),
            Some("/bin/sh -c 'id'")
        );
        assert_eq!(
            extract_command(r#"RUN{program}+="/tmp/x""#).as_deref(),
            Some("/tmp/x")
        );
        assert_eq!(
            extract_command(r#"PROGRAM=="/usr/bin/test""#).as_deref(),
            Some("/usr/bin/test")
        );
        assert!(extract_command("SUBSYSTEM==\"usb\"").is_none());
    }
}
