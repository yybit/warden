//! PAM configuration integrity.
//!
//! PAM is a high-value persistence point: an injected module or a `pam_exec`
//! line runs code inside the authentication path. The check resolves module
//! paths against the common multiarch locations and flags modules outside
//! them, missing modules, and dangerous module options.

use crate::checks::Check;
use crate::ctx::ScanContext;
use crate::model::{Confidence, Finding, Severity};
use crate::util;
use anyhow::Result;
use std::path::Path;

const MAX_CONFIG: u64 = 2 * util::MB;
const MAX_FINDINGS: usize = 200;

/// Common PAM module directories across distributions and macOS.
const MODULE_DIRS: &[&str] = &[
    "/lib/security",
    "/lib64/security",
    "/usr/lib/security",
    "/usr/lib64/security",
    "/lib/x86_64-linux-gnu/security",
    "/usr/lib/x86_64-linux-gnu/security",
    "/lib/aarch64-linux-gnu/security",
    "/usr/lib/aarch64-linux-gnu/security",
    "/usr/lib/pam",
];

pub struct PamCheck;

impl Check for PamCheck {
    fn id(&self) -> &'static str {
        "persist.pam"
    }
    fn title(&self) -> &'static str {
        "PAM authentication modules"
    }
    fn description(&self) -> &'static str {
        "PAM modules and configuration: non-standard/missing modules, pam_exec/pam_python, nullok, writable files."
    }

    fn run(&self, ctx: &ScanContext) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        let mut files = util::files_in(&ctx.abs("/etc/pam.d"));
        let pam_conf = ctx.abs("/etc/pam.conf");
        if pam_conf.is_file() {
            files.push(pam_conf);
        }

        for file in files {
            let logical = ctx.disp(&file);
            if let Some(mode) = util::mode_of(&file) {
                if util::is_world_writable(mode) {
                    findings.push(
                        Finding::new(
                            self.id(),
                            Severity::High,
                            "PAM configuration is world-writable",
                            "Any user can rewrite the authentication stack",
                        )
                        .at(&logical, None)
                        .fix("chmod o-w and verify the file contents")
                        .confidence(Confidence::Certain)
                        .mitre("T1556.003"),
                    );
                }
            }

            for (line_no, text) in util::read_lines(&file, MAX_CONFIG) {
                let t = text.trim();
                if t.is_empty() || t.starts_with('#') || t.starts_with('@') {
                    continue;
                }
                let parts: Vec<&str> = t.split_whitespace().collect();
                if parts.len() < 2 {
                    continue;
                }
                let kind = parts[0].trim_start_matches('-');
                if !matches!(kind, "auth" | "account" | "password" | "session") {
                    continue;
                }
                // The control field may be `required` or a bracketed list such
                // as `[success=1 default=ignore]`, so locate the module token
                // instead of assuming a fixed index.
                let module_idx = match parts
                    .iter()
                    .enumerate()
                    .skip(1)
                    .find(|(_, tok)| tok.ends_with(".so") || tok.starts_with('/'))
                {
                    Some((i, _)) => i,
                    None => continue,
                };
                let module = parts[module_idx];
                let args = &parts[module_idx + 1..];

                if let Some((severity, title, mitre)) = line_risk(module, args) {
                    findings.push(
                        Finding::new(self.id(), severity, title, "PAM rule can execute code or weaken authentication")
                            .at(&logical, Some(line_no))
                            .evidence(t)
                            .fix("Remove the module or restore the distribution default for this service")
                            .confidence(Confidence::Likely)
                            .mitre(mitre),
                    );
                    continue;
                }

                if let Some((severity, title)) = module_issue(ctx, module) {
                    findings.push(
                        Finding::new(
                            self.id(),
                            severity,
                            title,
                            "PAM references a module that does not resolve to a standard location",
                        )
                        .at(&logical, Some(line_no))
                        .evidence(t)
                        .fix("Reinstall the PAM package or remove the custom module")
                        .confidence(Confidence::Likely)
                        .mitre("T1556.003"),
                    );
                }
            }
        }

        if findings.len() > MAX_FINDINGS {
            findings.truncate(MAX_FINDINGS);
            findings.push(
                Finding::new(
                    self.id(),
                    Severity::Info,
                    "PAM findings truncated",
                    format!("more than {MAX_FINDINGS} PAM findings; only the first {MAX_FINDINGS} are shown"),
                )
                .confidence(Confidence::Certain),
            );
        }
        Ok(findings)
    }
}

fn module_issue(ctx: &ScanContext, module: &str) -> Option<(Severity, &'static str)> {
    if module.starts_with('/') {
        let exists = ctx.abs(module).is_file();
        let standard = is_standard_absolute(module);
        return match (standard, exists) {
            (false, _) => Some((
                Severity::High,
                "PAM loads a module from a non-standard absolute path",
            )),
            (true, false) => Some((Severity::Medium, "PAM module file is missing")),
            (true, true) => None,
        };
    }

    let found = MODULE_DIRS
        .iter()
        .any(|dir| ctx.abs(Path::new(dir).join(module)).is_file());
    if found {
        None
    } else {
        Some((
            Severity::Medium,
            "PAM module not found in standard directories",
        ))
    }
}

fn is_standard_absolute(module: &str) -> bool {
    MODULE_DIRS.iter().any(|dir| {
        module
            .strip_prefix(dir)
            .map(|rest| rest.starts_with('/'))
            .unwrap_or(false)
    })
}

fn line_risk(module: &str, args: &[&str]) -> Option<(Severity, &'static str, &'static str)> {
    if module.ends_with("pam_python.so") {
        return Some((
            Severity::High,
            "PAM loads the Python bridge (pam_python)",
            "T1556.003",
        ));
    }
    if module.ends_with("pam_exec.so") {
        let joined = args.join(" ").to_ascii_lowercase();
        let suspicious = [
            "/tmp", "/dev/shm", "/var/tmp", "curl", "wget", "sh -c", "bash -c",
        ]
        .iter()
        .any(|needle| joined.contains(needle));
        if suspicious {
            return Some((
                Severity::High,
                "pam_exec runs a suspicious command",
                "T1556.003",
            ));
        }
    }
    if module.ends_with("pam_unix.so")
        && args
            .iter()
            .any(|arg| arg.to_ascii_lowercase().contains("nullok"))
    {
        return Some((
            Severity::Medium,
            "pam_unix allows empty passwords (nullok)",
            "T1078",
        ));
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flags_exec_and_python() {
        assert!(line_risk("pam_exec.so", &["/bin/sh", "-c", "curl x"]).is_some());
        assert!(line_risk("pam_exec.so", &["/usr/bin/true"]).is_none());
        assert!(line_risk("pam_python.so", &[]).is_some());
        assert!(line_risk("pam_unix.so", &["nullok"]).is_some());
        assert!(line_risk("pam_unix.so", &["try_first_pass"]).is_none());
    }

    #[test]
    fn absolute_module_dirs() {
        assert!(is_standard_absolute(
            "/lib/x86_64-linux-gnu/security/pam_unix.so"
        ));
        assert!(is_standard_absolute("/usr/lib/pam/pam_unix.so"));
        assert!(!is_standard_absolute("/tmp/pam_evil.so"));
        assert!(!is_standard_absolute("/lib/securityevil/x.so"));
    }
}
