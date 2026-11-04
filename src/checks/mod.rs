//! Check registry and shared finding constructors.

pub mod at;
pub mod clamav;
pub mod containers;
pub mod files;
pub mod host;
pub mod mac;
pub mod malicious;
pub mod osv;
pub mod packages;
pub mod pam;
pub mod persistence;
pub mod ssh;
pub mod targets;
pub mod udev;
pub mod yara;

use crate::ctx::ScanContext;
use crate::heuristics::SignalHit;
use crate::model::{Confidence, Finding, Os};

/// A single check.
///
/// Contract:
/// - Read-only: no fixing or quarantine (automatic response needs human approval).
/// - Must tolerate missing paths (containers, minimal systems, cross-platform images).
/// - Unreadable paths are not findings; report them through coverage.
pub trait Check: Sync {
    fn id(&self) -> &'static str;
    fn title(&self) -> &'static str;
    /// One-sentence description of what the check inspects (shown in coverage/TUI).
    fn description(&self) -> &'static str {
        self.title()
    }
    fn platforms(&self) -> &'static [Os] {
        &[Os::Linux, Os::MacOs]
    }
    /// Why this check cannot run now (used for honest coverage reporting).
    fn skip_reason(&self, _ctx: &ScanContext) -> Option<String> {
        None
    }
    fn run(&self, ctx: &ScanContext) -> anyhow::Result<Vec<Finding>>;
}

pub fn registry() -> Vec<Box<dyn Check>> {
    vec![
        Box::new(persistence::CronCheck),
        Box::new(persistence::SystemdCheck),
        Box::new(persistence::ShellRcCheck),
        Box::new(pam::PamCheck),
        Box::new(udev::UdevCheck),
        Box::new(at::AtCheck),
        Box::new(containers::ContainerConfigCheck),
        Box::new(persistence::LoaderCheck),
        Box::new(ssh::SshCheck),
        Box::new(mac::LaunchdCheck),
        Box::new(mac::MacSignatureCheck),
        Box::new(files::SuidCheck),
        Box::new(files::WorldWritableCheck),
        Box::new(files::SuspiciousBinCheck),
        Box::new(files::WebshellCheck),
        Box::new(files::IocCheck),
        Box::new(host::AccountsCheck),
        Box::new(host::ListenersCheck),
        Box::new(host::HardeningCheck),
        Box::new(yara::YaraCheck),
        Box::new(clamav::ClamavCheck),
        Box::new(packages::PackageIntegrityCheck),
        Box::new(osv::OsvCheck),
        Box::new(malicious::MaliciousCheck),
    ]
}

/// Merge multiple signals at one location into a single finding:
/// One suspicious line often matches several patterns; reporting each makes the output unreadable.
pub fn combined_finding(
    check: &str,
    title: &str,
    path: &str,
    line: Option<usize>,
    detail: &str,
    hits: &[SignalHit],
    mitre: &'static str,
) -> Option<Finding> {
    let top = hits.iter().max_by(|a, b| a.severity.cmp(&b.severity))?;
    let descs: Vec<&str> = hits.iter().map(|h| h.desc).collect();
    let mut f = Finding::new(
        check,
        top.severity,
        format!("{title}：{}", top.desc),
        descs.join("；"),
    )
    .at(path, line)
    .evidence(detail)
    .fix(top.remedy)
    .confidence(Confidence::Heuristic)
    .mitre(mitre);
    // Additional matched patterns go into the message
    if hits.len() > 1 {
        f.message = format!("matched {} signals: {}", hits.len(), descs.join("; "));
    }
    Some(f)
}

/// Sort by severity (desc), then check and path, so output is stable across runs.
pub fn sort_findings(findings: &mut [Finding]) {
    findings.sort_by(|a, b| {
        b.severity
            .cmp(&a.severity)
            .then_with(|| a.check.cmp(&b.check))
            .then_with(|| a.path.cmp(&b.path))
            .then_with(|| a.line.cmp(&b.line))
    });
}

#[cfg(test)]
mod tests {
    use super::registry;
    use std::collections::HashSet;

    /// Coverage/TUI metadata is user-facing; do not let a new check ship with blanks
    /// or a duplicate id.
    #[test]
    fn registry_metadata_is_complete() {
        let mut ids = HashSet::new();
        for check in registry() {
            assert!(ids.insert(check.id()), "duplicate check id: {}", check.id());
            assert!(
                !check.title().trim().is_empty(),
                "{} has no title",
                check.id()
            );
            assert!(
                !check.description().trim().is_empty(),
                "{} has no description",
                check.id()
            );
            assert!(
                !check.platforms().is_empty(),
                "{} has no platforms",
                check.id()
            );
        }
    }
}
