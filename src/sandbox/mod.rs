//! Linux sandbox: run untrusted programs/installers in isolation, observe behavior, and assign risk.
//!
//! Usage (two-stage; download and execution are deliberately separated):
//!   1. `warden sandbox fetch <url>` -- controlled download + static inspection (no execution)
//!   2. `warden sandbox run -- /work/<file>` -- execute in a network-isolated sandbox and capture file changes
//!
//! Evidence sources, ordered by reliability:
//!   - Filesystem diff: which files the sample created or modified (cron, systemd, rc, ld.so.preload, ...)
//!   - IOC hashes: whether dropped files match known-malicious samples
//!   - strace (optional): egress attempts, execve chain, kernel/injection syscalls
//!   - Command-line heuristics: suspicious traits in the invoked command

pub mod bwrap;
pub mod capture;
pub mod engine;
pub mod fetch;
pub mod trace;
pub mod vm;

pub use engine::{dispatch, print_command, Engine, VmOptions};

use crate::checks::sort_findings;
use crate::ctx::Format;
use crate::heuristics::command_signals;
use crate::model::{Confidence, Finding, Severity};
use crate::util::{self, FileKind};
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TraceMode {
    Auto,
    Off,
}

#[derive(Debug, Clone)]
pub struct RunConfig {
    pub cmd: Vec<String>,
    pub workdir: Option<PathBuf>,
    pub timeout: Duration,
    pub max_file_size: u64,
    pub ioc: Option<PathBuf>,
    pub yara: Vec<PathBuf>,
    pub clamav: bool,
    pub clamav_db: Option<PathBuf>,
    pub limits: bwrap::CgroupLimits,
    pub trace: TraceMode,
    pub keep: bool,
    pub print_command: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Isolation {
    pub backend: String,
    pub backend_version: String,
    pub namespaces: Vec<String>,
    pub network: String,
    pub root_filesystem: String,
    pub writable_capture: Vec<String>,
    pub masked: Vec<String>,
    pub host_uid: u32,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ExitInfo {
    /// exited / signaled / timeout
    pub status: String,
    pub code: Option<i32>,
    pub signal: Option<i32>,
    pub duration_ms: u64,
    pub timed_out: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Artifact {
    pub path: String,
    pub change: String,
    pub kind: String,
    pub size: u64,
    pub executable: bool,
    pub sha256: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SandboxReport {
    pub tool: String,
    pub version: String,
    pub started_at: String,
    pub duration_ms: u64,
    pub command: Vec<String>,
    pub isolation: Isolation,
    pub exit: ExitInfo,
    pub findings: Vec<Finding>,
    pub artifacts: Vec<Artifact>,
    pub artifacts_total: usize,
    pub score: u32,
    pub verdict: String,
    pub workdir: String,
    pub kept: bool,
    pub trace_file: Option<String>,
    pub stdout: String,
    pub stderr: String,
    pub notes: Vec<String>,
}

pub fn exit_code(report: &SandboxReport) -> i32 {
    if report.findings.iter().any(|f| f.severity >= Severity::High) {
        1
    } else {
        0
    }
}

fn classify(logical: &str, kind: FileKind) -> Option<(Severity, &'static str, &'static str)> {
    let sev = |s: Severity, title: &'static str, mitre: &'static str| Some((s, title, mitre));

    if logical == "/etc/ld.so.preload" {
        return sev(
            Severity::Critical,
            "Wrote /etc/ld.so.preload (library injection)",
            "T1574.006",
        );
    }
    if logical.starts_with("/etc/cron") || logical.starts_with("/var/spool/cron") {
        return sev(
            Severity::Critical,
            "Wrote a cron persistence location",
            "T1053.003",
        );
    }
    if logical.starts_with("/etc/systemd") || logical.starts_with("/home/sandbox/.config/systemd") {
        return sev(Severity::High, "Wrote a systemd service", "T1543.002");
    }
    if is_home_rc(logical) {
        return sev(Severity::High, "Wrote a shell startup script", "T1546.004");
    }
    if logical.starts_with("/etc/profile")
        || logical == "/etc/bash.bashrc"
        || logical.starts_with("/etc/zsh")
    {
        return sev(
            Severity::High,
            "Wrote a system-wide shell startup script",
            "T1546.004",
        );
    }
    if logical.starts_with("/etc/sudoers") {
        return sev(
            Severity::High,
            "sudoers changed (privilege persistence)",
            "T1548.003",
        );
    }
    if logical.starts_with("/etc/pam.d") {
        return sev(
            Severity::High,
            "PAM authentication module changed",
            "T1556.003",
        );
    }
    if logical.starts_with("/etc/modprobe.d") {
        return sev(
            Severity::High,
            "Wrote a modprobe kernel module hook",
            "T1547.006",
        );
    }
    if logical.starts_with("/etc/ld.so.conf.d") {
        return sev(Severity::High, "Added a library search path", "T1574.006");
    }
    if logical.starts_with("/etc/ssh") || logical.starts_with("/home/sandbox/.ssh") {
        return sev(
            Severity::High,
            "SSH configuration or keys changed",
            "T1098.004",
        );
    }
    if logical.starts_with("/home/sandbox/.config/autostart") {
        return sev(
            Severity::High,
            "Wrote a desktop autostart entry",
            "T1547.013",
        );
    }
    if logical.starts_with("/usr/local/bin")
        || logical.starts_with("/usr/local/sbin")
        || logical.starts_with("/home/sandbox/.local/bin")
    {
        let high = kind.is_executable_format();
        return sev(
            if high {
                Severity::High
            } else {
                Severity::Medium
            },
            "Installed or dropped an executable",
            "T1204.002",
        );
    }
    if logical == "/etc/hosts" || logical == "/etc/resolv.conf" || logical == "/etc/nsswitch.conf" {
        return sev(
            Severity::Medium,
            "Name resolution configuration changed",
            "T1556",
        );
    }
    if logical.starts_with("/etc/") {
        return sev(Severity::Low, "System config file changed", "T1222.002");
    }
    None
}

fn is_home_rc(logical: &str) -> bool {
    let rest = match logical.strip_prefix("/home/sandbox/") {
        Some(r) => r,
        None => return false,
    };
    matches!(
        rest,
        ".bashrc"
            | ".bash_profile"
            | ".bash_login"
            | ".profile"
            | ".zshrc"
            | ".zprofile"
            | ".zshenv"
            | ".config/fish/config.fish"
    )
}

fn kind_label(kind: FileKind) -> &'static str {
    match kind {
        FileKind::Elf => "ELF",
        FileKind::MachO => "Mach-O",
        FileKind::Script => "script",
        FileKind::Other => "file",
    }
}

fn human_size(n: u64) -> String {
    if n < 1024 {
        format!("{n} B")
    } else if n < 1024 * 1024 {
        format!("{:.1} KiB", n as f64 / 1024.0)
    } else if n < 1024 * 1024 * 1024 {
        format!("{:.1} MiB", n as f64 / (1024.0 * 1024.0))
    } else {
        format!("{:.1} GiB", n as f64 / (1024.0 * 1024.0 * 1024.0))
    }
}

fn read_head(path: &Path, chars: usize) -> String {
    util::read_text(path, 4 * util::MB)
        .map(|s| s.chars().take(chars).collect::<String>())
        .unwrap_or_default()
}

pub(super) fn score(findings: &[Finding]) -> u32 {
    let mut s: u32 = 0;
    for f in findings {
        s += match f.severity {
            Severity::Critical => 50,
            Severity::High => 25,
            Severity::Medium => 10,
            Severity::Low => 3,
            Severity::Info => 0,
        };
    }
    s.min(100)
}

pub(super) fn verdict(findings: &[Finding]) -> &'static str {
    let max = findings.iter().map(|f| f.severity).max();
    match max {
        Some(Severity::Critical) | Some(Severity::High) => "high-risk",
        Some(Severity::Medium) => "suspicious",
        Some(Severity::Low) => "low-risk",
        _ => "clean",
    }
}

fn isolation(_layout: &capture::Layout) -> Isolation {
    Isolation {
        backend: "bubblewrap".into(),
        backend_version: bwrap::version().unwrap_or_else(|| "unknown".into()),
        namespaces: vec![
            "user".into(),
            "pid".into(),
            "net".into(),
            "ipc".into(),
            "uts".into(),
            "cgroup".into(),
        ],
        network: "isolated (no egress)".into(),
        root_filesystem: "tmpfs + ro-bind /usr".into(),
        writable_capture: vec![
            "/etc".into(),
            "/usr/local".into(),
            "/home/sandbox".into(),
            "/tmp".into(),
            "/work".into(),
            "/var/tmp".into(),
            "/var/log".into(),
            "/var/spool/cron".into(),
        ],
        masked: vec![
            "/home".into(),
            "/root".into(),
            "/mnt".into(),
            "/boot".into(),
            "/srv".into(),
            "/sys".into(),
        ],
        host_uid: unsafe { libc::getuid() },
    }
}

pub(crate) fn shell_join(parts: &[std::ffi::OsString]) -> String {
    parts
        .iter()
        .map(|p| {
            let s = p.to_string_lossy();
            if s.chars()
                .any(|c| c.is_whitespace() || "'\"$`\\".contains(c))
            {
                format!("'{}'", s.replace('\'', "'\\''"))
            } else {
                s.into_owned()
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

pub fn print_local_command(cfg: &RunConfig) -> Result<()> {
    if cfg.cmd.is_empty() {
        anyhow::bail!("missing command (pass it after --)");
    }
    if cfg!(target_os = "macos") {
        anyhow::bail!(
            "sandbox run is Linux-only (bubblewrap + Linux namespaces). On macOS use `warden sandbox fetch` for static quarantine analysis, or run the sample inside a Linux VM."
        );
    }
    let layout = capture::Layout::create(cfg.workdir.as_deref())?;
    let plain = bwrap::command_parts(&layout, &cfg.cmd, None);
    let parts = if cfg.limits.enabled() {
        bwrap::wrap_with_scope(&plain, &cfg.limits, "warden-sandbox-preview")
    } else {
        plain
    };
    println!("{}", shell_join(&parts));
    if !cfg.keep {
        layout.cleanup();
    } else {
        eprintln!("work directory kept: {}", layout.base.display());
    }
    Ok(())
}

pub fn run_local(cfg: RunConfig) -> Result<SandboxReport> {
    if cfg.cmd.is_empty() {
        anyhow::bail!("missing command (pass it after --)");
    }
    if cfg!(target_os = "macos") {
        anyhow::bail!(
            "sandbox run is Linux-only (bubblewrap + Linux namespaces). On macOS use `warden sandbox fetch` for static quarantine analysis, or run the sample inside a Linux VM."
        );
    }
    if !bwrap::available() {
        anyhow::bail!(
            "bubblewrap not found. Install it first (Debian/Ubuntu: apt install bubblewrap; Arch: pacman -S bubblewrap; Fedora: dnf install bubblewrap)"
        );
    }

    let started_at = util::now_rfc3339();
    let started = std::time::Instant::now();

    let intel = match &cfg.ioc {
        Some(p) => {
            let loaded = crate::intel::Intel::load(std::slice::from_ref(p))?;
            if loaded.is_empty() {
                anyhow::bail!("IOC source contains no valid entries: {}", p.display());
            }
            Some(loaded)
        }
        None => None,
    };

    let layout = capture::Layout::create(cfg.workdir.as_deref())?;
    let mut notes = Vec::new();
    if layout.etc_copy_incomplete {
        notes.push(
            "Some /etc files (shadow/sudoers) are unreadable and were replaced with empty placeholders".to_string(),
        );
    }

    let before = capture::snapshot(&layout, cfg.max_file_size);
    let trace_path = match cfg.trace {
        TraceMode::Auto if trace::available() => Some(layout.logs.join("trace.log")),
        _ => None,
    };
    let plain_parts = bwrap::command_parts(&layout, &cfg.cmd, trace_path.as_deref());
    let mut parts = plain_parts.clone();
    let mut scope_unit: Option<String> = None;
    let limits_requested = cfg.limits.enabled();
    let mut limits_applied = false;
    if limits_requested && bwrap::cgroup_available(&cfg.limits) {
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let unit = format!("warden-sandbox-{}-{}", std::process::id(), stamp);
        parts = bwrap::wrap_with_scope(&plain_parts, &cfg.limits, &unit);
        scope_unit = Some(unit);
        limits_applied = true;
    }

    let outcome = match bwrap::execute(&parts, cfg.timeout, &layout.logs, scope_unit.as_deref()) {
        Ok(outcome) => outcome,
        Err(e) if scope_unit.is_some() => {
            notes.push(format!(
                "cgroup limits could not be applied ({e:#}); retrying without them"
            ));
            limits_applied = false;
            bwrap::execute(&plain_parts, cfg.timeout, &layout.logs, None)?
        }
        Err(e) => return Err(e),
    };

    if limits_requested {
        if limits_applied {
            notes.push(format!(
                "cgroup v2 limits applied: {}",
                cfg.limits.describe()
            ));
        } else {
            notes.push(
                "cgroup v2 limits were requested but are unavailable (systemd user scope); only timeout and rlimits apply"
                    .into(),
            );
        }
    }
    let after = capture::snapshot(&layout, cfg.max_file_size);
    let diff = capture::diff(&before, &after);

    let mut findings: Vec<Finding> = Vec::new();

    // 1) The invoked command itself
    let joined = cfg.cmd.join(" ");
    let hits = command_signals(&joined);
    if let Some(f) = crate::checks::combined_finding(
        "sandbox.command",
        "Invoked command contains suspicious traits",
        "/work",
        None,
        &joined,
        &hits,
        "T1204.002",
    ) {
        findings.push(f);
    }

    // 2) Filesystem changes
    let mut artifacts: Vec<Artifact> = Vec::new();
    let mut ioc_hits: HashSet<String> = HashSet::new();
    for change in &diff.changes {
        let logical = &change.logical;
        let st = &change.state;
        artifacts.push(Artifact {
            path: logical.clone(),
            change: change.change.as_str().to_string(),
            kind: kind_label(st.kind).to_string(),
            size: st.size,
            executable: st.exec,
            sha256: st.hash.clone(),
        });

        if change.change == capture::ChangeKind::Deleted {
            if logical.starts_with("/etc/") || logical.starts_with("/usr/local/") {
                findings.push(
                    Finding::new(
                        "sandbox.delete",
                        Severity::Medium,
                        "Deleted a system file",
                        "System config or programs were deleted during execution (possibly anti-forensics)",
                    )
                    .at(logical.clone(), None)
                    .evidence(format!("deleted {}", logical))
                    .fix("Check whether this is part of an install/uninstall flow")
                    .confidence(Confidence::Likely)
                    .mitre("T1070.004"),
                );
            }
            continue;
        }

        let evidence = format!(
            "{} {} {} {}",
            change.change.label_zh(),
            kind_label(st.kind),
            human_size(st.size),
            st.hash
                .as_ref()
                .map(|h| format!("sha256:{}", &h[..16.min(h.len())]))
                .unwrap_or_default()
        );

        if let Some((sev, title, mitre)) = classify(logical, st.kind) {
            let mut sev = sev;
            // Executable formats are escalated in any config directory
            if st.kind.is_executable_format() && sev < Severity::High {
                sev = Severity::High;
            }
            findings.push(
                Finding::new(
                    "sandbox.persistence",
                    sev,
                    title,
                    "The file was created or modified during sandbox execution",
                )
                .at(logical.clone(), None)
                .evidence(evidence.clone())
                .fix("Confirm this is expected installer behavior; otherwise treat it as a persistence backdoor")
                .confidence(Confidence::Certain)
                .mitre(mitre),
            );
        } else if st.kind.is_executable_format() && change.change != capture::ChangeKind::Deleted {
            // Native executables outside system dirs (/tmp, /work, $HOME)
            let lib_ext = ["so", "node", "dylib", "o", "a", "bundle", "rlib"];
            let is_lib = logical
                .rsplit('.')
                .next()
                .map(|e| lib_ext.contains(&e.to_ascii_lowercase().as_str()))
                .unwrap_or(false);
            if !(is_lib && !st.exec) {
                findings.push(
                    Finding::new(
                        "sandbox.drop",
                        Severity::High,
                        "Dropped a native executable",
                        format!(
                            "{} binary created during sandbox execution",
                            kind_label(st.kind)
                        ),
                    )
                    .at(logical.clone(), None)
                    .evidence(evidence.clone())
                    .fix("Quarantine the file and cross-check its hash with multiple engines")
                    .confidence(Confidence::Likely)
                    .mitre("T1204.002"),
                );
            }
        }

        // Generated scripts containing backdoor commands
        if st.kind == FileKind::Script && change.change == capture::ChangeKind::Created {
            if let Some(text) = util::read_text(&st.host, 256 * 1024) {
                let script_hits: Vec<_> = text.lines().flat_map(command_signals).collect();
                if !script_hits.is_empty() {
                    let top = script_hits
                        .iter()
                        .max_by_key(|h| h.severity)
                        .map(|h| h.severity)
                        .unwrap_or(Severity::Medium);
                    findings.push(
                        Finding::new(
                            "sandbox.script",
                            top,
                            "Generated script contains suspicious commands",
                            "The dropped shell script matches backdoor behavior patterns",
                        )
                        .at(logical.clone(), None)
                        .evidence(format!("{} {}", evidence, script_hits[0].desc))
                        .fix("Review the script before deciding whether to keep it")
                        .confidence(Confidence::Heuristic)
                        .mitre("T1059.004"),
                    );
                }
            }
        }

        // Threat intelligence (hashes from any supported feed format)
        if let Some(intel) = &intel {
            if change.change != capture::ChangeKind::Deleted {
                if let Some(hit) = intel.match_file(&st.host, cfg.max_file_size) {
                    if ioc_hits.insert(hit.value.clone()) {
                        findings.push(
                            Finding::new(
                                "sandbox.intel",
                                Severity::Critical,
                                format!("Dropped file matches threat intel ({})", hit.kind),
                                "The dropped file matches an IOC feed entry",
                            )
                            .at(logical.clone(), None)
                            .evidence(format!("{}:{}", hit.kind, hit.value))
                            .fix("Preserve the sample, isolate the host, and follow incident response")
                            .confidence(Confidence::Certain)
                            .mitre("T1204.002"),
                        );
                    }
                }
            }
        }
    }

    // 3) YARA rules over dropped artifacts
    if !cfg.yara.is_empty() {
        match crate::signatures::SignatureEngine::load(&cfg.yara) {
            Ok(engine) => {
                let mut files: Vec<PathBuf> = diff
                    .changes
                    .iter()
                    .filter(|c| {
                        c.change != capture::ChangeKind::Deleted
                            && c.state.size <= cfg.max_file_size
                    })
                    .map(|c| c.state.host.clone())
                    .collect();
                files.sort();
                files.dedup();
                let matched =
                    engine.scan_paths(&files, cfg.max_file_size as usize, Duration::from_secs(10));
                let mut count = 0usize;
                for (host, matches) in matched {
                    let logical = layout
                        .map_logical(&host)
                        .unwrap_or_else(|| host.to_string_lossy().into_owned());
                    for m in matches {
                        findings.push(engine.to_finding(&m, "sandbox.yara", &logical));
                        count += 1;
                    }
                }
                notes.push(format!(
                    "YARA: {} rule(s) from {} file(s); {} match(es) on dropped artifacts",
                    engine.rule_count,
                    engine.sources.len(),
                    count
                ));
            }
            Err(e) => notes.push(format!("YARA rules failed to load: {e:#}")),
        }
    }

    // 4) Optional ClamAV scan over dropped artifacts
    if cfg.clamav {
        match crate::clamav::ClamAv::discover() {
            Some(av) => {
                let files: Vec<PathBuf> = diff
                    .changes
                    .iter()
                    .filter(|c| {
                        c.change != capture::ChangeKind::Deleted
                            && c.state.size <= cfg.max_file_size
                    })
                    .map(|c| c.state.host.clone())
                    .collect();
                match av.scan(&files, cfg.clamav_db.as_deref(), Duration::from_secs(60)) {
                    Ok(scan) => {
                        for hit in &scan.hits {
                            let logical = layout
                                .map_logical(&hit.path)
                                .unwrap_or_else(|| hit.path.to_string_lossy().into_owned());
                            findings.push(
                                Finding::new(
                                    "sandbox.clamav",
                                    Severity::High,
                                    format!("ClamAV detected {}", hit.signature),
                                    "A dropped file matches a known-malware signature",
                                )
                                .at(logical, None)
                                .evidence(format!("signature={}", hit.signature))
                                .fix("Quarantine the file and preserve the sample")
                                .confidence(Confidence::Certain)
                                .mitre("T1204.002"),
                            );
                        }
                        notes.push(format!(
                            "ClamAV: {}; {} artifact(s) scanned; {} hit(s)",
                            av.version(),
                            scan.targets,
                            scan.hits.len()
                        ));
                    }
                    Err(e) => notes.push(format!("ClamAV scan failed: {e:#}")),
                }
            }
            None => notes.push("--clamav requested but clamscan was not found in PATH".into()),
        }
    }

    // 5) strace behavior
    let mut trace_file = None;
    if let Some(path) = &trace_path {
        if path.is_file() {
            let result = trace::parse_file(path);
            if result.lines == 0 {
                notes
                    .push("strace produced no records (possibly blocked by seccomp/ptrace)".into());
            } else {
                notes.push(format!(
                    "strace recorded {} lines: {}",
                    result.lines,
                    result.events.join("；")
                ));
            }
            findings.extend(result.findings);
            trace_file = Some(path.to_string_lossy().into_owned());
        }
    } else {
        notes.push("strace is not installed: egress attempts and the execve chain were not observed; judgement relies on file changes".into());
    }

    // 6) Exit status
    let (status_str, code, signal) = if outcome.timed_out {
        (
            "timeout".to_string(),
            None,
            bwrap::status_signal(&outcome.status),
        )
    } else if let Some(sig) = bwrap::status_signal(&outcome.status) {
        ("signaled".to_string(), None, Some(sig))
    } else {
        (
            "exited".to_string(),
            bwrap::status_code(&outcome.status),
            None,
        )
    };
    if !outcome.timed_out && code == Some(137) && cfg.limits.mem_bytes.is_some() {
        findings.push(
            Finding::new(
                "sandbox.exit",
                Severity::Low,
                "Process was SIGKILLed (likely memory limit)",
                "Exit code 137 usually means the kernel OOM killer or the cgroup memory limit terminated the process",
            )
            .at("/work", None)
            .fix("Confirm the memory demand; raise --mem only after reviewing the sample")
            .confidence(Confidence::Likely),
        );
    }

    if outcome.timed_out {
        findings.push(
            Finding::new(
                "sandbox.timeout",
                Severity::Medium,
                "Sample execution timed out",
                format!(
                    "Killed after {} seconds; it may still be unpacking, looping, or waiting for network, so observation is incomplete",
                    cfg.timeout.as_secs()
                ),
            )
            .at("/work", None)
            .fix("Increase --timeout or combine with static analysis")
            .confidence(Confidence::Certain)
            .mitre("T1497"),
        );
    }

    // Merge and sort
    let mut seen = HashSet::new();
    findings.retain(|f| seen.insert(f.fingerprint()));
    sort_findings(&mut findings);

    let artifacts_total = artifacts.len();
    if artifacts_total > 1000 {
        artifacts.truncate(1000);
        notes.push(format!(
            "{artifacts_total} filesystem changes; only the first 1000 are reported"
        ));
    }

    let score = score(&findings);
    let verdict = verdict(&findings).to_string();

    notes.push(format!(
        "Snapshot covered {} -> {} files.",
        diff.files_before, diff.files_after
    ));
    notes.push(
        "The isolation layer shares the host kernel (user namespace); targeted kernel exploits may escape. Use a microVM for those."
            .into(),
    );
    notes.push("Network is isolated, so installers cannot go online; download into --workdir first and run offline.".into());

    if !cfg.keep {
        notes.push("The work directory was cleaned up; use --keep to preserve it.".into());
    }

    let report = SandboxReport {
        tool: "warden".into(),
        version: env!("CARGO_PKG_VERSION").into(),
        started_at,
        duration_ms: started.elapsed().as_millis() as u64,
        command: cfg.cmd.clone(),
        isolation: isolation(&layout),
        exit: ExitInfo {
            status: status_str,
            code,
            signal,
            duration_ms: outcome.duration.as_millis() as u64,
            timed_out: outcome.timed_out,
        },
        findings,
        artifacts,
        artifacts_total,
        score,
        verdict,
        workdir: layout.base.to_string_lossy().into_owned(),
        kept: cfg.keep,
        trace_file,
        stdout: read_head(&layout.logs.join("stdout.log"), 4000),
        stderr: read_head(&layout.logs.join("stderr.log"), 4000),
        notes,
    };

    if cfg.keep {
        // Preserve the scene: skip cleanup
    } else {
        layout.cleanup();
    }

    Ok(report)
}

pub fn doctor() -> String {
    let mut out = String::new();
    let bwrap_path = util::command_exists("bwrap");
    out.push_str("warden sandbox doctor\n\n");
    if cfg!(target_os = "macos") {
        out.push_str(
            "macOS note : `sandbox run` uses the Lima VM backend (`--engine vm`); local bubblewrap is Linux-only.\n             `sandbox fetch`, the static scanner, YARA and ClamAV work natively.\n\n",
        );
    }

    out.push_str(&format!(
        "bubblewrap : {}\n",
        if bwrap_path {
            format!(
                "{} ({})",
                which("bwrap").unwrap_or_else(|| "?".into()),
                bwrap::version().unwrap_or_else(|| "unknown".into())
            )
        } else if cfg!(target_os = "macos") {
            "not applicable on macOS (installed inside the Linux VM)".into()
        } else {
            "missing -- install it before using the sandbox".into()
        }
    ));

    out.push_str(&format!(
        "engine     : auto -> {} (host={})\n",
        match engine::resolve(engine::Engine::Auto) {
            engine::Choice::Local => "local (bubblewrap)",
            engine::Choice::Vm => "vm (Lima)",
        },
        std::env::consts::OS
    ));
    out.push_str(&format!(
        "limactl    : {}\n",
        if util::command_exists("limactl") {
            "available (used by --engine vm)"
        } else {
            "not installed (needed for --engine vm / sandbox vm up)"
        }
    ));

    let userns = util::read_text(Path::new("/proc/sys/user/max_user_namespaces"), 4096)
        .and_then(|s| s.trim().parse::<u64>().ok())
        .unwrap_or(0);
    out.push_str(&format!(
        "user ns    : {}\n",
        if cfg!(target_os = "macos") {
            "not applicable on macOS (the VM backend uses the guest kernel)".into()
        } else if userns > 0 {
            format!("available (max_user_namespaces={userns})")
        } else {
            "unavailable (container or kernel restriction); the sandbox cannot start".into()
        }
    ));

    out.push_str(&format!(
        "clamscan   : {}\n",
        match crate::clamav::ClamAv::discover() {
            Some(av) => av.version().to_string(),
            None => "not installed (optional; run freshclam after installing)".to_string(),
        }
    ));
    out.push_str(&format!(
        "strace     : {}\n",
        if trace::available() {
            "available (observes egress and execve)".into()
        } else {
            "not installed (optional; install for richer behavior evidence)".to_string()
        }
    ));
    out.push_str(&format!(
        "curl       : {}\n",
        if util::command_exists("curl") {
            "available (sandbox fetch)".into()
        } else {
            "not installed (sandbox fetch requires curl)".to_string()
        }
    ));

    let default_limits = bwrap::CgroupLimits {
        mem_bytes: Some(2 * 1024 * 1024 * 1024),
        cpus: Some(2.0),
        pids: Some(256),
    };
    out.push_str(&format!(
        "cgroup v2  : {}\n",
        if cfg!(target_os = "macos") {
            "inside the Linux VM only (guest systemd user scope)".to_string()
        } else if bwrap::cgroup_available(&default_limits) {
            format!(
                "available via systemd user scope (defaults: {})",
                default_limits.describe()
            )
        } else {
            "unavailable (no systemd user scope); limits fall back to timeout + rlimits".to_string()
        }
    ));

    let tmp_fs = util::run("stat", &["-f", "-c", "%T", "/tmp"])
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| "unknown".into());
    out.push_str(&format!(
        "temp dir   : /tmp ({tmp_fs}){}",
        if tmp_fs == "tmpfs" {
            " -- note: sandbox copies live in memory, large sample writes consume RAM\n"
        } else {
            "\n"
        }
    ));

    out.push_str("\nRecommendations:\n");
    if !bwrap_path {
        out.push_str("  - Install bubblewrap and retry\n");
    }
    if !trace::available() {
        out.push_str("  - Install strace for egress attempts and the exec chain (optional)\n");
    }
    if crate::clamav::ClamAv::discover().is_none() {
        out.push_str("  - Install ClamAV and run `freshclam` to enable --clamav\n");
    }
    out.push_str("  - First run `warden sandbox run --keep -- /bin/echo hello` to validate the environment\n");
    out.push_str(
        "  - Do not repeatedly run known kernel-exploit samples in a shared-kernel sandbox\n",
    );
    if cfg!(target_os = "macos") {
        out.push_str(
            "  - Install Lima (`brew install lima`) and run `warden sandbox vm up` for dynamic analysis\n",
        );
    }
    out
}

fn which(name: &str) -> Option<String> {
    std::env::var_os("PATH").and_then(|paths| {
        std::env::split_paths(&paths)
            .map(|d| d.join(name))
            .find(|p| p.is_file())
            .map(|p| p.to_string_lossy().into_owned())
    })
}

impl SandboxReport {
    pub fn render(&self, format: Format) -> String {
        match format {
            Format::Json => serde_json::to_string_pretty(self)
                .unwrap_or_else(|e| format!("{{\"error\":\"{e}\"}}")),
            Format::Sarif => render_text(self, false),
            Format::Text => render_text(self, true),
        }
    }
}

fn render_text(r: &SandboxReport, _color: bool) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "{} sandbox {} · {} · network={} · verdict {}\n",
        r.tool, r.version, r.isolation.backend_version, r.isolation.network, r.verdict
    ));
    out.push_str(&format!("command: {}\n", r.command.join(" ")));
    out.push_str(&format!(
        "exit: {} code={:?} signal={:?} · elapsed {} ms · filesystem changes {} · risk {}/100\n\n",
        r.exit.status, r.exit.code, r.exit.signal, r.exit.duration_ms, r.artifacts_total, r.score
    ));

    if r.findings.is_empty() {
        out.push_str("No suspicious behavior detected.\n\n");
    }
    for f in &r.findings {
        out.push_str(&format!(
            "[{:<8}] {}{}\n",
            f.severity.as_str().to_uppercase(),
            f.check,
            f.path
                .as_ref()
                .map(|p| format!("  {p}"))
                .unwrap_or_default()
        ));
        out.push_str(&format!("         {}\n", f.title));
        if f.message != f.title {
            out.push_str(&format!("         {}\n", f.message));
        }
        if let Some(e) = &f.evidence {
            out.push_str(&format!("         evidence: {e}\n"));
        }
        if let Some(fix) = &f.remediation {
            out.push_str(&format!("         remediation: {fix}\n"));
        }
        out.push('\n');
    }

    if !r.artifacts.is_empty() {
        out.push_str(&format!(
            "---- Filesystem changes ({}) ----\n",
            r.artifacts_total
        ));
        for a in r.artifacts.iter().take(30) {
            out.push_str(&format!(
                "  {:<8} {:<7} {:>9}  {}{}\n",
                a.change,
                a.kind,
                human_size(a.size),
                a.path,
                if a.executable { " [exec]" } else { "" }
            ));
        }
        if r.artifacts_total > 30 {
            out.push_str(&format!(
                "  ... {} more entries in JSON output\n",
                r.artifacts_total - 30
            ));
        }
        out.push('\n');
    }

    if !r.stdout.trim().is_empty() {
        out.push_str("---- stdout (truncated) ----\n");
        out.push_str(r.stdout.trim_end());
        out.push_str("\n\n");
    }
    if !r.stderr.trim().is_empty() {
        out.push_str("---- stderr (truncated) ----\n");
        out.push_str(r.stderr.trim_end());
        out.push_str("\n\n");
    }

    out.push_str("---- Notes ----\n");
    for n in &r.notes {
        out.push_str(&format!("  - {n}\n"));
    }
    if r.kept {
        out.push_str(&format!("  work directory kept: {}\n", r.workdir));
    }
    if let Some(t) = &r.trace_file {
        out.push_str(&format!("  strace log: {t}\n"));
    }
    out
}
