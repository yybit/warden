//! File-level checks: SUID/capabilities, writable paths, masqueraded binaries, webshells, IOC hashes.

use crate::checks::Check;
use crate::ctx::ScanContext;
use crate::intel::Intel;
use crate::model::{Confidence, Finding, Severity, SnapshotItem};
use crate::util;
use anyhow::Result;
use rayon::prelude::*;
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

// ---------------------------------------------------------------- suid

/// setuid/setgid programs shipped by common distributions. Matching here reduces noise, not risk.
const KNOWN_SUID: &[&str] = &[
    "sudo",
    "sudoedit",
    "su",
    "passwd",
    "chsh",
    "chfn",
    "chage",
    "gpasswd",
    "newgrp",
    "mount",
    "umount",
    "mount.nfs",
    "mount.cifs",
    "fusermount",
    "fusermount3",
    "ping",
    "ping6",
    "traceroute",
    "traceroute6",
    "pkexec",
    "polkit-agent-helper-1",
    "dbus-daemon-launch-helper",
    "at",
    "crontab",
    "expiry",
    "wall",
    "write",
    "ssh-agent",
    "unix_chkpwd",
    "pam_extrausers_chkpwd",
    "pt_chown",
    "dotlockfile",
    "Xorg",
    "Xorg.wrap",
    "chrome-sandbox",
    "vmware-user-suid-wrapper",
    "nvidia-modprobe",
    "screen",
    "sudoers",
    "bwrap",
    "fusermount-glusterfs",
    "postdrop",
    "postqueue",
    "procmail",
    "ssh-keysign",
    "nullmailer-queue",
    "krb5-user",
    "ksu",
    "qemu-bridge-helper",
    "utempter",
    "newuidmap",
    "newgidmap",
    "gst-ptp-helper",
    "dumpcap",
    "snap-confine",
    "login",
    "quota",
    "lockfile",
];

/// Capabilities held by standard distribution components. Matching reduces noise; still watch baseline changes.
const KNOWN_CAPS: &[&str] = &[
    "newuidmap",
    "newgidmap",
    "gst-ptp-helper",
    "dumpcap",
    "ping",
    "Xorg",
    "chrome-sandbox",
    "qemu-bridge-helper",
];

fn suid_scan_dirs(ctx: &ScanContext) -> Vec<(PathBuf, usize)> {
    let mut dirs: Vec<(PathBuf, usize)> = vec![
        (ctx.abs("/usr/bin"), 1),
        (ctx.abs("/usr/sbin"), 1),
        (ctx.abs("/usr/local/bin"), 1),
        (ctx.abs("/usr/local/sbin"), 1),
        (ctx.abs("/usr/local/lib"), 2),
        (ctx.abs("/usr/lib"), 2),
        (ctx.abs("/usr/libexec"), 2),
        (ctx.abs("/opt"), 3),
    ];
    if ctx.user_scope {
        dirs.push((ctx.home_abs().join(".local/bin"), 1));
    }
    // /bin and /sbin are usually symlinks into /usr: de-duplicate by real path
    for extra in ["/bin", "/sbin"] {
        let p = ctx.abs(extra);
        if let Ok(real) = std::fs::canonicalize(&p) {
            if !dirs.iter().any(|(d, _)| d == &real) {
                dirs.push((real, 1));
            }
        }
    }
    dirs.retain(|(d, _)| d.is_dir());
    dirs.sort();
    dirs.dedup_by(|a, b| a.0 == b.0);
    dirs
}

/// Collect all regular files with setuid/setgid bits (also used by baselines).
pub fn collect_suid(ctx: &ScanContext) -> Vec<(PathBuf, u32)> {
    let mut out = Vec::new();
    for (dir, depth) in suid_scan_dirs(ctx) {
        for entry in WalkDir::new(&dir)
            .max_depth(depth)
            .follow_links(false)
            .into_iter()
            .filter_map(|e| e.ok())
        {
            if !entry.file_type().is_file() {
                continue;
            }
            let mode = match util::mode_of(entry.path()) {
                Some(m) => m,
                None => continue,
            };
            if util::is_setuid_mode(mode) || util::is_setgid_mode(mode) {
                out.push((entry.path().to_path_buf(), mode));
            }
            if out.len() > 50_000 {
                return out;
            }
        }
    }
    out.sort();
    out.dedup_by(|a, b| a.0 == b.0);
    out
}

fn cap_risk(caps: &str) -> Option<(Severity, &'static str)> {
    let c = caps.to_ascii_lowercase();
    let high = [
        "cap_sys_admin",
        "cap_sys_ptrace",
        "cap_sys_module",
        "cap_setuid",
        "cap_setgid",
        "cap_dac_override",
        "cap_dac_read_search",
        "cap_sys_rawio",
        "cap_sys_chroot",
    ];
    if high.iter().any(|h| c.contains(h)) {
        return Some((Severity::High, "holds a high-privilege capability"));
    }
    let medium = ["cap_net_admin", "cap_bpf", "cap_perfmon", "cap_sys_time"];
    if medium.iter().any(|m| c.contains(m)) {
        return Some((Severity::Medium, "holds an elevated capability"));
    }
    None
}

pub struct SuidCheck;

impl Check for SuidCheck {
    fn id(&self) -> &'static str {
        "fs.suid"
    }
    fn title(&self) -> &'static str {
        "SUID/SGID and file capabilities"
    }
    fn description(&self) -> &'static str {
        "Unknown SUID/SGID binaries, SUID files in unusual locations, and high-privilege file capabilities."
    }

    fn run(&self, ctx: &ScanContext) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        for (path, mode) in collect_suid(ctx) {
            let logical = ctx.disp(&path);
            let name = path
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default();
            let privileged_dir = logical.starts_with("/usr/local")
                || logical.starts_with("/opt")
                || logical.starts_with("/home")
                || logical.starts_with("/Users")
                || logical.starts_with("/tmp");

            if KNOWN_SUID.contains(&name.as_str()) {
                // A known program in an unusual directory is still worth reporting
                if privileged_dir {
                    findings.push(
                        Finding::new(
                            self.id(),
                            Severity::Medium,
                            "Known SUID program in an unusual directory",
                            "The name is a standard component, but the path is outside the package manager",
                        )
                        .at(&logical, None)
                        .evidence(format!("mode={:04o} name={}", mode & 0o7777, name))
                        .fix("Verify origin and package signature; drop the setuid bit unless required")
                        .confidence(Confidence::Likely)
                        .mitre("T1548.001"),
                    );
                }
                continue;
            }

            let severity = if privileged_dir {
                Severity::High
            } else {
                Severity::Medium
            };
            findings.push(
                Finding::new(
                    self.id(),
                    severity,
                    "Unknown SUID/SGID executable",
                    format!(
                        "The {} bit lets any user run as the file owner; binaries outside system packages often mean a privilege-escalation backdoor",
                        if util::is_setuid_mode(mode) {
                            "setuid"
                        } else {
                            "setgid"
                        }
                    ),
                )
                .at(&logical, None)
                .evidence(format!("mode={:04o}", mode & 0o7777))
                .fix("Verify the origin; if unauthorized, chmod u-s,g-s or delete")
                .confidence(Confidence::Heuristic)
                .mitre("T1548.001"),
            );
        }

        // File capabilities (getcap is optional; skip silently when absent)
        if util::command_exists("getcap") {
            for (dir, _) in suid_scan_dirs(ctx) {
                let out = match util::run("getcap", &["-r", &dir.to_string_lossy()]) {
                    Some(o) => o,
                    None => continue,
                };
                for line in out.lines() {
                    let line = line.trim();
                    if line.is_empty() {
                        continue;
                    }
                    let (path_str, caps) = match line.split_once(' ') {
                        Some(v) => v,
                        None => continue,
                    };
                    let base = Path::new(path_str)
                        .file_name()
                        .map(|n| n.to_string_lossy().into_owned())
                        .unwrap_or_default();
                    if KNOWN_CAPS.contains(&base.as_str()) {
                        continue;
                    }
                    if let Some((sev, desc)) = cap_risk(caps) {
                        findings.push(
                            Finding::new(
                                self.id(),
                                sev,
                                "Executable holds extra capabilities",
                                desc,
                            )
                            .at(ctx.disp(Path::new(path_str)), None)
                            .evidence(line.to_string())
                            .fix(
                                "Verify the origin; remove unnecessary capabilities with setcap -r",
                            )
                            .confidence(Confidence::Likely)
                            .mitre("T1548.001"),
                        );
                    }
                }
            }
        }

        // Container/socket endpoints: world-writable means host takeover.
        for sock in [
            "/var/run/docker.sock",
            "/run/docker.sock",
            "/run/containerd/containerd.sock",
        ] {
            let p = ctx.abs(sock);
            if let Some(mode) = util::mode_of(&p) {
                if util::is_world_writable(mode) {
                    findings.push(
                        Finding::new(
                            self.id(),
                            Severity::High,
                            "Container runtime socket is world-writable",
                            "Any local user can control containers, which usually means root on the host",
                        )
                        .at(ctx.disp(&p), None)
                        .evidence(format!("mode={:04o}", mode & 0o7777))
                        .fix("Restrict the socket to root and the docker group")
                        .confidence(Confidence::Certain)
                        .mitre("T1611"),
                    );
                }
            }
        }

        Ok(findings)
    }
}

pub fn snapshot(ctx: &ScanContext) -> Vec<SnapshotItem> {
    collect_suid(ctx)
        .into_iter()
        .map(|(path, mode)| {
            let logical = ctx.disp(&path);
            SnapshotItem {
                key: format!("suid|{logical}|{:04o}", mode & 0o7777),
                kind: "suid".into(),
                path: logical,
                detail: format!("mode={:04o}", mode & 0o7777),
            }
        })
        .collect()
}

// ---------------------------------------------------------------- world writable

const SAFE_WRITABLE: &[&str] = &["/tmp", "/var/tmp", "/dev/shm", "/run/user", "/private/tmp"];

fn flagged_dir(dir: &Path) -> bool {
    SAFE_WRITABLE.iter().any(|s| dir.starts_with(s))
}

pub struct WorldWritableCheck;

impl Check for WorldWritableCheck {
    fn id(&self) -> &'static str {
        "fs.world_writable"
    }
    fn title(&self) -> &'static str {
        "Command hijacking via writable directories"
    }
    fn description(&self) -> &'static str {
        "Writable directories in PATH and writable files under /etc or /usr/local/bin."
    }

    fn run(&self, ctx: &ScanContext) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        let mut seen: HashSet<String> = HashSet::new();

        // Only inspect PATH for local scans (an image's PATH belongs to the host, not the target)
        if ctx.is_local() {
            if let Some(path_env) = std::env::var_os("PATH") {
                for p in std::env::split_paths(&path_env) {
                    let s = p.to_string_lossy().into_owned();
                    if s.is_empty() || s == "." || !p.is_absolute() {
                        let key = format!("path-rel|{s}");
                        if seen.insert(key) {
                            findings.push(
                                Finding::new(
                                    self.id(),
                                    Severity::Medium,
                                    "PATH contains a relative entry",
                                    "Relative entries change with the working directory and enable command hijacking",
                                )
                                .at(if s.is_empty() { "(empty)" } else { &s }, None)
                                .fix("Remove relative entries from PATH")
                                .confidence(Confidence::Certain)
                                .mitre("T1574.007"),
                            );
                        }
                        continue;
                    }
                    if flagged_dir(&p) {
                        continue;
                    }
                    if let Some(mode) = util::mode_of(&p) {
                        if util::is_world_writable(mode)
                            && !util::is_sticky(mode)
                            && seen.insert(s.clone())
                        {
                            findings.push(
                                Finding::new(
                                    self.id(),
                                    Severity::High,
                                    "Directory in PATH is world-writable",
                                    "An attacker can plant a same-named program and wait for another user to run it",
                                )
                                .at(&s, None)
                                .evidence(format!("mode={:04o}", mode & 0o7777))
                                .fix("chmod o-w and verify the directory owner")
                                .confidence(Confidence::Certain)
                                .mitre("T1574.007"),
                            );
                        }
                    }
                }
            }
        }

        // /etc and key bin directories
        let mut targets = vec![
            ctx.abs("/etc"),
            ctx.abs("/usr/local/bin"),
            ctx.abs("/usr/local/sbin"),
        ];
        if ctx.os == crate::model::Os::MacOs {
            targets.push(ctx.abs("/Library/LaunchDaemons"));
        }
        for dir in targets {
            if !dir.is_dir() {
                continue;
            }
            for entry in WalkDir::new(&dir)
                .max_depth(1)
                .follow_links(false)
                .into_iter()
                .filter_map(|e| e.ok())
            {
                let path = entry.path();
                if path == dir {
                    continue;
                }
                let mode = match util::mode_of(path) {
                    Some(m) => m,
                    None => continue,
                };
                let logical = ctx.disp(path);
                if entry.file_type().is_dir() {
                    if util::is_world_writable(mode)
                        && !util::is_sticky(mode)
                        && seen.insert(logical.clone())
                    {
                        findings.push(
                            Finding::new(
                                self.id(),
                                Severity::Medium,
                                "Critical directory is world-writable",
                                "Configs and programs inside can be replaced by unprivileged users",
                            )
                            .at(&logical, None)
                            .fix("chmod o-w")
                            .confidence(Confidence::Certain)
                            .mitre("T1574"),
                        );
                    }
                } else if util::is_world_writable(mode) && seen.insert(logical.clone()) {
                    let is_bin = logical.starts_with("/usr/local/bin")
                        || logical.starts_with("/usr/local/sbin");
                    findings.push(
                        Finding::new(
                            self.id(),
                            Severity::High,
                            if is_bin {
                                "Executable is world-writable"
                            } else {
                                "System config is world-writable"
                            },
                            "Unprivileged users can modify it, enabling privilege escalation or persistence",
                        )
                        .at(&logical, None)
                        .evidence(format!("mode={:04o}", mode & 0o7777))
                        .fix("chmod o-w and check whether the contents were tampered with")
                        .confidence(Confidence::Certain)
                        .mitre("T1574"),
                    );
                }
            }
        }

        Ok(findings)
    }
}

// ---------------------------------------------------------------- masquerading binaries

const DOC_EXT: &[&str] = &[
    "jpg", "jpeg", "png", "gif", "bmp", "webp", "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx",
    "zip", "rar", "7z", "tar", "gz", "bz2", "mp3", "mp4", "avi", "mkv", "txt", "csv", "html",
    "htm", "md", "log", "json", "xml", "svg",
];

fn suspicious_roots(ctx: &ScanContext) -> Vec<(PathBuf, &'static str)> {
    let mut v: Vec<(PathBuf, &'static str)> = vec![
        (ctx.abs("/tmp"), "/tmp"),
        (ctx.abs("/var/tmp"), "/var/tmp"),
        (ctx.abs("/dev/shm"), "/dev/shm"),
    ];
    if ctx.os == crate::model::Os::MacOs {
        v.push((ctx.abs("/Users/Shared"), "/Users/Shared"));
    }
    if ctx.user_scope {
        let home = ctx.home_abs();
        v.push((home.join("Downloads"), "~/Downloads"));
        v.push((home.join("Public"), "~/Public"));
    }
    v.retain(|(p, _)| p.is_dir());
    v
}

fn kind_label(k: util::FileKind) -> &'static str {
    match k {
        util::FileKind::Elf => "ELF",
        util::FileKind::MachO => "Mach-O",
        util::FileKind::Script => "script",
        util::FileKind::Other => "other",
    }
}

pub struct SuspiciousBinCheck;

impl Check for SuspiciousBinCheck {
    fn id(&self) -> &'static str {
        "fs.suspicious_bin"
    }
    fn title(&self) -> &'static str {
        "Masqueraded / dropped executables"
    }
    fn description(&self) -> &'static str {
        "ELF/Mach-O masquerading as documents, native binaries in temp dirs, and hidden executables."
    }

    fn run(&self, ctx: &ScanContext) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        let mut seen: HashSet<String> = HashSet::new();

        for (root, label) in suspicious_roots(ctx) {
            let mut count = 0usize;
            for entry in WalkDir::new(&root)
                .max_depth(4)
                .follow_links(false)
                .into_iter()
                .filter_map(|e| e.ok())
            {
                count += 1;
                if count > 50_000 {
                    break;
                }
                if !entry.file_type().is_file() {
                    continue;
                }
                let path = entry.path();
                let kind = util::file_kind(path);
                if kind == util::FileKind::Other {
                    continue;
                }
                let logical = ctx.disp(path);
                if !seen.insert(logical.clone()) {
                    continue;
                }
                let name = path
                    .file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_default();
                let ext = path
                    .extension()
                    .and_then(|e| e.to_str())
                    .unwrap_or("")
                    .to_ascii_lowercase();

                // Shared libraries/objects (e.g. Bun/Python temp .so/.node) are not executable entry points
                // and usually lack the exec bit: skip them so build caches are not treated as malware.
                let lib_ext = ["so", "node", "dylib", "o", "a", "bundle", "rlib"];
                if kind.is_executable_format()
                    && lib_ext.contains(&ext.as_str())
                    && util::mode_of(path).map(|m| m & 0o111 == 0).unwrap_or(false)
                {
                    continue;
                }

                // 1) Document/image extension with an executable format -> masquerading
                if DOC_EXT.contains(&ext.as_str()) && kind.is_executable_format() {
                    findings.push(
                        Finding::new(
                            self.id(),
                            Severity::Critical,
                            "Executable masquerading as a document/image",
                            format!("extension .{ext}, actual format {}", kind_label(kind)),
                        )
                        .at(&logical, None)
                        .fix("Quarantine the file and trace the download source")
                        .confidence(Confidence::Certain)
                        .mitre("T1036.005"),
                    );
                    continue;
                }

                // 2) Native executables in temp directories
                if kind.is_executable_format() && (label.contains("tmp") || label == "/dev/shm") {
                    findings.push(
                        Finding::new(
                            self.id(),
                            Severity::High,
                            "Native executable in a temp directory",
                            format!(
                                "{} binary located in {}; legitimate programs do not run from there",
                                kind_label(kind),
                                label
                            ),
                        )
                        .at(&logical, None)
                        .fix("Verify the origin; delete if unauthorized and review execution history")
                        .confidence(Confidence::Heuristic)
                        .mitre("T1204.002"),
                    );
                    continue;
                }

                // 3) Hidden executables
                if name.starts_with('.') && kind.is_executable_format() {
                    findings.push(
                        Finding::new(
                            self.id(),
                            Severity::High,
                            "Hidden executable",
                            "Dot-prefixed native binaries are often used to evade manual review",
                        )
                        .at(&logical, None)
                        .fix("Verify the origin; delete if unauthorized")
                        .confidence(Confidence::Heuristic)
                        .mitre("T1564.001"),
                    );
                }
            }
        }
        Ok(findings)
    }
}

// ---------------------------------------------------------------- webshell

const WEB_EXT: &[&str] = &[
    "php", "php3", "php4", "php5", "php7", "phtml", "phps", "inc", "jsp", "jspx", "jspf", "asp",
    "aspx", "ashx", "asmx", "cgi", "pl", "py",
];

fn webshell_hits(text: &str) -> Vec<(&'static str, Severity, &'static str)> {
    // Strip whitespace before matching to defeat `eval ( $_POST` style padding
    let compact: String = text
        .to_ascii_lowercase()
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();
    let mut out: Vec<(&'static str, Severity, &'static str)> = Vec::new();
    let mut add = |code: &'static str, sev: Severity, desc: &'static str| {
        if !out.iter().any(|(c, _, _)| *c == code) {
            out.push((code, sev, desc));
        }
    };

    if [
        "eval($_post",
        "eval($_get",
        "eval($_request",
        "eval($_cookie",
    ]
    .iter()
    .any(|p| compact.contains(p))
    {
        add(
            "eval-input",
            Severity::Critical,
            "eval executes request parameters directly",
        );
    }
    if compact.contains("assert($_") {
        add(
            "assert-input",
            Severity::Critical,
            "assert executes request parameters",
        );
    }
    if [
        "system($_",
        "exec($_",
        "shell_exec($_",
        "passthru($_",
        "popen($_",
    ]
    .iter()
    .any(|p| compact.contains(p))
    {
        add(
            "shell-exec-input",
            Severity::Critical,
            "Command execution function receives request parameters",
        );
    }
    if compact.contains("base64_decode(")
        && (compact.contains("eval(") || compact.contains("assert("))
    {
        add(
            "base64-eval",
            Severity::High,
            "base64-decoded code executed dynamically",
        );
    }
    if compact.contains("gzinflate(") && (compact.contains("eval(") || compact.contains("assert("))
    {
        add(
            "gzinflate-eval",
            Severity::High,
            "compressed payload inflated and executed",
        );
    }
    if compact.contains("preg_replace(") && compact.contains("/e") {
        add(
            "preg-eval",
            Severity::High,
            "preg_replace /e modifier executes code",
        );
    }
    if compact.contains("str_rot13(") && compact.contains("eval(") {
        add(
            "rot13-eval",
            Severity::Medium,
            "rot13-obfuscated code executed",
        );
    }
    if compact.contains("runtime.getruntime().exec") || compact.contains("processbuilder(") {
        add(
            "java-exec",
            Severity::High,
            "system command execution in JSP",
        );
    }
    if compact.contains("eval(request") || compact.contains("execute(request") {
        add("asp-eval", Severity::High, "ASP evaluates request content");
    }
    let hex_escapes = compact.matches("\\x").count();
    if hex_escapes >= 40 {
        add(
            "obfuscated",
            Severity::Medium,
            "Large number of hex escapes (obfuscated payload)",
        );
    }
    out.sort_by_key(|h| std::cmp::Reverse(h.1));
    out
}

pub struct WebshellCheck;

impl Check for WebshellCheck {
    fn id(&self) -> &'static str {
        "fs.webshell"
    }
    fn title(&self) -> &'static str {
        "Webshell indicators"
    }
    fn description(&self) -> &'static str {
        "PHP/JSP/ASP webshell indicators such as eval($_POST) and base64_decode chains."
    }

    fn skip_reason(&self, ctx: &ScanContext) -> Option<String> {
        if ctx.cfg.webroots.is_empty() {
            Some("no --webroot (web directory) provided".into())
        } else {
            None
        }
    }

    fn run(&self, ctx: &ScanContext) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        if ctx.cfg.webroots.is_empty() {
            return Ok(findings);
        }
        for webroot in &ctx.cfg.webroots {
            let dir = ctx.abs(webroot);
            if !dir.is_dir() {
                continue;
            }
            for entry in WalkDir::new(&dir)
                .max_depth(12)
                .follow_links(false)
                .into_iter()
                .filter_map(|e| e.ok())
            {
                if !entry.file_type().is_file() {
                    continue;
                }
                let path = entry.path();
                let ext = path
                    .extension()
                    .and_then(|e| e.to_str())
                    .unwrap_or("")
                    .to_ascii_lowercase();
                if !WEB_EXT.contains(&ext.as_str()) {
                    continue;
                }
                let text = match util::read_text(path, 2 * util::MB) {
                    Some(t) => t,
                    None => continue,
                };
                let hits = webshell_hits(&text);
                if hits.is_empty() {
                    continue;
                }
                let top = hits[0].1;
                let descs: Vec<&str> = hits.iter().map(|(_, _, d)| *d).collect();
                findings.push(
                    Finding::new(
                        self.id(),
                        top,
                        "Suspected webshell",
                        format!("matched {} signals: {}", hits.len(), descs.join("; ")),
                    )
                    .at(ctx.disp(path), None)
                    .fix("Quarantine the file, compare with deployment records, and inspect sibling scripts")
                    .confidence(Confidence::Heuristic)
                    .mitre("T1505.003"),
                );
            }
        }
        Ok(findings)
    }
}

// ---------------------------------------------------------------- IOC

pub struct IocCheck;

impl Check for IocCheck {
    fn id(&self) -> &'static str {
        "ioc.hash"
    }
    fn title(&self) -> &'static str {
        "Threat-intelligence matching"
    }
    fn description(&self) -> &'static str {
        "SHA-256, SHA-1, and MD5 matching against local IOC feeds."
    }

    fn skip_reason(&self, ctx: &ScanContext) -> Option<String> {
        if ctx.cfg.ioc.is_none() {
            Some("no --ioc (hash/URL/domain/IP feed) provided".into())
        } else {
            None
        }
    }

    fn run(&self, ctx: &ScanContext) -> Result<Vec<Finding>> {
        let ioc_path = match &ctx.cfg.ioc {
            Some(p) => p,
            None => return Ok(Vec::new()),
        };
        let intel = Intel::load(std::slice::from_ref(ioc_path))?;
        if intel.is_empty() {
            anyhow::bail!(
                "IOC source contains no valid entries (hashes/URLs/domains/IPs): {}",
                ioc_path.display()
            );
        }
        if !intel.has_file_hashes() {
            return Ok(vec![Finding::new(
                self.id(),
                Severity::Info,
                "IOC feed has no file hashes",
                format!(
                    "loaded {}; URL/domain/IP entries are used by sandbox fetch",
                    intel.counts()
                ),
            )
            .confidence(Confidence::Certain)]);
        }

        let roots: Vec<PathBuf> = if ctx.cfg.paths.is_empty() {
            let mut v = vec![
                ctx.home_abs(),
                ctx.abs("/tmp"),
                ctx.abs("/var/tmp"),
                ctx.abs("/usr/local/bin"),
            ];
            if ctx.os == crate::model::Os::MacOs {
                v.push(ctx.abs("/Users/Shared"));
            }
            v
        } else {
            ctx.cfg.paths.iter().map(|p| ctx.abs(p)).collect()
        };

        let mut files = Vec::new();
        for r in roots {
            if r.is_dir() {
                files.extend(walk_files(&r, Some(8)));
            }
        }
        files.sort();
        files.dedup();

        let max = ctx.cfg.max_file_size;
        let hits: Vec<(PathBuf, crate::intel::Hit)> = files
            .par_iter()
            .filter_map(|p| intel.match_file(p, max).map(|hit| (p.clone(), hit)))
            .collect();

        let mut findings = Vec::new();
        for (path, hit) in hits {
            findings.push(
                Finding::new(
                    self.id(),
                    Severity::Critical,
                    format!("File matches threat intel ({})", hit.kind),
                    "File content matches an entry in the IOC feed",
                )
                .at(ctx.disp(&path), None)
                .evidence(format!("{}:{}", hit.kind, hit.value))
                .fix("Quarantine the file, preserve the sample, and follow incident response")
                .confidence(Confidence::Certain)
                .mitre("T1204.002"),
            );
        }
        Ok(findings)
    }
}

fn walk_files(root: &Path, max_depth: Option<usize>) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut wd = WalkDir::new(root).follow_links(false);
    if let Some(d) = max_depth {
        wd = wd.max_depth(d);
    }
    for entry in wd.into_iter().filter_map(|e| e.ok()) {
        if entry.file_type().is_file() {
            out.push(entry.path().to_path_buf());
        }
        if out.len() > 500_000 {
            break;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn webshell_detects_eval() {
        let hits = webshell_hits("<?php @eval ( $_POST['x'] ); ?>");
        assert!(hits.iter().any(|(c, _, _)| *c == "eval-input"));
        assert!(hits[0].1 >= Severity::High);
    }

    #[test]
    fn webshell_ignores_clean_php() {
        let hits = webshell_hits("<?php echo htmlspecialchars($_POST['name']); ?>");
        assert!(hits.is_empty());
    }
}
