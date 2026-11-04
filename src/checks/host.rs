//! Host-level checks: accounts, listening ports, hardening state.

use crate::checks::Check;
use crate::ctx::ScanContext;
use crate::model::{Confidence, Finding, Os, Severity, SnapshotItem};
use crate::util;
use anyhow::Result;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::{Path, PathBuf};

const MAX_CONFIG: u64 = 4 * util::MB;

// ---------------------------------------------------------------- accounts

struct Account {
    name: String,
    uid: u32,
    shell: String,
    line: usize,
}

fn accounts(ctx: &ScanContext) -> Vec<Account> {
    let mut out = Vec::new();
    for (line, text) in util::read_lines(&ctx.abs("/etc/passwd"), MAX_CONFIG) {
        let t = text.trim();
        if t.is_empty() || t.starts_with('#') {
            continue;
        }
        let f: Vec<&str> = t.split(':').collect();
        if f.len() < 7 {
            continue;
        }
        if let Ok(uid) = f[2].parse::<u32>() {
            out.push(Account {
                name: f[0].to_string(),
                uid,
                shell: f[6].to_string(),
                line,
            });
        }
    }
    out
}

fn login_shell(shell: &str) -> bool {
    !shell.is_empty()
        && !shell.ends_with("nologin")
        && !shell.ends_with("/false")
        && !shell.ends_with("/sync")
        && shell != "/bin/true"
}

pub struct AccountsCheck;

impl Check for AccountsCheck {
    fn id(&self) -> &'static str {
        "host.accounts"
    }
    fn title(&self) -> &'static str {
        "Accounts and privilege configuration"
    }
    fn description(&self) -> &'static str {
        "Extra UID 0 accounts, empty passwords, writable login shells, and passwordless sudo."
    }

    fn run(&self, ctx: &ScanContext) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        let accounts = accounts(ctx);

        // 1) Extra UID 0 accounts
        let roots: Vec<&Account> = accounts.iter().filter(|a| a.uid == 0).collect();
        if roots.len() > 1 {
            for a in roots.iter().filter(|a| a.name != "root") {
                findings.push(
                    Finding::new(
                        self.id(),
                        Severity::High,
                        "Additional UID 0 account",
                        format!(
                            "Account `{}` is root-equivalent (UID 0) but is usually not in the baseline",
                            a.name
                        ),
                    )
                    .at("/etc/passwd", Some(a.line))
                    .evidence(format!("{}:x:0:…:{}", a.name, a.shell))
                    .fix("Verify the account origin; if unauthorized, lock it and review login records")
                    .confidence(Confidence::Certain)
                    .mitre("T1136.001"),
                );
            }
        }

        // 2) Login shell points to a writable/non-standard path
        for a in &accounts {
            if !login_shell(&a.shell) {
                continue;
            }
            if a.shell.starts_with("/tmp")
                || a.shell.starts_with("/var/tmp")
                || a.shell.starts_with("/dev/shm")
                || a.shell.starts_with("/home")
                || a.shell.starts_with("/Users")
            {
                findings.push(
                    Finding::new(
                        self.id(),
                        Severity::Critical,
                        "Account login shell is in a writable directory",
                        "Login runs a replaceable program, a stealthy persistence method",
                    )
                    .at("/etc/passwd", Some(a.line))
                    .evidence(format!("{} shell={}", a.name, a.shell))
                    .fix(
                        "Restore a standard shell and verify whether the account was tampered with",
                    )
                    .confidence(Confidence::Certain)
                    .mitre("T1136.001"),
                );
            }
        }

        // 3) Empty passwords in /etc/shadow (requires root)
        let shadow_path = ctx.abs("/etc/shadow");
        let shadow = util::read_text(&shadow_path, MAX_CONFIG);
        let nullok = pam_nullok(ctx);
        match &shadow {
            Some(text) => {
                let login_users: HashSet<&str> = accounts
                    .iter()
                    .filter(|a| login_shell(&a.shell))
                    .map(|a| a.name.as_str())
                    .collect();
                for (line, raw) in text.lines().enumerate() {
                    let f: Vec<&str> = raw.split(':').collect();
                    if f.len() < 2 {
                        continue;
                    }
                    if f[1].is_empty() && login_users.contains(f[0]) {
                        let (severity, title, message, fix) = match &nullok {
                            Some(file) => (
                                Severity::Critical,
                                "Account has no password and PAM allows null passwords",
                                format!(
                                    "`{}` has an empty hash; `nullok` in {} lets local login/console authenticate without a password (SSH service settings may still block it)",
                                    f[0],
                                    ctx.disp(file)
                                ),
                                "Set a password or lock the account; remove nullok if it is not required",
                            ),
                            None => (
                                Severity::High,
                                "Account has no password",
                                format!(
                                    "`{}` has an empty hash; login depends on the PAM/service configuration",
                                    f[0]
                                ),
                                "Set a password or lock the account",
                            ),
                        };
                        findings.push(
                            Finding::new(self.id(), severity, title, message)
                                .at("/etc/shadow", Some(line + 1))
                                .evidence(format!(
                                    "{}::… pam_nullok={}",
                                    f[0],
                                    if nullok.is_some() { "true" } else { "false" }
                                ))
                                .fix(fix)
                                .confidence(Confidence::Certain)
                                .mitre("T1078"),
                        );
                    }
                }
            }
            None if shadow_path.exists() => {
                findings.push(
                    Finding::new(
                        self.id(),
                        Severity::Info,
                        "Cannot read /etc/shadow",
                        "Empty-password checks require root and were not covered",
                    )
                    .at("/etc/shadow", None)
                    .fix("Re-run with sudo to cover this check")
                    .confidence(Confidence::Certain),
                );
            }
            None => {}
        }

        // 3b) macOS local accounts live in /etc/master.passwd
        if ctx.os == Os::MacOs {
            if let Some(text) = util::read_text(&ctx.abs("/etc/master.passwd"), MAX_CONFIG) {
                let login_users: HashSet<&str> = accounts
                    .iter()
                    .filter(|a| login_shell(&a.shell))
                    .map(|a| a.name.as_str())
                    .collect();
                for (line, raw) in text.lines().enumerate() {
                    let f: Vec<&str> = raw.split(':').collect();
                    if f.len() >= 2 && f[1].is_empty() && login_users.contains(f[0]) {
                        findings.push(
                            Finding::new(
                                self.id(),
                                Severity::Critical,
                                "Account has an empty password",
                                format!("`{}` can log in without a password", f[0]),
                            )
                            .at("/etc/master.passwd", Some(line + 1))
                            .fix("Set a strong password or lock the account immediately")
                            .confidence(Confidence::Certain)
                            .mitre("T1078"),
                        );
                    }
                }
            }
        }

        // 4) Passwordless sudo
        let mut sudo_files = vec![ctx.abs("/etc/sudoers")];
        sudo_files.extend(util::files_in(&ctx.abs("/etc/sudoers.d")));
        for file in sudo_files {
            for (line, text) in util::read_lines(&file, MAX_CONFIG) {
                let t = text.trim();
                if t.is_empty() || t.starts_with('#') || t.starts_with("Defaults") {
                    continue;
                }
                if !t.contains("NOPASSWD:") && !t.contains("!authenticate") {
                    continue;
                }
                let broad = t.contains("ALL=(ALL") && t.to_ascii_uppercase().contains("ALL");
                findings.push(
                    Finding::new(
                        self.id(),
                        if broad {
                            Severity::High
                        } else {
                            Severity::Medium
                        },
                        "Passwordless sudo rule",
                        if broad {
                            "Any command escalates to root without a password; a compromised account means full compromise"
                        } else {
                            "A passwordless sudo rule exists; confirm it follows least privilege"
                        },
                    )
                    .at(ctx.disp(&file), Some(line))
                    .evidence(t)
                    .fix("Remove unnecessary NOPASSWD or restrict it to specific commands")
                    .confidence(Confidence::Likely)
                    .mitre("T1548.003"),
                );
            }
        }

        // 5) macOS: extra UID 0 accounts in OpenDirectory
        if ctx.os == Os::MacOs && ctx.is_local() && util::command_exists("dscl") {
            if let Some(out) = util::run("dscl", &[".", "-list", "/Users", "UniqueID"]) {
                for line in out.lines() {
                    let mut it = line.split_whitespace();
                    if let (Some(name), Some(uid)) = (it.next(), it.next()) {
                        if uid == "0" && name != "root" {
                            findings.push(
                                Finding::new(
                                    self.id(),
                                    Severity::High,
                                    "UID 0 account exists in OpenDirectory",
                                    format!("`{name}` is root-equivalent"),
                                )
                                .at("/Local/Default/Users", None)
                                .evidence(line.trim())
                                .fix("Verify the account origin; disable it if unauthorized")
                                .confidence(Confidence::Certain)
                                .mitre("T1136.001"),
                            );
                        }
                    }
                }
            }
        }

        Ok(findings)
    }
}

// ---------------------------------------------------------------- listeners

#[derive(Debug, Clone)]
pub struct Listener {
    pub proto: &'static str,
    pub addr: String,
    pub port: u16,
    pub pid: Option<u32>,
    pub exe: Option<String>,
    pub uid: Option<u32>,
}

fn parse_proc_addr(s: &str) -> Option<(String, u16)> {
    let (ip, port) = s.split_once(':')?;
    let port = u16::from_str_radix(port, 16).ok()?;
    let addr = if ip.len() == 8 {
        let v = u32::from_str_radix(ip, 16).ok()?;
        std::net::Ipv4Addr::from(v.to_le_bytes()).to_string()
    } else if ip.len() == 32 {
        let mut bytes = [0u8; 16];
        for i in 0..4 {
            let v = u32::from_str_radix(&ip[i * 8..i * 8 + 8], 16).ok()?;
            bytes[i * 4..i * 4 + 4].copy_from_slice(&v.to_le_bytes());
        }
        std::net::Ipv6Addr::from(bytes).to_string()
    } else {
        format!("[{ip}]")
    };
    Some((addr, port))
}

fn proc_net(path: &Path, _proto: &'static str, listen_state: &str) -> Vec<(String, u16, u64)> {
    let text = match util::read_text(path, 8 * util::MB) {
        Some(t) => t,
        None => return Vec::new(),
    };
    let mut out = Vec::new();
    for line in text.lines().skip(1) {
        let f: Vec<&str> = line.split_whitespace().collect();
        // sl local_address rem_address st ... uid timeout inode
        if f.len() < 10 || f[3] != listen_state {
            continue;
        }
        if let Some((addr, port)) = parse_proc_addr(f[1]) {
            if let Ok(inode) = f[9].parse::<u64>() {
                if inode != 0 {
                    out.push((addr, port, inode));
                }
            }
        }
    }
    out
}

fn proc_uid(pid: u32) -> Option<u32> {
    let status = util::read_text(&PathBuf::from(format!("/proc/{pid}/status")), 256 * 1024)?;
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("Uid:") {
            return rest.split_whitespace().next()?.parse().ok();
        }
    }
    None
}

fn socket_owners(inodes: &HashSet<u64>) -> HashMap<u64, (u32, String, u32)> {
    let mut map = HashMap::new();
    let proc_dir = match std::fs::read_dir("/proc") {
        Ok(d) => d,
        Err(_) => return map,
    };
    for entry in proc_dir.flatten() {
        let pid: u32 = match entry.file_name().to_string_lossy().parse() {
            Ok(p) => p,
            Err(_) => continue,
        };
        let fd_dir = Path::new("/proc").join(pid.to_string()).join("fd");
        let mut found = Vec::new();
        if let Ok(fds) = std::fs::read_dir(&fd_dir) {
            for fd in fds.flatten() {
                if let Ok(target) = std::fs::read_link(fd.path()) {
                    let t = target.to_string_lossy();
                    if let Some(rest) = t.strip_prefix("socket:[") {
                        if let Some(num) = rest.strip_suffix(']') {
                            if let Ok(inode) = num.parse::<u64>() {
                                if inodes.contains(&inode) {
                                    found.push(inode);
                                }
                            }
                        }
                    }
                }
            }
        }
        if found.is_empty() {
            continue;
        }
        let exe = std::fs::read_link(format!("/proc/{pid}/exe"))
            .ok()
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_default();
        let uid = proc_uid(pid).unwrap_or(0);
        for ino in found {
            map.entry(ino).or_insert((pid, exe.clone(), uid));
        }
    }
    map
}

fn linux_listeners() -> Vec<Listener> {
    let mut raw = Vec::new();
    raw.extend(
        proc_net(Path::new("/proc/net/tcp"), "tcp", "0A")
            .into_iter()
            .map(|(a, p, i)| (a, p, i, "tcp")),
    );
    raw.extend(
        proc_net(Path::new("/proc/net/tcp6"), "tcp6", "0A")
            .into_iter()
            .map(|(a, p, i)| (a, p, i, "tcp6")),
    );
    raw.extend(
        proc_net(Path::new("/proc/net/udp"), "udp", "07")
            .into_iter()
            .map(|(a, p, i)| (a, p, i, "udp")),
    );
    raw.extend(
        proc_net(Path::new("/proc/net/udp6"), "udp6", "07")
            .into_iter()
            .map(|(a, p, i)| (a, p, i, "udp6")),
    );

    let inodes: HashSet<u64> = raw.iter().map(|r| r.2).collect();
    let owners = socket_owners(&inodes);

    raw.into_iter()
        .map(|(addr, port, inode, proto)| {
            let owner = owners.get(&inode);
            Listener {
                proto,
                addr,
                port,
                pid: owner.map(|(p, _, _)| *p),
                exe: owner.map(|(_, e, _)| e.clone()).filter(|e| !e.is_empty()),
                uid: owner.map(|(_, _, u)| *u),
            }
        })
        .collect()
}

fn mac_listeners() -> Vec<Listener> {
    let out = match util::run("lsof", &["-nP", "-iTCP", "-sTCP:LISTEN", "-Fpcun"]) {
        Some(o) => o,
        None => return Vec::new(),
    };
    let mut pid = None;
    let mut uid = None;
    let mut listeners = Vec::new();
    for line in out.lines() {
        let mut chars = line.chars();
        let tag = match chars.next() {
            Some(c) => c,
            None => continue,
        };
        let val = chars.as_str();
        match tag {
            'p' => pid = val.trim().parse::<u32>().ok(),
            'u' => uid = val.trim().parse::<u32>().ok(),
            'n' => {
                let (addr, port) = match val.rsplit_once(':') {
                    Some((a, p)) => (a.to_string(), p.trim().parse::<u16>().ok()),
                    None => continue,
                };
                if let Some(port) = port {
                    let exe = pid.and_then(|p| {
                        util::run("ps", &["-p", &p.to_string(), "-o", "comm="])
                            .map(|s| s.trim().to_string())
                            .filter(|s| !s.is_empty())
                    });
                    listeners.push(Listener {
                        proto: "tcp",
                        addr,
                        port,
                        pid,
                        exe,
                        uid,
                    });
                }
            }
            _ => {}
        }
    }
    listeners
}

pub fn collect_listeners(ctx: &ScanContext) -> Vec<Listener> {
    if !ctx.is_local() {
        return Vec::new();
    }
    let mut l = match ctx.os {
        Os::Linux => linux_listeners(),
        Os::MacOs => mac_listeners(),
    };
    l.sort_by(|a, b| (a.port, a.proto).cmp(&(b.port, b.proto)));
    l.dedup_by(|a, b| a.port == b.port && a.proto == b.proto && a.exe == b.exe);
    l
}

/// System users running root-owned binaries from system directories commonly
/// bind low ports through capabilities (systemd-resolved:53, networkd:546,
/// dnsmasq:53, ...). Those are not post-exploitation daemons.
fn is_system_service(uid: u32, exe: &str) -> bool {
    uid < 1000 && is_system_path(exe) && util::owner_uid(Path::new(exe)) == Some(0)
}

fn is_system_path(exe: &str) -> bool {
    const PREFIXES: &[&str] = &[
        "/usr/lib/systemd/",
        "/lib/systemd/",
        "/usr/bin/",
        "/usr/sbin/",
        "/bin/",
        "/sbin/",
    ];
    PREFIXES.iter().any(|p| exe.starts_with(p))
}

fn suspicious_exe(exe: &str) -> Option<(Severity, &'static str)> {
    if exe.contains("(deleted)") {
        return Some((
            Severity::High,
            "Listener executable has been deleted (running in memory)",
        ));
    }
    let p = exe.to_ascii_lowercase();
    if p.starts_with("/tmp/") || p.starts_with("/var/tmp/") || p.starts_with("/dev/shm/") {
        return Some((
            Severity::High,
            "Listener runs from a world-writable directory",
        ));
    }
    None
}

pub struct ListenersCheck;

impl Check for ListenersCheck {
    fn id(&self) -> &'static str {
        "host.listeners"
    }
    fn title(&self) -> &'static str {
        "Listening ports and processes"
    }
    fn description(&self) -> &'static str {
        "Listeners running from temp dirs or deleted executables, and non-root privileged ports."
    }

    fn skip_reason(&self, ctx: &ScanContext) -> Option<String> {
        if ctx.is_local() {
            None
        } else {
            Some("live listeners are only visible on the running host; image scans skip port/process mapping".into())
        }
    }

    fn run(&self, ctx: &ScanContext) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        if !ctx.is_local() {
            return Ok(findings);
        }
        let listeners = collect_listeners(ctx);
        let mut unmapped = 0usize;

        for l in &listeners {
            let exe = match &l.exe {
                Some(e) => e.clone(),
                None => {
                    unmapped += 1;
                    continue;
                }
            };

            if let Some((sev, desc)) = suspicious_exe(&exe) {
                findings.push(
                    Finding::new(self.id(), sev, desc, "This process should not listen as a resident service")
                        .at(exe.clone(), None)
                        .evidence(format!(
                            "{} {}:{} pid={}",
                            l.proto,
                            l.addr,
                            l.port,
                            l.pid.unwrap_or(0)
                        ))
                        .fix("Verify the process origin; if unauthorized, terminate it and preserve the sample")
                        .confidence(Confidence::Likely)
                        .mitre("T1571"),
                );
                continue;
            }

            // Non-root process on a privileged port usually relies on a capability; verify it
            if let Some(uid) = l.uid {
                if uid != 0 && l.port < 1024 && !is_system_service(uid, &exe) {
                    findings.push(
                        Finding::new(
                            self.id(),
                            Severity::High,
                            "Non-root process listening on a privileged port",
                            "It holds a capability to bind a low port, possibly a post-exploitation daemon",
                        )
                        .at(exe.clone(), None)
                        .evidence(format!(
                            "{} {}:{} pid={} uid={}",
                            l.proto,
                            l.addr,
                            l.port,
                            l.pid.unwrap_or(0),
                            uid
                        ))
                        .fix("Verify the service identity and bind mechanism (systemd socket or setcap)")
                        .confidence(Confidence::Likely)
                        .mitre("T1571"),
                    );
                }
            }

            // Executable path is missing (PID reuse or deleted payload)
            if !exe.starts_with('[') && !Path::new(&exe).exists() {
                findings.push(
                    Finding::new(
                        self.id(),
                        Severity::Medium,
                        "Listener executable does not exist",
                        "The payload may have been deleted, or process details are inaccessible",
                    )
                    .at(exe.clone(), None)
                    .evidence(format!(
                        "{} {}:{} pid={}",
                        l.proto,
                        l.addr,
                        l.port,
                        l.pid.unwrap_or(0)
                    ))
                    .fix("Confirm with ps / lsof and memory forensics")
                    .confidence(Confidence::Heuristic)
                    .mitre("T1070.004"),
                );
            }
        }

        if unmapped > 0 && !ctx.privileged {
            findings.push(
                Finding::new(
                    self.id(),
                    Severity::Info,
                    "Some listening ports cannot be mapped to processes",
                    format!("{unmapped} listening sockets belong to other users; root is required to map them"),
                )
                .at("/proc/net/tcp", None)
                .fix("Re-run with sudo")
                .confidence(Confidence::Certain),
            );
        }

        Ok(findings)
    }
}

pub fn snapshot(ctx: &ScanContext) -> Vec<SnapshotItem> {
    collect_listeners(ctx)
        .into_iter()
        .filter(|l| l.pid.is_some())
        .map(|l| {
            let exe = l.exe.unwrap_or_else(|| "?".into());
            SnapshotItem {
                key: format!("listen|{}|{}|{}|{}", l.proto, l.addr, l.port, exe),
                kind: "listener".into(),
                path: exe.clone(),
                detail: format!("{} {}:{}", l.proto, l.addr, l.port),
            }
        })
        .collect()
}

// ---------------------------------------------------------------- hardening

/// Path of the PAM config that enables empty passwords, if any.
fn pam_nullok(ctx: &ScanContext) -> Option<std::path::PathBuf> {
    for file in [
        "/etc/pam.d/system-auth",
        "/etc/pam.d/password-auth",
        "/etc/pam.d/system-login",
        "/etc/pam.d/system-local-login",
        "/etc/pam.d/common-auth",
        "/etc/pam.d/common-password",
        "/etc/pam.d/login",
    ] {
        if let Some(text) = ctx.read(file, 1024 * 1024) {
            if pam_text_allows_nullok(&text) {
                return Some(ctx.abs(file));
            }
        }
    }
    None
}

fn pam_text_allows_nullok(text: &str) -> bool {
    text.lines().any(|line| {
        let line = line.trim();
        !line.starts_with('#')
            && line.contains("pam_unix.so")
            && line.split_whitespace().any(|tok| tok == "nullok")
    })
}

fn secure_boot_state() -> Option<bool> {
    let dir = Path::new("/sys/firmware/efi/efivars");
    for entry in std::fs::read_dir(dir).ok()?.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        if name.starts_with("SecureBoot-") {
            let data = std::fs::read(entry.path()).ok()?;
            // EFI variable: 4-byte attributes header followed by the value.
            return data.get(4).map(|b| *b == 1);
        }
    }
    None
}

fn read_num(path: &str) -> Option<u64> {
    util::read_text(Path::new(path), 4096)?.trim().parse().ok()
}

pub struct HardeningCheck;

impl Check for HardeningCheck {
    fn id(&self) -> &'static str {
        "host.hardening"
    }
    fn title(&self) -> &'static str {
        "Kernel and system hardening state"
    }
    fn description(&self) -> &'static str {
        "Kernel taint, ASLR, SELinux/AppArmor, Secure Boot, lockdown, ptrace_scope, auditd; macOS SIP/Gatekeeper/FileVault/XProtect."
    }

    fn run(&self, ctx: &ScanContext) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        if !ctx.is_local() {
            return Ok(findings);
        }

        match ctx.os {
            Os::Linux => {
                // Kernel taint: forced or unsigned modules are common rootkit traces
                if let Some(taint) = read_num("/proc/sys/kernel/tainted") {
                    let checks: &[(u64, Severity, &str)] = &[
                        (
                            0x2,
                            Severity::High,
                            "kernel module was force-loaded (taint bit 1)",
                        ),
                        (
                            0x400,
                            Severity::High,
                            "kernel loaded an unsigned module (taint bit 10)",
                        ),
                        (
                            0x1,
                            Severity::Medium,
                            "kernel loaded a proprietary module (taint bit 0)",
                        ),
                        (
                            0x200,
                            Severity::Low,
                            "kernel loaded an out-of-tree module (taint bit 9)",
                        ),
                        (
                            0x8000,
                            Severity::Low,
                            "kernel loaded a staging driver (taint bit 15)",
                        ),
                    ];
                    for (bit, sev, desc) in checks {
                        if taint & bit != 0 {
                            findings.push(
                                Finding::new(self.id(), *sev, "Abnormal kernel taint flags", *desc)
                                    .at("/proc/sys/kernel/tainted", None)
                                    .evidence(format!("tainted=0x{taint:x}"))
                                    .fix("Verify module origin with lsmod / dmesg")
                                    .confidence(Confidence::Likely)
                                    .mitre("T1547.006"),
                            );
                        }
                    }
                }
                if let Some(v) = read_num("/proc/sys/kernel/randomize_va_space") {
                    if v != 2 {
                        findings.push(
                            Finding::new(
                                self.id(),
                                Severity::Low,
                                "ASLR is not fully enabled",
                                format!("randomize_va_space={v}, expected 2"),
                            )
                            .at("/proc/sys/kernel/randomize_va_space", None)
                            .fix("sysctl -w kernel.randomize_va_space=2")
                            .confidence(Confidence::Certain)
                            .mitre("T1553"),
                        );
                    }
                }

                if let Some(v) = util::read_text(Path::new("/sys/fs/selinux/enforce"), 4096) {
                    if v.trim() == "0" {
                        findings.push(
                            Finding::new(
                                self.id(),
                                Severity::Medium,
                                "SELinux is in permissive mode",
                                "Policy violations are logged but not enforced",
                            )
                            .at("/sys/fs/selinux/enforce", None)
                            .fix("setenforce 1 and fix the resulting denials")
                            .confidence(Confidence::Certain)
                            .mitre("T1562.001"),
                        );
                    }
                }

                if let Some(v) =
                    util::read_text(Path::new("/sys/module/apparmor/parameters/enabled"), 4096)
                {
                    if v.trim().eq_ignore_ascii_case("n") {
                        findings.push(
                            Finding::new(
                                self.id(),
                                Severity::Medium,
                                "AppArmor is disabled",
                                "The kernel module is present but confinement is turned off",
                            )
                            .at("/sys/module/apparmor/parameters/enabled", None)
                            .fix("Enable AppArmor and load the distribution profiles")
                            .confidence(Confidence::Certain)
                            .mitre("T1562.001"),
                        );
                    }
                }

                if secure_boot_state() == Some(false) {
                    findings.push(
                        Finding::new(
                            self.id(),
                            Severity::Medium,
                            "Secure Boot is disabled",
                            "Unsigned boot components can be loaded",
                        )
                        .at("/sys/firmware/efi/efivars", None)
                        .fix("Enable Secure Boot in firmware and sign the boot chain")
                        .confidence(Confidence::Certain)
                        .mitre("T1542.001"),
                    );
                }

                if let Some(v) = util::read_text(Path::new("/sys/kernel/security/lockdown"), 4096) {
                    if v.contains("[none]") {
                        findings.push(
                            Finding::new(
                                self.id(),
                                Severity::Medium,
                                "Kernel lockdown is disabled",
                                "Lockdown can block direct kernel memory and module access",
                            )
                            .at("/sys/kernel/security/lockdown", None)
                            .fix("Boot with lockdown=integrity or lockdown=confidentiality")
                            .confidence(Confidence::Certain)
                            .mitre("T1562.001"),
                        );
                    }
                }

                if let Some(v) = read_num("/proc/sys/kernel/yama/ptrace_scope") {
                    if v == 0 {
                        findings.push(
                            Finding::new(
                                self.id(),
                                Severity::Low,
                                "Yama ptrace scope is unrestricted",
                                "Any process can ptrace another process in the same user",
                            )
                            .at("/proc/sys/kernel/yama/ptrace_scope", None)
                            .fix("sysctl -w kernel.yama.ptrace_scope=1")
                            .confidence(Confidence::Certain)
                            .mitre("T1055.008"),
                        );
                    }
                }

                if let Some(text) = util::read_text(Path::new("/etc/audit/auditd.conf"), 256 * 1024)
                {
                    for line in text.lines() {
                        let t = line.trim();
                        let (key, value) = match t.split_once('=') {
                            Some(v) => (v.0.trim(), v.1.trim()),
                            None => continue,
                        };
                        if matches!(key, "space_left_action" | "admin_space_left_action")
                            && matches!(value.to_ascii_lowercase().as_str(), "ignore" | "suspend")
                        {
                            findings.push(
                                Finding::new(
                                    self.id(),
                                    Severity::Medium,
                                    "auditd stops or ignores disk pressure",
                                    format!("{key}={value} can silently drop audit events"),
                                )
                                .at("/etc/audit/auditd.conf", None)
                                .evidence(t)
                                .fix("Use rotate/exec/single so audit availability is preserved")
                                .confidence(Confidence::Likely)
                                .mitre("T1562.002"),
                            );
                        }
                    }
                }
            }
            Os::MacOs => {
                // SIP
                if let Some(out) = util::run("csrutil", &["status"]) {
                    if out.to_ascii_lowercase().contains("disabled") {
                        findings.push(
                            Finding::new(
                                self.id(),
                                Severity::High,
                                "System Integrity Protection (SIP) is disabled",
                                "With SIP off, system directories can be modified, a common prerequisite for persistent backdoors",
                            )
                            .at("/System/Library", None)
                            .evidence(out.trim())
                            .fix("Boot into Recovery and run csrutil enable")
                            .confidence(Confidence::Certain)
                            .mitre("T1562.001"),
                        );
                    }
                }
                // Gatekeeper
                if let Some(out) = util::run("spctl", &["--status"]) {
                    if out.to_ascii_lowercase().contains("disabled") {
                        findings.push(
                            Finding::new(
                                self.id(),
                                Severity::Medium,
                                "Gatekeeper is disabled",
                                "Unsigned apps run directly, lowering the bar for malware",
                            )
                            .at("/var/db/SystemPolicy", None)
                            .evidence(out.trim())
                            .fix("spctl --global-enable")
                            .confidence(Confidence::Certain)
                            .mitre("T1553.001"),
                        );
                    }
                }
                // FileVault
                if let Some(out) = util::run("fdesetup", &["status"]) {
                    if out.to_ascii_lowercase().contains("off") {
                        findings.push(
                            Finding::new(
                                self.id(),
                                Severity::Medium,
                                "FileVault is not enabled",
                                "The disk is unencrypted; offline access bypasses login controls",
                            )
                            .at("/", None)
                            .evidence(out.trim())
                            .fix("Enable FileVault")
                            .confidence(Confidence::Certain)
                            .mitre("T1005"),
                        );
                    }
                }
                // XProtect presence
                let xp = Path::new("/Library/Apple/System/Library/CoreServices/XProtect.bundle");
                if !xp.exists() {
                    findings.push(
                        Finding::new(
                            self.id(),
                            Severity::Medium,
                            "XProtect component not found",
                            "The built-in malware signature bundle is missing and may have been removed",
                        )
                        .at(xp.to_string_lossy().into_owned(), None)
                        .fix("Reinstall system updates or run software update")
                        .confidence(Confidence::Likely)
                        .mitre("T1562.001"),
                    );
                }
            }
        }

        Ok(findings)
    }
}

#[allow(dead_code)]
fn dedupe_paths(v: Vec<PathBuf>) -> Vec<PathBuf> {
    let mut v = v;
    v.sort();
    v.dedup();
    v
}

#[allow(dead_code)]
fn by_port(l: &[Listener]) -> BTreeMap<u16, Vec<&Listener>> {
    let mut m: BTreeMap<u16, Vec<&Listener>> = BTreeMap::new();
    for x in l {
        m.entry(x.port).or_default().push(x);
    }
    m
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proc_addr_v4() {
        let (addr, port) = parse_proc_addr("0100007F:1F90").unwrap();
        assert_eq!(addr, "127.0.0.1");
        assert_eq!(port, 8080);
    }

    #[test]
    fn proc_addr_v6_any() {
        let (addr, port) = parse_proc_addr("00000000000000000000000000000000:0016").unwrap();
        assert_eq!(addr, "::");
        assert_eq!(port, 22);
    }

    #[test]
    fn detects_pam_nullok() {
        assert!(pam_text_allows_nullok(
            "auth required pam_unix.so try_first_pass nullok"
        ));
        assert!(!pam_text_allows_nullok(
            "# auth required pam_unix.so nullok"
        ));
        assert!(!pam_text_allows_nullok("auth required pam_unix.so"));
    }

    #[test]
    fn login_shell_filter() {
        assert!(login_shell("/bin/bash"));
        assert!(!login_shell("/usr/sbin/nologin"));
        assert!(!login_shell("/bin/false"));
    }

    #[test]
    fn system_service_paths() {
        assert!(is_system_path("/usr/lib/systemd/systemd-resolved"));
        assert!(is_system_path("/usr/bin/dnsmasq"));
        assert!(!is_system_path("/tmp/evil"));
        assert!(!is_system_path("/usr/local/bin/custom"));
    }

    #[test]
    fn deleted_exe_is_suspicious() {
        assert!(suspicious_exe("/usr/bin/foo (deleted)").is_some());
        assert!(suspicious_exe("/tmp/.x/x").is_some());
        assert!(suspicious_exe("/usr/sbin/sshd").is_none());
    }
}
