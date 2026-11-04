//! Optional strace parsing: behavior invisible to file diffs (egress attempts, exec chain, kernel ops).
//!
//! strace is optional: the sandbox works without it, but the report states that egress targets were not observed.
//! The parser only depends on the text format, so it is unit-tested with fixtures on machines without strace.

use crate::model::{Confidence, Finding, Severity};
use crate::util;
use std::collections::BTreeSet;
use std::path::Path;

const SUSPICIOUS_PORTS: &[u16] = &[4444, 1337, 31337, 6667, 9001, 4443, 2323, 6666];

const INTERESTING_BINS: &[&str] = &[
    "sh",
    "bash",
    "dash",
    "zsh",
    "perl",
    "python",
    "python3",
    "ruby",
    "nc",
    "ncat",
    "netcat",
    "curl",
    "wget",
    "base64",
    "xxd",
    "openssl",
    "chmod",
    "chattr",
    "crontab",
    "systemctl",
    "launchctl",
    "sudo",
    "su",
    "ssh",
    "scp",
    "socat",
];

/// strace is an optional enhancement, not a hard dependency.
pub fn available() -> bool {
    util::command_exists("strace")
}

pub struct TraceResult {
    pub findings: Vec<Finding>,
    pub events: Vec<String>,
    pub lines: usize,
}

fn strip_prefix(line: &str) -> &str {
    let mut s = line.trim_start();
    if let Some(rest) = s.strip_prefix("[pid ") {
        if let Some(end) = rest.find(']') {
            s = rest[end + 1..].trim_start();
        }
    } else {
        // -f mode prefixes lines with "1234  "
        let digits = s.chars().take_while(|c| c.is_ascii_digit()).count();
        if digits > 0 && s[digits..].starts_with(' ') {
            s = s[digits..].trim_start();
        }
    }
    s
}

fn between<'a>(s: &'a str, start: &str, end: &str) -> Option<&'a str> {
    let i = s.find(start)? + start.len();
    let j = s[i..].find(end)?;
    Some(&s[i..i + j])
}

fn parse_connect(line: &str) -> Option<(String, u16)> {
    if !line.contains("connect(") || line.contains("AF_UNIX") {
        return None;
    }
    let port: u16 = between(line, "sin_port=htons(", ")")?.parse().ok()?;
    let ip = between(line, "sin_addr=inet_addr(\"", "\"")
        .or_else(|| between(line, "inet_pton(AF_INET6, \"", "\""))?
        .to_string();
    Some((ip, port))
}

fn is_local_addr(ip: &str) -> bool {
    ip.starts_with("127.")
        || ip == "0.0.0.0"
        || ip == "::"
        || ip == "::1"
        || ip.starts_with("::ffff:127.")
}

fn first_string_arg(s: &str) -> Option<&str> {
    let i = s.find('"')? + 1;
    let j = s[i..].find('"')?;
    Some(&s[i..i + j])
}

fn is_persistence_path(p: &str) -> bool {
    p.starts_with("/etc/cron")
        || p.starts_with("/etc/systemd")
        || p.starts_with("/var/spool/cron")
        || p == "/etc/ld.so.preload"
        || p.starts_with("/etc/ld.so.conf")
        || p.starts_with("/etc/modprobe.d")
        || p.starts_with("/etc/profile")
        || p.starts_with("/etc/sudoers")
        || p.starts_with("/etc/pam.d")
        || p.starts_with("/home/sandbox/.ssh")
        || p.starts_with("/home/sandbox/.config/systemd")
        || p.starts_with("/home/sandbox/Library/LaunchAgents")
}

pub fn parse_file(path: &Path) -> TraceResult {
    let text = util::read_text(path, 64 * util::MB).unwrap_or_default();
    let mut findings: Vec<Finding> = Vec::new();
    let mut events = Vec::new();
    let mut seen_codes: BTreeSet<(String, String)> = BTreeSet::new();
    let mut execs: BTreeSet<String> = BTreeSet::new();
    let mut kernel_ops: BTreeSet<String> = BTreeSet::new();
    let mut deleted: BTreeSet<String> = BTreeSet::new();
    let mut connects: BTreeSet<(String, u16)> = BTreeSet::new();
    let mut lines = 0usize;

    for raw in text.lines() {
        lines += 1;
        let line = strip_prefix(raw);
        if line.is_empty() {
            continue;
        }

        if let Some((ip, port)) = parse_connect(line) {
            if !is_local_addr(&ip) && connects.insert((ip.clone(), port)) {
                let suspicious = SUSPICIOUS_PORTS.contains(&port);
                let (sev, title) = if suspicious {
                    (
                        Severity::Critical,
                        "Attempted connection to a common C2/reverse-shell port",
                    )
                } else if port == 80 || port == 443 {
                    (
                        Severity::Medium,
                        "Attempted connection to an external web service",
                    )
                } else {
                    (
                        Severity::High,
                        "Attempted connection to an external address",
                    )
                };
                let key = ("sandbox.trace.net".to_string(), format!("{ip}:{port}"));
                if seen_codes.insert(key) {
                    findings.push(
                        Finding::new("sandbox.trace.net", sev, title, "Egress is isolated by the network namespace; the connection never completes")
                            .at("/proc/net", None)
                            .evidence(format!("connect {ip}:{port}"))
                            .fix("Confirm the address is a business dependency; otherwise query it against C2 intelligence")
                            .confidence(Confidence::Likely)
                            .mitre("T1071"),
                    );
                }
            }
            continue;
        }

        if line.starts_with("execve(") || line.starts_with("execveat(") {
            if let Some(arg) = first_string_arg(line) {
                let base = Path::new(arg)
                    .file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_else(|| arg.to_string());
                execs.insert(base);
            }
            continue;
        }

        for op in ["init_module(", "finit_module(", "bpf(", "ptrace("] {
            if line.starts_with(op) || line.contains(&format!(" {op}")) {
                kernel_ops.insert(op.trim_end_matches('(').to_string());
            }
        }
        if line.starts_with("mount(") {
            kernel_ops.insert("mount".into());
        }

        if line.starts_with("unlink(")
            || line.starts_with("unlinkat(")
            || line.starts_with("rename(")
        {
            if let Some(arg) = first_string_arg(line) {
                if is_persistence_path(arg) {
                    deleted.insert(arg.to_string());
                }
            }
        }
    }

    if !connects.is_empty() {
        events.push(format!(
            "egress attempts: {} destination(s)",
            connects.len()
        ));
    }
    if !execs.is_empty() {
        events.push(format!(
            "execve: {}",
            execs.iter().cloned().collect::<Vec<_>>().join(", ")
        ));
    }
    if !kernel_ops.is_empty() {
        events.push(format!(
            "kernel/injection operations: {}",
            kernel_ops.iter().cloned().collect::<Vec<_>>().join(", ")
        ));
    }

    let interesting: Vec<String> = execs
        .iter()
        .filter(|b| INTERESTING_BINS.contains(&b.as_str()))
        .cloned()
        .collect();
    if !interesting.is_empty() {
        let high = interesting.iter().any(|b| {
            matches!(
                b.as_str(),
                "nc" | "ncat" | "netcat" | "base64" | "socat" | "xxd" | "openssl"
            )
        });
        findings.push(
            Finding::new(
                "sandbox.trace.exec",
                if high { Severity::High } else { Severity::Medium },
                "Shell interpreter or download/encoding tool executed in the sandbox",
                format!("observed in the exec chain: {}", interesting.join(", ")),
            )
            .at("/proc", None)
            .evidence(interesting.join(" "))
            .fix("Inspect arguments to determine whether a stage-2 payload was downloaded or decoded")
            .confidence(Confidence::Heuristic)
            .mitre("T1059.004"),
        );
    }

    if !kernel_ops.is_empty() {
        findings.push(
            Finding::new(
                "sandbox.trace.kernel",
                Severity::High,
                "Attempted kernel/process injection operations",
                "The sample invoked mount/ptrace/module/bpf and similar syscalls",
            )
            .at("/proc", None)
            .evidence(kernel_ops.iter().cloned().collect::<Vec<_>>().join(", "))
            .fix("Re-run in a microVM or dedicated analysis VM; do not repeat in a shared-kernel sandbox")
            .confidence(Confidence::Likely)
            .mitre("T1611"),
        );
    }

    if !deleted.is_empty() {
        findings.push(
            Finding::new(
                "sandbox.trace.delete",
                Severity::Medium,
                "Attempted deletion of persistence/system config files",
                "May be anti-forensics or cleanup of installer leftovers",
            )
            .at(
                deleted
                    .iter()
                    .next()
                    .cloned()
                    .unwrap_or_else(|| "/etc".into()),
                None,
            )
            .evidence(deleted.iter().cloned().collect::<Vec<_>>().join(", "))
            .fix("Confirm intent; restore from the package manager if needed")
            .confidence(Confidence::Heuristic)
            .mitre("T1070.004"),
        );
    }

    TraceResult {
        findings,
        events,
        lines,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"
1234  connect(3, {sa_family=AF_INET, sin_port=htons(4444), sin_addr=inet_addr("203.0.113.9")}, 16) = -1 EINPROGRESS
1234  connect(4, {sa_family=AF_INET, sin_port=htons(443), sin_addr=inet_addr("127.0.0.1")}, 16) = -1 ECONNREFUSED
1234  execve("/usr/bin/curl", ["curl", "http://x"], 0x0) = 0
[pid 1235] execve("/bin/sh", ["sh", "-c", "id"], 0x0) = 0
1234  openat(AT_FDCWD, "/etc/cron.d/x", O_WRONLY|O_CREAT, 0666) = 3
1234  unlink("/etc/ld.so.preload") = 0
1234  ptrace(PTRACE_TRACEME, 0, NULL, NULL) = 0
1234  execve("/usr/bin/ps", ["ps"], 0x0) = 0
"#;

    #[test]
    fn parses_network_and_exec() {
        let dir = std::env::temp_dir().join(format!("warden-trace-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("trace.log");
        std::fs::write(&p, SAMPLE).unwrap();
        let r = parse_file(&p);
        assert!(r
            .findings
            .iter()
            .any(|f| f.check == "sandbox.trace.net" && f.severity == Severity::Critical));
        // Loopback connections must not produce findings
        assert!(!r
            .findings
            .iter()
            .any(|f| f.evidence.as_deref() == Some("connect 127.0.0.1:443")));
        assert!(r.findings.iter().any(|f| f.check == "sandbox.trace.exec"));
        assert!(r.findings.iter().any(|f| f.check == "sandbox.trace.kernel"));
        assert!(r.findings.iter().any(|f| f.check == "sandbox.trace.delete"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn pid_prefix_forms() {
        assert_eq!(strip_prefix("1234  connect(3"), "connect(3");
        assert_eq!(strip_prefix("[pid 1234] connect(3"), "connect(3");
    }
}
