//! SSH backdoors: forced commands in authorized_keys, risky sshd settings, host key permissions.

use crate::checks::Check;
use crate::ctx::ScanContext;
use crate::model::{Confidence, Finding, Os, Severity};
use crate::util;
use anyhow::Result;
use sha2::{Digest, Sha256};
use std::path::PathBuf;

const MAX_CONFIG: u64 = 2 * util::MB;

const KEY_TYPES: &[&str] = &[
    "ssh-rsa",
    "ssh-dss",
    "ssh-ed25519",
    "ecdsa-sha2-nistp256",
    "ecdsa-sha2-nistp384",
    "ecdsa-sha2-nistp521",
    "sk-ssh-ed25519@openssh.com",
    "sk-ecdsa-sha2-nistp256@openssh.com",
];

#[derive(Debug, Clone)]
pub struct AuthorizedKey {
    pub file: PathBuf,
    pub line: usize,
    pub options: String,
    pub kind: String,
    /// Stable fingerprint for baselines (no comment or line number)
    pub fingerprint: String,
    pub comment: String,
}

fn sha256_hex(s: &str) -> String {
    let mut h = Sha256::new();
    h.update(s.as_bytes());
    format!("{:x}", h.finalize())
}

fn authorized_key_files(ctx: &ScanContext) -> Vec<PathBuf> {
    let mut v = Vec::new();
    // root's authorized_keys is the highest-value target; always inspect it
    v.push(ctx.abs("/root/.ssh/authorized_keys"));
    if ctx.os == Os::MacOs {
        v.push(ctx.abs("/var/root/.ssh/authorized_keys"));
    }
    if ctx.user_scope {
        v.push(ctx.home_abs().join(".ssh/authorized_keys"));
    }
    // Other users (usually require root to read)
    for base in ["/home", "/Users"] {
        let dir = ctx.abs(base);
        if let Ok(rd) = std::fs::read_dir(&dir) {
            let mut users: Vec<PathBuf> = rd.filter_map(|e| e.ok()).map(|e| e.path()).collect();
            users.sort();
            for u in users {
                if u.is_dir() {
                    v.push(u.join(".ssh/authorized_keys"));
                }
            }
        }
    }
    v.retain(|p| p.is_file());
    v.sort();
    v.dedup();
    v
}

pub fn authorized_key_entries(ctx: &ScanContext) -> Vec<AuthorizedKey> {
    let mut out = Vec::new();
    for file in authorized_key_files(ctx) {
        for (line, text) in util::read_lines(&file, MAX_CONFIG) {
            let t = text.trim();
            if t.is_empty() || t.starts_with('#') {
                continue;
            }
            let tokens: Vec<&str> = t.split_whitespace().collect();
            let key_idx = match tokens.iter().position(|tok| KEY_TYPES.contains(tok)) {
                Some(i) => i,
                None => continue,
            };
            let kind = tokens[key_idx].to_string();
            let body = tokens.get(key_idx + 1).copied().unwrap_or("");
            let comment = tokens[key_idx + 2..].join(" ");
            out.push(AuthorizedKey {
                file: file.clone(),
                line,
                options: tokens[..key_idx].join(" "),
                kind: kind.clone(),
                fingerprint: sha256_hex(&format!("{kind} {body}")),
                comment,
            });
        }
    }
    out
}

fn sshd_config_files(ctx: &ScanContext) -> Vec<PathBuf> {
    let mut v = vec![ctx.abs("/etc/ssh/sshd_config")];
    for p in util::files_in(&ctx.abs("/etc/ssh/sshd_config.d")) {
        v.push(p);
    }
    v.retain(|p| p.is_file());
    v
}

struct Rule {
    severity: Severity,
    title: &'static str,
    message: &'static str,
    fix: &'static str,
}

/// sshd setting judgement table. `None` means safe or irrelevant.
fn judge(key: &str, value: &str) -> Option<Rule> {
    let key = key.to_ascii_lowercase();
    let val = value.trim().to_ascii_lowercase();
    match key.as_str() {
        "permitrootlogin" if val == "yes" => Some(Rule {
            severity: Severity::Medium,
            title: "Direct root login allowed",
            message: "PermitRootLogin yes exposes root to password and key brute force",
            fix: "Set prohibit-password or no",
        }),
        "permitemptypasswords" if val == "yes" => Some(Rule {
            severity: Severity::High,
            title: "Empty-password login allowed",
            message: "Accounts with empty passwords can log in over SSH",
            fix: "Set no and remove empty-password accounts",
        }),
        "permituserenvironment" if val == "yes" => Some(Rule {
            severity: Severity::High,
            title: "User environment injection allowed",
            message: "PermitUserEnvironment allows injecting LD_PRELOAD and similar via ~/.ssh/environment",
            fix: "Set no unless explicitly required",
        }),
        "authorizedkeyscommand" if !val.is_empty() && val != "none" => Some(Rule {
            severity: Severity::High,
            title: "AuthorizedKeysCommand is enabled",
            message: "It runs an external program during authentication, a common SSH backdoor hook",
            fix: "Verify the command source; otherwise delete the line",
        }),
        "authorizedkeysfile" if val.starts_with('/') && !val.starts_with("/etc/ssh") => {
            Some(Rule {
                severity: Severity::High,
                title: "Unusual authorized_keys location",
                message: "The key file points to an absolute path outside /etc/ssh, which may be a backdoor",
                fix: "Restore .ssh/authorized_keys",
            })
        }
        "forcecommand" if !val.is_empty() && val != "none" => Some(Rule {
            severity: Severity::Medium,
            title: "Global SSH ForceCommand",
            message: "Every session runs a fixed command; confirm whether this is an approved jump-host setup",
            fix: "Keep only if verified; otherwise remove",
        }),
        "passwordauthentication" if val == "yes" => Some(Rule {
            severity: Severity::Low,
            title: "Password authentication allowed",
            message: "Passwords are weaker than keys and easier to credential-stuff",
            fix: "Keep only if required; otherwise set no",
        }),
        _ => None,
    }
}

pub struct SshCheck;

impl Check for SshCheck {
    fn id(&self) -> &'static str {
        "persist.ssh"
    }
    fn title(&self) -> &'static str {
        "SSH backdoors and configuration risks"
    }
    fn description(&self) -> &'static str {
        "SSH authorized_keys command= backdoors, dangerous sshd settings, and host-key permissions."
    }

    fn run(&self, ctx: &ScanContext) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        for k in authorized_key_entries(ctx) {
            let logical = ctx.disp(&k.file);
            if k.options.contains("command=") {
                findings.push(
                    Finding::new(
                        self.id(),
                        Severity::High,
                        "authorized_keys entry forces a command",
                        "This key always runs the given command on login, a classic persistence backdoor",
                    )
                    .at(&logical, Some(k.line))
                    .evidence(format!(
                        "{} {} {} {}",
                        k.options, k.kind, k.fingerprint, k.comment
                    ))
                    .fix("Verify the key and command; delete the line if unauthorized")
                    .confidence(Confidence::Likely)
                    .mitre("T1098.004"),
                );
            }
        }

        // Permissions: group/other writable means the file can be planted
        for file in authorized_key_files(ctx) {
            if let Some(mode) = util::mode_of(&file) {
                if mode & 0o022 != 0 {
                    findings.push(
                        Finding::new(
                            self.id(),
                            Severity::High,
                            "authorized_keys permissions are too permissive",
                            "Other users can modify it, i.e. write login credentials",
                        )
                        .at(ctx.disp(&file), None)
                        .fix("chmod 600 and chown to the owning user")
                        .confidence(Confidence::Certain)
                        .mitre("T1098.004"),
                    );
                }
            }
        }

        for file in sshd_config_files(ctx) {
            for (line, text) in util::read_lines(&file, MAX_CONFIG) {
                let t = text.trim();
                if t.is_empty() || t.starts_with('#') {
                    continue;
                }
                let mut parts = t.split_whitespace();
                let key = match parts.next() {
                    Some(k) => k,
                    None => continue,
                };
                let value: Vec<&str> = parts.collect();
                if value.is_empty() {
                    continue;
                }
                if let Some(rule) = judge(key, &value.join(" ")) {
                    findings.push(
                        Finding::new(self.id(), rule.severity, rule.title, rule.message)
                            .at(ctx.disp(&file), Some(line))
                            .evidence(t)
                            .fix(rule.fix)
                            .confidence(Confidence::Likely)
                            .mitre("T1556.003"),
                    );
                }
            }
        }

        // Host private keys must not be readable by other users
        for file in util::files_in(&ctx.abs("/etc/ssh")) {
            let name = file.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if !(name.starts_with("ssh_host_") && name.ends_with("_key")) {
                continue;
            }
            if let Some(mode) = util::mode_of(&file) {
                if mode & 0o077 != 0 {
                    findings.push(
                        Finding::new(
                            self.id(),
                            Severity::Medium,
                            "SSH host private key permissions are too permissive",
                            "Other users can read the host key, enabling MITM or lateral movement",
                        )
                        .at(ctx.disp(&file), None)
                        .fix("chmod 600 and chown root:root")
                        .confidence(Confidence::Certain)
                        .mitre("T1552.004"),
                    );
                }
            }
        }

        Ok(findings)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn root_login_flag() {
        assert!(judge("PermitRootLogin", "yes").is_some());
        assert!(judge("PermitRootLogin", "prohibit-password").is_none());
    }

    #[test]
    fn authorized_keys_command_flag() {
        assert!(judge("AuthorizedKeysCommand", "/usr/local/bin/evil").is_some());
        assert!(judge("AuthorizedKeysCommand", "none").is_none());
    }

    #[test]
    fn key_line_parsing() {
        let line =
            "command=\"/bin/sh -c id\",no-pty ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIabc me@host";
        let tokens: Vec<&str> = line.split_whitespace().collect();
        let idx = tokens.iter().position(|t| KEY_TYPES.contains(t)).unwrap();
        assert_eq!(tokens[..idx].join(" "), "command=\"/bin/sh -c id\",no-pty");
        assert_eq!(tokens[idx], "ssh-ed25519");
    }
}
