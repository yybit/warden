//! Allowlist.
//!
//! Goal: keep known-good-but-suspicious entries (in-house ops scripts, vendor agents)
//! out of the noise while preserving auditability: every rule has a reason and an optional expiry.

use crate::model::Finding;
use crate::util;
use anyhow::{Context, Result};
use serde::Deserialize;
use std::path::Path;

#[derive(Debug, Clone, Deserialize)]
pub struct AllowRule {
    /// Check id; `*` matches all checks
    pub check: String,
    /// Path glob matched against `Finding.path`
    #[serde(default)]
    pub path: Option<String>,
    /// Fingerprint glob matched against `Finding::fingerprint`; takes precedence over `path`
    #[serde(default)]
    pub fingerprint: Option<String>,
    /// Human-readable justification (required for audit; not used for matching)
    #[serde(default)]
    #[allow(dead_code)]
    pub reason: String,
    /// `YYYY-MM-DD`; the rule is ignored after this date
    #[serde(default)]
    pub expires: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
struct AllowFile {
    #[serde(default)]
    allow: Vec<AllowRule>,
}

#[derive(Debug, Default)]
pub struct Allowlist {
    pub rules: Vec<AllowRule>,
    pub expired: usize,
}

impl Allowlist {
    pub fn load(path: &Path) -> Result<Self> {
        let text = util::read_text(path, 4 * util::MB)
            .with_context(|| format!("cannot read allowlist: {}", path.display()))?;
        let parsed: AllowFile = toml::from_str(&text)
            .with_context(|| format!("invalid allowlist format: {}", path.display()))?;
        let today = util::today();
        let mut expired = 0usize;
        let rules = parsed
            .allow
            .into_iter()
            .filter(|r| match &r.expires {
                Some(date) if date.as_str() < today.as_str() => {
                    expired += 1;
                    false
                }
                _ => true,
            })
            .collect();
        Ok(Allowlist { rules, expired })
    }

    pub fn is_allowed(&self, f: &Finding) -> bool {
        self.rules.iter().any(|r| rule_matches(r, f))
    }
}

fn rule_matches(rule: &AllowRule, f: &Finding) -> bool {
    if rule.check != "*" && rule.check != f.check {
        return false;
    }
    if let Some(fp) = &rule.fingerprint {
        return util::glob_match(fp, &f.fingerprint());
    }
    if let Some(pat) = &rule.path {
        return match &f.path {
            Some(p) => util::glob_match(pat, p),
            None => false,
        };
    }
    // check only: suppress every finding from that check (use sparingly)
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Confidence, Severity};

    fn finding(check: &str, path: &str) -> Finding {
        Finding::new(check, Severity::High, "t", "m")
            .at(path, None)
            .confidence(Confidence::Likely)
    }

    #[test]
    fn matches_check_and_glob() {
        let rules = vec![AllowRule {
            check: "fs.suid".into(),
            path: Some("/usr/local/bin/*".into()),
            fingerprint: None,
            reason: "vendor".into(),
            expires: None,
        }];
        let list = Allowlist { rules, expired: 0 };
        assert!(list.is_allowed(&finding("fs.suid", "/usr/local/bin/agent")));
        assert!(!list.is_allowed(&finding("fs.suid", "/usr/bin/evil")));
        assert!(!list.is_allowed(&finding("persist.cron", "/usr/local/bin/agent")));
    }

    #[test]
    fn expired_rule_is_ignored() -> Result<()> {
        let dir = std::env::temp_dir().join(format!("warden-allow-{}", std::process::id()));
        std::fs::create_dir_all(&dir)?;
        let p = dir.join("allow.toml");
        std::fs::write(
            &p,
            "[[allow]]\ncheck=\"fs.suid\"\npath=\"/x\"\nreason=\"r\"\nexpires=\"2000-01-01\"\n",
        )?;
        let list = Allowlist::load(&p)?;
        assert_eq!(list.expired, 1);
        assert!(list.rules.is_empty());
        let _ = std::fs::remove_dir_all(&dir);
        Ok(())
    }
}
