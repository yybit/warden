//! Policy file for scan defaults.
//!
//! Precedence: explicit CLI flags win; otherwise values come from the policy
//! (or built-in defaults). Lists (`checks`, `paths`, ...) are replaced by the
//! policy only when the corresponding CLI list is empty.

use anyhow::{Context, Result};
use serde::Deserialize;
use std::path::{Path, PathBuf};

/// Commented template written by `warden config init`.
pub const TEMPLATE: &str = r#"# Warden policy file. Every key is optional; omit this file unless you need
# to override the built-in defaults. Show effective defaults with:
#   warden config show
#
# min_severity = "low"          # info|low|medium|high|critical
# fail_on = "high"              # exit 1 at or above this level; "never" disables
# checks = ["persist", "fs"]    # prefixes are accepted; empty means all
# exclude = ["fs.suid"]
# paths = ["/srv/data"]
# webroots = ["/var/www"]       # empty list disables auto-detection
# ioc = "/etc/warden/ioc.txt"
# yara = ["/etc/warden/rules"]
# clamav = true                 # false disables auto-detection
# clamav_db = "/var/lib/clamav"
# clamav_max_db_age_days = 7
# verify_packages = false       # slow, opt-in
# malicious = "/etc/warden/malicious"  # ossf/malicious-packages checkout
# osv = false                  # sends package names to osv.dev
# osv_url = "https://api.osv.dev"
# osv_max_age_hours = 24
# max_file_size = "64M"
# allowlist = "/etc/warden/allowlist.toml"
"#;

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    pub min_severity: Option<String>,
    pub fail_on: Option<String>,
    pub checks: Option<Vec<String>>,
    pub exclude: Option<Vec<String>>,
    pub paths: Option<Vec<PathBuf>>,
    pub webroots: Option<Vec<PathBuf>>,
    pub ioc: Option<PathBuf>,
    pub yara: Option<Vec<PathBuf>>,
    pub clamav: Option<bool>,
    pub clamav_db: Option<PathBuf>,
    pub clamav_max_db_age_days: Option<i64>,
    pub verify_packages: Option<bool>,
    pub malicious: Option<PathBuf>,
    pub osv: Option<bool>,
    pub osv_url: Option<String>,
    pub osv_max_age_hours: Option<u64>,
    /// Human-readable size, e.g. `64M`.
    pub max_file_size: Option<String>,
    pub allowlist: Option<PathBuf>,
}

/// Discover the default policy file (user, then system-wide).
pub fn discover() -> Option<PathBuf> {
    Policy::discover()
}

impl Policy {
    pub fn load(path: &Path) -> Result<Self> {
        let text = crate::util::read_text(path, crate::util::MB)
            .with_context(|| format!("cannot read policy: {}", path.display()))?;
        toml::from_str(&text).with_context(|| format!("invalid policy format: {}", path.display()))
    }

    /// User policy first, then a system-wide policy.
    pub fn discover() -> Option<PathBuf> {
        let user = crate::util::home_dir().join(".config/warden/policy.toml");
        if user.is_file() {
            return Some(user);
        }
        let system = PathBuf::from("/etc/warden/policy.toml");
        if system.is_file() {
            return Some(system);
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_full_policy() {
        let text = r#"
min_severity = "medium"
fail_on = "critical"
checks = ["persist", "fs"]
exclude = ["fs.suid"]
paths = ["/srv"]
webroots = ["/var/www"]
ioc = "/etc/warden/ioc.txt"
yara = ["./rules"]
clamav = true
clamav_db = "/var/lib/clamav"
clamav_max_db_age_days = 14
verify_packages = false
max_file_size = "128M"
allowlist = "/etc/warden/allowlist.toml"
"#;
        let p: Policy = toml::from_str(text).unwrap();
        assert_eq!(p.min_severity.as_deref(), Some("medium"));
        assert_eq!(p.fail_on.as_deref(), Some("critical"));
        assert_eq!(p.checks.unwrap(), vec!["persist", "fs"]);
        assert_eq!(p.max_file_size.as_deref(), Some("128M"));
        assert_eq!(p.clamav_max_db_age_days, Some(14));
    }

    #[test]
    fn template_is_valid() {
        let p: Policy = toml::from_str(TEMPLATE).unwrap();
        assert!(p.checks.is_none());
        assert!(p.min_severity.is_none());
    }

    #[test]
    fn rejects_unknown_keys() {
        let err =
            toml::from_str::<Policy>("min_severity = \"low\"\ntypo_key = true\n").unwrap_err();
        assert!(err.to_string().contains("unknown field"));
    }
}
