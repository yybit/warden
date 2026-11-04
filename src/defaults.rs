//! Built-in defaults and auto-detection.
//!
//! Most users should not need a policy file. These defaults are applied when
//! neither the CLI nor a policy provides a value:
//! - web roots commonly used by distributions are scanned for webshells
//! - YARA rule directories under `~/.config/warden/rules`, `/etc/warden/rules`,
//!   and `/usr/share/warden/rules` are loaded when present
//! - ClamAV is enabled automatically only when `clamscan` and a database exist

use crate::util;
use std::path::{Path, PathBuf};

pub fn detect_webroots(root: &Path) -> Vec<PathBuf> {
    const CANDIDATES: &[&str] = &[
        "var/www/html",
        "var/www",
        "srv/www",
        "usr/share/nginx/html",
        "var/lib/nginx/html",
    ];
    let mut out: Vec<PathBuf> = Vec::new();
    for candidate in CANDIDATES {
        // Config paths are logical: `--root` is applied later by ScanContext.
        let logical = Path::new("/").join(candidate);
        let actual = root.join(candidate);
        if !actual.is_dir() {
            continue;
        }
        // Keep only the broadest root: /var/www covers /var/www/html.
        if out.iter().any(|p| logical.starts_with(p)) {
            continue;
        }
        out.retain(|p| !p.starts_with(&logical));
        out.push(logical);
    }
    out
}

pub fn detect_yara_dirs() -> Vec<PathBuf> {
    let mut candidates = vec![
        util::home_dir().join(".config/warden/rules"),
        PathBuf::from("/etc/warden/rules"),
        PathBuf::from("/usr/share/warden/rules"),
    ];
    candidates.retain(|p| p.is_dir());
    candidates
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_existing_webroots_only() {
        let dir = std::env::temp_dir().join(format!(
            "warden-defaults-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(dir.join("var/www/html")).unwrap();
        std::fs::create_dir_all(dir.join("srv/www")).unwrap();
        let found = detect_webroots(&dir);
        assert!(found.iter().any(|p| p.ends_with("var/www")));
        assert!(found.iter().any(|p| p.ends_with("srv/www")));
        assert!(!found.iter().any(|p| p.ends_with("var/www/html")));
        assert!(!found.iter().any(|p| p.ends_with("usr/share/nginx/html")));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
