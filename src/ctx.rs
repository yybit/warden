//! Scan context: path relocation (`--root`), platform detection, privilege state.

use crate::model::Os;
use crate::util;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    Text,
    Json,
    Sarif,
}

#[derive(Debug, Clone)]
pub struct Config {
    /// Filesystem root. `/` scans the local host; point it at a mounted image for offline scans.
    pub root: PathBuf,
    /// Extra scan roots (IOC / suspicious files).
    pub paths: Vec<PathBuf>,
    /// Web roots for the webshell check; empty skips it.
    pub webroots: Vec<PathBuf>,
    /// IOC file (SHA-256 list).
    pub ioc: Option<PathBuf>,
    /// YARA rule files or directories.
    pub yara: Vec<PathBuf>,
    /// Enable the optional ClamAV backend.
    pub clamav: bool,
    /// Directory with malicious-package OSV records.
    pub malicious: Option<PathBuf>,
    /// Warn when the ClamAV database is older than this many days (0 disables).
    pub clamav_max_db_age_days: i64,
    /// Verify package-managed files (dpkg/rpm/pacman).
    pub verify_packages: bool,
    /// Query OSV for package vulnerabilities (network).
    pub osv: bool,
    pub osv_url: String,
    pub osv_max_age_hours: u64,
    /// ClamAV database directory passed to `clamscan -d`.
    pub clamav_db: Option<PathBuf>,
    pub format: Format,
    pub output: Option<PathBuf>,
    pub min_severity: crate::model::Severity,
    pub fail_on: Option<crate::model::Severity>,
    /// Run only these checks (empty means all).
    pub only: Vec<String>,
    pub exclude: Vec<String>,
    pub baseline: Option<PathBuf>,
    pub save_baseline: Option<PathBuf>,
    pub allowlist: Option<PathBuf>,
    pub max_file_size: u64,
    pub user_scope: Option<bool>,
    pub color: bool,
    pub verbose: bool,
    pub quiet: bool,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            root: PathBuf::from("/"),
            paths: Vec::new(),
            webroots: Vec::new(),
            ioc: None,
            yara: Vec::new(),
            clamav: false,
            malicious: None,
            clamav_max_db_age_days: 7,
            verify_packages: false,
            osv: false,
            osv_url: "https://api.osv.dev".into(),
            osv_max_age_hours: 24,
            clamav_db: None,
            format: Format::Text,
            output: None,
            min_severity: crate::model::Severity::Low,
            fail_on: Some(crate::model::Severity::High),
            only: Vec::new(),
            exclude: Vec::new(),
            baseline: None,
            save_baseline: None,
            allowlist: None,
            max_file_size: 64 * util::MB,
            user_scope: None,
            color: true,
            verbose: false,
            quiet: false,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ScanContext {
    pub cfg: Config,
    pub os: Os,
    pub privileged: bool,
    /// Logical home directory (without the root prefix)
    pub home: String,
    pub user_scope: bool,
}

impl ScanContext {
    pub fn new(cfg: Config) -> Self {
        let os = detect_os(&cfg.root);
        let home = util::home_dir().to_string_lossy().into_owned();
        let user_scope = cfg.user_scope.unwrap_or_else(|| cfg.root == Path::new("/"));
        ScanContext {
            cfg,
            os,
            privileged: util::is_root(),
            home,
            user_scope,
        }
    }

    /// Map a logical path (e.g. `/etc/cron.d`) to the real path under `--root`.
    pub fn abs(&self, logical: impl AsRef<Path>) -> PathBuf {
        let p = logical.as_ref();
        if p.is_absolute() {
            self.cfg.root.join(p.strip_prefix("/").unwrap_or(p))
        } else {
            self.cfg.root.join(p)
        }
    }

    /// Map a real path back to its logical form for output, baselines, and allowlists.
    pub fn disp(&self, p: &Path) -> String {
        if self.cfg.root == Path::new("/") {
            p.to_string_lossy().into_owned()
        } else {
            match p.strip_prefix(&self.cfg.root) {
                Ok(rest) => format!("/{}", rest.to_string_lossy()),
                Err(_) => p.to_string_lossy().into_owned(),
            }
        }
    }

    pub fn read(&self, logical: &str, max: u64) -> Option<String> {
        util::read_text(&self.abs(logical), max)
    }

    pub fn home_abs(&self) -> PathBuf {
        self.abs(&self.home)
    }

    pub fn is_local(&self) -> bool {
        self.cfg.root == Path::new("/")
    }
}

/// Platform detection prefers filesystem content so macOS images can be scanned from Linux.
pub fn detect_os(root: &Path) -> Os {
    if root.join("System/Library").is_dir()
        || root.join("Library/LaunchDaemons").is_dir()
        || root
            .join("System/Library/CoreServices/SystemVersion.plist")
            .exists()
    {
        return Os::MacOs;
    }
    if root.join("etc/os-release").exists() || root.join("etc/passwd").exists() {
        return Os::Linux;
    }
    if cfg!(target_os = "macos") {
        Os::MacOs
    } else {
        Os::Linux
    }
}
