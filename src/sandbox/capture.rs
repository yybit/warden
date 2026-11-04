//! Sandbox filesystem layout and pre/post-execution snapshots.
//!
//! Key design: writable copies of the directories a sample may rewrite (/etc, /usr/local,
//! /var/spool/cron, $HOME, /tmp) are bound into the sandbox; a snapshot diff then shows exactly what changed.
//! This needs neither root nor overlayfs and reveals the landing spots directly. /usr stays read-only.

use crate::util::{self, FileKind};
use anyhow::{Context, Result};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

const MAX_WALK_ENTRIES: usize = 300_000;

pub struct Layout {
    pub base: PathBuf,
    pub etc: PathBuf,
    pub home: PathBuf,
    pub tmp: PathBuf,
    pub usr_local: PathBuf,
    pub var_tmp: PathBuf,
    pub var_log: PathBuf,
    pub spool_cron: PathBuf,
    pub work: PathBuf,
    pub logs: PathBuf,
    /// User-supplied workdir is not deleted during cleanup
    pub user_workdir: bool,
    /// Some /etc files (shadow/sudoers) are unreadable as non-root, so the copy is incomplete
    pub etc_copy_incomplete: bool,
}

impl Layout {
    pub fn create(workdir: Option<&Path>) -> Result<Self> {
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let base =
            std::env::temp_dir().join(format!("warden-sandbox-{}-{}", std::process::id(), stamp));
        fs::create_dir_all(&base)
            .with_context(|| format!("cannot create sandbox directory: {}", base.display()))?;

        let etc = base.join("etc");
        let home = base.join("home");
        let tmp = base.join("tmp");
        let usr_local = base.join("usr-local");
        let var_tmp = base.join("var-tmp");
        let var_log = base.join("var-log");
        let spool_cron = base.join("spool-cron");
        let logs = base.join("logs");
        for d in [
            &etc,
            &home,
            &tmp,
            &usr_local,
            &var_tmp,
            &var_log,
            &spool_cron,
            &logs,
        ] {
            fs::create_dir_all(d)?;
        }
        // Standard directory skeleton: installers often write /usr/local/bin directly
        for sub in ["bin", "sbin", "lib", "share", "include", "etc"] {
            fs::create_dir_all(usr_local.join(sub))?;
        }
        fs::create_dir_all(home.join(".config"))?;
        fs::create_dir_all(home.join(".local/bin"))?;

        let etc_copy_incomplete = populate_etc(&etc)?;

        let (work, user_workdir) = match workdir {
            Some(p) => {
                fs::create_dir_all(p)
                    .with_context(|| format!("cannot create work directory: {}", p.display()))?;
                let p = fs::canonicalize(p)?;
                (p, true)
            }
            None => {
                let p = base.join("work");
                fs::create_dir_all(&p)?;
                (p, false)
            }
        };

        Ok(Layout {
            base,
            etc,
            home,
            tmp,
            usr_local,
            var_tmp,
            var_log,
            spool_cron,
            work,
            logs,
            user_workdir,
            etc_copy_incomplete,
        })
    }

    /// Host path -> logical sandbox path (keeps reports and baselines consistent)
    pub fn map_logical(&self, host: &Path) -> Option<String> {
        let roots: [(&Path, &str); 8] = [
            (&self.etc, "/etc"),
            (&self.home, "/home/sandbox"),
            (&self.tmp, "/tmp"),
            (&self.usr_local, "/usr/local"),
            (&self.var_tmp, "/var/tmp"),
            (&self.var_log, "/var/log"),
            (&self.spool_cron, "/var/spool/cron"),
            (&self.work, "/work"),
        ];
        for (root, logical) in roots {
            if let Ok(rest) = host.strip_prefix(root) {
                if rest.as_os_str().is_empty() {
                    continue;
                }
                return Some(format!("{logical}/{}", rest.to_string_lossy()));
            }
        }
        None
    }

    /// Force cleanup: restore directory permissions first (/etc contains 0555 dirs), then remove recursively.
    pub fn cleanup(&self) {
        let _ = std::process::Command::new("chmod")
            .args(["-R", "u+rwX"])
            .arg(&self.base)
            .status();
        let _ = fs::remove_dir_all(&self.base);
        // Keep the user-supplied workdir; remove only what we created
        if !self.user_workdir {
            let _ = fs::remove_dir_all(&self.work);
        }
    }
}

/// Copy host /etc. Unreadable files (shadow/sudoers) get empty placeholders so
/// programs do not take completely different code paths due to missing config.
fn populate_etc(dest: &Path) -> Result<bool> {
    let mut incomplete = false;
    if Path::new("/etc").is_dir() {
        // shadow/sudoers are expected to fail; silence that noise
        let status = std::process::Command::new("cp")
            .arg("-a")
            .arg("/etc/.")
            .arg(dest)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();
        match status {
            Ok(s) if s.success() => {}
            _ => incomplete = true,
        }
        // Grant directory write permission: the sandbox runs unprivileged, otherwise /etc writes fail
        let _ = std::process::Command::new("chmod")
            .args(["-R", "u+rwX"])
            .arg(dest)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();
    }
    for f in ["shadow", "gshadow", "sudoers", "subuid", "subgid"] {
        let p = dest.join(f);
        if !p.exists() {
            let _ = fs::write(&p, b"");
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&p, fs::Permissions::from_mode(0o644));
            incomplete = true;
        }
    }
    Ok(incomplete)
}

#[derive(Clone, Debug)]
pub struct FileState {
    pub host: PathBuf,
    pub size: u64,
    pub mtime_ns: i64,
    pub hash: Option<String>,
    pub kind: FileKind,
    pub exec: bool,
    pub symlink: Option<String>,
}

impl FileState {
    fn same_content(&self, other: &FileState) -> bool {
        self.size == other.size
            && self.mtime_ns == other.mtime_ns
            && self.symlink == other.symlink
            && match (&self.hash, &other.hash) {
                (Some(a), Some(b)) => a == b,
                _ => true,
            }
    }
}

pub fn snapshot(layout: &Layout, hash_limit: u64) -> BTreeMap<String, FileState> {
    let roots = [
        &layout.etc,
        &layout.home,
        &layout.tmp,
        &layout.usr_local,
        &layout.var_tmp,
        &layout.var_log,
        &layout.spool_cron,
        &layout.work,
    ];
    let mut map = BTreeMap::new();
    let mut seen = 0usize;

    for root in roots {
        for entry in WalkDir::new(root)
            .follow_links(false)
            .into_iter()
            .filter_map(|e| e.ok())
        {
            seen += 1;
            if seen > MAX_WALK_ENTRIES {
                return map;
            }
            let path = entry.path();
            let ft = entry.file_type();
            if !ft.is_file() && !ft.is_symlink() {
                continue;
            }
            if let Ok(rest) = path.strip_prefix(root) {
                if rest.as_os_str().is_empty() {
                    continue;
                }
            }
            let logical = match layout.map_logical(path) {
                Some(l) => l,
                None => continue,
            };
            let meta = match fs::symlink_metadata(path) {
                Ok(m) => m,
                Err(_) => continue,
            };
            let symlink = if ft.is_symlink() {
                fs::read_link(path)
                    .ok()
                    .map(|p| p.to_string_lossy().into_owned())
            } else {
                None
            };
            let mtime_ns = meta
                .modified()
                .ok()
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|d| d.as_nanos() as i64)
                .unwrap_or(0);
            let kind = if ft.is_file() {
                util::file_kind(path)
            } else {
                FileKind::Other
            };
            let exec = if ft.is_file() {
                util::mode_of(path).map(|m| m & 0o111 != 0).unwrap_or(false)
            } else {
                false
            };
            let hash = if ft.is_file() {
                util::sha256_file(path, hash_limit)
            } else {
                None
            };
            map.insert(
                logical,
                FileState {
                    host: path.to_path_buf(),
                    size: meta.len(),
                    mtime_ns,
                    hash,
                    kind,
                    exec,
                    symlink,
                },
            );
        }
    }
    map
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChangeKind {
    Created,
    Modified,
    Deleted,
}

impl ChangeKind {
    pub fn as_str(self) -> &'static str {
        match self {
            ChangeKind::Created => "created",
            ChangeKind::Modified => "modified",
            ChangeKind::Deleted => "deleted",
        }
    }
    pub fn label_zh(self) -> &'static str {
        match self {
            ChangeKind::Created => "created",
            ChangeKind::Modified => "modified",
            ChangeKind::Deleted => "deleted",
        }
    }
}

pub struct Change {
    pub logical: String,
    pub change: ChangeKind,
    pub state: FileState,
}

pub struct CaptureDiff {
    pub changes: Vec<Change>,
    pub files_before: usize,
    pub files_after: usize,
}

pub fn diff(
    before: &BTreeMap<String, FileState>,
    after: &BTreeMap<String, FileState>,
) -> CaptureDiff {
    let mut changes = Vec::new();
    for (logical, state) in after {
        match before.get(logical) {
            None => changes.push(Change {
                logical: logical.clone(),
                change: ChangeKind::Created,
                state: state.clone(),
            }),
            Some(old) if !old.same_content(state) => changes.push(Change {
                logical: logical.clone(),
                change: ChangeKind::Modified,
                state: state.clone(),
            }),
            _ => {}
        }
    }
    for (logical, state) in before {
        if !after.contains_key(logical) {
            changes.push(Change {
                logical: logical.clone(),
                change: ChangeKind::Deleted,
                state: state.clone(),
            });
        }
    }
    changes.sort_by(|a, b| a.logical.cmp(&b.logical));
    CaptureDiff {
        changes,
        files_before: before.len(),
        files_after: after.len(),
    }
}
