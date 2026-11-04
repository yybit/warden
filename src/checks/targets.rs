//! Shared file targets for content scanners (YARA, ClamAV).
//!
//! Scanning the whole filesystem with signatures is slow and mostly wasted.
//! These targets cover persistence configuration, dropped-file locations,
//! web roots, and any explicit `--path` roots.

use crate::ctx::ScanContext;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

const MAX_FILES: usize = 50_000;

pub fn high_value_targets(ctx: &ScanContext) -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = Vec::new();
    let max_size = ctx.cfg.max_file_size;

    for logical in [
        "/etc/crontab",
        "/etc/ld.so.preload",
        "/etc/environment",
        "/etc/bash.bashrc",
        "/etc/zsh/zshenv",
        "/etc/rc.local",
    ] {
        let p = ctx.abs(logical);
        if p.is_file() {
            out.push(p);
        }
    }

    let dirs: &[(&str, usize)] = &[
        ("/etc/cron.d", 3),
        ("/etc/cron.hourly", 2),
        ("/etc/cron.daily", 2),
        ("/etc/cron.weekly", 2),
        ("/etc/cron.monthly", 2),
        ("/etc/systemd/system", 4),
        ("/etc/systemd/user", 4),
        ("/etc/profile.d", 2),
        ("/etc/ld.so.conf.d", 2),
        ("/etc/modprobe.d", 2),
        ("/etc/sudoers.d", 2),
        ("/var/spool/cron", 3),
        ("/usr/local/bin", 2),
        ("/usr/local/sbin", 2),
        ("/tmp", 4),
        ("/var/tmp", 4),
        ("/dev/shm", 3),
    ];
    for (dir, depth) in dirs {
        walk_into(&mut out, &ctx.abs(dir), *depth, max_size);
    }

    if ctx.user_scope {
        let home = ctx.home_abs();
        for name in [
            ".bashrc",
            ".bash_profile",
            ".profile",
            ".zshrc",
            ".zprofile",
        ] {
            let p = home.join(name);
            if p.is_file() {
                out.push(p);
            }
        }
        for (sub, depth) in [
            (".ssh", 3),
            (".config/systemd/user", 4),
            (".local/bin", 2),
            ("Downloads", 4),
            ("Public", 3),
        ] {
            walk_into(&mut out, &home.join(sub), depth, max_size);
        }
    }

    for p in &ctx.cfg.paths {
        walk_into(&mut out, &ctx.abs(p), 12, max_size);
    }
    for p in &ctx.cfg.webroots {
        walk_into(&mut out, &ctx.abs(p), 10, max_size);
    }

    out.sort();
    out.dedup();
    out.truncate(MAX_FILES);
    out
}

fn walk_into(out: &mut Vec<PathBuf>, dir: &Path, depth: usize, max_size: u64) {
    if !dir.is_dir() {
        return;
    }
    for entry in WalkDir::new(dir)
        .max_depth(depth)
        .follow_links(false)
        .into_iter()
        .filter_map(|e| e.ok())
    {
        if out.len() >= MAX_FILES {
            return;
        }
        if !entry.file_type().is_file() {
            continue;
        }
        if let Ok(meta) = entry.metadata() {
            if meta.len() <= max_size {
                out.push(entry.path().to_path_buf());
            }
        }
    }
}
