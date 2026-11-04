//! Filesystem and process helpers. Read-only: they never modify the scanned host.

use sha2::{Digest, Sha256};
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

pub const MB: u64 = 1024 * 1024;

/// Serializes tests that write and execute helper scripts. Without it, a
/// fork in one test can inherit a write handle for a script another test is
/// about to exec, producing ETXTBSY.
#[cfg(test)]
pub static SPAWN_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

pub fn is_root() -> bool {
    // SAFETY: geteuid is async-signal-safe and has no side effects.
    unsafe { libc::geteuid() == 0 }
}

pub fn home_dir() -> PathBuf {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| PathBuf::from("/root"))
}

pub fn now_rfc3339() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

pub fn today() -> String {
    chrono::Utc::now().format("%Y-%m-%d").to_string()
}

/// Read a file as bytes, capped by size. Returns None if missing or too large.
pub fn read_bytes(p: &Path, max: u64) -> Option<Vec<u8>> {
    let meta = fs::metadata(p).ok()?;
    if !meta.is_file() || meta.len() > max {
        return None;
    }
    fs::read(p).ok()
}

/// Read as text, replacing invalid UTF-8 lossily so config lines are not skipped.
pub fn read_text(p: &Path, max: u64) -> Option<String> {
    let bytes = read_bytes(p, max)?;
    Some(String::from_utf8_lossy(&bytes).into_owned())
}

/// Read lines; line numbers start at 1.
pub fn read_lines(p: &Path, max: u64) -> Vec<(usize, String)> {
    read_text(p, max)
        .map(|s| {
            s.lines()
                .enumerate()
                .map(|(i, l)| (i + 1, l.to_string()))
                .collect()
        })
        .unwrap_or_default()
}

/// Direct children that are directories (non-recursive), sorted.
pub fn dirs_in(dir: &Path) -> Vec<PathBuf> {
    let mut v: Vec<PathBuf> = match fs::read_dir(dir) {
        Ok(rd) => rd
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .filter(|p| p.is_dir())
            .collect(),
        Err(_) => Vec::new(),
    };
    v.sort();
    v
}

/// Direct children that are files (non-recursive), sorted, ignoring read errors.
pub fn files_in(dir: &Path) -> Vec<PathBuf> {
    let mut v: Vec<PathBuf> = match fs::read_dir(dir) {
        Ok(rd) => rd
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .filter(|p| {
                fs::symlink_metadata(p)
                    .map(|m| m.is_file())
                    .unwrap_or(false)
            })
            .collect(),
        Err(_) => Vec::new(),
    };
    v.sort();
    v
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileKind {
    Elf,
    MachO,
    Script,
    Other,
}

impl FileKind {
    pub fn is_executable_format(self) -> bool {
        matches!(self, FileKind::Elf | FileKind::MachO)
    }
}

/// Detect file type by magic bytes, never by extension (extensions are what attackers forge).
pub fn file_kind(p: &Path) -> FileKind {
    let mut buf = [0u8; 8];
    let mut f = match fs::File::open(p) {
        Ok(f) => f,
        Err(_) => return FileKind::Other,
    };
    let n = match f.read(&mut buf) {
        Ok(n) => n,
        Err(_) => return FileKind::Other,
    };
    if n >= 2 && buf[0] == b'#' && buf[1] == b'!' {
        return FileKind::Script;
    }
    if n < 4 {
        return FileKind::Other;
    }
    let b = &buf[..4];
    if b == [0x7f, b'E', b'L', b'F'] {
        return FileKind::Elf;
    }
    match b {
        // Mach-O 32/64-bit, both endiannesses, plus FAT/universal binaries
        [0xfe, 0xed, 0xfa, 0xce]
        | [0xfe, 0xed, 0xfa, 0xcf]
        | [0xce, 0xfa, 0xed, 0xfe]
        | [0xcf, 0xfa, 0xed, 0xfe]
        | [0xca, 0xfe, 0xba, 0xbe]
        | [0xbe, 0xba, 0xfe, 0xca] => FileKind::MachO,
        _ => FileKind::Other,
    }
}

/// Permission bits. Symlinks are followed: we care about the effective target,
/// not the constant `lrwxrwxrwx` of the link itself (otherwise /etc/localtime is a false positive).
pub fn mode_of(p: &Path) -> Option<u32> {
    use std::os::unix::fs::PermissionsExt;
    fs::metadata(p).ok().map(|m| m.permissions().mode())
}

pub fn owner_uid(p: &Path) -> Option<u32> {
    use std::os::unix::fs::MetadataExt;
    fs::metadata(p).ok().map(|m| m.uid())
}

pub fn is_setuid_mode(mode: u32) -> bool {
    mode & 0o4000 != 0
}

pub fn is_setgid_mode(mode: u32) -> bool {
    mode & 0o2000 != 0
}

pub fn is_world_writable(mode: u32) -> bool {
    mode & 0o002 != 0
}

pub fn is_sticky(mode: u32) -> bool {
    mode & 0o1000 != 0
}

/// Run a system command and return stdout. Missing/failing commands yield None; callers degrade gracefully.
pub fn run(cmd: &str, args: &[&str]) -> Option<String> {
    let out = Command::new(cmd)
        .args(args)
        .env("LC_ALL", "C")
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// Run a command with a wall-clock timeout. Returns None on timeout/spawn failure.
/// Stdout/stderr are captured; both pipes are drained on separate threads so a
/// chatty process cannot block on a full pipe.
pub fn run_timeout(cmd: &str, args: &[&str], timeout: Duration) -> Option<Output> {
    let mut child = Command::new(cmd)
        .args(args)
        .env("LC_ALL", "C")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .ok()?;

    let mut stdout = child.stdout.take()?;
    let mut stderr = child.stderr.take()?;
    let out_thread = std::thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = stdout.read_to_end(&mut buf);
        buf
    });
    let err_thread = std::thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = stderr.read_to_end(&mut buf);
        buf
    });

    let started = Instant::now();
    let status = loop {
        match child.try_wait() {
            Ok(Some(s)) => break s,
            Ok(None) => {}
            Err(_) => return None,
        }
        if started.elapsed() >= timeout {
            let _ = child.kill();
            let _ = child.wait();
            return None;
        }
        std::thread::sleep(Duration::from_millis(50));
    };

    Some(Output {
        status,
        stdout: out_thread.join().ok()?,
        stderr: err_thread.join().ok()?,
    })
}

/// Whether a command exists in PATH (for optional external tools).
pub fn command_exists(cmd: &str) -> bool {
    std::env::var_os("PATH")
        .map(|paths| std::env::split_paths(&paths).any(|d| d.join(cmd).is_file()))
        .unwrap_or(false)
}

/// Streaming SHA-256 so large files are never read into memory.
pub fn sha256_file(p: &Path, max_size: u64) -> Option<String> {
    let meta = fs::metadata(p).ok()?;
    if !meta.is_file() || meta.len() > max_size || meta.len() == 0 {
        return None;
    }
    let mut f = fs::File::open(p).ok()?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = f.read(&mut buf).ok()?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Some(format!("{:x}", hasher.finalize()))
}

/// Single-line glob supporting `*` and `?`, used for allowlist path matching.
/// No globset dependency: rules only match one path and need no `**` semantics.
pub fn glob_match(pattern: &str, text: &str) -> bool {
    let p: Vec<char> = pattern.chars().collect();
    let t: Vec<char> = text.chars().collect();
    let mut pi = 0usize;
    let mut ti = 0usize;
    let mut star: Option<usize> = None;
    let mut mark = 0usize;

    while ti < t.len() {
        if pi < p.len() && (p[pi] == '?' || p[pi] == t[ti]) {
            pi += 1;
            ti += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star = Some(pi);
            pi += 1;
            mark = ti;
        } else if let Some(sp) = star {
            pi = sp + 1;
            mark += 1;
            ti = mark;
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == '*' {
        pi += 1;
    }
    pi == p.len()
}

/// Normalize a command line for baseline fingerprints: collapse and trim whitespace.
pub fn normalize(s: &str) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Parse a human-readable size: `64M`, `512K`, `1048576`.
pub fn parse_size(s: &str) -> Result<u64, String> {
    let s = s.trim();
    if s.is_empty() {
        return Err("empty value".into());
    }
    let (num, mult) = match s.chars().last().unwrap().to_ascii_lowercase() {
        'k' => (&s[..s.len() - 1], 1024u64),
        'm' => (&s[..s.len() - 1], 1024 * 1024),
        'g' => (&s[..s.len() - 1], 1024 * 1024 * 1024),
        _ => (s, 1u64),
    };
    num.trim()
        .parse::<u64>()
        .map(|n| n.saturating_mul(mult))
        .map_err(|_| format!("cannot parse size: {s}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn glob_basic() {
        assert!(glob_match("/usr/local/bin/*", "/usr/local/bin/foo"));
        assert!(glob_match("*", "/anything"));
        assert!(!glob_match("/usr/bin/*", "/usr/local/bin/foo"));
        assert!(glob_match("/etc/*.conf", "/etc/a.conf"));
        assert!(!glob_match("/etc/*.conf", "/etc/a.toml"));
        assert!(glob_match("/a/?/c", "/a/b/c"));
    }

    #[test]
    fn size_parse() {
        assert_eq!(parse_size("64M").unwrap(), 64 * MB);
        assert_eq!(parse_size("1024").unwrap(), 1024);
        assert!(parse_size("abc").is_err());
    }

    #[test]
    fn normalize_collapses_space() {
        assert_eq!(normalize("  a   b\tc "), "a b c");
    }
}
