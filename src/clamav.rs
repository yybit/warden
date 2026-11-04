//! Optional ClamAV backend.
//!
//! ClamAV is invoked as a **separate process** (`clamscan`) rather than linked
//! via `libclamav`. This keeps the GPL-2.0 boundary at the process level and
//! lets operators install/update signatures independently (see
//! docs/SIGNATURES.md). The backend is disabled unless `--clamav` is passed.

use crate::util;
use anyhow::{Context, Result};
use chrono::NaiveDateTime;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClamHit {
    pub path: PathBuf,
    pub signature: String,
}

#[derive(Debug, Clone)]
pub struct ClamScan {
    pub hits: Vec<ClamHit>,
    pub timed_out: bool,
    pub exit_code: Option<i32>,
    pub targets: usize,
}

#[derive(Debug, Clone)]
pub struct ClamAv {
    bin: PathBuf,
    version: String,
}

impl ClamAv {
    /// Locate `clamscan` in PATH and read its version string.
    pub fn discover() -> Option<Self> {
        let bin = which("clamscan")?;
        Self::with_binary(bin).ok()
    }

    /// Use an explicit binary (also used by tests).
    pub fn with_binary(bin: PathBuf) -> Result<Self> {
        let version = Command::new(&bin)
            .arg("--version")
            .output()
            .ok()
            .filter(|o| o.status.success())
            .map(|o| {
                String::from_utf8_lossy(&o.stdout)
                    .lines()
                    .next()
                    .unwrap_or("")
                    .trim()
                    .to_string()
            })
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "unknown".to_string());
        Ok(ClamAv { bin, version })
    }

    pub fn version(&self) -> &str {
        &self.version
    }

    /// Database build date from strings such as
    /// `ClamAV 1.4.3/27450/Wed Nov  5 08:12:34 2025`.
    pub fn db_date(&self) -> Option<NaiveDateTime> {
        let parts: Vec<&str> = self.version.split('/').collect();
        if parts.len() < 3 {
            return None;
        }
        // Skip the weekday: it is redundant and a mismatched weekday should
        // not make the database age unparseable.
        let mut tokens = parts[2].split_whitespace();
        let _weekday = tokens.next()?;
        let normalized = tokens.collect::<Vec<_>>().join(" ");
        NaiveDateTime::parse_from_str(&normalized, "%b %d %H:%M:%S %Y").ok()
    }

    pub fn db_age_days(&self) -> Option<i64> {
        let date = self.db_date()?;
        Some((chrono::Utc::now().naive_utc() - date).num_days())
    }

    /// Scan a list of regular files. Exit code 1 means "virus found" and is
    /// expected; other non-zero codes are reported in the coverage detail.
    pub fn scan(
        &self,
        targets: &[PathBuf],
        db: Option<&Path>,
        timeout: Duration,
    ) -> Result<ClamScan> {
        // clamscan's -f format is one path per line; a path containing a
        // newline cannot be represented (vanishingly rare, skipped explicitly).
        let usable: Vec<&PathBuf> = targets
            .iter()
            .filter(|p| !p.to_string_lossy().contains('\n'))
            .collect();
        if usable.is_empty() {
            return Ok(ClamScan {
                hits: Vec::new(),
                timed_out: false,
                exit_code: None,
                targets: 0,
            });
        }

        let list = write_file_list(&usable)?;
        let mut cmd = Command::new(&self.bin);
        cmd.args(["--no-summary", "--infected", "--stdout", "-f"])
            .arg(&list)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        if let Some(db) = db {
            cmd.arg("-d").arg(db);
        }

        let started = Instant::now();
        let mut child = cmd
            .spawn()
            .with_context(|| format!("cannot start {}", self.bin.display()))?;
        let stdout = child.stdout.take().expect("piped stdout");
        let reader = std::thread::spawn(move || {
            let mut buf = Vec::new();
            let mut out = stdout;
            let _ = out.read_to_end(&mut buf);
            String::from_utf8_lossy(&buf).into_owned()
        });

        let mut timed_out = false;
        let status = loop {
            if let Some(st) = child.try_wait()? {
                break Some(st);
            }
            if started.elapsed() >= timeout {
                timed_out = true;
                let _ = child.kill();
                let _ = child.wait();
                break None;
            }
            std::thread::sleep(Duration::from_millis(50));
        };

        let text = reader.join().unwrap_or_default();
        let _ = std::fs::remove_file(&list);

        Ok(ClamScan {
            hits: parse_output(&text),
            timed_out,
            exit_code: status.and_then(|s| s.code()),
            targets: usable.len(),
        })
    }
}

/// Parse `path: SignatureName FOUND` lines. Other ClamAV output is ignored.
pub fn parse_output(text: &str) -> Vec<ClamHit> {
    let mut hits = Vec::new();
    for line in text.lines() {
        let line = line.trim_end();
        let rest = match line.strip_suffix(" FOUND") {
            Some(r) => r,
            None => continue,
        };
        let (path, signature) = match rest.rsplit_once(": ") {
            Some(v) => v,
            None => continue,
        };
        if path.is_empty() || signature.is_empty() || signature.starts_with("LibClamAV") {
            continue;
        }
        hits.push(ClamHit {
            path: PathBuf::from(path),
            signature: signature.to_string(),
        });
    }
    hits.sort_by(|a, b| {
        (a.path.as_os_str(), &a.signature).cmp(&(b.path.as_os_str(), &b.signature))
    });
    hits.dedup();
    hits
}

fn write_file_list(targets: &[&PathBuf]) -> Result<PathBuf> {
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let path = std::env::temp_dir().join(format!(
        "warden-clamav-{}-{}.list",
        std::process::id(),
        stamp
    ));
    let mut body = String::new();
    for p in targets {
        body.push_str(&p.to_string_lossy());
        body.push('\n');
    }
    std::fs::write(&path, body).context("cannot write ClamAV file list")?;
    Ok(path)
}

/// True when `clamscan` and a local signature database are both present.
/// Used by the default profile; `--clamav` still forces the backend.
pub fn auto_available() -> bool {
    if !util::command_exists("clamscan") {
        return false;
    }
    ["/var/lib/clamav", "/usr/local/share/clamav"]
        .iter()
        .any(|dir| {
            std::fs::read_dir(dir)
                .map(|rd| {
                    rd.flatten().any(|entry| {
                        let name = entry.file_name().to_string_lossy().to_ascii_lowercase();
                        name.ends_with(".cvd") || name.ends_with(".cld") || name.ends_with(".cud")
                    })
                })
                .unwrap_or(false)
        })
}

fn which(name: &str) -> Option<PathBuf> {
    std::env::var_os("PATH").and_then(|paths| {
        std::env::split_paths(&paths)
            .map(|d| d.join(name))
            .find(|p| p.is_file())
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn parses_found_lines() {
        let text = "\
/tmp/a.bin: Unix.Trojan.Mirai-1 FOUND
/tmp/b.bin: OK
LibClamAV Warning: something odd
/etc/cron.d/x: Win.Test.EICAR_HDB-1 FOUND
";
        let hits = parse_output(text);
        assert_eq!(hits.len(), 2);
        assert_eq!(hits[0].path, PathBuf::from("/etc/cron.d/x"));
        assert_eq!(hits[0].signature, "Win.Test.EICAR_HDB-1");
        assert_eq!(hits[1].path, PathBuf::from("/tmp/a.bin"));
    }

    #[test]
    fn parses_database_date() {
        let av = ClamAv {
            bin: PathBuf::from("/bin/true"),
            version: "ClamAV 1.4.3/27450/Wed Nov  5 08:12:34 2025".into(),
        };
        let date = av.db_date().unwrap();
        assert_eq!(date.format("%Y-%m-%d").to_string(), "2025-11-05");
        assert!(av.db_age_days().is_some());

        let fake = ClamAv {
            bin: PathBuf::from("/bin/true"),
            version: "Fake ClamAV 1.4/27450/Thu Jan  1 00:00:00 2020".into(),
        };
        assert!(fake.db_date().is_some());

        let unknown = ClamAv {
            bin: PathBuf::from("/bin/true"),
            version: "ClamAV 1.4.3".into(),
        };
        assert!(unknown.db_date().is_none());
    }

    #[test]
    fn runs_external_scanner_and_parses_hits() {
        let _spawn = crate::util::SPAWN_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let dir = std::env::temp_dir().join(format!(
            "warden-clamav-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let sample = dir.join("evil.bin");
        std::fs::write(&sample, b"not a real virus").unwrap();

        let fake = dir.join("clamscan");
        std::fs::write(
            &fake,
            r#"#!/bin/sh
if [ "$1" = "--version" ]; then
  echo "Fake ClamAV 1.0/1/2026"
  exit 0
fi
prev=""
for a in "$@"; do
  if [ "$prev" = "-f" ]; then f="$a"; fi
  prev="$a"
done
first=$(head -n1 "$f")
echo "$first: Fake-Test-Signature FOUND"
exit 1
"#,
        )
        .unwrap();
        std::fs::set_permissions(&fake, std::fs::Permissions::from_mode(0o755)).unwrap();

        let av = ClamAv::with_binary(fake).unwrap();
        let scan = av
            .scan(std::slice::from_ref(&sample), None, Duration::from_secs(5))
            .unwrap();
        assert_eq!(scan.hits.len(), 1);
        assert_eq!(scan.hits[0].path, sample);
        assert_eq!(scan.hits[0].signature, "Fake-Test-Signature");
        assert_eq!(scan.targets, 1);
        assert!(!scan.timed_out);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
