//! OSV (osv.dev) supply-chain checks.
//!
//! Opt-in by design: package lists are sent to osv.dev and the scan needs
//! network access. Results are cached under `~/.cache/warden/osv/` to avoid
//! repeated queries. Only ecosystems with OSV coverage are queried (Debian,
//! Ubuntu, Alpine, Rocky Linux, AlmaLinux, Wolfi); others are skipped.

use crate::model::Severity;
use crate::util;
use anyhow::{Context, Result};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, SystemTime};

const QUERY_CHUNK: usize = 100;
const MAX_PACKAGES: usize = 5_000;
const TIMEOUT: Duration = Duration::from_secs(60);

#[derive(Debug, Clone)]
pub struct OsvConfig {
    pub base_url: String,
    pub cache_dir: PathBuf,
    pub max_age_hours: u64,
    /// Test/embedded override for curl.
    pub curl: Option<PathBuf>,
}

impl Default for OsvConfig {
    fn default() -> Self {
        OsvConfig {
            base_url: "https://api.osv.dev".into(),
            cache_dir: util::home_dir().join(".cache/warden/osv"),
            max_age_hours: 24,
            curl: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Package {
    pub name: String,
    pub version: String,
    pub ecosystem: &'static str,
}

#[derive(Debug, Clone)]
pub struct Vuln {
    pub id: String,
    pub summary: String,
    pub details: String,
    pub severity: Severity,
    pub aliases: Vec<String>,
    pub fixed: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct Hit {
    pub package: Package,
    pub vuln: Vuln,
}

/// Map `/etc/os-release` to the OSV ecosystem name.
pub fn ecosystem_from_os_release(text: &str) -> Option<&'static str> {
    let mut id = String::new();
    let mut like = String::new();
    for line in text.lines() {
        let (k, v) = match line.trim().split_once('=') {
            Some(kv) => kv,
            None => continue,
        };
        let v = v.trim().trim_matches('"').to_ascii_lowercase();
        match k.trim() {
            "ID" => id = v,
            "ID_LIKE" => like = v,
            _ => {}
        }
    }
    match id.as_str() {
        "ubuntu" => Some("Ubuntu"),
        "debian" => Some("Debian"),
        "alpine" => Some("Alpine"),
        "rocky" => Some("Rocky Linux"),
        "almalinux" => Some("AlmaLinux"),
        "wolfi" => Some("Wolfi"),
        _ if like.split_whitespace().any(|x| x == "debian") => Some("Debian"),
        _ if like.split_whitespace().any(|x| x == "alpine") => Some("Alpine"),
        _ => None,
    }
}

pub fn detect_ecosystem() -> Option<&'static str> {
    let text = util::read_text(Path::new("/etc/os-release"), 128 * 1024)?;
    ecosystem_from_os_release(&text)
}

/// Enumerate installed packages in the format OSV expects.
pub fn installed_packages(ecosystem: &'static str) -> Result<Vec<Package>> {
    let raw = match ecosystem {
        "Ubuntu" | "Debian" => dpkg_packages()?,
        "Alpine" => apk_packages()?,
        "Rocky Linux" | "AlmaLinux" => rpm_packages()?,
        _ => Vec::new(),
    };
    let mut out: Vec<Package> = Vec::new();
    for (name, version) in raw {
        if name.is_empty() || version.is_empty() {
            continue;
        }
        let p = Package {
            name,
            version,
            ecosystem,
        };
        if !out.contains(&p) {
            out.push(p);
        }
        if out.len() >= MAX_PACKAGES {
            break;
        }
    }
    out.sort();
    Ok(out)
}

fn dpkg_packages() -> Result<Vec<(String, String)>> {
    // Source package names are what OSV's Debian/Ubuntu entries use.
    let fmt = r"${binary:Package}\t${source:Package}\t${source:Version}\t${Version}\t${db:Status-Abbrev}\n";
    let out = util::run_timeout("dpkg-query", &["-W", &format!("-f={fmt}")], TIMEOUT)
        .ok_or_else(|| anyhow::anyhow!("dpkg-query failed or timed out"))?;
    let text = if out.status.success() {
        String::from_utf8_lossy(&out.stdout).into_owned()
    } else {
        // Older dpkg-query builds may not know source:Version; fall back to
        // binary package/version (still valid OSV input for many entries).
        let out = util::run_timeout(
            "dpkg-query",
            &["-W", "-f=${binary:Package}\t${Version}\n"],
            TIMEOUT,
        )
        .ok_or_else(|| anyhow::anyhow!("dpkg-query failed or timed out"))?;
        if !out.status.success() {
            anyhow::bail!("dpkg-query exited with {:?}", out.status.code());
        }
        let text = String::from_utf8_lossy(&out.stdout).into_owned();
        return Ok(text
            .lines()
            .filter_map(|line| {
                let (n, v) = line.split_once('\t')?;
                Some((n.trim().to_string(), v.trim().to_string()))
            })
            .collect());
    };
    let mut out = Vec::new();
    for line in text.lines() {
        let f: Vec<&str> = line.split('\t').collect();
        if f.len() < 5 || !f[4].starts_with("ii") {
            continue;
        }
        let name = if f[1].trim().is_empty() { f[0] } else { f[1] };
        let version = if f[2].trim().is_empty() { f[3] } else { f[2] };
        out.push((name.trim().to_string(), version.trim().to_string()));
    }
    Ok(out)
}

fn rpm_packages() -> Result<Vec<(String, String)>> {
    let fmt = r"%{NAME}\t%{VERSION}-%{RELEASE}\n";
    let out = util::run_timeout("rpm", &["-qa", &format!("--qf={fmt}")], TIMEOUT)
        .ok_or_else(|| anyhow::anyhow!("rpm failed or timed out"))?;
    if !out.status.success() {
        anyhow::bail!("rpm exited with {:?}", out.status.code());
    }
    Ok(String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter_map(|line| {
            let (n, v) = line.split_once('\t')?;
            Some((n.trim().to_string(), v.trim().to_string()))
        })
        .collect())
}

fn apk_packages() -> Result<Vec<(String, String)>> {
    let out = util::run_timeout("apk", &["info", "-v"], TIMEOUT)
        .ok_or_else(|| anyhow::anyhow!("apk failed or timed out"))?;
    if !out.status.success() {
        anyhow::bail!("apk exited with {:?}", out.status.code());
    }
    Ok(String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter_map(|line| {
            let line = line.trim();
            // e.g. musl-1.2.5-r0: split at the first hyphen followed by a digit.
            let mut split = None;
            for (i, c) in line.char_indices() {
                if c == '-' {
                    if let Some(next) = line[i + 1..].chars().next() {
                        if next.is_ascii_digit() {
                            split = Some(i);
                            break;
                        }
                    }
                }
            }
            let i = split?;
            Some((line[..i].to_string(), line[i + 1..].to_string()))
        })
        .collect())
}

/// Query OSV, using a freshness-bounded cache. Returns `(hits, from_cache)`.
pub fn query(packages: &[Package], cfg: &OsvConfig) -> Result<(Vec<Hit>, bool)> {
    if packages.is_empty() {
        return Ok((Vec::new(), false));
    }
    let key = cache_key(packages);
    let cache_file = cfg
        .cache_dir
        .join(format!("{}.json", &key[..32.min(key.len())]));

    if cfg.max_age_hours > 0 {
        if let Some(doc) = read_fresh_cache(&cache_file, cfg.max_age_hours) {
            return Ok((parse_response(&doc, packages), true));
        }
    }

    match fetch_response(packages, cfg) {
        Ok(doc) => {
            let _ = write_cache(&cache_file, &doc);
            Ok((parse_response(&doc, packages), false))
        }
        Err(e) => {
            // A stale cache is better than a failed scan, but say so via the
            // boolean (the caller reports it as an Info item).
            if let Ok(text) = std::fs::read_to_string(&cache_file) {
                if let Ok(doc) = serde_json::from_str::<Value>(&text) {
                    return Ok((parse_response(&doc, packages), true));
                }
            }
            Err(e)
        }
    }
}

fn fetch_response(packages: &[Package], cfg: &OsvConfig) -> Result<Value> {
    let curl = cfg
        .curl
        .clone()
        .or_else(|| which("curl"))
        .ok_or_else(|| anyhow::anyhow!("curl is required for OSV queries"))?;
    let endpoint = format!("{}/v1/querybatch", cfg.base_url.trim_end_matches('/'));

    let mut merged = Vec::new();
    for chunk in packages.chunks(QUERY_CHUNK) {
        let body = json!({
            "queries": chunk.iter().map(|p| json!({
                "package": { "name": p.name, "ecosystem": p.ecosystem },
                "version": p.version,
            })).collect::<Vec<_>>(),
        });
        let body = serde_json::to_vec(&body)?;

        let mut child = Command::new(&curl)
            .args([
                "-fsS",
                "--proto",
                "=https,http",
                "--proto-redir",
                "=https,http",
                "--max-time",
                "60",
                "-X",
                "POST",
                "-H",
                "Content-Type: application/json",
                "--data-binary",
                "@-",
                &endpoint,
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .context("cannot execute curl for OSV")?;
        child
            .stdin
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("cannot open curl stdin"))?
            .write_all(&body)?;
        drop(child.stdin.take());
        let out = child.wait_with_output()?;
        if !out.status.success() {
            anyhow::bail!(
                "OSV query failed: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            );
        }
        let value: Value =
            serde_json::from_slice(&out.stdout).context("invalid OSV response JSON")?;
        let results = value
            .get("results")
            .and_then(|r| r.as_array())
            .ok_or_else(|| anyhow::anyhow!("OSV response has no results array"))?;
        for result in results {
            merged.push(result.clone());
        }
    }
    Ok(json!({ "results": merged }))
}

fn parse_response(doc: &Value, packages: &[Package]) -> Vec<Hit> {
    let results = match doc.get("results").and_then(|r| r.as_array()) {
        Some(r) => r,
        None => return Vec::new(),
    };
    let mut hits = Vec::new();
    for (i, result) in results.iter().enumerate() {
        let package = match packages.get(i) {
            Some(p) => p,
            None => break,
        };
        let vulns = match result.get("vulns").and_then(|v| v.as_array()) {
            Some(v) => v,
            None => continue,
        };
        let mut seen = std::collections::HashSet::new();
        for raw in vulns {
            if let Some(vuln) = parse_vuln(raw) {
                if seen.insert(vuln.id.clone()) {
                    hits.push(Hit {
                        package: package.clone(),
                        vuln,
                    });
                }
            }
        }
    }
    hits
}

fn parse_vuln(raw: &Value) -> Option<Vuln> {
    let id = raw.get("id")?.as_str()?.to_string();
    let summary = raw
        .get("summary")
        .and_then(|s| s.as_str())
        .unwrap_or("")
        .to_string();
    let details = raw
        .get("details")
        .and_then(|s| s.as_str())
        .unwrap_or("")
        .chars()
        .take(600)
        .collect();
    let aliases = string_array(raw.get("aliases"));
    let severity = severity_of(raw);
    let mut fixed = Vec::new();
    if let Some(affected) = raw.get("affected").and_then(|a| a.as_array()) {
        for item in affected {
            if let Some(f) = item
                .get("database_specific")
                .and_then(|d| d.get("fixed"))
                .and_then(|f| f.as_str())
            {
                if !fixed.iter().any(|x| x == f) {
                    fixed.push(f.to_string());
                }
            }
            if let Some(ranges) = item.get("ranges").and_then(|r| r.as_array()) {
                for range in ranges {
                    if let Some(events) = range.get("events").and_then(|e| e.as_array()) {
                        for event in events {
                            if let Some(f) = event.get("fixed").and_then(|f| f.as_str()) {
                                if !fixed.iter().any(|x| x == f) {
                                    fixed.push(f.to_string());
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    Some(Vuln {
        id,
        summary,
        details,
        severity,
        aliases,
        fixed,
    })
}

fn severity_of(raw: &Value) -> Severity {
    let text = raw
        .get("database_specific")
        .and_then(|d| d.get("severity"))
        .and_then(|s| s.as_str())
        .or_else(|| {
            raw.get("ecosystem_specific")
                .and_then(|d| d.get("severity"))
                .and_then(|s| s.as_str())
        })
        .unwrap_or("");
    match text.to_ascii_uppercase().as_str() {
        "CRITICAL" => Severity::Critical,
        "HIGH" => Severity::High,
        "MODERATE" | "MEDIUM" => Severity::Medium,
        "LOW" => Severity::Low,
        _ => Severity::Medium,
    }
}

fn string_array(value: Option<&Value>) -> Vec<String> {
    value
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|x| x.as_str())
                .map(|s| s.to_string())
                .collect()
        })
        .unwrap_or_default()
}

fn cache_key(packages: &[Package]) -> String {
    let mut h = Sha256::new();
    h.update(env!("CARGO_PKG_VERSION").as_bytes());
    h.update(b"osv-cache-v1");
    for p in packages {
        h.update(p.ecosystem.as_bytes());
        h.update([0]);
        h.update(p.name.as_bytes());
        h.update([0]);
        h.update(p.version.as_bytes());
        h.update([0]);
    }
    format!("{:x}", h.finalize())
}

fn read_fresh_cache(path: &Path, max_age_hours: u64) -> Option<Value> {
    let meta = std::fs::metadata(path).ok()?;
    let modified = meta.modified().ok()?;
    let age = SystemTime::now().duration_since(modified).ok()?;
    if age > Duration::from_secs(max_age_hours.saturating_mul(3600)) {
        return None;
    }
    let text = std::fs::read_to_string(path).ok()?;
    serde_json::from_str(&text).ok()
}

fn write_cache(path: &Path, doc: &Value) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let tmp = path.with_extension(format!("part-{}", std::process::id()));
    std::fs::write(&tmp, serde_json::to_vec(doc)?)?;
    std::fs::rename(&tmp, path)?;
    Ok(())
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
    fn ecosystem_mapping() {
        assert_eq!(
            ecosystem_from_os_release("ID=ubuntu\nID_LIKE=debian\n"),
            Some("Ubuntu")
        );
        assert_eq!(ecosystem_from_os_release("ID=\"debian\"\n"), Some("Debian"));
        assert_eq!(ecosystem_from_os_release("ID=arch\n"), None);
        assert_eq!(
            ecosystem_from_os_release("ID=unknown\nID_LIKE=debian\n"),
            Some("Debian")
        );
    }

    #[test]
    fn apk_version_split() {
        // The splitter is exercised through installed_packages on Alpine only;
        // keep a small pure check of the boundary logic.
        let line = "python3-3.12.1-r0";
        let mut split = None;
        for (i, c) in line.char_indices() {
            if c == '-' {
                if let Some(next) = line[i + 1..].chars().next() {
                    if next.is_ascii_digit() {
                        split = Some(i);
                        break;
                    }
                }
            }
        }
        let i = split.unwrap();
        assert_eq!(&line[..i], "python3");
        assert_eq!(&line[i + 1..], "3.12.1-r0");
    }

    #[test]
    fn parses_osv_vulnerability() {
        let raw: Value = serde_json::from_str(
            r#"{
              "id":"GHSA-test",
              "summary":"test vuln",
              "details":"details",
              "aliases":["CVE-2026-0001"],
              "database_specific":{"severity":"HIGH"},
              "affected":[{"ranges":[{"events":[{"introduced":"1.0"},{"fixed":"1.2.3"}]}]}]
            }"#,
        )
        .unwrap();
        let v = parse_vuln(&raw).unwrap();
        assert_eq!(v.id, "GHSA-test");
        assert_eq!(v.severity, Severity::High);
        assert_eq!(v.fixed, vec!["1.2.3"]);
        assert_eq!(v.aliases, vec!["CVE-2026-0001"]);
    }

    #[test]
    fn queries_and_caches_with_fake_curl() {
        let _spawn = crate::util::SPAWN_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let dir = std::env::temp_dir().join(format!(
            "warden-osv-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let fake = dir.join("curl");
        std::fs::write(
            &fake,
            r#"#!/bin/sh
cat >/dev/null
printf '%s' '{"results":[{"vulns":[{"id":"OSV-1","summary":"bad","database_specific":{"severity":"CRITICAL"},"affected":[{"ranges":[{"events":[{"fixed":"2.0"}]}]}]}]}]}'
"#,
        )
        .unwrap();
        std::fs::set_permissions(&fake, std::fs::Permissions::from_mode(0o755)).unwrap();

        let package = Package {
            name: "demo".into(),
            version: "1.0".into(),
            ecosystem: "Debian",
        };
        let cfg = OsvConfig {
            base_url: "http://osv.invalid".into(),
            cache_dir: dir.join("cache"),
            max_age_hours: 24,
            curl: Some(fake),
        };
        let (hits, cached) = query(std::slice::from_ref(&package), &cfg).unwrap();
        assert!(!cached);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].vuln.severity, Severity::Critical);

        // Second call must use the cache without invoking curl.
        let cached_cfg = OsvConfig {
            curl: None,
            ..cfg.clone()
        };
        let (hits, cached) = query(std::slice::from_ref(&package), &cached_cfg).unwrap();
        assert!(cached);
        assert_eq!(hits.len(), 1);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
