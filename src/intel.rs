//! Threat-intelligence feeds.
//!
//! `--ioc` accepts a plain list or an abuse.ch CSV export, auto-detecting
//! SHA-256/SHA-1/MD5 hashes, URLs, domains, and IPs. File hashes are matched by
//! the static scanner; URLs/domains/IPs are used by quarantine fetch.

use crate::util;
use anyhow::{Context, Result};
use md5::Md5;
use sha1::Sha1;
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::io::Read;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

const MAX_FEED: u64 = 512 * util::MB;
const MAX_HASH_FILE: u64 = 64 * util::MB;

#[derive(Debug, Default)]
pub struct Intel {
    pub sha256: HashSet<String>,
    pub sha1: HashSet<String>,
    pub md5: HashSet<String>,
    pub urls: HashSet<String>,
    pub domains: HashSet<String>,
    pub ips: HashSet<String>,
}

#[derive(Debug, Clone)]
pub struct Hit {
    pub kind: &'static str,
    pub value: String,
}

/// Default directory used by `warden intel fetch/show` and auto-loaded by scan.
pub fn default_dir() -> PathBuf {
    util::home_dir().join(".config/warden/intel")
}

/// The default directory only when it contains at least one file.
pub fn default_source() -> Option<PathBuf> {
    let dir = default_dir();
    if dir.is_dir() && !util::files_in(&dir).is_empty() {
        Some(dir)
    } else {
        None
    }
}

pub struct FetchRequest {
    pub url: String,
    pub name: Option<String>,
    pub headers: Vec<String>,
    pub dir: PathBuf,
    pub max_size: u64,
    pub timeout: Duration,
    pub sha256: Option<String>,
    /// Test/embedded override for curl.
    pub curl: Option<PathBuf>,
}

/// Download a feed atomically, optionally verifying a pinned checksum.
pub fn fetch_feed(req: &FetchRequest) -> Result<PathBuf> {
    let curl = req
        .curl
        .clone()
        .or_else(|| which("curl"))
        .ok_or_else(|| anyhow::anyhow!("curl is required to download feeds"))?;
    std::fs::create_dir_all(&req.dir)
        .with_context(|| format!("cannot create intel directory: {}", req.dir.display()))?;

    let name = req.name.clone().unwrap_or_else(|| sanitize_name(&req.url));
    let dest = req.dir.join(&name);
    let tmp = req.dir.join(format!(".part-{}", std::process::id()));

    let max = req.max_size.to_string();
    let timeout = req.timeout.as_secs().to_string();
    let mut cmd = Command::new(curl);
    cmd.args([
        "-fsSL",
        "--proto",
        "=https,http",
        "--proto-redir",
        "=https,http",
        "--max-redirs",
        "5",
        "--connect-timeout",
        "10",
        "--max-time",
        &timeout,
        "--max-filesize",
        &max,
        "-o",
    ])
    .arg(&tmp);
    for header in &req.headers {
        cmd.arg("-H").arg(expand_vars(header)?);
    }
    cmd.arg("--").arg(&req.url);

    let out = cmd.output().context("cannot execute curl")?;
    if !out.status.success() {
        let _ = std::fs::remove_file(&tmp);
        anyhow::bail!(
            "feed download failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }

    let size = std::fs::metadata(&tmp)?.len();
    if size == 0 {
        let _ = std::fs::remove_file(&tmp);
        anyhow::bail!("downloaded feed is empty");
    }
    if size > req.max_size {
        let _ = std::fs::remove_file(&tmp);
        anyhow::bail!("downloaded feed exceeds the {} byte limit", req.max_size);
    }

    if let Some(expected) = &req.sha256 {
        let actual = util::sha256_file(&tmp, req.max_size + 1)
            .ok_or_else(|| anyhow::anyhow!("cannot hash the downloaded feed"))?;
        let expected = expected.trim().to_ascii_lowercase();
        if actual != expected {
            let _ = std::fs::remove_file(&tmp);
            anyhow::bail!("feed checksum mismatch: expected {expected}, got {actual}");
        }
    }

    std::fs::rename(&tmp, &dest)
        .with_context(|| format!("cannot store feed at {}", dest.display()))?;
    Ok(dest)
}

pub fn feed_files(dir: &Path) -> Vec<(PathBuf, u64)> {
    util::files_in(dir)
        .into_iter()
        .filter_map(|p| {
            let size = std::fs::metadata(&p).ok()?.len();
            Some((p, size))
        })
        .collect()
}

fn which(name: &str) -> Option<PathBuf> {
    std::env::var_os("PATH").and_then(|paths| {
        std::env::split_paths(&paths)
            .map(|d| d.join(name))
            .find(|p| p.is_file())
    })
}

fn sanitize_name(url: &str) -> String {
    let path = url.split(['?', '#']).next().unwrap_or(url);
    let last = path.rsplit('/').next().unwrap_or("");
    let cleaned: String = last
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_') {
                c
            } else {
                '_'
            }
        })
        .collect();
    let cleaned = cleaned.trim_matches('.').to_string();
    if cleaned.is_empty() {
        "feed.csv".into()
    } else {
        cleaned.chars().take(80).collect()
    }
}

fn expand_vars(input: &str) -> Result<String> {
    let mut out = String::new();
    let mut chars = input.chars().peekable();
    while let Some(c) = chars.next() {
        if c != '$' {
            out.push(c);
            continue;
        }
        let name = if chars.peek() == Some(&'{') {
            chars.next();
            let mut name = String::new();
            for ch in chars.by_ref() {
                if ch == '}' {
                    break;
                }
                name.push(ch);
            }
            name
        } else {
            let mut name = String::new();
            while let Some(&ch) = chars.peek() {
                if ch.is_ascii_alphanumeric() || ch == '_' {
                    name.push(ch);
                    chars.next();
                } else {
                    break;
                }
            }
            name
        };
        if name.is_empty() {
            out.push('$');
            continue;
        }
        let value = std::env::var(&name)
            .with_context(|| format!("environment variable {name} is not set"))?;
        out.push_str(&value);
    }
    Ok(out)
}

impl Intel {
    pub fn load(paths: &[PathBuf]) -> Result<Self> {
        let mut intel = Intel::default();
        for path in paths {
            intel.load_path(path)?;
        }
        Ok(intel)
    }

    pub fn is_empty(&self) -> bool {
        self.sha256.is_empty()
            && self.sha1.is_empty()
            && self.md5.is_empty()
            && self.urls.is_empty()
            && self.domains.is_empty()
            && self.ips.is_empty()
    }

    pub fn has_file_hashes(&self) -> bool {
        !self.sha256.is_empty() || !self.sha1.is_empty() || !self.md5.is_empty()
    }

    pub fn counts(&self) -> String {
        format!(
            "sha256={} sha1={} md5={} url={} domain={} ip={}",
            self.sha256.len(),
            self.sha1.len(),
            self.md5.len(),
            self.urls.len(),
            self.domains.len(),
            self.ips.len()
        )
    }

    fn load_path(&mut self, path: &Path) -> Result<()> {
        if path.is_dir() {
            for file in util::files_in(path) {
                // A bad file in a feed directory should not abort the scan.
                let _ = self.load_file(&file);
            }
            Ok(())
        } else {
            self.load_file(path)
        }
    }

    fn load_file(&mut self, path: &Path) -> Result<()> {
        let text = util::read_text(path, MAX_FEED)
            .with_context(|| format!("cannot read IOC feed: {}", path.display()))?;
        if looks_like_csv(&text) {
            self.load_csv(&text)?;
        } else {
            for line in text.lines() {
                self.classify(line);
            }
        }
        Ok(())
    }

    fn load_csv(&mut self, text: &str) -> Result<()> {
        let mut reader = csv::ReaderBuilder::new()
            .flexible(true)
            .from_reader(text.as_bytes());
        let headers = reader.headers().context("invalid IOC CSV header")?.clone();

        let mut cols = Columns::default();
        for (i, header) in headers.iter().enumerate() {
            let h = header
                .trim()
                .trim_start_matches('\u{feff}')
                .to_ascii_lowercase();
            match h.as_str() {
                _ if h.contains("sha256") => cols.sha256 = Some(i),
                _ if h.contains("sha1") => cols.sha1 = Some(i),
                _ if h.contains("md5") => cols.md5 = Some(i),
                "url" => cols.url = Some(i),
                "dst_ip" | "ip_address" | "dst_ip_addr" => cols.ip = Some(i),
                "domain" | "hostname" => cols.domain = Some(i),
                "ioc_value" => cols.ioc_value = Some(i),
                "ioc_type" => cols.ioc_type = Some(i),
                _ => {}
            }
        }

        let known = cols.sha256.is_some()
            || cols.sha1.is_some()
            || cols.md5.is_some()
            || cols.url.is_some()
            || cols.ip.is_some()
            || cols.domain.is_some()
            || cols.ioc_value.is_some();

        for record in reader.records().flatten() {
            if !known {
                for field in record.iter() {
                    self.classify(field);
                }
                continue;
            }
            if let Some(i) = cols.sha256 {
                if let Some(v) = record.get(i) {
                    self.insert_hex(v, 64);
                }
            }
            if let Some(i) = cols.sha1 {
                if let Some(v) = record.get(i) {
                    self.insert_hex(v, 40);
                }
            }
            if let Some(i) = cols.md5 {
                if let Some(v) = record.get(i) {
                    self.insert_hex(v, 32);
                }
            }
            if let Some(i) = cols.url {
                if let Some(v) = record.get(i) {
                    self.insert_url(v);
                }
            }
            if let Some(i) = cols.domain {
                if let Some(v) = record.get(i) {
                    self.insert_domain(v);
                }
            }
            if let Some(i) = cols.ip {
                if let Some(v) = record.get(i) {
                    self.insert_ip(v);
                }
            }
            if let (Some(vi), Some(ti)) = (cols.ioc_value, cols.ioc_type) {
                if let (Some(value), Some(kind)) = (record.get(vi), record.get(ti)) {
                    self.classify_typed(value, kind);
                }
            }
        }
        Ok(())
    }

    fn classify_typed(&mut self, value: &str, kind: &str) {
        match kind.trim().to_ascii_lowercase().as_str() {
            "sha256_hash" | "sha256" => self.insert_hex(value, 64),
            "sha1_hash" | "sha1" => self.insert_hex(value, 40),
            "md5_hash" | "md5" => self.insert_hex(value, 32),
            "url" | "uri" => self.insert_url(value),
            "domain" | "hostname" => self.insert_domain(value),
            "ip:port" | "ip" => self.insert_ip(value),
            _ => self.classify(value),
        }
    }

    fn classify(&mut self, raw: &str) {
        let value = raw.trim().trim_matches('"').trim();
        if value.is_empty() || value.starts_with('#') {
            return;
        }
        if value.len() == 64 {
            self.insert_hex(value, 64);
        } else if value.len() == 40 {
            self.insert_hex(value, 40);
        } else if value.len() == 32 {
            self.insert_hex(value, 32);
        } else if value.to_ascii_lowercase().starts_with("http://")
            || value.to_ascii_lowercase().starts_with("https://")
        {
            self.insert_url(value);
        } else if value.parse::<IpAddr>().is_ok() {
            self.insert_ip(value);
        } else if looks_like_domain(value) {
            self.insert_domain(value);
        }
    }

    fn insert_hex(&mut self, value: &str, len: usize) {
        let v = value.trim().trim_matches('"').to_ascii_lowercase();
        if v.len() != len || !v.chars().all(|c| c.is_ascii_hexdigit()) {
            return;
        }
        match len {
            64 => {
                self.sha256.insert(v);
            }
            40 => {
                self.sha1.insert(v);
            }
            32 => {
                self.md5.insert(v);
            }
            _ => {}
        }
    }

    fn insert_url(&mut self, value: &str) {
        let v = value.trim().trim_matches('"').to_ascii_lowercase();
        if v.starts_with("http://") || v.starts_with("https://") {
            self.urls.insert(v);
        }
    }

    fn insert_domain(&mut self, value: &str) {
        let v = value.trim().trim_matches('"').to_ascii_lowercase();
        if looks_like_domain(&v) {
            self.domains.insert(v);
        }
    }

    fn insert_ip(&mut self, value: &str) {
        let v = value.trim().trim_matches('"');
        if let Ok(ip) = v.parse::<IpAddr>() {
            self.ips.insert(ip.to_string());
            return;
        }
        // Feodo/ThreatFox often use ip:port.
        if let Some((host, _)) = v.rsplit_once(':') {
            if let Ok(ip) = host.trim_matches(['[', ']']).parse::<IpAddr>() {
                self.ips.insert(ip.to_string());
            }
        }
    }

    pub fn match_file(&self, path: &Path, max_size: u64) -> Option<Hit> {
        let max = max_size.min(MAX_HASH_FILE);
        if !self.sha256.is_empty() {
            if let Some(h) = digest_file::<Sha256>(path, max) {
                if self.sha256.contains(&h) {
                    return Some(Hit {
                        kind: "sha256",
                        value: h,
                    });
                }
            }
        }
        if !self.sha1.is_empty() {
            if let Some(h) = digest_file::<Sha1>(path, max) {
                if self.sha1.contains(&h) {
                    return Some(Hit {
                        kind: "sha1",
                        value: h,
                    });
                }
            }
        }
        if !self.md5.is_empty() {
            if let Some(h) = digest_file::<Md5>(path, max) {
                if self.md5.contains(&h) {
                    return Some(Hit {
                        kind: "md5",
                        value: h,
                    });
                }
            }
        }
        None
    }

    pub fn match_url(&self, url: &str) -> Option<Hit> {
        let lower = url.trim().to_ascii_lowercase();
        if self.urls.contains(&lower) {
            return Some(Hit {
                kind: "url",
                value: lower,
            });
        }
        let host = host_of(&lower)?;
        self.match_host(&host)
    }

    pub fn match_host(&self, host: &str) -> Option<Hit> {
        let host = host.trim_matches(['[', ']']).to_ascii_lowercase();
        if self.ips.contains(&host) {
            return Some(Hit {
                kind: "ip",
                value: host,
            });
        }
        if self.domains.contains(&host) {
            return Some(Hit {
                kind: "domain",
                value: host,
            });
        }
        // `*.example.com` matches any subdomain (but not the apex).
        let mut suffix = host.as_str();
        while let Some((_, rest)) = suffix.split_once('.') {
            let wildcard = format!("*.{rest}");
            if self.domains.contains(&wildcard) {
                return Some(Hit {
                    kind: "domain",
                    value: wildcard,
                });
            }
            suffix = rest;
        }
        None
    }
}

#[derive(Default)]
struct Columns {
    sha256: Option<usize>,
    sha1: Option<usize>,
    md5: Option<usize>,
    url: Option<usize>,
    domain: Option<usize>,
    ip: Option<usize>,
    ioc_value: Option<usize>,
    ioc_type: Option<usize>,
}

fn looks_like_csv(text: &str) -> bool {
    let head = match text.lines().find(|l| !l.trim().is_empty()) {
        Some(l) => l.to_ascii_lowercase(),
        None => return false,
    };
    head.contains(',')
        && [
            "sha256",
            "sha1",
            "md5",
            "ioc_value",
            "dst_ip",
            "url",
            "domain",
        ]
        .iter()
        .any(|needle| head.contains(needle))
}

fn looks_like_domain(value: &str) -> bool {
    value.len() <= 253
        && value.contains('.')
        && !value.contains('/')
        && !value.contains(' ')
        && !value.starts_with('.')
        && !value.ends_with('.')
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '.' | '_' | '*'))
}

fn host_of(url: &str) -> Option<String> {
    let rest = url.split_once("://")?.1;
    let authority = rest.split(['/', '?', '#']).next()?;
    let host = if let Some(stripped) = authority.strip_prefix('[') {
        stripped.split(']').next()?.to_string()
    } else {
        authority
            .rsplit_once(':')
            .map(|(h, _)| h)
            .unwrap_or(authority)
            .to_string()
    };
    if host.is_empty() {
        None
    } else {
        Some(host)
    }
}

fn digest_file<D: Digest + Default>(path: &Path, max_size: u64) -> Option<String> {
    let meta = std::fs::metadata(path).ok()?;
    if !meta.is_file() || meta.len() == 0 || meta.len() > max_size {
        return None;
    }
    let mut file = std::fs::File::open(path).ok()?;
    let mut hasher = D::default();
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = file.read(&mut buf).ok()?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    let digest = hasher.finalize();
    Some(digest.iter().map(|b| format!("{b:02x}")).collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_malwarebazaar_csv() {
        let text = "first_seen_utc,sha256_hash,md5_hash,sha1_hash,reporter,file_name,tags\n2026-01-01,aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa,bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb,cccccccccccccccccccccccccccccccccccccccc,me,sample,exe\n";
        let mut intel = Intel::default();
        intel.load_csv(text).unwrap();
        assert_eq!(intel.sha256.len(), 1);
        assert_eq!(intel.md5.len(), 1);
        assert_eq!(intel.sha1.len(), 1);
    }

    #[test]
    fn parses_threatfox_types() {
        let text = "first_seen_utc,ioc_id,ioc_value,ioc_type,threat_type\n2026-01-01,1,evil.example.com,domain,botnet\n2026-01-01,2,http://bad.example/x,url,botnet\n2026-01-01,3,203.0.113.9:8443,ip:port,c2\n";
        let mut intel = Intel::default();
        intel.load_csv(text).unwrap();
        assert!(intel.domains.contains("evil.example.com"));
        assert!(intel.urls.contains("http://bad.example/x"));
        assert!(intel.ips.contains("203.0.113.9"));
    }

    #[test]
    fn matches_hashes_urls_and_wildcards() {
        let dir = std::env::temp_dir().join(format!(
            "warden-intel-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let sample = dir.join("sample.bin");
        std::fs::write(&sample, b"intel sample").unwrap();
        let hash = util::sha256_file(&sample, 1024).unwrap();
        let feed = dir.join("feed.txt");
        std::fs::write(
            &feed,
            format!("{hash}\nhttps://bad.example/x\n*.evil.example\n192.0.2.10\n"),
        )
        .unwrap();

        let intel = Intel::load(&[feed]).unwrap();
        assert_eq!(intel.match_file(&sample, 1024).unwrap().kind, "sha256");
        assert!(intel.match_url("https://bad.example/x").is_some());
        assert!(intel.match_url("https://sub.evil.example/a").is_some());
        assert_eq!(
            intel.match_url("http://192.0.2.10:8080/").unwrap().kind,
            "ip"
        );
        assert!(intel.match_url("https://good.example/").is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn expands_headers() {
        std::env::set_var("WARDEN_TEST_KEY", "secret");
        assert_eq!(
            expand_vars("Auth-Key: $WARDEN_TEST_KEY").unwrap(),
            "Auth-Key: secret"
        );
        assert_eq!(
            expand_vars("Auth-Key: ${WARDEN_TEST_KEY}").unwrap(),
            "Auth-Key: secret"
        );
        assert!(expand_vars("$WARDEN_MISSING_TEST_VAR").is_err());
    }

    #[test]
    fn fetches_feed_with_checksum() {
        use std::os::unix::fs::PermissionsExt;
        let _spawn = crate::util::SPAWN_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());

        std::env::set_var("WARDEN_TEST_KEY", "secret");
        let dir = std::env::temp_dir().join(format!(
            "warden-intel-fetch-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let payload =
            "sha256_hash\naaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n";
        let fake = dir.join("curl");
        std::fs::write(
            &fake,
            format!(
                r#"#!/bin/sh
out=""; prev=""
for a in "$@"; do
  if [ "$prev" = "-o" ]; then out="$a"; fi
  prev="$a"
done
printf '%s' '{}' > "$out"
"#,
                payload
            ),
        )
        .unwrap();
        std::fs::set_permissions(&fake, std::fs::Permissions::from_mode(0o755)).unwrap();

        let req = FetchRequest {
            url: "http://example.invalid/feed.csv".into(),
            name: Some("feed.csv".into()),
            headers: vec!["X-Test: $WARDEN_TEST_KEY".into()],
            dir: dir.join("intel"),
            max_size: 1024 * 1024,
            timeout: Duration::from_secs(5),
            sha256: None,
            curl: Some(fake),
        };
        let path = fetch_feed(&req).unwrap();
        assert!(path.is_file());
        assert_eq!(std::fs::read_to_string(&path).unwrap(), payload);

        let intel = Intel::load(&[path]).unwrap();
        assert_eq!(intel.sha256.len(), 1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn plain_text_classifies() {
        let mut intel = Intel::default();
        intel.classify("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        intel.classify("evil.example");
        intel.classify("198.51.100.4");
        assert_eq!(intel.sha256.len(), 1);
        assert_eq!(intel.domains.len(), 1);
        assert_eq!(intel.ips.len(), 1);
    }
}
