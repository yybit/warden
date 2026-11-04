//! Offline known-malicious package detection.
//!
//! Consumes a clone of `ossf/malicious-packages` (or any directory of OSV JSON
//! records) and matches installed npm / PyPI / crates.io packages. This is
//! fully offline: the dataset is user-supplied, so there is no API key or
//! privacy trade-off.

use crate::util;
use anyhow::Result;
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

const MAX_DATASET_FILES: usize = 200_000;
const MAX_LOCAL_FILES: usize = 100_000;

#[derive(Debug, Clone)]
pub struct InstalledPackage {
    pub ecosystem: &'static str,
    pub name: String,
    pub version: String,
}

#[derive(Debug, Clone)]
pub struct Affected {
    pub id: String,
    pub summary: String,
    pub details: String,
    pub aliases: Vec<String>,
    versions: Vec<String>,
    ranges: Vec<VersionRange>,
}

#[derive(Debug, Clone, Default)]
struct VersionRange {
    introduced: Option<String>,
    fixed: Option<String>,
    last_affected: Option<String>,
}

#[derive(Debug, Default)]
pub struct Dataset {
    entries: HashMap<(String, String), Vec<Affected>>,
    pub records: usize,
    pub files: usize,
    pub parse_errors: usize,
}

impl Dataset {
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn load(dir: &Path) -> Result<Self> {
        let mut dataset = Dataset::default();
        for entry in WalkDir::new(dir)
            .max_depth(10)
            .follow_links(false)
            .into_iter()
            .filter_map(|e| e.ok())
        {
            if !entry.file_type().is_file() {
                continue;
            }
            if entry.path().extension().and_then(|e| e.to_str()) != Some("json") {
                continue;
            }
            if dataset.files >= MAX_DATASET_FILES {
                break;
            }
            let text = match util::read_text(entry.path(), 4 * util::MB) {
                Some(t) => t,
                None => continue,
            };
            dataset.files += 1;
            let value: Value = match serde_json::from_str(&text) {
                Ok(v) => v,
                Err(_) => {
                    dataset.parse_errors += 1;
                    continue;
                }
            };
            if let Value::Array(items) = &value {
                for item in items {
                    dataset.add_record(item);
                }
            } else {
                dataset.add_record(&value);
            }
        }
        Ok(dataset)
    }

    fn add_record(&mut self, raw: &Value) {
        let id = raw.get("id").and_then(|v| v.as_str()).unwrap_or("");
        if id.is_empty() {
            return;
        }
        let summary = raw
            .get("summary")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let details: String = raw
            .get("details")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .chars()
            .take(600)
            .collect();
        let aliases: Vec<String> = raw
            .get("aliases")
            .and_then(|v| v.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|x| x.as_str())
                    .map(|s| s.to_string())
                    .collect()
            })
            .unwrap_or_default();

        let affected = match raw.get("affected").and_then(|a| a.as_array()) {
            Some(a) => a,
            None => return,
        };
        for item in affected {
            let pkg = match item.get("package") {
                Some(p) => p,
                None => continue,
            };
            let ecosystem = pkg
                .get("ecosystem")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_ascii_lowercase();
            let name = pkg
                .get("name")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_ascii_lowercase();
            if ecosystem.is_empty() || name.is_empty() {
                continue;
            }
            let versions = item
                .get("versions")
                .and_then(|v| v.as_array())
                .map(|a| {
                    a.iter()
                        .filter_map(|x| x.as_str())
                        .map(|s| s.to_ascii_lowercase())
                        .collect()
                })
                .unwrap_or_default();
            let mut ranges = Vec::new();
            if let Some(rs) = item.get("ranges").and_then(|r| r.as_array()) {
                for range in rs {
                    let mut r = VersionRange::default();
                    if let Some(events) = range.get("events").and_then(|e| e.as_array()) {
                        for event in events {
                            if r.introduced.is_none() {
                                r.introduced = event
                                    .get("introduced")
                                    .and_then(|v| v.as_str())
                                    .map(|s| s.to_string());
                            }
                            if r.fixed.is_none() {
                                r.fixed = event
                                    .get("fixed")
                                    .and_then(|v| v.as_str())
                                    .map(|s| s.to_string());
                            }
                            if r.last_affected.is_none() {
                                r.last_affected = event
                                    .get("last_affected")
                                    .and_then(|v| v.as_str())
                                    .map(|s| s.to_string());
                            }
                        }
                    }
                    ranges.push(r);
                }
            }
            let entry = Affected {
                id: id.to_string(),
                summary: summary.clone(),
                details: details.clone(),
                aliases: aliases.clone(),
                versions,
                ranges,
            };
            self.entries
                .entry((ecosystem, name))
                .or_default()
                .push(entry);
            self.records += 1;
        }
    }

    pub fn matches(&self, pkg: &InstalledPackage) -> Option<&Affected> {
        let key = (
            pkg.ecosystem.to_ascii_lowercase(),
            pkg.name.to_ascii_lowercase(),
        );
        let entries = self.entries.get(&key)?;
        entries
            .iter()
            .find(|entry| entry_matches(entry, &pkg.version))
    }
}

fn entry_matches(entry: &Affected, version: &str) -> bool {
    let v = version.trim_start_matches('v').to_ascii_lowercase();
    if entry
        .versions
        .iter()
        .any(|x| x.trim_start_matches('v') == v)
    {
        return true;
    }
    if entry.ranges.is_empty() {
        // Name-only record: treat as affecting all versions.
        return entry.versions.is_empty();
    }
    entry.ranges.iter().any(|r| {
        let after_introduced = match &r.introduced {
            Some(i) => compare_versions(&v, i)
                .map(|o| o != std::cmp::Ordering::Less)
                .unwrap_or(true),
            None => true,
        };
        let before_fixed = match &r.fixed {
            Some(f) => compare_versions(&v, f)
                .map(|o| o == std::cmp::Ordering::Less)
                .unwrap_or(true),
            None => true,
        };
        let before_last = match &r.last_affected {
            Some(l) => compare_versions(&v, l)
                .map(|o| o != std::cmp::Ordering::Greater)
                .unwrap_or(true),
            None => true,
        };
        after_introduced && before_fixed && before_last
    })
}

fn compare_versions(a: &str, b: &str) -> Option<std::cmp::Ordering> {
    let tokenize = |s: &str| -> Vec<String> {
        s.trim_start_matches('v')
            .split(|c: char| !c.is_ascii_alphanumeric())
            .filter(|x| !x.is_empty())
            .map(|x| x.to_ascii_lowercase())
            .collect()
    };
    let (a, b) = (tokenize(a), tokenize(b));
    if a.is_empty() || b.is_empty() {
        return None;
    }
    for i in 0..a.len().max(b.len()) {
        let x = a.get(i).map(String::as_str).unwrap_or("0");
        let y = b.get(i).map(String::as_str).unwrap_or("0");
        let ord = match (x.parse::<u64>(), y.parse::<u64>()) {
            (Ok(n), Ok(m)) => n.cmp(&m),
            _ => x.cmp(y),
        };
        if ord != std::cmp::Ordering::Equal {
            return Some(ord);
        }
    }
    Some(std::cmp::Ordering::Equal)
}

/// Global packages plus optional project-level manifests under `paths`.
/// Default dataset location used when `--malicious` is not given.
pub fn default_dir() -> Option<PathBuf> {
    let dir = util::home_dir().join(".config/warden/malicious");
    if dir.is_dir() {
        Some(dir)
    } else {
        None
    }
}

pub fn installed_packages(paths: &[PathBuf], live: bool) -> Vec<InstalledPackage> {
    let mut out = Vec::new();
    if live {
        out.extend(npm_global());
        out.extend(pip_global());
        out.extend(cargo_global());
    }
    for path in paths {
        out.extend(scan_local(path));
    }
    let mut seen = HashSet::new();
    out.retain(|p| seen.insert(format!("{}|{}|{}", p.ecosystem, p.name, p.version)));
    out.sort_by(|a, b| {
        (&a.ecosystem, &a.name, &a.version).cmp(&(&b.ecosystem, &b.name, &b.version))
    });
    out
}

fn npm_global() -> Vec<InstalledPackage> {
    let out = match util::run_timeout(
        "npm",
        &["ls", "-g", "--json", "--depth=0"],
        std::time::Duration::from_secs(30),
    ) {
        Some(o) => o,
        None => return Vec::new(),
    };
    parse_npm(&String::from_utf8_lossy(&out.stdout))
}

fn parse_npm(text: &str) -> Vec<InstalledPackage> {
    let value: Value = match serde_json::from_str(text) {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };
    value
        .get("dependencies")
        .and_then(|d| d.as_object())
        .map(|deps| {
            deps.iter()
                .filter_map(|(name, meta)| {
                    let version = meta.get("version")?.as_str()?;
                    Some(InstalledPackage {
                        ecosystem: "npm",
                        name: name.to_string(),
                        version: version.to_string(),
                    })
                })
                .collect()
        })
        .unwrap_or_default()
}

fn pip_global() -> Vec<InstalledPackage> {
    let candidates: &[(&str, &[&str])] = &[
        ("python3", &["-m", "pip", "list", "--format=json"]),
        ("pip3", &["list", "--format=json"]),
        ("pip", &["list", "--format=json"]),
    ];
    for (cmd, args) in candidates {
        if let Some(out) = util::run_timeout(cmd, args, std::time::Duration::from_secs(30)) {
            if out.status.success() {
                let parsed = parse_pip(&String::from_utf8_lossy(&out.stdout));
                if !parsed.is_empty() {
                    return parsed;
                }
            }
        }
    }
    Vec::new()
}

fn parse_pip(text: &str) -> Vec<InstalledPackage> {
    let value: Value = match serde_json::from_str(text) {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };
    value
        .as_array()
        .map(|items| {
            items
                .iter()
                .filter_map(|item| {
                    let name = item.get("name")?.as_str()?;
                    let version = item.get("version")?.as_str()?;
                    Some(InstalledPackage {
                        ecosystem: "pypi",
                        name: name.to_string(),
                        version: version.to_string(),
                    })
                })
                .collect()
        })
        .unwrap_or_default()
}

fn cargo_global() -> Vec<InstalledPackage> {
    let out = match util::run_timeout(
        "cargo",
        &["install", "--list"],
        std::time::Duration::from_secs(30),
    ) {
        Some(o) => o,
        None => return Vec::new(),
    };
    parse_cargo(&String::from_utf8_lossy(&out.stdout))
}

fn parse_cargo(text: &str) -> Vec<InstalledPackage> {
    text.lines()
        .filter_map(|line| {
            let line = line.trim();
            let (name, rest) = line.split_once(" v")?;
            let version = rest.split(':').next()?.trim();
            if name.is_empty() || version.is_empty() {
                return None;
            }
            Some(InstalledPackage {
                ecosystem: "crates.io",
                name: name.to_string(),
                version: version.to_string(),
            })
        })
        .collect()
}

fn scan_local(root: &Path) -> Vec<InstalledPackage> {
    let mut out = Vec::new();
    if !root.is_dir() {
        return out;
    }
    let mut count = 0usize;
    for entry in WalkDir::new(root)
        .max_depth(12)
        .follow_links(false)
        .into_iter()
        .filter_map(|e| e.ok())
    {
        count += 1;
        if count > MAX_LOCAL_FILES {
            break;
        }
        if !entry.file_type().is_file() {
            continue;
        }
        let path = entry.path();
        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        if name == "package.json" {
            if let Some(pkg) = parse_package_json(path) {
                out.push(pkg);
            }
        } else if (name == "METADATA" || name == "PKG-INFO")
            && path
                .parent()
                .and_then(|p| p.file_name())
                .map(|n| {
                    n.to_string_lossy().ends_with(".dist-info")
                        || n.to_string_lossy().ends_with(".egg-info")
                })
                .unwrap_or(false)
        {
            if let Some(pkg) = parse_python_metadata(path) {
                out.push(pkg);
            }
        }
    }
    out
}

fn parse_package_json(path: &Path) -> Option<InstalledPackage> {
    let text = util::read_text(path, 2 * util::MB)?;
    let value: Value = serde_json::from_str(&text).ok()?;
    let name = value.get("name")?.as_str()?.to_string();
    let version = value.get("version")?.as_str()?.to_string();
    Some(InstalledPackage {
        ecosystem: "npm",
        name,
        version,
    })
}

fn parse_python_metadata(path: &Path) -> Option<InstalledPackage> {
    let text = util::read_text(path, util::MB)?;
    let mut name = None;
    let mut version = None;
    for line in text.lines().take(50) {
        if let Some(v) = line.strip_prefix("Name:") {
            name = Some(v.trim().to_string());
        } else if let Some(v) = line.strip_prefix("Version:") {
            version = Some(v.trim().to_string());
        }
        if name.is_some() && version.is_some() {
            break;
        }
    }
    Some(InstalledPackage {
        ecosystem: "pypi",
        name: name?,
        version: version?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_package_lists() {
        let npm = r#"{"dependencies":{"evil":{"version":"1.2.3"},"ok":{"version":"2.0.0"}}}"#;
        assert_eq!(parse_npm(npm).len(), 2);
        let pip = r#"[{"name":"evil","version":"1.0"},{"name":"ok","version":"2.0"}]"#;
        assert_eq!(parse_pip(pip).len(), 2);
        let cargo = "evil v1.2.3:\\n    evil\\nok v0.1.0:\\n";
        assert_eq!(parse_cargo(cargo)[0].version, "1.2.3");
    }

    #[test]
    fn matches_versions_and_ranges() {
        let range = Affected {
            id: "MAL-1".into(),
            summary: "bad".into(),
            details: "".into(),
            aliases: vec![],
            versions: vec!["1.2.3".into()],
            ranges: vec![VersionRange {
                introduced: Some("2.0.0".into()),
                fixed: Some("2.1.0".into()),
                last_affected: None,
            }],
        };
        assert!(entry_matches(&range, "1.2.3"));
        assert!(entry_matches(&range, "2.0.5"));
        assert!(!entry_matches(&range, "2.1.0"));
        assert!(!entry_matches(&range, "3.0.0"));
    }

    #[test]
    fn loads_osv_dataset() {
        let dir = std::env::temp_dir().join(format!(
            "warden-mal-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("record.json"),
            r#"{"id":"MAL-TEST","summary":"malicious","affected":[{"package":{"ecosystem":"npm","name":"evil-pkg"},"versions":["1.2.3"]}]}"#,
        )
        .unwrap();
        let dataset = Dataset::load(&dir).unwrap();
        assert_eq!(dataset.records, 1);
        let pkg = InstalledPackage {
            ecosystem: "npm",
            name: "evil-pkg".into(),
            version: "1.2.3".into(),
        };
        assert!(dataset.matches(&pkg).is_some());
        let pkg2 = InstalledPackage {
            ecosystem: "npm",
            name: "evil-pkg".into(),
            version: "1.2.4".into(),
        };
        assert!(dataset.matches(&pkg2).is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
