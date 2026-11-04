//! YARA-X integration.
//!
//! Design choices:
//! - No third-party rule packs are bundled. Operators pass `--yara <dir|file>`
//!   so licensing and freshness stay with them (see docs/SIGNATURES.md).
//! - Rule metadata drives severity and context: `severity`/`level`,
//!   `description`/`desc`/`info`, `reference`, `author`, `license`,
//!   `attack`/`mitre`/`technique`.
//! - One compiled rule set per invocation; a single scanner is reused for all
//!   files to avoid recompiling or recreating the WASM store per file.

use crate::model::{Confidence, Finding, Severity};
use anyhow::Result;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::Duration;
use walkdir::WalkDir;
use yara_x::{Compiler, MetaValue, Rules, Scanner};

const MAX_RULE_FILES: usize = 5_000;

#[derive(Debug, Clone)]
pub struct YaraMatch {
    pub rule: String,
    pub namespace: String,
    pub tags: Vec<String>,
    pub meta: BTreeMap<String, String>,
}

pub struct SignatureEngine {
    rules: Rules,
    pub rule_count: usize,
    pub sources: Vec<PathBuf>,
    pub warnings: Vec<String>,
    /// True when the compiled rules came from the on-disk cache.
    pub cached: bool,
}

impl SignatureEngine {
    /// Compile every `.yar` / `.yara` file under the given paths.
    ///
    /// Individual rule files that fail to compile produce warnings; the run
    /// only fails when no rule compiled at all.
    pub fn load(paths: &[PathBuf]) -> Result<Self> {
        Self::load_with_cache(paths, None)
    }

    /// Load rules, optionally using a compiled-rule cache under `cache_root`.
    /// The cache key covers the warden version and every rule file's content.
    pub fn load_with_cache(paths: &[PathBuf], cache_root: Option<PathBuf>) -> Result<Self> {
        let files = collect_rule_files(paths);
        if files.is_empty() {
            anyhow::bail!(
                "no .yar/.yara rule files found under: {}",
                paths
                    .iter()
                    .map(|p| p.display().to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        }

        // Read first so the compiler never borrows a temporary string.
        let mut sources: Vec<(PathBuf, String)> = Vec::new();
        for f in &files {
            match std::fs::read_to_string(f) {
                Ok(text) => sources.push((f.clone(), text)),
                Err(e) => eprintln!("warden: cannot read rule file {}: {e}", f.display()),
            }
        }

        let key = cache_key(&sources);
        let cache_root = cache_root.or_else(default_cache_root);
        let cache_file = cache_root
            .as_ref()
            .map(|root| root.join("yara").join(format!("{key}.rules")));

        if let Some(file) = &cache_file {
            if let Ok(bytes) = std::fs::read(file) {
                if let Ok(rules) = Rules::deserialize(&bytes) {
                    let rule_count = rules.iter().count();
                    if rule_count > 0 {
                        return Ok(SignatureEngine {
                            rules,
                            rule_count,
                            sources: sources.into_iter().map(|(p, _)| p).collect(),
                            warnings: Vec::new(),
                            cached: true,
                        });
                    }
                }
                // Corrupt or stale format: drop it and recompile.
                let _ = std::fs::remove_file(file);
            }
        }

        let mut compiler = Compiler::new();
        let mut warnings = Vec::new();
        for (path, text) in &sources {
            if let Err(e) = compiler.add_source(text.as_str()) {
                warnings.push(format!("{}: {e}", path.display()));
            }
        }

        let rules = compiler.build();
        let rule_count = rules.iter().count();
        if rule_count == 0 {
            let detail = if warnings.is_empty() {
                "no rules were compiled".to_string()
            } else {
                warnings.join("; ")
            };
            anyhow::bail!("YARA rules failed to compile: {detail}");
        }

        if let Some(file) = &cache_file {
            if let Ok(bytes) = rules.serialize() {
                if let Some(parent) = file.parent() {
                    let _ = std::fs::create_dir_all(parent);
                }
                let tmp = file.with_extension(format!("part-{}", std::process::id()));
                if std::fs::write(&tmp, &bytes).is_ok() {
                    use std::os::unix::fs::PermissionsExt;
                    let _ = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600));
                    let _ = std::fs::rename(&tmp, file);
                }
            }
        }

        Ok(SignatureEngine {
            rules,
            rule_count,
            sources: sources.into_iter().map(|(p, _)| p).collect(),
            warnings,
            cached: false,
        })
    }

    /// Scan a list of files, reusing one scanner.
    pub fn scan_paths(
        &self,
        paths: &[PathBuf],
        max_scan_size: usize,
        timeout: Duration,
    ) -> Vec<(PathBuf, Vec<YaraMatch>)> {
        let mut scanner = Scanner::new(&self.rules);
        scanner.max_scan_size(max_scan_size).set_timeout(timeout);

        let mut out = Vec::new();
        for path in paths {
            match scanner.scan_file(path) {
                Ok(results) => {
                    let matches = collect_matches(&results);
                    if !matches.is_empty() {
                        out.push((path.clone(), matches));
                    }
                }
                // Unreadable, too large, or timed-out files are skipped; the
                // caller already has coverage information for the scan root.
                Err(_) => continue,
            }
        }
        out
    }

    pub fn scan_file(
        &self,
        path: &Path,
        max_scan_size: usize,
        timeout: Duration,
    ) -> Result<Vec<YaraMatch>> {
        let mut scanner = Scanner::new(&self.rules);
        scanner.max_scan_size(max_scan_size).set_timeout(timeout);
        let results = scanner
            .scan_file(path)
            .map_err(|e| anyhow::anyhow!("YARA scan failed for {}: {e}", path.display()))?;
        Ok(collect_matches(&results))
    }

    pub fn to_finding(&self, m: &YaraMatch, check: &str, path: &str) -> Finding {
        let severity = meta_lookup(&m.meta, &["severity", "level", "threat_level"])
            .and_then(|v| Severity::parse(v))
            .unwrap_or(Severity::Medium);

        let title = meta_lookup(&m.meta, &["description", "desc", "info"])
            .cloned()
            .unwrap_or_else(|| format!("YARA rule matched: {}", m.rule));

        let mut message = format!("rule `{}` matched", m.rule);
        if !m.tags.is_empty() {
            message.push_str(&format!(" (tags: {})", m.tags.join(", ")));
        }

        let mut evidence = vec![format!("rule={}", m.rule)];
        if !m.namespace.is_empty() && m.namespace != "default" {
            evidence.push(format!("namespace={}", m.namespace));
        }
        for key in ["reference", "ref", "author", "license", "source"] {
            if let Some(v) = meta_lookup(&m.meta, &[key]) {
                evidence.push(format!("{key}={v}"));
            }
        }

        let mut f = Finding::new(check, severity, title, message)
            .at(path, None)
            .evidence(evidence.join(" · "))
            .fix("Treat the file as untrusted, quarantine it, and verify its origin")
            .confidence(Confidence::Likely);

        for key in ["attack", "mitre", "technique"] {
            if let Some(v) = meta_lookup(&m.meta, &[key]) {
                for token in v.split([',', ' ', ';']) {
                    let t = token.trim();
                    if t.len() >= 3
                        && t.starts_with('T')
                        && t[1..].starts_with(|c: char| c.is_ascii_digit())
                        && !f.mitre.iter().any(|x| x == t)
                    {
                        f.mitre.push(t.to_string());
                    }
                }
            }
        }
        f
    }
}

fn default_cache_root() -> Option<PathBuf> {
    if let Some(p) = std::env::var_os("XDG_CACHE_HOME") {
        return Some(PathBuf::from(p));
    }
    std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".cache"))
}

fn cache_key(sources: &[(PathBuf, String)]) -> String {
    let mut h = Sha256::new();
    h.update(env!("CARGO_PKG_VERSION").as_bytes());
    h.update(b"yara-cache-v1");
    for (path, text) in sources {
        h.update(path.to_string_lossy().as_bytes());
        h.update((text.len() as u64).to_le_bytes());
        h.update(text.as_bytes());
    }
    format!("{:x}", h.finalize())
}

fn collect_matches(results: &yara_x::ScanResults<'_, '_>) -> Vec<YaraMatch> {
    results
        .matching_rules()
        .map(|rule| {
            let mut meta = BTreeMap::new();
            for (k, v) in rule.metadata() {
                meta.insert(k.to_string(), meta_value_to_string(v));
            }
            YaraMatch {
                rule: rule.identifier().to_string(),
                namespace: rule.namespace().to_string(),
                tags: rule.tags().map(|t| t.identifier().to_string()).collect(),
                meta,
            }
        })
        .collect()
}

fn meta_value_to_string(v: MetaValue<'_>) -> String {
    match v {
        MetaValue::Integer(i) => i.to_string(),
        MetaValue::Float(f) => f.to_string(),
        MetaValue::Bool(b) => b.to_string(),
        MetaValue::String(s) => s.to_string(),
        MetaValue::Bytes(b) => String::from_utf8_lossy(b).into_owned(),
    }
}

fn meta_lookup<'a>(meta: &'a BTreeMap<String, String>, keys: &[&str]) -> Option<&'a String> {
    meta.iter()
        .find(|(k, _)| keys.iter().any(|want| k.eq_ignore_ascii_case(want)))
        .map(|(_, v)| v)
}

fn is_rule_file(path: &Path) -> bool {
    matches!(
        path.extension()
            .and_then(|e| e.to_str())
            .map(|e| e.to_ascii_lowercase())
            .as_deref(),
        Some("yar") | Some("yara")
    )
}

fn collect_rule_files(paths: &[PathBuf]) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for p in paths {
        if p.is_file() {
            if is_rule_file(p) {
                out.push(p.clone());
            }
        } else if p.is_dir() {
            for entry in WalkDir::new(p)
                .follow_links(false)
                .max_depth(32)
                .into_iter()
                .filter_map(|e| e.ok())
            {
                if entry.file_type().is_file() && is_rule_file(entry.path()) {
                    out.push(entry.path().to_path_buf());
                }
                if out.len() >= MAX_RULE_FILES {
                    break;
                }
            }
        }
    }
    out.sort();
    out.dedup();
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "warden-yara-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(dir.join("rules")).unwrap();
        std::fs::write(
            dir.join("rules/test.yar"),
            r#"
rule warden_test_backdoor {
  meta:
    severity = "high"
    description = "selftest backdoor marker"
    attack = "T1059.001, T1543"
    license = "test-only"
  strings:
    $marker = "WARDEN_YARA_TEST_MARKER"
  condition:
    $marker
}
"#,
        )
        .unwrap();
        std::fs::write(
            dir.join("sample.bin"),
            b"prefix WARDEN_YARA_TEST_MARKER suffix",
        )
        .unwrap();
        dir
    }

    #[test]
    fn compiles_and_matches_with_metadata() {
        let dir = fixture();
        let engine = SignatureEngine::load(&[dir.join("rules")]).unwrap();
        assert_eq!(engine.rule_count, 1);
        let matches = engine
            .scan_file(&dir.join("sample.bin"), 1024 * 1024, Duration::from_secs(5))
            .unwrap();
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].rule, "warden_test_backdoor");
        assert_eq!(
            matches[0].meta.get("severity").map(String::as_str),
            Some("high")
        );

        let f = engine.to_finding(&matches[0], "yara.rules", "/sample.bin");
        assert_eq!(f.severity, Severity::High);
        assert_eq!(f.title, "selftest backdoor marker");
        assert!(f.mitre.iter().any(|t| t == "T1059.001"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn compiled_rules_are_cached() {
        let dir = fixture();
        let cache = dir.join("cache");
        let first =
            SignatureEngine::load_with_cache(&[dir.join("rules")], Some(cache.clone())).unwrap();
        assert!(!first.cached);
        assert_eq!(first.rule_count, 1);
        let cached =
            SignatureEngine::load_with_cache(&[dir.join("rules")], Some(cache.clone())).unwrap();
        assert!(cached.cached);
        assert_eq!(cached.rule_count, 1);

        // Content change invalidates the cache.
        std::fs::write(
            dir.join("rules/test.yar"),
            "rule changed { strings: $a = \"CHANGED\" condition: $a }",
        )
        .unwrap();
        let rebuilt = SignatureEngine::load_with_cache(&[dir.join("rules")], Some(cache)).unwrap();
        assert!(!rebuilt.cached);
        assert_eq!(rebuilt.rule_count, 1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn no_rules_is_an_error() {
        let dir = fixture();
        let empty = dir.join("empty");
        std::fs::create_dir_all(&empty).unwrap();
        assert!(SignatureEngine::load(&[empty]).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
