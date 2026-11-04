//! Controlled download (quarantine fetch): download only, never execute.
//!
//! Design: split download and execution into two stages. The download stage handles **content**
//! (malicious files, forged extensions); the execution stage handles **behavior** (persistence, egress, payload drops).
//! Execution always happens in a network-isolated sandbox, so the sample cannot fetch stage 2 while observed.

use super::{score, verdict};
use crate::ctx::Format;
use crate::heuristics::command_signals;
use crate::intel::Intel;
use crate::model::{Confidence, Finding, Severity};
use crate::util::{self, FileKind};
use anyhow::{Context, Result};
use serde::Serialize;
use std::collections::BTreeSet;
use std::path::PathBuf;
use std::process::Command;
use std::time::Duration;

pub struct FetchConfig {
    pub url: String,
    pub output: PathBuf,
    pub max_size: u64,
    pub timeout: Duration,
    pub ioc: Option<PathBuf>,
    pub yara: Vec<PathBuf>,
    pub clamav: bool,
    pub clamav_db: Option<PathBuf>,
}

#[derive(Debug, Serialize)]
pub struct FetchReport {
    pub tool: String,
    pub version: String,
    pub url: String,
    pub path: String,
    pub size: u64,
    pub sha256: String,
    pub kind: String,
    pub executable: bool,
    pub output_dir: String,
    pub findings: Vec<Finding>,
    pub score: u32,
    pub verdict: String,
    pub next_step: String,
}

pub fn exit_code(report: &FetchReport) -> i32 {
    if report.findings.iter().any(|f| f.severity >= Severity::High) {
        1
    } else {
        0
    }
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
        "download".into()
    } else {
        cleaned.chars().take(80).collect()
    }
}

fn kind_label(kind: FileKind) -> &'static str {
    match kind {
        FileKind::Elf => "ELF",
        FileKind::MachO => "Mach-O",
        FileKind::Script => "script",
        FileKind::Other => "unknown/data",
    }
}

fn human(n: u64) -> String {
    if n < 1024 {
        format!("{n} B")
    } else if n < 1024 * 1024 {
        format!("{:.1} KiB", n as f64 / 1024.0)
    } else {
        format!("{:.1} MiB", n as f64 / (1024.0 * 1024.0))
    }
}

fn embedded_urls(text: &str) -> Vec<String> {
    let mut set = BTreeSet::new();
    for tok in text.split_whitespace() {
        let t = tok.trim_matches(|c: char| {
            matches!(
                c,
                '"' | '\'' | '(' | ')' | ',' | ';' | '<' | '>' | ']' | '['
            )
        });
        if (t.starts_with("http://") || t.starts_with("https://")) && t.len() < 300 {
            set.insert(t.to_string());
        }
        if set.len() >= 10 {
            break;
        }
    }
    set.into_iter().collect()
}

pub fn run(cfg: FetchConfig) -> Result<FetchReport> {
    if !cfg.url.starts_with("http://") && !cfg.url.starts_with("https://") {
        anyhow::bail!("only http/https URLs are supported: {}", cfg.url);
    }
    if !util::command_exists("curl") {
        anyhow::bail!("sandbox fetch requires curl");
    }
    std::fs::create_dir_all(&cfg.output)
        .with_context(|| format!("cannot create output directory: {}", cfg.output.display()))?;
    let output = std::fs::canonicalize(&cfg.output)?;

    let name = sanitize_name(&cfg.url);
    let tmp = output.join(format!(".part-{}", std::process::id()));

    let timeout = cfg.timeout.as_secs().to_string();
    let max_size = cfg.max_size.to_string();
    let out = Command::new("curl")
        .args([
            "-q",
            "-sS",
            "-L",
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
            &max_size,
            "--no-progress-meter",
            "-A",
            "warden-fetch/0.1",
            "-o",
            &tmp.to_string_lossy(),
            "--",
            &cfg.url,
        ])
        .output()
        .context("cannot execute curl")?;

    if !out.status.success() {
        let _ = std::fs::remove_file(&tmp);
        let err = String::from_utf8_lossy(&out.stderr);
        let hint = match out.status.code() {
            Some(63) => " (exceeded --max-size, aborted)",
            Some(28) => " (timeout)",
            Some(6) => " (cannot resolve host)",
            Some(7) => " (cannot connect)",
            _ => "",
        };
        anyhow::bail!("download failed{hint}: {}", err.trim());
    }

    let meta = std::fs::metadata(&tmp).context("downloaded file is missing")?;
    if meta.len() == 0 {
        let _ = std::fs::remove_file(&tmp);
        anyhow::bail!("downloaded content is empty");
    }
    if meta.len() > cfg.max_size {
        let _ = std::fs::remove_file(&tmp);
        anyhow::bail!("downloaded content exceeds the {} byte limit", cfg.max_size);
    }

    let hash = util::sha256_file(&tmp, cfg.max_size + 1)
        .ok_or_else(|| anyhow::anyhow!("cannot compute SHA-256"))?;
    let final_path = output.join(format!("{}-{}", &hash[..16], name));
    std::fs::rename(&tmp, &final_path).context("cannot store the downloaded file")?;

    let kind = util::file_kind(&final_path);
    let executable = util::mode_of(&final_path)
        .map(|m| m & 0o111 != 0)
        .unwrap_or(false);
    let mut findings = Vec::new();
    let intel = match &cfg.ioc {
        Some(p) => Some(Intel::load(std::slice::from_ref(p))?),
        None => None,
    };
    if let Some(intel) = &intel {
        if let Some(hit) = intel.match_url(&cfg.url) {
            findings.push(
                Finding::new(
                    "fetch.intel",
                    Severity::Critical,
                    "Download URL matches threat intel",
                    "The requested URL is listed in the IOC feed",
                )
                .at(final_path.to_string_lossy().into_owned(), None)
                .evidence(format!("{}:{}", hit.kind, hit.value))
                .fix("Do not execute; preserve the sample and investigate the source")
                .confidence(Confidence::Certain)
                .mitre("T1204.002"),
            );
        }
    }

    let ext = final_path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    let doc_ext = [
        "jpg", "jpeg", "png", "gif", "pdf", "doc", "docx", "xls", "xlsx", "zip", "txt", "csv",
        "html", "svg",
    ];
    if kind.is_executable_format() {
        let (sev, title) = if doc_ext.contains(&ext.as_str()) {
            (
                Severity::Critical,
                format!("Executable disguised as .{ext}"),
            )
        } else {
            (
                Severity::High,
                "Downloaded content is a native executable".to_string(),
            )
        };
        findings.push(
            Finding::new(
                "fetch.binary",
                sev,
                title,
                "Behavior can only be assessed by executing the binary in a sandbox",
            )
            .at(final_path.to_string_lossy().into_owned(), None)
            .evidence(format!("{} · {}", kind_label(kind), human(meta.len())))
            .fix("Never run it on the host; execute offline with warden sandbox run")
            .confidence(Confidence::Certain)
            .mitre("T1204.002"),
        );
    } else if kind == FileKind::Script {
        findings.push(
            Finding::new(
                "fetch.script",
                Severity::Medium,
                "Downloaded content is a script",
                "Scripts are not executed during download; review them and run them in the sandbox",
            )
            .at(final_path.to_string_lossy().into_owned(), None)
            .evidence(kind_label(kind))
            .fix("Run it with sandbox run and observe filesystem changes")
            .confidence(Confidence::Certain)
            .mitre("T1059.004"),
        );
    }

    // Text content inspection (no execution)
    if let Some(text) = util::read_text(&final_path, 2 * util::MB) {
        let hits: Vec<_> = text.lines().flat_map(command_signals).collect();
        if let Some(top) = hits.iter().max_by_key(|h| h.severity) {
            let descs: Vec<&str> = hits.iter().map(|h| h.desc).collect();
            findings.push(
                Finding::new(
                    "fetch.content",
                    top.severity,
                    "File content contains backdoor / download-and-execute patterns",
                    format!("matched {} signals: {}", hits.len(), descs.join("; ")),
                )
                .at(final_path.to_string_lossy().into_owned(), None)
                .evidence(top.desc)
                .fix("Treat it as untrusted and run it only in the sandbox")
                .confidence(Confidence::Heuristic)
                .mitre("T1204.002"),
            );
        }
        let urls = embedded_urls(&text);
        if !urls.is_empty() {
            findings.push(
                Finding::new(
                    "fetch.urls",
                    Severity::Info,
                    "Embedded egress addresses",
                    "Useful as C2 / download URL leads",
                )
                .at(final_path.to_string_lossy().into_owned(), None)
                .evidence(urls.join(", "))
                .confidence(Confidence::Likely)
                .mitre("T1071"),
            );
        }
    }

    // IOC
    if let Some(intel) = &intel {
        if let Some(hit) = intel.match_file(&final_path, cfg.max_size) {
            findings.push(
                Finding::new(
                    "fetch.intel",
                    Severity::Critical,
                    format!("Downloaded content matches threat intel ({})", hit.kind),
                    "The file hash is listed in the IOC feed",
                )
                .at(final_path.to_string_lossy().into_owned(), None)
                .evidence(format!("{}:{}", hit.kind, hit.value))
                .fix("Do not execute; preserve the sample and follow incident response")
                .confidence(Confidence::Certain)
                .mitre("T1204.002"),
            );
        }
    }

    // YARA rules over the downloaded file
    if !cfg.yara.is_empty() {
        let engine = crate::signatures::SignatureEngine::load(&cfg.yara)?;
        let matches = engine.scan_file(
            &final_path,
            cfg.max_size as usize,
            std::time::Duration::from_secs(10),
        )?;
        for m in matches {
            findings.push(engine.to_finding(&m, "fetch.yara", &final_path.to_string_lossy()));
        }
    }

    // Optional ClamAV scan over the downloaded file
    if cfg.clamav {
        match crate::clamav::ClamAv::discover() {
            Some(av) => {
                let scan = av.scan(
                    std::slice::from_ref(&final_path),
                    cfg.clamav_db.as_deref(),
                    std::time::Duration::from_secs(60),
                )?;
                for hit in scan.hits {
                    findings.push(
                        Finding::new(
                            "fetch.clamav",
                            Severity::High,
                            format!("ClamAV detected {}", hit.signature),
                            "The downloaded file matches a known-malware signature",
                        )
                        .at(final_path.to_string_lossy().into_owned(), None)
                        .evidence(format!("signature={}", hit.signature))
                        .fix("Do not execute; preserve the sample and follow incident response")
                        .confidence(Confidence::Certain)
                        .mitre("T1204.002"),
                    );
                }
            }
            None => {
                findings.push(
                    Finding::new(
                        "fetch.clamav",
                        Severity::Info,
                        "ClamAV backend unavailable",
                        "--clamav was requested but clamscan was not found in PATH",
                    )
                    .confidence(Confidence::Certain),
                );
            }
        }
    }

    crate::checks::sort_findings(&mut findings);

    let report = FetchReport {
        tool: "warden".into(),
        version: env!("CARGO_PKG_VERSION").into(),
        url: cfg.url.clone(),
        path: final_path.to_string_lossy().into_owned(),
        size: meta.len(),
        sha256: hash,
        kind: kind_label(kind).to_string(),
        executable,
        output_dir: output.to_string_lossy().into_owned(),
        score: score(&findings),
        verdict: verdict(&findings).to_string(),
        findings,
        next_step: format!(
            "warden sandbox run --workdir {} -- /work/{}",
            output.to_string_lossy(),
            final_path
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default()
        ),
    };
    Ok(report)
}

impl FetchReport {
    pub fn render(&self, format: Format) -> String {
        if matches!(format, Format::Json | Format::Sarif) {
            return serde_json::to_string_pretty(self)
                .unwrap_or_else(|e| format!("{{\"error\":\"{e}\"}}"));
        }
        let mut out = String::new();
        out.push_str(&format!(
            "{} {} · fetch · {}\n\n",
            self.tool, self.version, self.url
        ));
        out.push_str(&format!("saved: {}\n", self.path));
        out.push_str(&format!(
            "size: {} · type: {} · executable bit: {}\n",
            human(self.size),
            self.kind,
            if self.executable { "yes" } else { "no" }
        ));
        out.push_str(&format!("sha256: {}\n", self.sha256));
        out.push_str(&format!(
            "verdict: {} (risk {}/100)\n\n",
            self.verdict, self.score
        ));
        for f in &self.findings {
            out.push_str(&format!(
                "[{:<8}] {} — {}\n",
                f.severity.as_str().to_uppercase(),
                f.check,
                f.title
            ));
            if let Some(e) = &f.evidence {
                out.push_str(&format!("         evidence: {e}\n"));
            }
            if let Some(r) = &f.remediation {
                out.push_str(&format!("         remediation: {r}\n"));
            }
        }
        out.push_str("\n---- Next step ----\n");
        out.push_str("  Static inspection is no substitute for behavior analysis. The file is not executed; run it offline in the sandbox:\n");
        out.push_str(&format!("  {}\n", self.next_step));
        out.push_str("\n  Note: sandbox run has no network by default; pre-download any dependencies into the same directory.\n");
        out
    }
}
