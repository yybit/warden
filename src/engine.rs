//! Scan orchestration: select checks -> run -> merge baseline drift -> apply allowlist/threshold -> report.

use crate::allowlist::Allowlist;
use crate::baseline::Baseline;
use crate::checks::{self, host, persistence, sort_findings};
use crate::ctx::{Config, ScanContext};
use crate::model::*;
use crate::util;
use anyhow::Result;
use std::path::PathBuf;
use std::time::Instant;

const MAX_FINDINGS_PER_CHECK: usize = 500;

pub fn hostname() -> String {
    util::read_text(std::path::Path::new("/proc/sys/kernel/hostname"), 4096)
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .or_else(|| util::run("hostname", &[]).map(|s| s.trim().to_string()))
        .unwrap_or_else(|| "unknown".into())
}

pub fn kernel_version() -> Option<String> {
    util::read_text(std::path::Path::new("/proc/sys/kernel/osrelease"), 4096)
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .or_else(|| util::run("uname", &["-r"]).map(|s| s.trim().to_string()))
}

/// Current persistence inventory (used by both baseline save and diff).
fn build_snapshot(ctx: &ScanContext) -> Baseline {
    let mut items = persistence::snapshot(ctx);
    items.extend(checks::files::snapshot(ctx));
    items.extend(host::snapshot(ctx));
    Baseline::new(hostname(), items)
}

pub fn snapshot_only(cfg: &Config) -> Baseline {
    build_snapshot(&ScanContext::new(cfg.clone()))
}

fn selected(id: &str, only: &[String], exclude: &[String]) -> bool {
    let matches = |p: &String| id == p.as_str() || id.starts_with(&format!("{p}."));
    (only.is_empty() || only.iter().any(matches)) && !exclude.iter().any(matches)
}

pub fn run(cfg: Config) -> Result<Report> {
    let started = Instant::now();
    let started_at = util::now_rfc3339();
    let ctx = ScanContext::new(cfg);
    let cfg = &ctx.cfg;

    // Allowlist: an explicit path must exist; otherwise try the per-user default.
    let allow = match &cfg.allowlist {
        Some(p) => Some(Allowlist::load(p)?),
        None => {
            let mut candidates = Vec::new();
            if ctx.is_local() {
                candidates.push(util::home_dir().join(".config/warden/allowlist.toml"));
            }
            candidates.push(std::path::PathBuf::from("/etc/warden/allowlist.toml"));
            candidates
                .iter()
                .find(|p| p.is_file())
                .and_then(|p| Allowlist::load(p).ok())
        }
    };

    let host = HostInfo {
        hostname: hostname(),
        os: ctx.os.to_string(),
        kernel: kernel_version(),
        privileged: ctx.privileged,
        root: cfg.root.to_string_lossy().into_owned(),
    };

    let mut findings: Vec<Finding> = Vec::new();
    let mut coverage: Vec<CheckCoverage> = Vec::new();

    for check in checks::registry() {
        let id = check.id().to_string();

        if !selected(&id, &cfg.only, &cfg.exclude) {
            continue;
        }

        if !check.platforms().contains(&ctx.os) {
            coverage.push(CheckCoverage {
                id,
                title: check.title().to_string(),
                description: check.description().to_string(),
                platforms: check.platforms().to_vec(),
                status: "skipped".into(),
                detail: Some(format!("not applicable on {}", ctx.os)),
                findings: 0,
            });
            continue;
        }
        if let Some(reason) = check.skip_reason(&ctx) {
            coverage.push(CheckCoverage {
                id,
                title: check.title().to_string(),
                description: check.description().to_string(),
                platforms: check.platforms().to_vec(),
                status: "skipped".into(),
                detail: Some(reason),
                findings: 0,
            });
            continue;
        }

        match check.run(&ctx) {
            Ok(mut found) => {
                let raw = found.len();
                if found.len() > MAX_FINDINGS_PER_CHECK {
                    found.truncate(MAX_FINDINGS_PER_CHECK);
                    found.push(
                        Finding::new(
                            check.id(),
                            Severity::Info,
                            "Too many results, truncated",
                            format!(
                                "{} results; kept the first {}. Narrow the scope or add allowlist entries.",
                                raw, MAX_FINDINGS_PER_CHECK
                            ),
                        )
                        .confidence(Confidence::Certain),
                    );
                }
                coverage.push(CheckCoverage {
                    id,
                    title: check.title().to_string(),
                    description: check.description().to_string(),
                    platforms: check.platforms().to_vec(),
                    status: "ran".into(),
                    detail: None,
                    findings: raw,
                });
                findings.extend(found);
            }
            Err(e) => coverage.push(CheckCoverage {
                id,
                title: check.title().to_string(),
                description: check.description().to_string(),
                platforms: check.platforms().to_vec(),
                status: "failed".into(),
                detail: Some(format!("{e:#}")),
                findings: 0,
            }),
        }
    }

    // Baseline drift (also filtered by --checks / --exclude)
    let mut baseline_summary = None;
    let baseline_wanted = selected("baseline.drift", &cfg.only, &cfg.exclude);
    if baseline_wanted && (cfg.baseline.is_some() || cfg.save_baseline.is_some()) {
        let current = build_snapshot(&ctx);
        if let Some(path) = &cfg.baseline {
            let old = Baseline::load(path)?;
            let d = crate::baseline::diff(&old, &current);
            for item in &d.added {
                findings.push(
                    Finding::new(
                        "baseline.drift",
                        Severity::High,
                        "New persistence entry since baseline",
                        format!("new [{}] since baseline: {}", item.kind, item.detail),
                    )
                    .at(item.path.clone(), None)
                    .evidence(item.detail.clone())
                    .fix("Confirm this change is authorized; otherwise start incident response")
                    .confidence(Confidence::Likely)
                    .mitre("T1543"),
                );
            }
            for item in &d.removed {
                findings.push(
                    Finding::new(
                        "baseline.drift",
                        Severity::Info,
                        "Persistence entry removed since baseline",
                        format!("[{}]: {}", item.kind, item.detail),
                    )
                    .at(item.path.clone(), None)
                    .evidence(item.detail.clone())
                    .confidence(Confidence::Likely),
                );
            }
            coverage.push(CheckCoverage {
                id: "baseline.drift".into(),
                title: "Baseline drift".into(),
                description: "Compare the current persistence inventory against a saved baseline and report additions/removals.".into(),
                platforms: vec![crate::model::Os::Linux, crate::model::Os::MacOs],
                status: "ran".into(),
                detail: Some(format!(
                    "{} added, {} removed, {} items in baseline",
                    d.added.len(),
                    d.removed.len(),
                    old.items.len()
                )),
                findings: d.added.len() + d.removed.len(),
            });
            baseline_summary = Some(BaselineSummary {
                file: path.to_string_lossy().into_owned(),
                created_at: Some(old.created_at.clone()),
                added: d.added.len(),
                removed: d.removed.len(),
                total: d.total,
            });
        }
        if let Some(path) = &cfg.save_baseline {
            let snapshot = current.clone();
            snapshot.save(path)?;
            if baseline_summary.is_none() {
                baseline_summary = Some(BaselineSummary {
                    file: path.to_string_lossy().into_owned(),
                    created_at: Some(snapshot.created_at.clone()),
                    added: 0,
                    removed: 0,
                    total: snapshot.items.len(),
                });
            }
        }
    }

    // Report unknown check ids instead of silently skipping them
    for want in &cfg.only {
        if !coverage
            .iter()
            .any(|c| c.id == *want || c.id.starts_with(&format!("{want}.")))
        {
            coverage.push(CheckCoverage {
                id: want.clone(),
                title: want.clone(),
                description: "Requested check id did not match any registered check.".into(),
                platforms: Vec::new(),
                status: "skipped".into(),
                detail: Some("no matching check found".into()),
                findings: 0,
            });
        }
    }

    // Overlapping scan roots (e.g. two webroots) can report the same file
    // twice; keep the first finding per check/path/evidence fingerprint.
    let mut seen = std::collections::HashSet::new();
    findings.retain(|f| seen.insert(f.fingerprint()));
    sort_findings(&mut findings);
    findings.retain(|f| f.severity >= cfg.min_severity);
    let mut suppressed = 0usize;
    if let Some(list) = &allow {
        findings.retain(|f| {
            if list.is_allowed(f) {
                suppressed += 1;
                false
            } else {
                true
            }
        });
    }
    let scanned_paths: Vec<String> = cfg
        .paths
        .iter()
        .map(|p| ctx.disp(p))
        .chain(cfg.webroots.iter().map(|p| ctx.disp(p)))
        .collect();

    Ok(Report {
        tool: "warden".into(),
        version: env!("CARGO_PKG_VERSION").into(),
        host,
        started_at,
        duration_ms: started.elapsed().as_millis() as u64,
        findings,
        suppressed,
        allowlist_expired: allow.as_ref().map(|a| a.expired).unwrap_or(0),
        checks: coverage,
        baseline: baseline_summary,
        scanned_paths,
    })
}

/// Exit code: 0 clean, 1 findings at or above the threshold, 2 usage/runtime error.
pub fn exit_code(report: &Report, fail_on: Option<Severity>) -> i32 {
    match fail_on {
        Some(threshold) => match report.max_severity() {
            Some(max) if max >= threshold => 1,
            _ => 0,
        },
        None => 0,
    }
}

#[allow(dead_code)]
fn default_baseline_path() -> PathBuf {
    PathBuf::from("warden-baseline.json")
}
