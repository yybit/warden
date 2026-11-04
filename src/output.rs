//! Output layer: human-readable text, JSON, and SARIF 2.1.0 for CI.

use crate::model::{Finding, Report, Severity};
use serde_json::json;

const RESET: &str = "\x1b[0m";

fn sev_color(sev: Severity) -> &'static str {
    match sev {
        Severity::Critical => "\x1b[1;97;41m",
        Severity::High => "\x1b[1;31m",
        Severity::Medium => "\x1b[1;33m",
        Severity::Low => "\x1b[36m",
        Severity::Info => "\x1b[2;37m",
    }
}

fn paint(s: &str, sev: Severity, color: bool) -> String {
    if color {
        format!("{}{}{}", sev_color(sev), s, RESET)
    } else {
        s.to_string()
    }
}

fn finding_text(f: &Finding, color: bool) -> String {
    let mut out = String::new();
    let tag = format!("{:<8}", f.severity.as_str().to_uppercase());
    let mut head = format!("[{}] {}", paint(&tag, f.severity, color), f.check);
    if let Some(p) = &f.path {
        head.push_str(&format!("  {p}"));
        if let Some(l) = f.line {
            head.push_str(&format!(":{l}"));
        }
    }
    out.push_str(&head);
    out.push('\n');
    out.push_str(&format!("         {}\n", f.title));
    if f.message != f.title {
        out.push_str(&format!("         {}\n", f.message));
    }
    if let Some(e) = &f.evidence {
        let e = if e.chars().count() > 300 {
            format!("{}…", e.chars().take(300).collect::<String>())
        } else {
            e.clone()
        };
        out.push_str(&format!("         evidence: {e}\n"));
    }
    if let Some(r) = &f.remediation {
        out.push_str(&format!("         remediation: {r}\n"));
    }
    let mut meta = format!("confidence {}", f.confidence.label());
    if !f.mitre.is_empty() {
        meta.push_str(&format!(" · ATT&CK {}", f.mitre.join(", ")));
    }
    out.push_str(&format!("         {meta}\n"));
    out
}

pub fn text(report: &Report, color: bool, verbose: bool, quiet: bool) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "{} {}  ·  {}  ·  {}  ·  root={}  ·  {}\n",
        report.tool,
        report.version,
        report.host.hostname,
        report.host.os,
        report.host.root,
        if report.host.privileged {
            "privileged (root)"
        } else {
            "unprivileged"
        }
    ));
    if let Some(k) = &report.host.kernel {
        out.push_str(&format!("kernel {k}\n"));
    }
    out.push('\n');

    if !quiet {
        if report.findings.is_empty() {
            out.push_str("No findings at or above the threshold.\n\n");
        }
        for f in &report.findings {
            out.push_str(&finding_text(f, color));
            out.push('\n');
        }
    }

    let total = report.findings.len();
    out.push_str("---- Summary ----\n");
    out.push_str(&format!(
        "  {} {} · {} {} · {} {} · {} {} · {} {} (total {})\n",
        paint(Severity::Critical.label(), Severity::Critical, color),
        report.count(Severity::Critical),
        paint(Severity::High.label(), Severity::High, color),
        report.count(Severity::High),
        paint(Severity::Medium.label(), Severity::Medium, color),
        report.count(Severity::Medium),
        paint(Severity::Low.label(), Severity::Low, color),
        report.count(Severity::Low),
        paint(Severity::Info.label(), Severity::Info, color),
        report.count(Severity::Info),
        total
    ));

    if report.suppressed > 0 {
        out.push_str(&format!(
            "  {} finding(s) suppressed by allowlist\n",
            report.suppressed
        ));
    }
    if report.allowlist_expired > 0 {
        out.push_str(&format!(
            "  note: {} allowlist rule(s) expired and were ignored\n",
            report.allowlist_expired
        ));
    }

    let ran = report.checks.iter().filter(|c| c.status == "ran").count();
    let skipped = report
        .checks
        .iter()
        .filter(|c| c.status == "skipped")
        .count();
    let failed = report
        .checks
        .iter()
        .filter(|c| c.status == "failed")
        .count();
    out.push_str(&format!(
        "  checks {}: {} ran · {} skipped · {} failed\n",
        report.checks.len(),
        ran,
        skipped,
        failed
    ));

    if verbose || failed > 0 {
        for c in report.checks.iter().filter(|c| c.status != "ran") {
            out.push_str(&format!(
                "    {} {} — {}\n",
                c.status,
                c.id,
                c.detail.as_deref().unwrap_or("")
            ));
        }
    }

    if let Some(b) = &report.baseline {
        out.push_str(&format!(
            "  baseline {}: {} added · {} removed · {} total\n",
            b.file, b.added, b.removed, b.total
        ));
    }

    out.push_str(&format!("  elapsed {} ms\n", report.duration_ms));

    if !report.host.privileged {
        out.push_str("\nNote: running unprivileged; /etc/shadow, other users' files, and some process details are unreadable.\n");
        out.push_str("      Run with sudo for full coverage. The scan is strictly read-only.\n");
    }
    out
}

pub fn json(report: &Report) -> String {
    serde_json::to_string_pretty(report).unwrap_or_else(|e| format!("{{\"error\":\"{e}\"}}"))
}

fn sarif_level(sev: Severity) -> &'static str {
    match sev {
        Severity::Critical | Severity::High => "error",
        Severity::Medium => "warning",
        Severity::Low | Severity::Info => "note",
    }
}

pub fn sarif(report: &Report) -> String {
    let mut rule_ids: Vec<&str> = report.findings.iter().map(|f| f.check.as_str()).collect();
    rule_ids.sort();
    rule_ids.dedup();

    let rules: Vec<serde_json::Value> = rule_ids
        .iter()
        .map(|id| {
            let title = report
                .checks
                .iter()
                .find(|c| c.id == *id)
                .map(|c| c.title.clone())
                .unwrap_or_else(|| id.to_string());
            json!({
                "id": id,
                "name": id,
                "shortDescription": { "text": title },
            })
        })
        .collect();

    let results: Vec<serde_json::Value> = report
        .findings
        .iter()
        .map(|f| {
            let mut msg = format!("{}: {}", f.title, f.message);
            if let Some(e) = &f.evidence {
                msg.push_str(&format!(" | evidence: {e}"));
            }
            let mut locs = Vec::new();
            if let Some(p) = &f.path {
                let mut region = json!({});
                if let Some(l) = f.line {
                    region = json!({ "startLine": l });
                }
                locs.push(json!({
                    "physicalLocation": {
                        "artifactLocation": { "uri": p },
                        "region": region
                    }
                }));
            }
            json!({
                "ruleId": f.check,
                "level": sarif_level(f.severity),
                "message": { "text": msg },
                "locations": locs,
                "properties": {
                    "severity": f.severity,
                    "confidence": f.confidence,
                    "remediation": f.remediation,
                    "attack": f.mitre,
                    "fingerprint": f.fingerprint(),
                }
            })
        })
        .collect();

    let doc = json!({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": report.tool,
                    "version": report.version,
                    "informationUri": "https://example.invalid/warden",
                    "rules": rules
                }
            },
            "invocations": [{
                "executionSuccessful": report.checks.iter().all(|c| c.status != "failed"),
                "startTimeUtc": report.started_at,
            }],
            "results": results
        }]
    });
    serde_json::to_string_pretty(&doc).unwrap_or_else(|e| format!("{{\"error\":\"{e}\"}}"))
}

impl Report {
    pub fn render(
        &self,
        format: crate::ctx::Format,
        color: bool,
        verbose: bool,
        quiet: bool,
    ) -> String {
        match format {
            crate::ctx::Format::Text => text(self, color, verbose, quiet),
            crate::ctx::Format::Json => json(self),
            crate::ctx::Format::Sarif => sarif(self),
        }
    }
}
