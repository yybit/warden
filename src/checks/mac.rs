//! macOS launchd persistence checks.
//!
//! Uses lightweight XML extraction instead of a plist dependency: only Label / Program /
//! ProgramArguments / RunAtLoad are needed, and macOS images must be scannable from Linux
//! (`--root`), so no host-specific API is used.

use crate::checks::{combined_finding, Check};
use crate::ctx::ScanContext;
use crate::heuristics::{command_signals, path_signals, SignalHit};
use crate::model::{Confidence, Finding, Os, Severity};
use crate::util;
use anyhow::Result;
use std::path::{Path, PathBuf};
use std::time::Duration;
use walkdir::WalkDir;

const MAX_PLIST: u64 = 8 * util::MB;

#[derive(Debug, Clone)]
pub struct LaunchdEntry {
    pub file: PathBuf,
    pub label: String,
    pub program: String,
    pub args: Vec<String>,
    pub run_at_load: bool,
}

fn decode_entities(s: &str) -> String {
    s.replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
}

/// Return the nearest `<string>..</string>` after `<key>K</key>`; bail if another key comes first.
fn plist_string(text: &str, key: &str) -> Option<String> {
    let needle = format!("<key>{key}</key>");
    let pos = text.find(&needle)? + needle.len();
    let rest = &text[pos..];
    let s_start = rest.find("<string>")?;
    if let Some(next_key) = rest.find("<key>") {
        if next_key < s_start {
            return None;
        }
    }
    let body_start = s_start + "<string>".len();
    let body_end = rest[body_start..].find("</string>")? + body_start;
    Some(decode_entities(rest[body_start..body_end].trim()))
}

fn plist_array(text: &str, key: &str) -> Vec<String> {
    let needle = format!("<key>{key}</key>");
    let pos = match text.find(&needle) {
        Some(p) => p + needle.len(),
        None => return Vec::new(),
    };
    let rest = &text[pos..];
    let arr_start = match rest.find("<array>") {
        Some(i) => i + "<array>".len(),
        None => return Vec::new(),
    };
    if let Some(next_key) = rest.find("<key>") {
        if next_key < arr_start {
            return Vec::new();
        }
    }
    let arr_end = match rest[arr_start..].find("</array>") {
        Some(i) => arr_start + i,
        None => return Vec::new(),
    };
    let body = &rest[arr_start..arr_end];
    body.split("<string>")
        .skip(1)
        .filter_map(|chunk| chunk.split("</string>").next())
        .map(|s| decode_entities(s.trim()))
        .filter(|s| !s.is_empty())
        .collect()
}

fn plist_bool(text: &str, key: &str) -> bool {
    let needle = format!("<key>{key}</key>");
    let pos = match text.find(&needle) {
        Some(p) => p + needle.len(),
        None => return false,
    };
    let rest = &text[pos..pos + 80.min(text.len() - pos)];
    rest.contains("<true/>")
}

fn plist_dirs(ctx: &ScanContext) -> Vec<PathBuf> {
    let mut v = vec![
        ctx.abs("/Library/LaunchDaemons"),
        ctx.abs("/Library/LaunchAgents"),
    ];
    if ctx.user_scope {
        v.push(ctx.home_abs().join("Library/LaunchAgents"));
    }
    v
}

/// Read an XML plist, converting binary plists with `plutil` when available
/// (macOS). Linux image scans without `plutil` simply skip binary plists.
fn read_plist_text(path: &Path) -> Option<String> {
    let text = util::read_text(path, MAX_PLIST)?;
    if text.contains("<plist") && !text.starts_with("bplist") {
        return Some(text);
    }
    if util::command_exists("plutil") {
        let p = path.to_string_lossy();
        if let Some(xml) = util::run("plutil", &["-convert", "xml1", "-o", "-", p.as_ref()]) {
            if xml.contains("<plist") {
                return Some(xml);
            }
        }
    }
    None
}

pub fn launchd_entries(ctx: &ScanContext) -> Vec<LaunchdEntry> {
    let mut out = Vec::new();
    for dir in plist_dirs(ctx) {
        for file in util::files_in(&dir) {
            if file.extension().and_then(|e| e.to_str()) != Some("plist") {
                continue;
            }
            let text = match read_plist_text(&file) {
                Some(t) => t,
                None => continue,
            };
            let label = plist_string(&text, "Label").unwrap_or_else(|| {
                file.file_stem()
                    .map(|s| s.to_string_lossy().into_owned())
                    .unwrap_or_default()
            });
            let args = plist_array(&text, "ProgramArguments");
            let program = plist_string(&text, "Program")
                .or_else(|| args.first().cloned())
                .unwrap_or_default();
            out.push(LaunchdEntry {
                file,
                label,
                program,
                args,
                run_at_load: plist_bool(&text, "RunAtLoad"),
            });
        }
    }
    out.sort_by(|a, b| a.file.cmp(&b.file));
    out
}

pub struct LaunchdCheck;

impl Check for LaunchdCheck {
    fn id(&self) -> &'static str {
        "persist.launchd"
    }
    fn title(&self) -> &'static str {
        "macOS launchd persistence"
    }
    fn description(&self) -> &'static str {
        "macOS LaunchDaemons/Agents pointing at /tmp, /Users/Shared, or missing programs."
    }
    fn platforms(&self) -> &'static [Os] {
        &[Os::MacOs]
    }

    fn run(&self, ctx: &ScanContext) -> Result<Vec<Finding>> {
        if ctx.os != Os::MacOs {
            return Ok(Vec::new());
        }
        let mut findings = Vec::new();

        for e in launchd_entries(ctx) {
            let logical = ctx.disp(&e.file);
            let system_scope = logical.starts_with("/Library/LaunchDaemons")
                || logical.starts_with("/Library/LaunchAgents");

            if system_scope {
                if let Some(uid) = util::owner_uid(&e.file) {
                    if uid != 0 {
                        findings.push(
                            Finding::new(
                                self.id(),
                                Severity::High,
                                "LaunchDaemon plist is not owned by root",
                                "System launchd jobs run as root; wrong ownership usually means tampering",
                            )
                            .at(&logical, None)
                            .fix("Verify the origin; unload and remove if unauthorized")
                            .confidence(Confidence::Certain)
                            .mitre("T1543.001"),
                        );
                    }
                }
                if let Some(mode) = util::mode_of(&e.file) {
                    if mode & 0o022 != 0 {
                        findings.push(
                            Finding::new(
                                self.id(),
                                Severity::High,
                                "launchd plist is writable by non-root",
                                "Anyone can rewrite the boot-time command",
                            )
                            .at(&logical, None)
                            .fix("chown root:wheel and chmod 644")
                            .confidence(Confidence::Certain)
                            .mitre("T1543.001"),
                        );
                    }
                }
            }

            let line = format!("{} {}", e.program, e.args.join(" "));
            let mut hits = command_signals(&line);
            for tok in e.args.iter().chain(std::iter::once(&e.program)) {
                if tok.starts_with('/') {
                    hits.extend(path_signals(tok));
                }
            }
            // /Users/Shared is a common macOS drop location
            if e.program.starts_with("/Users/Shared") || line.contains("/Users/Shared") {
                hits.push(SignalHit {
                    code: "exec-from-shared",
                    severity: Severity::High,
                    desc: "Executes from /Users/Shared",
                    remedy: "Shared directories must not host persistent startup items",
                });
            }
            hits.sort_by_key(|h| std::cmp::Reverse(h.severity));
            hits.dedup_by(|a, b| a.code == b.code);

            if let Some(f) = combined_finding(
                self.id(),
                "Suspicious launchd startup item",
                &logical,
                None,
                &format!(
                    "label={} run_at_load={} {}",
                    e.label,
                    e.run_at_load,
                    line.trim()
                ),
                &hits,
                "T1543.001",
            ) {
                findings.push(f);
            }

            // Missing program: either a removed payload or a stale plist
            if !e.program.is_empty() && !ctx.abs(&e.program).exists() {
                findings.push(
                    Finding::new(
                        self.id(),
                        Severity::Medium,
                        "launchd item points to a missing program",
                        "It may be a deleted payload or a stale configuration",
                    )
                    .at(&logical, None)
                    .evidence(format!("label={} program={}", e.label, e.program))
                    .fix("Unload and remove the plist after verification")
                    .confidence(Confidence::Likely)
                    .mitre("T1543.001"),
                );
            }
        }
        Ok(findings)
    }
}

#[allow(dead_code)]
fn is_plist(p: &Path) -> bool {
    p.extension().and_then(|e| e.to_str()) == Some("plist")
}

// ---------------------------------------------------------------- code signatures

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SigState {
    Unsigned,
    Signed,
    Unknown,
}

pub struct MacSignatureCheck;

impl Check for MacSignatureCheck {
    fn id(&self) -> &'static str {
        "macos.signature"
    }
    fn title(&self) -> &'static str {
        "macOS code signatures"
    }
    fn description(&self) -> &'static str {
        "Unsigned Mach-O binaries and ad-hoc signatures in apps, downloads, and launchd programs."
    }
    fn platforms(&self) -> &'static [Os] {
        &[Os::MacOs]
    }

    fn run(&self, ctx: &ScanContext) -> Result<Vec<Finding>> {
        let mut targets: Vec<PathBuf> = Vec::new();

        for (dir, depth) in [("/Applications", 8usize), ("/Users/Shared", 6), ("/tmp", 3)] {
            walk_macho(&ctx.abs(dir), depth, &mut targets);
        }
        if ctx.user_scope {
            let home = ctx.home_abs();
            walk_macho(&home.join("Applications"), 8, &mut targets);
            walk_macho(&home.join("Downloads"), 4, &mut targets);
        }
        for entry in launchd_entries(ctx) {
            if entry.program.is_empty() {
                continue;
            }
            let program = ctx.abs(&entry.program);
            if program.is_file() {
                targets.push(program);
            }
        }
        targets.sort();
        targets.dedup();
        targets.truncate(5_000);

        let mut findings = Vec::new();
        let mut codesign_budget = 50usize;
        for path in targets {
            let data = match util::read_bytes(&path, 64 * util::MB) {
                Some(d) => d,
                None => continue,
            };
            match macho_signature(&data) {
                Some(SigState::Unsigned) => {
                    findings.push(
                        Finding::new(
                            self.id(),
                            Severity::High,
                            "Unsigned Mach-O executable",
                            "The binary has no code-signature load command; malware commonly ships unsigned",
                        )
                        .at(ctx.disp(&path), None)
                        .evidence(format!("size={} bytes", data.len()))
                        .fix("Confirm the origin; remove it or replace it with a signed build")
                        .confidence(Confidence::Certain)
                        .mitre("T1553.001"),
                    );
                }
                Some(SigState::Signed) => {
                    // Static parsing cannot distinguish ad-hoc from a trusted
                    // signature; codesign can, but only on a live macOS host.
                    let logical = ctx.disp(&path);
                    let adhoc_candidate = logical.starts_with("/tmp")
                        || logical.starts_with("/Users/Shared")
                        || logical.contains("/Downloads/");
                    if ctx.is_local() && adhoc_candidate && codesign_budget > 0 {
                        codesign_budget -= 1;
                        if let Some(detail) = codesign_adhoc(&path) {
                            findings.push(
                                Finding::new(
                                    self.id(),
                                    Severity::High,
                                    "Ad-hoc signed Mach-O executable",
                                    "Ad-hoc signatures are not backed by a Developer ID and are common for dropped payloads",
                                )
                                .at(ctx.disp(&path), None)
                                .evidence(detail)
                                .fix("Remove the binary unless it is a consciously built local tool")
                                .confidence(Confidence::Likely)
                                .mitre("T1553.001"),
                            );
                        }
                    }
                }
                _ => {}
            }
        }
        Ok(findings)
    }
}

fn walk_macho(dir: &Path, depth: usize, out: &mut Vec<PathBuf>) {
    if !dir.is_dir() {
        return;
    }
    for entry in WalkDir::new(dir)
        .max_depth(depth)
        .follow_links(false)
        .into_iter()
        .filter_map(|e| e.ok())
    {
        if !entry.file_type().is_file() {
            continue;
        }
        let path = entry.path();
        let s = path.to_string_lossy();
        // Skip frameworks/helpers inside app bundles; only the main executable
        // and explicit launchd programs are interesting here.
        if s.contains(".app/Contents/") && !s.contains(".app/Contents/MacOS/") {
            continue;
        }
        if let Ok(meta) = entry.metadata() {
            if meta.len() < 4 || meta.len() > 64 * util::MB {
                continue;
            }
        }
        out.push(path.to_path_buf());
    }
}

fn codesign_adhoc(path: &Path) -> Option<String> {
    let p = path.to_str()?;
    let out = util::run_timeout(
        "codesign",
        &["-dv", "--verbose=4", p],
        Duration::from_secs(5),
    )?;
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    if text.contains("Signature=adhoc") {
        Some("Signature=adhoc".into())
    } else if text.contains("not signed at all") {
        Some("code object is not signed at all".into())
    } else {
        None
    }
}

/// Returns None for non-Mach-O data.
fn macho_signature(data: &[u8]) -> Option<SigState> {
    if data.len() < 4 {
        return None;
    }
    let magic = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
    match magic {
        0xFEEDFACE => Some(thin_signature(data, 28, false)),
        0xCEFAEDFE => Some(thin_signature(data, 28, true)),
        0xFEEDFACF => Some(thin_signature(data, 32, false)),
        0xCFFAEDFE => Some(thin_signature(data, 32, true)),
        0xCAFEBABE => Some(fat_signature(data, false, false)),
        0xBEBAFECA => Some(fat_signature(data, true, false)),
        0xCAFEBABF => Some(fat_signature(data, false, true)),
        0xBFBAFECA => Some(fat_signature(data, true, true)),
        _ => None,
    }
}

fn thin_signature(data: &[u8], header_size: usize, little_endian: bool) -> SigState {
    let ncmds = match read_u32(data, 16, little_endian) {
        Some(v) => v as usize,
        None => return SigState::Unknown,
    };
    let sizeofcmds = match read_u32(data, 20, little_endian) {
        Some(v) => v as usize,
        None => return SigState::Unknown,
    };
    if ncmds == 0 || sizeofcmds == 0 {
        return SigState::Unsigned;
    }
    let end = header_size.saturating_add(sizeofcmds);
    if end > data.len() {
        return SigState::Unknown;
    }
    let mut offset = header_size;
    for _ in 0..ncmds {
        let cmd = match read_u32(data, offset, little_endian) {
            Some(v) => v,
            None => return SigState::Unknown,
        };
        let size = match read_u32(data, offset + 4, little_endian) {
            Some(v) => v as usize,
            None => return SigState::Unknown,
        };
        if size < 8 || offset + size > data.len() {
            return SigState::Unknown;
        }
        if cmd == 0x1d {
            // LC_CODE_SIGNATURE
            return SigState::Signed;
        }
        offset += size;
    }
    SigState::Unsigned
}

fn fat_signature(data: &[u8], little_endian: bool, fat64: bool) -> SigState {
    let count = match read_u32(data, 4, little_endian) {
        Some(v) if v > 0 && v <= 32 => v as usize,
        _ => return SigState::Unknown,
    };
    let entry_size = if fat64 { 32 } else { 20 };
    let mut any_unsigned = false;
    let mut any_signed = false;

    for i in 0..count {
        let base = 8 + i * entry_size;
        let (offset, size) = if fat64 {
            (
                match read_u64(data, base + 8, little_endian) {
                    Some(v) => v as usize,
                    None => return SigState::Unknown,
                },
                match read_u64(data, base + 16, little_endian) {
                    Some(v) => v as usize,
                    None => return SigState::Unknown,
                },
            )
        } else {
            (
                match read_u32(data, base + 8, little_endian) {
                    Some(v) => v as usize,
                    None => return SigState::Unknown,
                },
                match read_u32(data, base + 12, little_endian) {
                    Some(v) => v as usize,
                    None => return SigState::Unknown,
                },
            )
        };
        if size == 0 || offset.saturating_add(size) > data.len() {
            return SigState::Unknown;
        }
        match macho_signature(&data[offset..offset + size]) {
            Some(SigState::Unsigned) => any_unsigned = true,
            Some(SigState::Signed) => any_signed = true,
            _ => return SigState::Unknown,
        }
    }
    if any_unsigned {
        SigState::Unsigned
    } else if any_signed {
        SigState::Signed
    } else {
        SigState::Unknown
    }
}

fn read_u32(data: &[u8], offset: usize, little_endian: bool) -> Option<u32> {
    let bytes = data.get(offset..offset + 4)?;
    let arr = [bytes[0], bytes[1], bytes[2], bytes[3]];
    Some(if little_endian {
        u32::from_le_bytes(arr)
    } else {
        u32::from_be_bytes(arr)
    })
}

fn read_u64(data: &[u8], offset: usize, little_endian: bool) -> Option<u64> {
    let bytes = data.get(offset..offset + 8)?;
    let mut arr = [0u8; 8];
    arr.copy_from_slice(bytes);
    Some(if little_endian {
        u64::from_le_bytes(arr)
    } else {
        u64::from_be_bytes(arr)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
<key>Label</key><string>com.example.agent</string>
<key>ProgramArguments</key>
<array><string>/tmp/payload</string><string>--daemon</string></array>
<key>RunAtLoad</key><true/>
</dict></plist>"#;

    #[test]
    fn extracts_fields() {
        assert_eq!(
            plist_string(SAMPLE, "Label").as_deref(),
            Some("com.example.agent")
        );
        assert_eq!(
            plist_array(SAMPLE, "ProgramArguments"),
            vec!["/tmp/payload", "--daemon"]
        );
        assert!(plist_bool(SAMPLE, "RunAtLoad"));
        assert!(plist_string(SAMPLE, "Program").is_none());
    }

    fn thin_le64(signed: bool) -> Vec<u8> {
        let mut v = vec![0u8; if signed { 48 } else { 32 }];
        v[0..4].copy_from_slice(&[0xcf, 0xfa, 0xed, 0xfe]); // MH_CIGAM_64
        if signed {
            v[16..20].copy_from_slice(&1u32.to_le_bytes()); // ncmds
            v[20..24].copy_from_slice(&16u32.to_le_bytes()); // sizeofcmds
            v[32..36].copy_from_slice(&0x1du32.to_le_bytes()); // LC_CODE_SIGNATURE
            v[36..40].copy_from_slice(&16u32.to_le_bytes());
        }
        v
    }

    #[test]
    fn detects_macho_signature_load_command() {
        assert_eq!(macho_signature(&thin_le64(false)), Some(SigState::Unsigned));
        assert_eq!(macho_signature(&thin_le64(true)), Some(SigState::Signed));
        assert!(macho_signature(b"\x7fELF\x02\x01\x01\x00").is_none());
    }

    #[test]
    fn detects_fat_signature() {
        let thin = thin_le64(true);
        let mut fat = vec![0u8; 64];
        fat[0..4].copy_from_slice(&[0xca, 0xfe, 0xba, 0xbe]); // FAT_MAGIC (BE)
        fat[4..8].copy_from_slice(&1u32.to_be_bytes());
        fat[16..20].copy_from_slice(&64u32.to_be_bytes()); // offset
        fat[20..24].copy_from_slice(&(thin.len() as u32).to_be_bytes());
        fat.extend_from_slice(&thin);
        assert_eq!(macho_signature(&fat), Some(SigState::Signed));
    }

    #[test]
    fn does_not_cross_keys() {
        let text = "<key>Program</key><key>Other</key><string>x</string>";
        assert!(plist_string(text, "Program").is_none());
    }
}
