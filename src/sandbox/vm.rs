//! Linux VM backend (Lima today; Virtualization.framework later).
//!
//! Host responsibilities: verify/start the VM, copy the job inputs and a
//! **Linux** warden binary into it, execute `warden sandbox run --format json`
//! inside, and import the report. The in-VM run still uses the local bwrap
//! backend, so filesystem diffing, IOC/YARA/ClamAV and cgroup limits behave
//! exactly as on Linux.

use super::engine::{SandboxJob, VmOptions};
use super::shell_join;
use crate::util::{self, FileKind};
use anyhow::{bail, Context, Result};
use serde_json::Value;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const JOB_DIR: &str = "/tmp/warden-job";

fn limactl_path(opts: &VmOptions) -> Result<PathBuf> {
    if let Some(p) = &opts.limactl {
        if p.is_file() {
            return Ok(p.clone());
        }
    }
    which("limactl").ok_or_else(|| {
        anyhow::anyhow!(
            "limactl not found. Install Lima (`brew install lima` on macOS) or pass a Linux VM runtime in a future backend."
        )
    })
}

fn which(name: &str) -> Option<PathBuf> {
    std::env::var_os("PATH").and_then(|paths| {
        std::env::split_paths(&paths)
            .map(|d| d.join(name))
            .find(|p| p.is_file())
    })
}

fn output_of(mut cmd: Command, what: &str) -> Result<Output> {
    // ETXTBSY can happen if another thread forked while a script was being
    // written (common in parallel tests, rare in production). Retry briefly.
    for attempt in 0..3 {
        match cmd.output() {
            Ok(out) => return Ok(out),
            Err(e) if e.raw_os_error() == Some(libc::ETXTBSY) && attempt < 2 => {
                std::thread::sleep(std::time::Duration::from_millis(30));
            }
            Err(e) => {
                return Err(e).with_context(|| format!("cannot execute {what}"));
            }
        }
    }
    unreachable!()
}

fn list_instances(bin: &Path) -> Result<Vec<(String, String)>> {
    let mut json_cmd = Command::new(bin);
    json_cmd.args(["list", "--json"]);
    if let Ok(out) = output_of(json_cmd, "`limactl list`") {
        if out.status.success() {
            let text = String::from_utf8_lossy(&out.stdout).into_owned();
            let parsed = parse_instances(&text, "");
            if !parsed.is_empty() {
                return Ok(parsed);
            }
        }
    }

    let mut text_cmd = Command::new(bin);
    text_cmd.arg("list");
    let out = text_cmd.output().context("cannot run `limactl list`")?;
    if !out.status.success() {
        bail!(
            "`limactl list` failed: {}",
            tail(&String::from_utf8_lossy(&out.stderr))
        );
    }
    Ok(parse_instances("", &String::from_utf8_lossy(&out.stdout)))
}

/// Parse both `limactl list --json` (array or JSON-lines) and the text table.
pub fn parse_instances(json: &str, text: &str) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = Vec::new();

    if let Ok(v) = serde_json::from_str::<Value>(json) {
        match &v {
            Value::Array(items) => {
                for item in items {
                    push_instance(&mut out, item);
                }
            }
            Value::Object(_) => push_instance(&mut out, &v),
            _ => {}
        }
    }
    if out.is_empty() {
        for line in json.lines() {
            if let Ok(v) = serde_json::from_str::<Value>(line) {
                push_instance(&mut out, &v);
            }
        }
    }
    if out.is_empty() {
        for line in text.lines() {
            let mut it = line.split_whitespace();
            let name = match it.next() {
                Some(n) => n,
                None => continue,
            };
            if matches!(name, "NAME" | "WARN" | "INFO") {
                continue;
            }
            let status = match it.next() {
                Some(s) => s,
                None => continue,
            };
            if status.eq_ignore_ascii_case("running") || status.eq_ignore_ascii_case("stopped") {
                out.push((name.to_string(), status.to_string()));
            }
        }
    }
    out
}

fn push_instance(out: &mut Vec<(String, String)>, v: &Value) {
    let name = field(v, &["name", "Name"]);
    let status = field(v, &["status", "Status"]);
    if let (Some(n), Some(s)) = (name, status) {
        if !out.iter().any(|(x, _)| x == &n) {
            out.push((n, s));
        }
    }
}

fn field(v: &Value, keys: &[&str]) -> Option<String> {
    for k in keys {
        if let Some(s) = v.get(*k).and_then(|x| x.as_str()) {
            return Some(s.to_string());
        }
    }
    None
}

fn ensure_running(bin: &Path, name: &str) -> Result<()> {
    let instances = list_instances(bin)?;
    match instances.iter().find(|(n, _)| n == name) {
        None => bail!(
            "Lima instance `{name}` not found. Create it with `warden sandbox vm up --name {name}` (after `brew install lima`)."
        ),
        Some((_, status)) if !status.eq_ignore_ascii_case("running") => bail!(
            "Lima instance `{name}` is `{status}`; start it with `warden sandbox vm up --name {name}`."
        ),
        _ => Ok(()),
    }
}

fn guest_sh(bin: &Path, name: &str, args: &[&str]) -> Result<()> {
    let mut cmd = Command::new(bin);
    cmd.arg("shell").arg(name).args(args);
    let out = output_of(cmd, "`limactl shell`")?;
    if !out.status.success() {
        bail!(
            "guest command `{}` failed: {}",
            args.join(" "),
            tail(&String::from_utf8_lossy(&out.stderr))
        );
    }
    Ok(())
}

fn copy_from(bin: &Path, name: &str, src: &str, dest: &Path) -> Result<()> {
    let mut cmd = Command::new(bin);
    cmd.arg("copy").arg(format!("{name}:{src}")).arg(dest);
    let out = output_of(cmd, "`limactl copy`")?;
    if !out.status.success() {
        bail!(
            "failed to copy {} from the VM: {}",
            src,
            tail(&String::from_utf8_lossy(&out.stderr))
        );
    }
    Ok(())
}

fn guest_artifact_path(base: &str, workdir: &str, logical: &str) -> Option<String> {
    // `/work` is the user-provided workdir copied into the job directory, not
    // a subdirectory of the disposable sandbox base.
    if let Some(rest) = logical.strip_prefix("/work/") {
        return Some(format!("{workdir}/{rest}"));
    }
    let (dir, rest) = [
        ("/etc/", "etc"),
        ("/home/sandbox/", "home"),
        ("/tmp/", "tmp"),
        ("/usr/local/", "usr-local"),
        ("/var/tmp/", "var-tmp"),
        ("/var/log/", "var-log"),
        ("/var/spool/cron/", "spool-cron"),
        ("/work/", "work"),
    ]
    .iter()
    .find_map(|(prefix, dir)| logical.strip_prefix(prefix).map(|rest| (*dir, rest)))?;
    Some(format!("{base}/{dir}/{rest}"))
}

fn shell_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

fn copy_into(bin: &Path, name: &str, src: &Path, dest: &str, recursive: bool) -> Result<()> {
    let mut cmd = Command::new(bin);
    cmd.arg("copy");
    if recursive {
        cmd.arg("-r");
    }
    cmd.arg(src).arg(format!("{name}:{dest}"));
    let out = output_of(cmd, "`limactl copy`")?;
    if !out.status.success() {
        bail!(
            "failed to copy {} into the VM: {}",
            src.display(),
            tail(&String::from_utf8_lossy(&out.stderr))
        );
    }
    Ok(())
}

fn stamp() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0)
}

/// The guest CLI invocation. Pure function so it can be unit-tested.
pub fn guest_run_args(
    job: &SandboxJob,
    guest_workdir: &str,
    guest_yara: &[String],
    guest_ioc: Option<&str>,
) -> Vec<String> {
    let mut args: Vec<String> = vec![
        "sandbox".into(),
        "run".into(),
        "--format".into(),
        "json".into(),
        "--workdir".into(),
        guest_workdir.into(),
        "--timeout".into(),
        job.timeout.as_secs().to_string(),
        "--max-file-size".into(),
        job.max_file_size.to_string(),
        // Always send all three: 0 means "disabled" and overrides guest defaults.
        "--mem".into(),
        job.limits.mem_bytes.unwrap_or(0).to_string(),
        "--cpus".into(),
        job.limits.cpus.unwrap_or(0.0).to_string(),
        "--pids".into(),
        job.limits.pids.unwrap_or(0).to_string(),
        "--trace".into(),
        match job.trace {
            super::TraceMode::Auto => "auto".into(),
            super::TraceMode::Off => "off".into(),
        },
    ];
    if job.clamav {
        args.push("--clamav".into());
    }
    if job.keep {
        args.push("--keep".into());
    }
    for y in guest_yara {
        args.push("--yara".into());
        args.push(y.clone());
    }
    if let Some(ioc) = guest_ioc {
        args.push("--ioc".into());
        args.push(ioc.into());
    }
    args.push("--".into());
    args.extend(job.cmd.iter().cloned());
    args
}

const MAX_GUEST_BINARY: u64 = 512 * 1024 * 1024;

fn verify_elf(path: &Path) -> Result<()> {
    if !path.is_file() {
        bail!("guest binary does not exist: {}", path.display());
    }
    if util::file_kind(path) != FileKind::Elf {
        bail!(
            "guest binary must be a Linux ELF binary (got {}); a macOS Mach-O binary cannot run in the VM",
            path.display()
        );
    }
    Ok(())
}

fn cache_root(opts: &VmOptions) -> PathBuf {
    if let Some(p) = &opts.cache_dir {
        return p.clone();
    }
    if let Some(p) = std::env::var_os("XDG_CACHE_HOME") {
        return PathBuf::from(p);
    }
    if let Some(home) = std::env::var_os("HOME") {
        return PathBuf::from(home).join(".cache");
    }
    std::env::temp_dir()
}

/// `<cache>/warden/guest/<version>/<arch>/warden`; the version segment makes
/// stale cached binaries unreachable after an upgrade.
fn cache_path(opts: &VmOptions) -> PathBuf {
    cache_root(opts)
        .join("warden")
        .join("guest")
        .join(env!("CARGO_PKG_VERSION"))
        .join(std::env::consts::ARCH)
        .join("warden")
}

fn curl_path(opts: &VmOptions) -> Result<PathBuf> {
    if let Some(p) = &opts.curl {
        if p.is_file() {
            return Ok(p.clone());
        }
    }
    which("curl").ok_or_else(|| anyhow::anyhow!("curl is required to download a guest binary"))
}

fn normalize_sha(s: &str) -> Result<String> {
    let h = s
        .trim()
        .strip_prefix("sha256:")
        .unwrap_or(s.trim())
        .trim()
        .to_ascii_lowercase();
    if h.len() == 64 && h.chars().all(|c| c.is_ascii_hexdigit()) {
        Ok(h)
    } else {
        bail!("invalid SHA-256: {s}")
    }
}

fn parse_checksum(text: &str) -> Result<String> {
    let token = text
        .split_whitespace()
        .find(|t| t.len() == 64 && t.chars().all(|c| c.is_ascii_hexdigit()))
        .ok_or_else(|| anyhow::anyhow!("checksum file contains no SHA-256"))?;
    normalize_sha(token)
}

fn download(opts: &VmOptions, url: &str, dest: &Path) -> Result<()> {
    let curl = curl_path(opts)?;
    if let Some(parent) = dest.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let max = MAX_GUEST_BINARY.to_string();
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
        "300",
        "--max-filesize",
        &max,
        "-o",
    ]);
    cmd.arg(dest).arg("--").arg(url);
    let out = output_of(cmd, "curl (guest binary download)")?;
    if !out.status.success() {
        let _ = std::fs::remove_file(dest);
        bail!(
            "failed to download {}: {}",
            url,
            tail(&String::from_utf8_lossy(&out.stderr))
        );
    }
    Ok(())
}

fn fetch_sidecar(opts: &VmOptions, url: &str) -> Result<String> {
    let tmp = std::env::temp_dir().join(format!(
        "warden-guest-sha-{}-{}",
        std::process::id(),
        stamp()
    ));
    download(opts, &format!("{url}.sha256"), &tmp)?;
    let text = util::read_text(&tmp, 1024 * 1024)
        .ok_or_else(|| anyhow::anyhow!("checksum file is unreadable"))?;
    let _ = std::fs::remove_file(&tmp);
    parse_checksum(&text)
}

/// Download (or reuse) a verified Linux guest binary.
pub fn fetch_guest(opts: &VmOptions) -> Result<PathBuf> {
    let url = opts
        .guest_url
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("no guest binary URL provided"))?;
    let dest = cache_path(opts);
    let sha_file = dest.with_extension("sha256");

    // Cache hit without touching the network: trust the pinned checksum or the
    // checksum saved when the file was downloaded.
    if dest.is_file() {
        let expected = match &opts.guest_sha256 {
            Some(h) => Some(normalize_sha(h)?),
            None => util::read_text(&sha_file, 4096).and_then(|t| parse_checksum(&t).ok()),
        };
        if let Some(expected) = expected {
            if util::sha256_file(&dest, MAX_GUEST_BINARY + 1).as_deref() == Some(expected.as_str())
            {
                return Ok(dest);
            }
        }
    }

    let expected = match &opts.guest_sha256 {
        Some(h) => normalize_sha(h)?,
        None => fetch_sidecar(opts, url)?,
    };

    let tmp = dest.with_extension(format!("part-{}", std::process::id()));
    download(opts, url, &tmp)?;
    let actual = util::sha256_file(&tmp, MAX_GUEST_BINARY + 1)
        .ok_or_else(|| anyhow::anyhow!("cannot hash the downloaded guest binary"))?;
    if actual != expected {
        let _ = std::fs::remove_file(&tmp);
        bail!("guest binary checksum mismatch: expected {expected}, got {actual}");
    }
    verify_elf(&tmp)?;
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o755))?;
    if let Some(parent) = dest.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::rename(&tmp, &dest).with_context(|| "cannot install the cached guest binary")?;
    let _ = std::fs::write(
        &sha_file,
        format!(
            "{expected}  {}\n",
            dest.file_name().unwrap_or_default().to_string_lossy()
        ),
    );
    Ok(dest)
}

fn resolve_guest_binary(opts: &VmOptions) -> Result<PathBuf> {
    if let Some(p) = &opts.guest_binary {
        verify_elf(p)?;
        return Ok(p.clone());
    }
    if opts.guest_url.is_some() {
        return fetch_guest(opts);
    }
    let cached = cache_path(opts);
    if cached.is_file() {
        verify_elf(&cached)?;
        return Ok(cached);
    }
    bail!(
        "no Linux guest binary. Pass --vm-guest-binary <linux-warden>, or --vm-guest-url <url> [--vm-guest-sha256 <hex>] (env: WARDEN_GUEST_URL / WARDEN_GUEST_SHA256). Cache: {}",
        cached.display()
    )
}

fn extract_json(text: &str) -> Option<&str> {
    // `limactl shell` may print MOTD/notice text containing braces; anchor on
    // the report marker instead of the first `{`.
    let marker = "\"tool\"";
    let idx = text.find(marker)?;
    let start = text[..idx].rfind('{')?;
    let end = text.rfind('}')?;
    if end > start {
        Some(&text[start..=end])
    } else {
        None
    }
}

fn tail(s: &str) -> String {
    let s = s.trim();
    let n = s.chars().count();
    if n > 800 {
        format!("…{}", s.chars().skip(n - 800).collect::<String>())
    } else {
        s.to_string()
    }
}

pub fn run(job: &SandboxJob, opts: &VmOptions) -> Result<super::SandboxReport> {
    let bin = limactl_path(opts)?;
    ensure_running(&bin, &opts.name)?;
    let guest_bin = resolve_guest_binary(opts)?;

    if job.clamav_db.is_some() {
        bail!(
            "--clamav-db is a host path and cannot be used with --engine vm; install ClamAV and its database inside the VM and omit --clamav-db"
        );
    }
    if job.keep && job.workdir.is_none() {
        bail!("--keep with --engine vm requires --workdir so artifacts have a host destination");
    }

    let (workdir, temp_work) = match &job.workdir {
        Some(p) => (std::fs::canonicalize(p).unwrap_or_else(|_| p.clone()), None),
        None => {
            let p = std::env::temp_dir().join(format!(
                "warden-vm-work-{}-{}",
                std::process::id(),
                stamp()
            ));
            std::fs::create_dir_all(&p)?;
            (p.clone(), Some(p))
        }
    };

    let setup = (|| -> Result<super::SandboxReport> {
        guest_sh(&bin, &opts.name, &["rm", "-rf", JOB_DIR])?;
        guest_sh(&bin, &opts.name, &["mkdir", "-p", JOB_DIR])?;
        copy_into(&bin, &opts.name, &workdir, &format!("{JOB_DIR}/work"), true)?;
        copy_into(
            &bin,
            &opts.name,
            &guest_bin,
            &format!("{JOB_DIR}/warden"),
            false,
        )?;
        guest_sh(
            &bin,
            &opts.name,
            &["chmod", "+x", &format!("{JOB_DIR}/warden")],
        )?;

        let mut guest_yara = Vec::new();
        for (i, path) in job.yara.iter().enumerate() {
            let dest = format!("{JOB_DIR}/yara-{i}");
            copy_into(&bin, &opts.name, path, &dest, path.is_dir())?;
            guest_yara.push(dest);
        }
        let guest_ioc = match &job.ioc {
            Some(path) => {
                let dest = format!("{JOB_DIR}/ioc");
                copy_into(&bin, &opts.name, path, &dest, false)?;
                Some(dest)
            }
            None => None,
        };

        let mut args = vec![format!("{JOB_DIR}/warden")];
        args.extend(guest_run_args(
            job,
            &format!("{JOB_DIR}/work"),
            &guest_yara,
            guest_ioc.as_deref(),
        ));
        let mut cmd = Command::new(&bin);
        cmd.arg("shell").arg(&opts.name).args(&args);
        let out = output_of(cmd, "`limactl shell`")?;
        let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&out.stderr).into_owned();

        let json = extract_json(&stdout).ok_or_else(|| {
            anyhow::anyhow!(
                "guest did not return a JSON report (exit {:?})\nstdout: {}\nstderr: {}",
                out.status.code(),
                tail(&stdout),
                tail(&stderr)
            )
        })?;
        let mut report: super::SandboxReport =
            serde_json::from_str(json).context("invalid SandboxReport JSON from guest")?;

        if report.version != env!("CARGO_PKG_VERSION") {
            bail!(
                "guest warden version {} does not match host {}; rebuild/copy a matching Linux binary",
                report.version,
                env!("CARGO_PKG_VERSION")
            );
        }

        report.notes.push(format!(
            "executed inside Lima VM `{}` (separate Linux kernel; host filesystem not shared)",
            opts.name
        ));
        report
            .notes
            .push(format!("guest binary: {}", guest_bin.display()));

        if job.keep && report.kept {
            let host_workdir = job
                .workdir
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("--keep requires --workdir"))?;
            // Archive inside the guest: `scp` follows symlinks and would fail on
            // the /etc copy. The archive is copied, never auto-extracted.
            let stage = stamp();
            let archive = format!("{JOB_DIR}/artifacts.tar.gz");
            let tar_dest = host_workdir.join(format!("warden-artifacts-{stage}.tar.gz"));
            let workdir = format!("{JOB_DIR}/work");
            let export = format!("{JOB_DIR}/export");
            // Stage base + workdir so the archive also contains files written
            // to /work, which lives outside the disposable sandbox base.
            let stage_cmd = format!(
                "rm -rf {export} && mkdir -p {export}/base {export}/work && cp -a {}/. {export}/base/ && cp -a {}/. {export}/work/",
                shell_quote(&report.workdir),
                shell_quote(&workdir),
            );
            let tar_cmd = format!("tar -C {export} -czf {archive} .");
            let packed = guest_sh(&bin, &opts.name, &["sh", "-c", &stage_cmd]).is_ok()
                && guest_sh(&bin, &opts.name, &["sh", "-c", &tar_cmd]).is_ok()
                && copy_from(&bin, &opts.name, &archive, &tar_dest).is_ok();

            if packed {
                report.notes.push(format!(
                    "artifacts archive copied to {} (extract manually)",
                    tar_dest.display()
                ));
                report.workdir = tar_dest.to_string_lossy().into_owned();
            } else {
                // Minimal guests (e.g. CoreOS-style images) may not ship tar.
                // Copy only the changed files listed in the report; this also
                // avoids scp following broken symlinks in the /etc copy.
                let dest_dir = host_workdir.join(format!("warden-artifacts-{stage}"));
                let mut copied = 0usize;
                for item in report.artifacts.iter().take(200) {
                    if item.change == "deleted" {
                        continue;
                    }
                    let guest_path = match guest_artifact_path(
                        &report.workdir,
                        &format!("{JOB_DIR}/work"),
                        &item.path,
                    ) {
                        Some(p) => p,
                        None => continue,
                    };
                    let dest = dest_dir.join(item.path.trim_start_matches('/'));
                    if let Some(parent) = dest.parent() {
                        let _ = std::fs::create_dir_all(parent);
                    }
                    if copy_from(&bin, &opts.name, &guest_path, &dest).is_ok() {
                        copied += 1;
                    }
                }
                if copied > 0 {
                    report.notes.push(format!(
                        "{} changed file(s) copied to {} (guest has no tar)",
                        copied,
                        dest_dir.display()
                    ));
                    report.workdir = dest_dir.to_string_lossy().into_owned();
                } else {
                    report.notes.push(format!(
                        "could not export artifacts; they remain inside the VM at {}",
                        report.workdir
                    ));
                }
            }
        }

        Ok::<super::SandboxReport, anyhow::Error>(report)
    })();

    let _ = guest_sh(&bin, &opts.name, &["rm", "-rf", JOB_DIR]);
    if let Some(p) = temp_work {
        let _ = std::fs::remove_dir_all(p);
    }
    setup
}

pub fn preview(job: &SandboxJob, opts: &VmOptions) -> Result<String> {
    let workdir = job
        .workdir
        .as_ref()
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_else(|| "<workdir>".into());
    let guest_bin = opts
        .guest_binary
        .as_ref()
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_else(|| "<linux-warden>".into());
    let guest_yara: Vec<String> = (0..job.yara.len())
        .map(|i| format!("{JOB_DIR}/yara-{i}"))
        .collect();
    let guest_ioc = job.ioc.as_ref().map(|_| format!("{JOB_DIR}/ioc"));
    let mut argv = vec![format!("{JOB_DIR}/warden")];
    argv.extend(guest_run_args(
        job,
        &format!("{JOB_DIR}/work"),
        &guest_yara,
        guest_ioc.as_deref(),
    ));
    let osargs: Vec<OsString> = argv.into_iter().map(OsString::from).collect();

    let mut lines = vec![
        format!("# backend: vm (Lima instance `{}`)", opts.name),
        format!("limactl shell {} rm -rf {JOB_DIR}", opts.name),
        format!("limactl shell {} mkdir -p {JOB_DIR}", opts.name),
        format!("limactl copy -r {workdir} {}:{JOB_DIR}/work", opts.name),
        format!("limactl copy {guest_bin} {}:{JOB_DIR}/warden", opts.name),
        format!("limactl shell {} chmod +x {JOB_DIR}/warden", opts.name),
    ];
    for (i, path) in job.yara.iter().enumerate() {
        lines.push(format!(
            "limactl copy {} {}:{JOB_DIR}/yara-{i}",
            path.display(),
            opts.name
        ));
    }
    if let Some(path) = &job.ioc {
        lines.push(format!(
            "limactl copy {} {}:{JOB_DIR}/ioc",
            path.display(),
            opts.name
        ));
    }
    lines.push(format!(
        "limactl shell {} {}",
        opts.name,
        shell_join(&osargs)
    ));
    lines.push(format!("limactl shell {} rm -rf {JOB_DIR}", opts.name));
    Ok(lines.join("\n"))
}

pub fn up(opts: &VmOptions) -> Result<()> {
    let bin = limactl_path(opts)?;
    let mut cmd = Command::new(&bin);
    cmd.args(["start", "--name", &opts.name, "--tty=false", &opts.image]);
    let out = output_of(cmd, "`limactl start`")?;
    if !out.status.success() {
        bail!(
            "failed to start Lima instance `{}`: {}",
            opts.name,
            tail(&String::from_utf8_lossy(&out.stderr))
        );
    }
    println!("Lima instance `{}` is starting.", opts.name);
    println!("Install sandbox dependencies inside the VM, for example:");
    println!(
        "  limactl shell {} -- sudo apt-get update && sudo apt-get install -y bubblewrap",
        opts.name
    );
    println!("Then provide a Linux build of warden via --vm-guest-binary, or auto-download it with --vm-guest-url / WARDEN_GUEST_URL, and run:");
    println!(
        "  warden sandbox run --engine vm --vm-name {} --vm-guest-binary ./warden-linux -- /bin/echo ok",
        opts.name
    );
    println!("Or let warden download and verify it:");
    println!(
        "  warden sandbox run --engine vm --vm-name {} --vm-guest-url <url> [--vm-guest-sha256 <hex>] -- /bin/echo ok",
        opts.name
    );
    Ok(())
}

pub fn status(opts: &VmOptions) -> Result<()> {
    let bin = limactl_path(opts)?;
    let instances = list_instances(&bin)?;
    if instances.is_empty() {
        println!("No Lima instances found.");
        return Ok(());
    }
    println!("{:<24} STATUS", "INSTANCE");
    for (name, status) in instances {
        println!("{name:<24} {status}");
    }
    Ok(())
}

pub fn down(opts: &VmOptions) -> Result<()> {
    let bin = limactl_path(opts)?;
    let out = output_of(
        {
            let mut c = Command::new(&bin);
            c.args(["stop", &opts.name]);
            c
        },
        "`limactl stop`",
    )?;
    if !out.status.success() {
        bail!(
            "failed to stop Lima instance `{}`: {}",
            opts.name,
            tail(&String::from_utf8_lossy(&out.stderr))
        );
    }
    println!("Lima instance `{}` stopped.", opts.name);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    struct Cleanup(PathBuf);
    impl Drop for Cleanup {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn sample_job(workdir: PathBuf) -> SandboxJob {
        SandboxJob {
            cmd: vec!["/bin/sh".into(), "/work/demo.sh".into()],
            workdir: Some(workdir),
            timeout: std::time::Duration::from_secs(30),
            max_file_size: 64 * 1024 * 1024,
            ioc: None,
            yara: Vec::new(),
            clamav: false,
            clamav_db: None,
            limits: super::super::bwrap::CgroupLimits {
                mem_bytes: Some(512 * 1024 * 1024),
                cpus: Some(1.5),
                pids: Some(128),
            },
            trace: super::super::TraceMode::Auto,
            keep: false,
            print_command: false,
        }
    }

    #[test]
    fn parses_instance_formats() {
        let arr = r#"[{"name":"a","status":"Running"},{"Name":"b","Status":"Stopped"}]"#;
        assert_eq!(
            parse_instances(arr, ""),
            vec![
                ("a".to_string(), "Running".to_string()),
                ("b".to_string(), "Stopped".to_string())
            ]
        );
        let lines = "{\"name\":\"c\",\"status\":\"Running\"}\n";
        assert_eq!(
            parse_instances(lines, ""),
            vec![("c".to_string(), "Running".to_string())]
        );
        let table = "NAME STATUS SSH ARCH\nx Running 127.0.0.1 0 aarch64\n";
        assert_eq!(
            parse_instances("", table),
            vec![("x".to_string(), "Running".to_string())]
        );
    }

    #[test]
    fn guest_args_include_limits_and_paths() {
        let dir = std::env::temp_dir();
        let job = sample_job(dir);
        let args = guest_run_args(
            &job,
            "/tmp/warden-job/work",
            &["/tmp/warden-job/yara-0".into()],
            Some("/tmp/warden-job/ioc"),
        );
        let joined = args.join(" ");
        assert!(joined.contains("--mem 536870912"));
        assert!(joined.contains("--cpus 1.5"));
        assert!(joined.contains("--pids 128"));
        assert!(joined.contains("--yara /tmp/warden-job/yara-0"));
        assert!(joined.contains("--ioc /tmp/warden-job/ioc"));
        assert!(joined.ends_with("-- /bin/sh /work/demo.sh"));
        let noisy = "welcome {not json}\n{\n  \"tool\": \"warden\", \"version\": \"x\"\n}";
        assert!(extract_json(noisy).unwrap().contains("\"tool\""));
    }

    #[test]
    fn normalizes_checksums() {
        let h = "A".repeat(64);
        assert_eq!(normalize_sha(&h).unwrap(), "a".repeat(64));
        assert_eq!(
            normalize_sha(&format!("sha256:{}", "b".repeat(64))).unwrap(),
            "b".repeat(64)
        );
        assert!(normalize_sha("nope").is_err());
        assert_eq!(
            parse_checksum(&format!("{}  warden-linux\n", "c".repeat(64))).unwrap(),
            "c".repeat(64)
        );
    }

    #[test]
    fn downloads_and_caches_guest_binary() {
        let _spawn = crate::util::SPAWN_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let dir = std::env::temp_dir().join(format!(
            "warden-guest-test-{}-{}",
            std::process::id(),
            stamp()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let _cleanup = Cleanup(dir.clone());
        let fixture = dir.join("warden-linux");
        std::fs::write(&fixture, [0x7f, b'E', b'L', b'F', 2, 1, 1, 0]).unwrap();
        let hash = util::sha256_file(&fixture, 1024).unwrap();

        let fake = dir.join("curl");
        let script = format!(
            r#"#!/bin/sh
out=""; last=""; prev=""
for a in "$@"; do
  if [ "$prev" = "-o" ]; then out="$a"; fi
  prev="$a"; last="$a"
done
case "$last" in
  *.sha256) printf '%s  warden\n' "{}" > "$out" ;;
  *) cp "{}" "$out" ;;
esac
"#,
            hash,
            fixture.display()
        );
        std::fs::write(&fake, script).unwrap();
        std::fs::set_permissions(&fake, std::fs::Permissions::from_mode(0o755)).unwrap();

        let opts = VmOptions {
            guest_url: Some("http://example.invalid/warden-linux".into()),
            cache_dir: Some(dir.join("cache")),
            curl: Some(fake.clone()),
            ..Default::default()
        };
        let path = fetch_guest(&opts).unwrap();
        assert!(path.is_file());
        assert_eq!(
            util::sha256_file(&path, 1024).as_deref(),
            Some(hash.as_str())
        );

        // Second call must hit the cache without invoking curl.
        let cached = VmOptions {
            curl: None,
            ..opts.clone()
        };
        assert_eq!(fetch_guest(&cached).unwrap(), path);

        // A wrong pinned checksum must fail and leave no cache entry.
        let bad = VmOptions {
            guest_sha256: Some("0".repeat(64)),
            cache_dir: Some(dir.join("cache-bad")),
            ..opts.clone()
        };
        assert!(fetch_guest(&bad).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn runs_against_fake_limactl() {
        let _spawn = crate::util::SPAWN_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let dir =
            std::env::temp_dir().join(format!("warden-vm-test-{}-{}", std::process::id(), stamp()));
        std::fs::create_dir_all(dir.join("work")).unwrap();
        let _cleanup = Cleanup(dir.clone());
        std::fs::write(dir.join("work/demo.sh"), b"echo hi").unwrap();

        let guest = dir.join("warden-linux");
        std::fs::write(&guest, [0x7f, b'E', b'L', b'F', 2, 1, 1, 0]).unwrap();

        let report = format!(
            r#"{{"tool":"warden","version":"{}","started_at":"2026-01-01T00:00:00Z","duration_ms":1,"command":["/bin/echo"],"isolation":{{"backend":"bubblewrap","backend_version":"x","namespaces":[],"network":"isolated (no egress)","root_filesystem":"tmpfs","writable_capture":[],"masked":[],"host_uid":1000}},"exit":{{"status":"exited","code":0,"signal":null,"duration_ms":1,"timed_out":false}},"findings":[],"artifacts":[],"artifacts_total":0,"score":0,"verdict":"clean","workdir":"/tmp/guest-sandbox","kept":false,"trace_file":null,"stdout":"","stderr":"","notes":[]}}"#,
            env!("CARGO_PKG_VERSION")
        );
        std::fs::write(dir.join("report.json"), report).unwrap();

        let fake = dir.join("limactl");
        let script = format!(
            r#"#!/bin/sh
case "$1" in
  list) echo '{{"name":"warden-sandbox","status":"Running"}}'; exit 0 ;;
  copy) exit 0 ;;
  shell)
    for a in "$@"; do
      if [ "$a" = "sandbox" ]; then cat "{}"; exit 1; fi
    done
    exit 0 ;;
esac
exit 0
"#,
            dir.join("report.json").display()
        );
        std::fs::write(&fake, script).unwrap();
        std::fs::set_permissions(&fake, std::fs::Permissions::from_mode(0o755)).unwrap();

        let opts = VmOptions {
            name: "warden-sandbox".into(),
            guest_binary: Some(guest),
            limactl: Some(fake),
            ..Default::default()
        };
        let job = sample_job(dir.join("work"));
        let report = run(&job, &opts).unwrap_or_else(|e| panic!("vm run failed: {e:#}"));
        assert_eq!(report.version, env!("CARGO_PKG_VERSION"));
        assert!(report.notes.iter().any(|n| n.contains("Lima VM")));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
