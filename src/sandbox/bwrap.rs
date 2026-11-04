//! bubblewrap isolation: argument construction, resource limits, and timeout-bounded execution.
//!
//! Isolation model (MVP):
//! - All of user/pid/net/ipc/uts/cgroup namespaces are unshared; **no network** by default
//! - Root filesystem: fresh tmpfs with /usr and other system directories read-only bound
//! - /etc, /usr/local, /var/spool/cron, $HOME, /tmp, /work use writable host-side copies
//! - /home, /root, /mnt, /boot, /srv are masked with tmpfs
//! - /proc and /dev are recreated; the environment is cleared
//!
//! Security note: the kernel is shared with the host. Kernel exploits can escape, so this is
//! for rapid behavior triage, not for targeted kernel exploits; use a microVM tier for those.

use super::capture::Layout;
use crate::util;
use anyhow::{Context, Result};
use std::ffi::OsString;
use std::fs::{self, File};
use std::os::unix::process::CommandExt;
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

pub const BWRAP: &str = "bwrap";

/// Resource limits applied through a transient systemd user scope (cgroup v2).
///
/// Without this, a malicious sample can fill the tmpfs-backed sandbox copies
/// (charged to host RAM) or fork-bomb the host; timeout and rlimits alone do
/// not bound aggregate memory or task count.
#[derive(Debug, Clone, Default)]
pub struct CgroupLimits {
    pub mem_bytes: Option<u64>,
    pub cpus: Option<f64>,
    pub pids: Option<u64>,
}

impl CgroupLimits {
    pub fn enabled(&self) -> bool {
        self.mem_bytes.is_some() || self.cpus.is_some() || self.pids.is_some()
    }

    fn properties(&self) -> Vec<String> {
        let mut props = Vec::new();
        if let Some(mem) = self.mem_bytes {
            props.push(format!("MemoryMax={mem}"));
            // Swap would defeat the memory bound; scopes ignore this if no swap.
            props.push("MemorySwapMax=0".to_string());
        }
        if let Some(pids) = self.pids {
            props.push(format!("TasksMax={pids}"));
        }
        if let Some(cpus) = self.cpus {
            let percent = (cpus * 100.0).round().clamp(1.0, 100_000.0) as u64;
            props.push(format!("CPUQuota={percent}%"));
        }
        props
    }

    pub fn describe(&self) -> String {
        let mut parts = Vec::new();
        if let Some(mem) = self.mem_bytes {
            parts.push(format!("memory {}", human_bytes(mem)));
        }
        if let Some(pids) = self.pids {
            parts.push(format!("tasks {pids}"));
        }
        if let Some(cpus) = self.cpus {
            parts.push(format!("CPU {:.0}%", (cpus * 100.0).round()));
        }
        parts.join(" · ")
    }
}

fn human_bytes(n: u64) -> String {
    if n >= 1024 * 1024 * 1024 {
        format!("{:.1} GiB", n as f64 / (1024.0 * 1024.0 * 1024.0))
    } else if n >= 1024 * 1024 {
        format!("{:.0} MiB", n as f64 / (1024.0 * 1024.0))
    } else {
        format!("{n} B")
    }
}

/// Check that a user-scoped systemd transient scope can enforce these limits.
/// Runs a tiny probe (`/bin/true`) with the real properties.
pub fn cgroup_available(limits: &CgroupLimits) -> bool {
    if !limits.enabled() {
        return false;
    }
    if !util::command_exists("systemd-run") || !util::command_exists("systemctl") {
        return false;
    }
    if std::env::var_os("XDG_RUNTIME_DIR").is_none() {
        return false;
    }
    let mut cmd = Command::new("systemd-run");
    cmd.args(["--user", "--scope", "--quiet", "--collect"]);
    for prop in limits.properties() {
        cmd.arg("-p").arg(prop);
    }
    cmd.args(["--", "/bin/true"]);
    cmd.output().map(|o| o.status.success()).unwrap_or(false)
}

/// Wrap a bwrap command in a transient user scope with cgroup v2 limits.
pub fn wrap_with_scope(parts: &[OsString], limits: &CgroupLimits, unit: &str) -> Vec<OsString> {
    let mut v: Vec<OsString> = Vec::new();
    for a in [
        "systemd-run",
        "--user",
        "--scope",
        "--quiet",
        "--collect",
        "--unit",
        unit,
    ] {
        v.push(OsString::from(a));
    }
    for prop in limits.properties() {
        v.push(OsString::from("-p"));
        v.push(OsString::from(prop));
    }
    v.push(OsString::from("--"));
    v.extend(parts.iter().cloned());
    v
}

fn stop_scope(unit: &str) {
    // systemctl requires the `.scope` suffix even though `systemd-run --unit`
    // accepts the bare name.
    let full = format!("{unit}.scope");
    // SIGKILL first: malware may ignore SIGTERM and the default stop timeout
    // would delay the caller.
    let _ = Command::new("systemctl")
        .args([
            "--user",
            "kill",
            "--kill-whom=all",
            "--signal=SIGKILL",
            &full,
        ])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();
    let _ = Command::new("systemctl")
        .args(["--user", "stop", &full])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();
}

pub fn available() -> bool {
    util::command_exists(BWRAP)
}

pub fn version() -> Option<String> {
    util::run(BWRAP, &["--version"]).map(|s| s.trim().to_string())
}

fn push(a: &mut Vec<OsString>, s: &str) {
    a.push(OsString::from(s));
}

fn pair(a: &mut Vec<OsString>, flag: &str, value: &Path) {
    a.push(OsString::from(flag));
    a.push(value.as_os_str().to_os_string());
}

fn pair_str(a: &mut Vec<OsString>, flag: &str, value: &str) {
    a.push(OsString::from(flag));
    a.push(OsString::from(value));
}

/// Recreate host /bin, /lib64, etc. (usually usr-merge symlinks) inside the sandbox.
fn bind_top_level(a: &mut Vec<OsString>, path: &str) {
    let p = Path::new(path);
    if !p.exists() && fs::symlink_metadata(p).is_err() {
        return;
    }
    match fs::read_link(p) {
        Ok(target) => {
            a.push(OsString::from("--symlink"));
            a.push(target.into_os_string());
            a.push(OsString::from(path));
        }
        Err(_) => {
            if p.is_dir() {
                pair(a, "--ro-bind", p);
                a.push(OsString::from(path));
            }
        }
    }
}

pub fn build_args(layout: &Layout) -> Vec<OsString> {
    let mut a: Vec<OsString> = Vec::new();

    push(&mut a, "--unshare-all");
    push(&mut a, "--die-with-parent");
    push(&mut a, "--new-session");
    pair_str(&mut a, "--hostname", "warden-sandbox");
    push(&mut a, "--clearenv");

    // Clean root: tmpfs plus read-only system directories
    push(&mut a, "--tmpfs");
    push(&mut a, "/");
    pair(&mut a, "--ro-bind", Path::new("/usr"));
    a.push(OsString::from("/usr"));
    for p in ["/bin", "/sbin", "/lib", "/lib64", "/lib32", "/libx32"] {
        bind_top_level(&mut a, p);
    }
    if Path::new("/opt").is_dir() {
        pair(&mut a, "--ro-bind", Path::new("/opt"));
        a.push(OsString::from("/opt"));
    }

    // Mask sensitive host directories
    for dir in [
        "/home", "/root", "/run", "/sys", "/var", "/mnt", "/boot", "/srv",
    ] {
        if Path::new(dir).is_dir() {
            push(&mut a, "--tmpfs");
            push(&mut a, dir);
        }
    }

    pair(&mut a, "--dev", Path::new("/dev"));
    pair(&mut a, "--proc", Path::new("/proc"));

    // Writable copies: these are the behavior observation surface
    pair(&mut a, "--bind", &layout.etc);
    a.push(OsString::from("/etc"));
    pair(&mut a, "--bind", &layout.usr_local);
    a.push(OsString::from("/usr/local"));

    push(&mut a, "--dir");
    push(&mut a, "/home/sandbox");
    pair(&mut a, "--bind", &layout.home);
    a.push(OsString::from("/home/sandbox"));

    pair(&mut a, "--bind", &layout.tmp);
    a.push(OsString::from("/tmp"));

    push(&mut a, "--dir");
    push(&mut a, "/work");
    pair(&mut a, "--bind", &layout.work);
    a.push(OsString::from("/work"));

    push(&mut a, "--dir");
    push(&mut a, "/var/tmp");
    pair(&mut a, "--bind", &layout.var_tmp);
    a.push(OsString::from("/var/tmp"));

    push(&mut a, "--dir");
    push(&mut a, "/var/log");
    pair(&mut a, "--bind", &layout.var_log);
    a.push(OsString::from("/var/log"));

    for d in ["/var/spool", "/var/spool/cron", "/var/lib"] {
        push(&mut a, "--dir");
        push(&mut a, d);
    }
    pair(&mut a, "--bind", &layout.spool_cron);
    a.push(OsString::from("/var/spool/cron"));

    push(&mut a, "--dir");
    push(&mut a, "/tmp/runtime");
    push(&mut a, "--chdir");
    push(&mut a, "/work");

    for (k, v) in [
        ("HOME", "/home/sandbox"),
        (
            "PATH",
            "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        ),
        ("TMPDIR", "/tmp"),
        ("TMP", "/tmp"),
        ("TEMP", "/tmp"),
        ("USER", "sandbox"),
        ("LOGNAME", "sandbox"),
        ("SHELL", "/bin/sh"),
        ("LANG", "C.UTF-8"),
        ("LC_ALL", "C.UTF-8"),
        ("XDG_RUNTIME_DIR", "/tmp/runtime"),
        ("XDG_CACHE_HOME", "/tmp/.cache"),
    ] {
        pair_str(&mut a, "--setenv", k);
        a.push(OsString::from(v));
    }

    a
}

/// Full command: optional strace prefix + bwrap + user command.
pub fn command_parts(layout: &Layout, cmd: &[String], trace_path: Option<&Path>) -> Vec<OsString> {
    let mut v: Vec<OsString> = Vec::new();
    if let Some(path) = trace_path {
        v.push(OsString::from("strace"));
        for a in [
            "-f",
            "-qq",
            "-s",
            "256",
            "-e",
            "trace=openat,open,creat,connect,execve,execveat,mount,ptrace,unlink,unlinkat,rename,renameat,init_module,finit_module,bpf",
        ] {
            v.push(OsString::from(a));
        }
        v.push(OsString::from("-o"));
        v.push(path.as_os_str().to_os_string());
        v.push(OsString::from("--"));
    }
    v.push(OsString::from(BWRAP));
    v.extend(build_args(layout));
    v.push(OsString::from("--"));
    for c in cmd {
        v.push(OsString::from(c));
    }
    v
}

pub struct RunOutcome {
    pub status: ExitStatus,
    pub timed_out: bool,
    pub duration: Duration,
}

pub fn execute(
    parts: &[OsString],
    timeout: Duration,
    logs: &Path,
    scope_unit: Option<&str>,
) -> Result<RunOutcome> {
    if parts.is_empty() {
        anyhow::bail!("empty command");
    }
    let program = &parts[0];
    let args = &parts[1..];

    let stdout =
        File::create(logs.join("stdout.log")).context("cannot create sandbox stdout log")?;
    let stderr =
        File::create(logs.join("stderr.log")).context("cannot create sandbox stderr log")?;

    let mut cmd = Command::new(program);
    cmd.args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::from(stdout))
        .stderr(Stdio::from(stderr));

    let cpu_limit = timeout.as_secs().saturating_add(10).max(5);
    // SAFETY: only async-signal-safe syscalls are used in pre_exec.
    unsafe {
        cmd.pre_exec(move || {
            libc::setsid();
            let cpu = libc::rlimit {
                rlim_cur: cpu_limit,
                rlim_max: cpu_limit,
            };
            libc::setrlimit(libc::RLIMIT_CPU, &cpu);
            let fsize = libc::rlimit {
                rlim_cur: 512 * 1024 * 1024,
                rlim_max: 512 * 1024 * 1024,
            };
            libc::setrlimit(libc::RLIMIT_FSIZE, &fsize);
            let core = libc::rlimit {
                rlim_cur: 0,
                rlim_max: 0,
            };
            libc::setrlimit(libc::RLIMIT_CORE, &core);
            Ok(())
        });
    }

    let start = Instant::now();
    let mut child = cmd.spawn().context(
        "cannot start bubblewrap (install bwrap and allow unprivileged user namespaces)",
    )?;

    let mut timed_out = false;
    let status = loop {
        if let Some(st) = child.try_wait()? {
            break st;
        }
        if start.elapsed() >= timeout {
            timed_out = true;
            if let Some(unit) = scope_unit {
                stop_scope(unit);
            }
            let _ = child.kill();
            break child.wait()?;
        }
        std::thread::sleep(Duration::from_millis(20));
    };

    if let Some(unit) = scope_unit {
        // `--collect` normally unloads the transient scope, but a killed
        // payload can leave it in `failed` state on some systemd versions.
        let full = format!("{unit}.scope");
        let _ = Command::new("systemctl")
            .args(["--user", "stop", &full])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();
        std::thread::sleep(Duration::from_millis(60));
        let _ = Command::new("systemctl")
            .args(["--user", "reset-failed", &full])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();
    }

    Ok(RunOutcome {
        status,
        timed_out,
        duration: start.elapsed(),
    })
}

pub fn status_code(status: &ExitStatus) -> Option<i32> {
    status.code()
}

pub fn status_signal(status: &ExitStatus) -> Option<i32> {
    status.signal()
}

#[allow(dead_code)]
fn home() -> PathBuf {
    util::home_dir()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn args_include_isolation_flags() {
        let layout = Layout::create(None).expect("layout");
        let args = build_args(&layout);
        let text: Vec<String> = args
            .iter()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        assert!(text.contains(&"--unshare-all".to_string()));
        assert!(text.contains(&"--die-with-parent".to_string()));
        assert!(text.contains(&"--clearenv".to_string()));
        assert!(text.iter().any(|a| a == "/home/sandbox"));
        layout.cleanup();
    }

    #[test]
    fn cgroup_properties_and_describe() {
        let limits = CgroupLimits {
            mem_bytes: Some(2 * 1024 * 1024 * 1024),
            cpus: Some(1.5),
            pids: Some(256),
        };
        assert!(limits.enabled());
        let props = limits.properties();
        assert!(props.iter().any(|p| p == "MemoryMax=2147483648"));
        assert!(props.iter().any(|p| p == "MemorySwapMax=0"));
        assert!(props.iter().any(|p| p == "TasksMax=256"));
        assert!(props.iter().any(|p| p == "CPUQuota=150%"));
        assert!(limits.describe().contains("2.0 GiB"));
        assert!(!CgroupLimits::default().enabled());
    }
}
