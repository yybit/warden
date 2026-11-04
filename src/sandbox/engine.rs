//! Sandbox backend selection.
//!
//! The job (`RunConfig`) is expressed in terms of the execution environment;
//! the compatibility contract between host and a remote execution environment
//! is the `SandboxReport` JSON emitted by `warden sandbox run --format json`.
//!
//! Backends:
//! - `LocalBackend`: bubblewrap on Linux (the existing implementation)
//! - `VmBackend`: a Linux VM (Lima today, Virtualization.framework later)
//!
//! Adding a backend must not change the CLI surface or the report schema.

use super::{print_local_command, run_local, RunConfig, SandboxReport};
use anyhow::Result;
use std::path::PathBuf;

/// In-process description of a sandbox job. Kept as an alias so the local
/// backend and existing callers share one type.
pub type SandboxJob = RunConfig;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Engine {
    /// Linux -> local bubblewrap; macOS -> VM.
    Auto,
    /// Force bubblewrap (fails on macOS).
    Local,
    /// Force a Linux VM backend.
    Vm,
}

#[derive(Debug, Clone)]
pub struct VmOptions {
    pub name: String,
    /// Linux build of warden copied into the guest.
    pub guest_binary: Option<PathBuf>,
    /// Image used by `sandbox vm up`.
    pub image: String,
    /// URL of a Linux warden binary to download when `guest_binary` is unset.
    pub guest_url: Option<String>,
    /// Expected SHA-256 for `guest_url`; falls back to `<url>.sha256`.
    pub guest_sha256: Option<String>,
    /// Cache root override (tests use a temp dir).
    pub cache_dir: Option<PathBuf>,
    /// Test/embedded override for `curl`.
    pub curl: Option<PathBuf>,
    /// Test/embedded override for the `limactl` binary.
    pub limactl: Option<PathBuf>,
}

impl Default for VmOptions {
    fn default() -> Self {
        VmOptions {
            name: "warden-sandbox".into(),
            guest_binary: None,
            image: "template://default".into(),
            guest_url: None,
            guest_sha256: None,
            cache_dir: None,
            curl: None,
            limactl: None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Choice {
    Local,
    Vm,
}

pub fn resolve(engine: Engine) -> Choice {
    match engine {
        Engine::Local => Choice::Local,
        Engine::Vm => Choice::Vm,
        Engine::Auto => {
            if cfg!(target_os = "macos") {
                Choice::Vm
            } else {
                Choice::Local
            }
        }
    }
}

pub trait Backend {
    fn run(&self, job: &SandboxJob) -> Result<SandboxReport>;
}

pub struct LocalBackend;

impl Backend for LocalBackend {
    fn run(&self, job: &SandboxJob) -> Result<SandboxReport> {
        run_local(job.clone())
    }
}

pub struct VmBackend {
    pub options: VmOptions,
}

impl Backend for VmBackend {
    fn run(&self, job: &SandboxJob) -> Result<SandboxReport> {
        super::vm::run(job, &self.options)
    }
}

pub fn dispatch(job: &SandboxJob, engine: Engine, vm: &VmOptions) -> Result<SandboxReport> {
    let backend: Box<dyn Backend> = match resolve(engine) {
        Choice::Local => Box::new(LocalBackend),
        Choice::Vm => Box::new(VmBackend {
            options: vm.clone(),
        }),
    };
    backend.run(job)
}

pub fn print_command(job: &SandboxJob, engine: Engine, vm: &VmOptions) -> Result<()> {
    match resolve(engine) {
        Choice::Local => print_local_command(job),
        Choice::Vm => {
            println!("{}", super::vm::preview(job, vm)?);
            Ok(())
        }
    }
}
