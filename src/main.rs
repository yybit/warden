//! CLI definition and command dispatch.

use clap::{Args, Parser, Subcommand, ValueEnum};
use std::io::IsTerminal;
use std::path::PathBuf;
use warden::ctx::{Config, Format};
use warden::model::Severity;
use warden::{
    baseline, checks, clamav, defaults, engine, intel, malicious, policy, sandbox, selftest, tui,
    util,
};

#[derive(Parser)]
#[command(
    name = "warden",
    version,
    about = "Host security scanner: trojans, backdoors, persistence, and misconfiguration (macOS / Linux)",
    after_help = "Examples:\n  warden scan\n  sudo warden scan --fail-on high --format sarif --output report.sarif\n  warden scan --webroot /var/www --baseline warden-baseline.json\n  warden baseline save --file warden-baseline.json\n  warden sandbox run --workdir ./samples --keep -- /work/installer.sh"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Option<Cmd>,
}

#[derive(Subcommand)]
enum Cmd {
    /// Scan the local host or a filesystem root
    Scan(ScanArgs),
    /// Save and inspect baselines
    Baseline {
        #[command(subcommand)]
        action: BaselineAction,
    },
    /// List all checks
    Checks {
        #[arg(long, value_enum, default_value_t = FormatArg::Text)]
        format: FormatArg,
    },
    /// End-to-end self-test with built-in fixtures (does not touch host config)
    Selftest,
    /// Show built-in defaults or write a policy template
    Config {
        #[command(subcommand)]
        action: ConfigAction,
    },
    /// Download and inspect IOC feeds
    Intel {
        #[command(subcommand)]
        action: IntelAction,
    },
    /// Run an untrusted program in an isolated sandbox and assess its behavior
    Sandbox {
        #[command(subcommand)]
        action: SandboxAction,
    },
}

#[derive(Subcommand)]
enum SandboxAction {
    /// Execute a command in a network-isolated sandbox and capture behavior
    Run(SandboxRunArgs),
    /// Manage the Linux VM used by --engine vm
    Vm {
        #[command(subcommand)]
        action: VmAction,
    },
    /// Download into a quarantine directory and inspect statically (no execution)
    Fetch(SandboxFetchArgs),
    /// Check sandbox dependencies and kernel capabilities
    Doctor,
}

#[derive(Copy, Clone, PartialEq, Eq, ValueEnum)]
enum TraceArg {
    Auto,
    Off,
}

impl From<TraceArg> for sandbox::TraceMode {
    fn from(v: TraceArg) -> Self {
        match v {
            TraceArg::Auto => sandbox::TraceMode::Auto,
            TraceArg::Off => sandbox::TraceMode::Off,
        }
    }
}

#[derive(Copy, Clone, PartialEq, Eq, ValueEnum)]
enum EngineArg {
    Auto,
    Local,
    Vm,
}

impl From<EngineArg> for sandbox::Engine {
    fn from(v: EngineArg) -> Self {
        match v {
            EngineArg::Auto => sandbox::Engine::Auto,
            EngineArg::Local => sandbox::Engine::Local,
            EngineArg::Vm => sandbox::Engine::Vm,
        }
    }
}

#[derive(Subcommand)]
enum VmAction {
    /// Create/start a Lima VM for dynamic analysis
    Up {
        #[arg(long, value_name = "NAME", default_value = "warden-sandbox")]
        name: String,
        #[arg(long, value_name = "IMAGE", default_value = "template://default")]
        image: String,
    },
    /// List Lima instances
    Status,
    /// Stop the Lima VM
    Down {
        #[arg(long, value_name = "NAME", default_value = "warden-sandbox")]
        name: String,
    },
    /// Download and verify the Linux guest binary into the cache
    FetchGuest {
        #[arg(long, value_name = "URL")]
        url: String,
        /// SHA-256; falls back to <url>.sha256
        #[arg(long, value_name = "HEX")]
        sha256: Option<String>,
    },
}

#[derive(Args)]
struct SandboxRunArgs {
    /// Host work directory bound to /work in the sandbox (place samples/packages here)
    #[arg(long, value_name = "DIR")]
    workdir: Option<PathBuf>,

    /// Timeout in seconds; the sandbox is killed afterwards
    #[arg(long, value_name = "SECS", default_value_t = 30)]
    timeout: u64,

    /// Per-file size limit for hashing and IOC matching
    #[arg(long, value_name = "SIZE", value_parser = util::parse_size, default_value = "64M")]
    max_file_size: u64,

    /// IOC feed; matched against files dropped in the sandbox
    #[arg(long, value_name = "FILE|DIR")]
    ioc: Option<PathBuf>,

    /// YARA rule file or directory; matched against dropped artifacts
    #[arg(long, value_name = "DIR|FILE")]
    yara: Vec<PathBuf>,

    /// Scan dropped artifacts with the local ClamAV database
    #[arg(long)]
    clamav: bool,

    /// ClamAV database directory (passed as -d)
    #[arg(long, value_name = "DIR")]
    clamav_db: Option<PathBuf>,

    /// Memory limit for the sandbox; 0 disables (requires systemd user scope)
    #[arg(long, value_name = "SIZE", value_parser = util::parse_size, default_value = "2G")]
    mem: u64,

    /// CPU quota in cores; 0 disables (e.g. 0.5, 2, 4)
    #[arg(long, value_name = "CORES", default_value_t = 2.0)]
    cpus: f64,

    /// Maximum tasks/processes; 0 disables
    #[arg(long, value_name = "N", default_value_t = 256)]
    pids: u64,

    /// Backend: auto (Linux=local, macOS=VM), local, or vm
    #[arg(long, value_enum, default_value_t = EngineArg::Auto)]
    engine: EngineArg,

    /// Lima instance name for --engine vm
    #[arg(long, value_name = "NAME", default_value = "warden-sandbox")]
    vm_name: String,

    /// Linux build of warden to copy into the VM (takes precedence over download)
    #[arg(long, value_name = "FILE")]
    vm_guest_binary: Option<PathBuf>,

    /// URL of a Linux warden binary to download and verify (or WARDEN_GUEST_URL)
    #[arg(long, value_name = "URL")]
    vm_guest_url: Option<String>,

    /// SHA-256 of the guest binary; falls back to <url>.sha256 or WARDEN_GUEST_SHA256
    #[arg(long, value_name = "HEX")]
    vm_guest_sha256: Option<String>,

    /// Syscall tracing: auto (use strace when available) or off
    #[arg(long, value_enum, default_value_t = TraceArg::Auto)]
    trace: TraceArg,

    /// Keep the sandbox directory (including the /etc copy and dropped files) for forensics
    #[arg(long)]
    keep: bool,

    /// Print the underlying bubblewrap command without executing it
    #[arg(long)]
    print_command: bool,

    #[arg(long, value_enum, default_value_t = FormatArg::Text)]
    format: FormatArg,

    /// Command to execute (must follow --)
    #[arg(last = true, required = true, value_name = "CMD")]
    cmd: Vec<String>,
}

#[derive(Args)]
struct SandboxFetchArgs {
    /// Download URL (http/https)
    url: String,

    /// Quarantine directory
    #[arg(long, value_name = "DIR", default_value = "warden-quarantine")]
    output: PathBuf,

    /// Per-file size limit
    #[arg(long, value_name = "SIZE", value_parser = util::parse_size, default_value = "100M")]
    max_size: u64,

    /// Download timeout in seconds
    #[arg(long, value_name = "SECS", default_value_t = 60)]
    timeout: u64,

    /// IOC feed; the URL and downloaded content are matched against it
    #[arg(long, value_name = "FILE|DIR")]
    ioc: Option<PathBuf>,

    /// YARA rule file or directory; matched against the downloaded file
    #[arg(long, value_name = "DIR|FILE")]
    yara: Vec<PathBuf>,

    /// Scan the downloaded file with the local ClamAV database
    #[arg(long)]
    clamav: bool,

    /// ClamAV database directory (passed as -d)
    #[arg(long, value_name = "DIR")]
    clamav_db: Option<PathBuf>,

    #[arg(long, value_enum, default_value_t = FormatArg::Text)]
    format: FormatArg,
}

#[derive(Copy, Clone, PartialEq, Eq, ValueEnum)]
enum FormatArg {
    Text,
    Json,
    Sarif,
}

impl std::fmt::Display for FormatArg {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            FormatArg::Text => "text",
            FormatArg::Json => "json",
            FormatArg::Sarif => "sarif",
        })
    }
}

impl From<FormatArg> for Format {
    fn from(v: FormatArg) -> Self {
        match v {
            FormatArg::Text => Format::Text,
            FormatArg::Json => Format::Json,
            FormatArg::Sarif => Format::Sarif,
        }
    }
}

#[derive(Args)]
struct ScanArgs {
    /// Filesystem root; point it at a mounted image for offline scans (e.g. /mnt/image)
    #[arg(long, value_name = "DIR", default_value = "/")]
    root: PathBuf,

    /// Extra scan roots for IOC matching; repeatable
    #[arg(long = "path", value_name = "DIR")]
    paths: Vec<PathBuf>,

    /// Web roots for the webshell check; repeatable
    #[arg(long = "webroot", value_name = "DIR")]
    webroots: Vec<PathBuf>,

    /// IOC feed (CSV or plain): SHA-256/SHA-1/MD5 hashes, URLs, domains, IPs
    #[arg(long, value_name = "FILE|DIR")]
    ioc: Option<PathBuf>,

    /// YARA rule file or directory (repeatable); no rules are bundled
    #[arg(long, value_name = "DIR|FILE")]
    yara: Vec<PathBuf>,

    /// Enable the optional ClamAV backend (requires clamscan)
    #[arg(long)]
    clamav: bool,

    /// Directory with ossf/malicious-packages OSV records (or ~/.config/warden/malicious)
    #[arg(long, value_name = "DIR")]
    malicious: Option<PathBuf>,

    /// Disable ClamAV even if it is installed or enabled by policy/defaults
    #[arg(long)]
    no_clamav: bool,

    /// Query OSV for known vulnerabilities in installed packages (network + privacy)
    #[arg(long)]
    osv: bool,

    /// Disable OSV even if a policy enables it
    #[arg(long)]
    no_osv: bool,

    /// OSV API base URL
    #[arg(long, value_name = "URL")]
    osv_url: Option<String>,

    /// OSV response cache age in hours (0 disables reads)
    #[arg(long, value_name = "HOURS")]
    osv_max_age_hours: Option<u64>,

    /// Warn when the ClamAV database is older than this many days (0 disables)
    #[arg(long, value_name = "DAYS")]
    clamav_max_db_age: Option<i64>,

    /// Verify package-managed files with dpkg/rpm/pacman (slow, opt-in)
    #[arg(long)]
    verify_packages: bool,

    /// Disable package verification even if a policy enables it
    #[arg(long)]
    no_verify_packages: bool,

    /// ClamAV database directory (passed as -d)
    #[arg(long, value_name = "DIR")]
    clamav_db: Option<PathBuf>,

    #[arg(long, value_enum, default_value_t = FormatArg::Text)]
    format: FormatArg,

    /// Write the report to a file (a summary is printed to the terminal)
    #[arg(long, value_name = "FILE")]
    output: Option<PathBuf>,

    /// Only show findings at or above this severity (default: low / policy)
    #[arg(long, value_name = "LEVEL", value_parser = parse_severity)]
    min_severity: Option<Severity>,

    /// Exit 1 when a finding reaches this severity; never always exits 0
    #[arg(long, value_enum, value_name = "LEVEL")]
    fail_on: Option<FailOn>,

    /// Run only these checks (prefixes such as persist or persist.cron are accepted)
    #[arg(long, value_delimiter = ',', value_name = "ID")]
    checks: Vec<String>,

    /// Exclude these checks (prefixes accepted)
    #[arg(long, value_delimiter = ',', value_name = "ID")]
    exclude: Vec<String>,

    /// Baseline file: report entries that appeared or disappeared
    #[arg(long, value_name = "FILE")]
    baseline: Option<PathBuf>,

    /// Save this scan's persistence inventory as the baseline
    #[arg(long, value_name = "FILE")]
    save_baseline: Option<PathBuf>,

    /// Allowlist TOML (default ~/.config/warden/allowlist.toml)
    #[arg(long, value_name = "FILE")]
    allowlist: Option<PathBuf>,

    /// Policy defaults (TOML); auto-discovers ~/.config/warden/policy.toml or /etc/warden/policy.toml
    #[arg(long, value_name = "FILE")]
    policy: Option<PathBuf>,

    /// Per-file size limit for hashing and IOC matching (default: 64M / policy)
    #[arg(long, value_name = "SIZE", value_parser = util::parse_size)]
    max_file_size: Option<u64>,

    /// Also scan the current user's home when using --root on an image
    #[arg(long, hide = true)]
    user_scope: bool,

    #[arg(long)]
    no_color: bool,

    /// Show details for skipped and failed checks
    #[arg(long)]
    verbose: bool,

    /// Print only the summary
    #[arg(long)]
    quiet: bool,

    /// Interactive terminal UI (TTY only; requires text output)
    #[arg(long)]
    tui: bool,
}

fn parse_policy_fail_on(s: &str) -> anyhow::Result<Option<Severity>> {
    if s.eq_ignore_ascii_case("never") || s.eq_ignore_ascii_case("none") {
        Ok(None)
    } else {
        Severity::parse(s)
            .map(Some)
            .ok_or_else(|| anyhow::anyhow!("invalid fail_on in policy: {s}"))
    }
}

fn build_config(args: ScanArgs, policy: Option<policy::Policy>) -> anyhow::Result<Config> {
    let p = policy.unwrap_or_default();

    let min_severity = if let Some(v) = args.min_severity {
        v
    } else if let Some(s) = p.min_severity.as_deref() {
        Severity::parse(s).ok_or_else(|| anyhow::anyhow!("invalid min_severity in policy: {s}"))?
    } else {
        Severity::Low
    };

    let fail_on = if let Some(f) = args.fail_on {
        f.into()
    } else if let Some(s) = p.fail_on.as_deref() {
        parse_policy_fail_on(s)?
    } else {
        Some(Severity::High)
    };

    let webroots = if !args.webroots.is_empty() {
        args.webroots
    } else if let Some(v) = p.webroots {
        v
    } else {
        defaults::detect_webroots(&args.root)
    };

    let yara = if !args.yara.is_empty() {
        args.yara
    } else if let Some(v) = p.yara {
        v
    } else {
        defaults::detect_yara_dirs()
    };

    let clamav = if args.no_clamav {
        false
    } else if args.clamav {
        true
    } else if let Some(v) = p.clamav {
        v
    } else {
        clamav::auto_available()
    };

    let verify_packages = if args.no_verify_packages {
        false
    } else if args.verify_packages {
        true
    } else {
        p.verify_packages.unwrap_or(false)
    };

    let malicious = args
        .malicious
        .or(p.malicious)
        .or_else(malicious::default_dir);

    let osv = if args.no_osv {
        false
    } else if args.osv {
        true
    } else {
        p.osv.unwrap_or(false)
    };

    let osv_url = args
        .osv_url
        .or(p.osv_url)
        .unwrap_or_else(|| "https://api.osv.dev".into());
    let osv_max_age_hours = args.osv_max_age_hours.or(p.osv_max_age_hours).unwrap_or(24);

    let max_file_size = if let Some(v) = args.max_file_size {
        v
    } else if let Some(s) = p.max_file_size.as_deref() {
        util::parse_size(s).map_err(|e| anyhow::anyhow!("invalid max_file_size in policy: {e}"))?
    } else {
        64 * util::MB
    };

    Ok(Config {
        root: args.root,
        paths: if args.paths.is_empty() {
            p.paths.unwrap_or_default()
        } else {
            args.paths
        },
        webroots,
        ioc: args.ioc.or(p.ioc).or_else(intel::default_source),
        yara,
        clamav,
        malicious,
        osv,
        osv_url,
        osv_max_age_hours,
        clamav_max_db_age_days: args
            .clamav_max_db_age
            .or(p.clamav_max_db_age_days)
            .unwrap_or(7),
        verify_packages,
        clamav_db: args.clamav_db.or(p.clamav_db),
        format: args.format.into(),
        output: args.output,
        min_severity,
        fail_on,
        only: if args.checks.is_empty() {
            p.checks.unwrap_or_default()
        } else {
            args.checks
        },
        exclude: if args.exclude.is_empty() {
            p.exclude.unwrap_or_default()
        } else {
            args.exclude
        },
        baseline: args.baseline,
        save_baseline: args.save_baseline,
        allowlist: args.allowlist.or(p.allowlist),
        max_file_size,
        user_scope: if args.user_scope { Some(true) } else { None },
        color: !args.no_color,
        verbose: args.verbose,
        quiet: args.quiet,
    })
}

#[derive(Subcommand)]
enum IntelAction {
    /// Download a feed into the intel directory (atomic, size/time limited)
    Fetch {
        #[arg(value_name = "URL")]
        url: String,
        /// Stored file name (defaults to the URL's last path segment)
        #[arg(long, value_name = "NAME")]
        name: Option<String>,
        /// Extra curl header; `$VAR` / `${VAR}` are expanded from the environment
        #[arg(long = "header", value_name = "K: V")]
        headers: Vec<String>,
        /// Verify the downloaded feed against this SHA-256
        #[arg(long, value_name = "HEX")]
        sha256: Option<String>,
        #[arg(long, value_name = "DIR")]
        dir: Option<PathBuf>,
        #[arg(long, value_name = "SIZE", value_parser = util::parse_size, default_value = "512M")]
        max_size: u64,
        #[arg(long, value_name = "SECS", default_value_t = 300)]
        timeout: u64,
    },
    /// List stored feeds and IOC counts (also used automatically by scan)
    Show {
        #[arg(long, value_name = "DIR")]
        dir: Option<PathBuf>,
        #[arg(long, value_enum, default_value_t = FormatArg::Text)]
        format: FormatArg,
    },
}

#[derive(Subcommand)]
enum ConfigAction {
    /// Print effective built-in defaults and auto-detected paths
    Show {
        #[arg(long, value_enum, default_value_t = FormatArg::Text)]
        format: FormatArg,
    },
    /// Write a commented policy template
    Init {
        #[arg(long, value_name = "FILE")]
        output: Option<PathBuf>,
        #[arg(long)]
        force: bool,
    },
}

#[derive(Subcommand)]
enum BaselineAction {
    /// Save the current persistence inventory as the baseline
    Save {
        #[arg(long, value_name = "FILE", default_value = "warden-baseline.json")]
        file: PathBuf,
        #[arg(long, value_name = "DIR", default_value = "/")]
        root: PathBuf,
        #[arg(long, hide = true)]
        user_scope: bool,
    },
    /// Show a baseline summary
    Show {
        #[arg(value_name = "FILE")]
        file: PathBuf,
        /// List every entry
        #[arg(long)]
        verbose: bool,
    },
}

fn parse_severity(s: &str) -> Result<Severity, String> {
    Severity::parse(s)
        .ok_or_else(|| format!("unknown severity: {s} (use info/low/medium/high/critical)"))
}

#[derive(Copy, Clone, PartialEq, Eq, ValueEnum)]
enum FailOn {
    Info,
    Low,
    Medium,
    High,
    Critical,
    Never,
}

impl From<FailOn> for Option<Severity> {
    fn from(v: FailOn) -> Self {
        match v {
            FailOn::Never => None,
            FailOn::Info => Some(Severity::Info),
            FailOn::Low => Some(Severity::Low),
            FailOn::Medium => Some(Severity::Medium),
            FailOn::High => Some(Severity::High),
            FailOn::Critical => Some(Severity::Critical),
        }
    }
}

fn main() {
    // Behave like a normal Unix filter when piped into `head`/`less`.
    #[cfg(unix)]
    unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_DFL);
    }
    let cli = Cli::parse();
    let code = match dispatch(cli) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("warden: {e:#}");
            2
        }
    };
    std::process::exit(code);
}

fn dispatch(cli: Cli) -> anyhow::Result<i32> {
    match cli.cmd {
        None => {
            use clap::CommandFactory;
            Cli::command().print_help()?;
            println!();
            Ok(0)
        }
        Some(Cmd::Scan(args)) => run_scan(args),
        Some(Cmd::Baseline { action }) => run_baseline(action),
        Some(Cmd::Checks { format }) => {
            let list: Vec<_> = checks::registry()
                .iter()
                .map(|c| {
                    serde_json::json!({
                        "id": c.id(),
                        "title": c.title(),
                        "platforms": c.platforms().iter().map(|p| p.as_str()).collect::<Vec<_>>(),
                    })
                })
                .collect();
            if matches!(format, FormatArg::Json) {
                println!("{}", serde_json::to_string_pretty(&list)?);
            } else {
                println!("{:<22} {:<10} Description", "ID", "Platforms");
                for c in checks::registry() {
                    let platforms: Vec<&str> = c.platforms().iter().map(|p| p.as_str()).collect();
                    println!("{:<22} {:<10} {}", c.id(), platforms.join(","), c.title());
                }
            }
            Ok(0)
        }
        Some(Cmd::Selftest) => {
            let ok = selftest::run()?;
            Ok(if ok { 0 } else { 1 })
        }
        Some(Cmd::Config { action }) => {
            match action {
                ConfigAction::Show { format } => show_defaults(format)?,
                ConfigAction::Init { output, force } => init_policy(output, force)?,
            }
            Ok(0)
        }
        Some(Cmd::Intel { action }) => {
            match action {
                IntelAction::Fetch {
                    url,
                    name,
                    headers,
                    sha256,
                    dir,
                    max_size,
                    timeout,
                } => {
                    let path = intel::fetch_feed(&intel::FetchRequest {
                        url,
                        name,
                        headers,
                        dir: dir.unwrap_or_else(intel::default_dir),
                        max_size,
                        timeout: std::time::Duration::from_secs(timeout.max(1)),
                        sha256,
                        curl: None,
                    })?;
                    println!("feed stored at {}", path.display());
                }
                IntelAction::Show { dir, format } => show_intel(dir, format)?,
            }
            Ok(0)
        }
        Some(Cmd::Sandbox { action }) => match action {
            SandboxAction::Doctor => {
                print!("{}", sandbox::doctor());
                Ok(0)
            }
            SandboxAction::Run(args) => {
                let engine = args.engine.into();
                let vm = sandbox::VmOptions {
                    name: args.vm_name.clone(),
                    guest_binary: args.vm_guest_binary.clone(),
                    guest_url: args
                        .vm_guest_url
                        .clone()
                        .or_else(|| std::env::var("WARDEN_GUEST_URL").ok()),
                    guest_sha256: args
                        .vm_guest_sha256
                        .clone()
                        .or_else(|| std::env::var("WARDEN_GUEST_SHA256").ok()),
                    ..Default::default()
                };
                let cfg = sandbox::RunConfig {
                    cmd: args.cmd,
                    workdir: args.workdir,
                    timeout: std::time::Duration::from_secs(args.timeout.max(1)),
                    max_file_size: args.max_file_size,
                    ioc: args.ioc,
                    yara: args.yara,
                    clamav: args.clamav,
                    clamav_db: args.clamav_db,
                    limits: sandbox::bwrap::CgroupLimits {
                        mem_bytes: (args.mem > 0).then_some(args.mem),
                        cpus: (args.cpus.is_finite() && args.cpus > 0.0).then_some(args.cpus),
                        pids: (args.pids > 0).then_some(args.pids),
                    },
                    trace: args.trace.into(),
                    keep: args.keep,
                    print_command: args.print_command,
                };
                if cfg.print_command {
                    sandbox::print_command(&cfg, engine, &vm)?;
                    return Ok(0);
                }
                let report = sandbox::dispatch(&cfg, engine, &vm)?;
                print!("{}", report.render(args.format.into()));
                Ok(sandbox::exit_code(&report))
            }
            SandboxAction::Vm { action } => {
                match action {
                    VmAction::Up { name, image } => {
                        sandbox::vm::up(&sandbox::VmOptions {
                            name,
                            image,
                            ..Default::default()
                        })?;
                    }
                    VmAction::Status => {
                        sandbox::vm::status(&sandbox::VmOptions::default())?;
                    }
                    VmAction::Down { name } => {
                        sandbox::vm::down(&sandbox::VmOptions {
                            name,
                            ..Default::default()
                        })?;
                    }
                    VmAction::FetchGuest { url, sha256 } => {
                        let path = sandbox::vm::fetch_guest(&sandbox::VmOptions {
                            guest_url: Some(url),
                            guest_sha256: sha256,
                            ..Default::default()
                        })?;
                        println!("guest binary cached at {}", path.display());
                    }
                }
                Ok(0)
            }
            SandboxAction::Fetch(args) => {
                let cfg = sandbox::fetch::FetchConfig {
                    url: args.url,
                    output: args.output,
                    max_size: args.max_size,
                    timeout: std::time::Duration::from_secs(args.timeout.max(1)),
                    ioc: args.ioc,
                    yara: args.yara,
                    clamav: args.clamav,
                    clamav_db: args.clamav_db,
                };
                let report = sandbox::fetch::run(cfg)?;
                print!("{}", report.render(args.format.into()));
                Ok(sandbox::fetch::exit_code(&report))
            }
        },
    }
}

fn human_size(n: u64) -> String {
    if n >= 1024 * 1024 * 1024 {
        format!("{:.1} GiB", n as f64 / (1024.0 * 1024.0 * 1024.0))
    } else if n >= 1024 * 1024 {
        format!("{:.1} MiB", n as f64 / (1024.0 * 1024.0))
    } else if n >= 1024 {
        format!("{:.1} KiB", n as f64 / 1024.0)
    } else {
        format!("{n} B")
    }
}

fn show_intel(dir: Option<PathBuf>, format: FormatArg) -> anyhow::Result<()> {
    let dir = dir.unwrap_or_else(intel::default_dir);
    let files = intel::feed_files(&dir);
    let loaded = if dir.is_dir() {
        intel::Intel::load(std::slice::from_ref(&dir)).unwrap_or_default()
    } else {
        intel::Intel::default()
    };

    if matches!(format, FormatArg::Json) {
        let doc = serde_json::json!({
            "dir": dir.display().to_string(),
            "counts": {
                "sha256": loaded.sha256.len(),
                "sha1": loaded.sha1.len(),
                "md5": loaded.md5.len(),
                "url": loaded.urls.len(),
                "domain": loaded.domains.len(),
                "ip": loaded.ips.len(),
            },
            "files": files.iter().map(|(p, size)| serde_json::json!({
                "path": p.display().to_string(),
                "size": size,
            })).collect::<Vec<_>>(),
        });
        println!("{}", serde_json::to_string_pretty(&doc)?);
        return Ok(());
    }

    println!("intel directory: {}", dir.display());
    println!("{}", loaded.counts());
    if files.is_empty() {
        println!("no feeds stored yet; use `warden intel fetch <url>`");
    } else {
        for (path, size) in files {
            println!(
                "  {:<40} {}",
                path.file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_default(),
                human_size(size)
            );
        }
    }
    Ok(())
}

fn show_defaults(format: FormatArg) -> anyhow::Result<()> {
    let webroots = defaults::detect_webroots(std::path::Path::new("/"));
    let yara = defaults::detect_yara_dirs();
    let clamav = clamav::auto_available();
    let policy = policy::discover();
    let intel_dir = intel::default_source();
    let home_allow = util::home_dir().join(".config/warden/allowlist.toml");
    let system_allow = PathBuf::from("/etc/warden/allowlist.toml");
    let allowlist = [home_allow, system_allow].into_iter().find(|p| p.is_file());

    let text_paths = |paths: &[PathBuf]| -> Vec<String> {
        paths.iter().map(|p| p.display().to_string()).collect()
    };

    if matches!(format, FormatArg::Json) {
        let doc = serde_json::json!({
            "min_severity": "low",
            "fail_on": "high",
            "max_file_size": "64M",
            "checks": "all",
            "verify_packages": false,
            "clamav": clamav,
            "webroots": text_paths(&webroots),
            "yara": text_paths(&yara),
            "policy_file": policy.map(|p| p.display().to_string()),
            "allowlist": allowlist.map(|p| p.display().to_string()),
            "intel": intel_dir.as_ref().map(|p| p.display().to_string()),
        });
        println!("{}", serde_json::to_string_pretty(&doc)?);
        return Ok(());
    }

    println!("Built-in defaults (no policy file required):\n");
    println!("min_severity      low");
    println!("fail_on           high");
    println!("max_file_size     64M");
    println!("checks            all applicable");
    println!("verify_packages   false (opt-in with --verify-packages)");
    println!("osv               false (opt-in with --osv; sends package names to osv.dev)");
    println!(
        "malicious pkgs    {}",
        malicious::default_dir()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|| "none (clone ossf/malicious-packages)".into())
    );
    println!(
        "clamav            {}",
        if clamav {
            "enabled (clamscan + database found)"
        } else {
            "disabled (clamscan or database missing)"
        }
    );
    println!(
        "webroots          {}",
        if webroots.is_empty() {
            "none detected".to_string()
        } else {
            text_paths(&webroots).join(", ")
        }
    );
    println!(
        "yara              {}",
        if yara.is_empty() {
            "no rule directories found".to_string()
        } else {
            text_paths(&yara).join(", ")
        }
    );
    println!(
        "policy file       {}",
        policy
            .map(|p| p.display().to_string())
            .unwrap_or_else(|| "none (built-in defaults)".into())
    );
    println!(
        "allowlist         {}",
        allowlist
            .map(|p| p.display().to_string())
            .unwrap_or_else(|| "none".into())
    );
    println!(
        "intel (auto)      {}",
        intel_dir
            .map(|p| p.display().to_string())
            .unwrap_or_else(|| "none (use `warden intel fetch <url>`)".into())
    );
    println!("\nOverride only what you need: `warden config init` writes a commented template.");
    Ok(())
}

fn init_policy(output: Option<PathBuf>, force: bool) -> anyhow::Result<()> {
    let path =
        output.unwrap_or_else(|| util::home_dir().join(".config/warden").join("policy.toml"));
    if path.exists() && !force {
        anyhow::bail!(
            "{} already exists; pass --force to overwrite",
            path.display()
        );
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&path, policy::TEMPLATE)?;
    println!("policy template written to {}", path.display());
    Ok(())
}

fn run_scan(args: ScanArgs) -> anyhow::Result<i32> {
    let tui = args.tui;
    let cli_format = args.format;
    let policy_path = args.policy.clone().or_else(policy::discover);
    let policy = match &policy_path {
        Some(path) => Some(policy::Policy::load(path)?),
        None => None,
    };
    let cfg = build_config(args, policy)?;

    if tui {
        if cfg.output.is_some() {
            anyhow::bail!("--tui cannot be combined with --output");
        }
        if !matches!(cli_format, FormatArg::Text) {
            anyhow::bail!("--tui only supports text output");
        }
        tui::run(cfg)?;
        return Ok(0);
    }
    let fail_on = cfg.fail_on;
    let format = cfg.format;
    let output_path = cfg.output.clone();
    let color =
        cfg.color && std::io::stdout().is_terminal() && std::env::var_os("NO_COLOR").is_none();
    let verbose = cfg.verbose;
    let quiet = cfg.quiet;

    let report = engine::run(cfg)?;
    let rendered = report.render(format, color, verbose, quiet);

    match output_path {
        Some(path) => {
            std::fs::write(&path, &rendered)?;
            println!(
                "report written to {} ({} findings, {} ms)",
                path.display(),
                report.findings.len(),
                report.duration_ms
            );
        }
        None => print!("{rendered}"),
    }
    Ok(engine::exit_code(&report, fail_on))
}

fn run_baseline(action: BaselineAction) -> anyhow::Result<i32> {
    match action {
        BaselineAction::Save {
            file,
            root,
            user_scope,
        } => {
            let cfg = Config {
                root,
                user_scope: if user_scope { Some(true) } else { None },
                ..Config::default()
            };
            let snapshot = engine::snapshot_only(&cfg);
            snapshot.save(&file)?;
            println!(
                "baseline saved to {} ({} items, created {})",
                file.display(),
                snapshot.items.len(),
                snapshot.created_at
            );
        }
        BaselineAction::Show { file, verbose } => {
            let b = baseline::Baseline::load(&file)?;
            println!(
                "{} · host={} · created={} · items={}",
                file.display(),
                b.host,
                b.created_at,
                b.items.len()
            );
            if verbose {
                for it in &b.items {
                    println!("  [{}] {} — {}", it.kind, it.path, it.detail);
                }
            } else {
                let mut counts: std::collections::BTreeMap<&str, usize> = Default::default();
                for it in &b.items {
                    *counts.entry(it.kind.as_str()).or_default() += 1;
                }
                for (k, v) in counts {
                    println!("  {k}: {v}");
                }
            }
        }
    }
    Ok(0)
}
