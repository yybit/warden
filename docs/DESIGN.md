# Warden Design

> Version 0.18 · Linux / macOS · Rust

## 1. Positioning

Warden is a **host integrity scanner** focused on the persistence, privilege, and configuration surface that trojans and backdoors actually use on Unix hosts. It also ships a **Linux sandbox** that executes an untrusted installer or binary offline and scores what it does.

Goals:

1. Cover the landing spots attackers actually use, not thousands of generic hardening tips.
2. Every finding carries verifiable evidence (path, line, command, hash).
3. Machine-consumable results (JSON / SARIF) suitable for CI and incident response.
4. Zero side effects by default: read-only, offline, no automatic response.

Non-goals:

- Real-time protection, EDR semantics, or memory forensics.
- Virus-family classification based on a proprietary signature cloud.
- Automatic deletion, quarantine, or "fixing" — a false positive costs more than a missed low-severity finding.
- A hardened anti-escape boundary for kernel exploits (see sandbox limitations).

In one sentence: **it does not answer "which family is this", it answers "what is sitting in this host's boot/login/loader chain that should not be there, and what did this installer actually change".**

## 2. Threat model

After gaining code execution, an attacker must solve "still here after reboot" and "keep privilege". On Unix the solutions converge:

| ATT&CK | Technique | Warden check |
|---|---|---|
| T1053.003 | Cron | `persist.cron` |
| T1543.002 | systemd service | `persist.systemd` |
| T1543.001 | launchd agent/daemon | `persist.launchd` |
| T1546.004 | Shell startup files | `persist.shell_rc` |
| T1574.006 | Dynamic linker hijack (`ld.so.preload`, `LD_PRELOAD`) | `persist.loader` |
| T1547.006 | Kernel module / modprobe hooks | `persist.loader` |
| T1098.004 | SSH authorized_keys | `persist.ssh` |
| T1556.003 | PAM / sshd authentication tampering | `persist.ssh` |
| T1548.001/003 | SUID, passwordless sudo | `fs.suid`, `host.accounts` |
| T1574.007 | PATH hijack | `fs.world_writable`, `persist.shell_rc` |
| T1036.005 | Masquerading (document → executable) | `fs.suspicious_bin` |
| T1505.003 | Web shell | `fs.webshell` |
| T1136 / T1078 | Account creation, empty passwords | `host.accounts` |
| T1571 | Non-standard listening port | `host.listeners` |

Assumptions:

- The attacker has a non-root user, or root without a kernel-level rootkit.
- The attacker reuses system mechanisms (cron/systemd/launchd) rather than writing a daemon.
- Memory-only/fileless attacks and kernel hiding (DKOM/LKM/eBPF rootkits) are out of scope; use memory forensics and a measured boot chain (Secure Boot / SIP) for those.

## 3. Architecture

```
┌──────────────────────────────────────────────────────────────┐
│ CLI (clap)                                                   │
│  scan · baseline save/show · checks · selftest · sandbox     │
└───────────────┬──────────────────────────────────────────────┘
                │ Config
                ▼
┌──────────────────────────────────────────────────────────────┐
│ ScanContext                                                   │
│  --root relocation · OS detection · privilege · user scope   │
└───────────────┬──────────────────────────────────────────────┘
                │
                ▼
┌──────────────────────────────────────────────────────────────┐
│ Engine                                                        │
│  select checks → run → baseline diff → threshold → allowlist │
│  coverage accounting (ran/skipped/failed)                     │
└──────┬───────────────────────────────┬───────────────────────┘
       │                               │
       ▼                               ▼
┌──────────────────┐          ┌───────────────────────────────┐
│ Checks (24)      │          │ Fact collectors               │
│  persist.*       │◄─────────│  cron/systemd/launchd/ssh     │
│  fs.*            │          │  SUID inventory / listeners   │
│  host.*          │          │  accounts  → also for baseline│
└──────┬───────────┘          └───────────────────────────────┘
       │ Finding
       ▼
┌──────────────────────────────────────────────────────────────┐
│ Output: text / JSON / SARIF 2.1.0                             │
└──────────────────────────────────────────────────────────────┘

Sandbox (separate path):
bwrap (namespaces) → timestamped run → FS snapshot diff
                    → optional strace parse → findings + score
```

### 3.1 Modules

| File | Responsibility |
|---|---|
| `src/main.rs` | CLI definition, argument parsing, exit codes |
| `src/lib.rs` | Public library surface shared by the CLI, TUI, sandbox, and GUI |
| `src/tui.rs` | Interactive terminal UI (`scan --tui`) |
| `apps/warden-gui/` | egui/eframe desktop app for macOS and Linux |
| `src/ctx.rs` | `--root` path mapping, OS detection, privilege/user-scope flags |
| `src/engine.rs` | Orchestration, check selection, baseline drift, thresholds, allowlist |
| `src/checks/mod.rs` | `Check` trait, registry, signal merging, stable sorting |
| `src/checks/persistence.rs` | cron / systemd / shell rc / loader |
| `src/checks/pam.rs` | PAM module integrity |
| `src/checks/udev.rs` | udev rule execution |
| `src/checks/at.rs` | at jobs |
| `src/checks/packages.rs` | dpkg/rpm/pacman file verification |
| `src/checks/containers.rs` | Docker/containerd/CRI-O/Podman/k3s/kubelet configuration |
| `src/osv.rs` | Package enumeration, OSV query/cache |
| `src/checks/osv.rs` | OSV finding mapping |
| `src/malicious.rs` | malicious-package dataset parsing and installed-package enumeration |
| `src/checks/malicious.rs` | malicious-package findings |
| `src/checks/ssh.rs` | authorized_keys / sshd_config / host keys |
| `src/checks/mac.rs` | launchd plist parsing and judgement |
| `src/checks/files.rs` | SUID/capabilities, writable paths, masquerading, webshells, IOC |
| `src/checks/host.rs` | accounts, sudoers, listeners, hardening |
| `src/checks/targets.rs` | Shared high-value scan targets for content scanners |
| `src/checks/yara.rs` | YARA finding mapping |
| `src/intel.rs` | IOC/feed parsing and hash/URL/domain/IP matching |
| `src/signatures.rs` | YARA-X rule loading, scanning, metadata mapping |
| `src/checks/clamav.rs` | Optional ClamAV check |
| `src/clamav.rs` | `clamscan` process integration and output parsing |
| `src/heuristics.rs` | Command/path risk signals (single source of truth) |
| `src/model.rs` | Severity / Confidence / Finding / Report |
| `src/baseline.rs` | Snapshot serialization and set diff |
| `src/allowlist.rs` | TOML rules and glob matching |
| `src/output.rs` | text / JSON / SARIF |
| `src/selftest.rs` | End-to-end assertions with built-in fixtures |
| `src/sandbox/` | bwrap isolation, FS capture, trace parsing, quarantine fetch |

### 3.2 Layering

1. **Fact layer** (`*_entries`, `collect_*`) parses system state into structures and makes no judgement.
2. **Judgement layer** (`*Check`) consumes facts and emits `Finding`s.
3. The same facts feed **baseline snapshots** and **checks**, so the two can never disagree.

Adding a persistence mechanism is one parser plus one check. Adding a detection idea is one signal in `heuristics`.

## 4. Static detection design

### 4.1 Three tiers

| Tier | Confidence | Example | Handling |
|---|---|---|---|
| Structured fact | Certain | non-empty `ld.so.preload`, duplicate UID 0, SUID bit, non-root unit file | Direct finding |
| Behavioral heuristic | Heuristic | `curl … \| bash`, `nc -e`, `base64 -d \| sh` | Reported as heuristic, highest matched severity |
| Content signature | Certain | IOC SHA-256, webshell patterns | Reported on match |

One line often matches several patterns. `combined_finding` merges them into one finding and lists all signals, which keeps output readable.

### 4.2 Key rules and why

**`persist.loader`: any content in `/etc/ld.so.preload` is Critical.** Healthy systems do not use it; anything there forces every dynamically linked process to load a library. It is the classic rootkit hook.

**`persist.cron`: permissions matter as much as content.** A cron file writable by group/other is High without reading a single line — write access is arbitrary scheduled code.

**`persist.systemd`: distinguish system and user units.** User units starting from `~/.config/systemd/user` are normal; a system unit whose `ExecStart` points at `/home` or `/tmp` is not.

**modprobe `install` hooks: only flag interpreters, writable paths, or behavioral matches.** Distributions preload modules with ordinary tools (`install libnvdimm /usr/bin/ndctl …`). "Not modprobe ⇒ alert" produces a permanent false positive.

**`fs.suid`: noise reduction without silence.** Known SUID programs (sudo/su/passwd/qemu-bridge-helper/utempter/…) in standard directories are skipped; the same names in `/usr/local`, `/opt`, or `/home` are Medium.

**`fs.suspicious_bin`: magic bytes, never extensions.** A document extension plus ELF/Mach-O magic is Critical (masquerading); a native binary in a temp dir is High; non-executable `.so/.node` build caches are skipped.

**`macos.signature`:** scans `/Applications` main executables, `/Users/Shared`, `/tmp`, `~/Downloads`, and launchd program paths. The static parser walks Mach-O load commands and reports files without `LC_CODE_SIGNATURE` as High; on a live Mac, `codesign -dv` additionally flags ad-hoc signatures for writable locations. It does not yet validate the signature chain or Team IDs. Full code-signing/notarization validation, TCC and BTM remain on the roadmap.

**`pkg.malicious`:** offline check against a local clone of `ossf/malicious-packages` (default `~/.config/warden/malicious`, override with `--malicious`). It indexes OSV JSON records by ecosystem/name, enumerates global npm/pip/cargo packages, and also scans `node_modules/*/package.json` and `*.dist-info/METADATA` under `--path` roots. Exact versions and simple range events (`introduced`/`fixed`/`last_affected`) are matched; hits are Critical. No network or API key is required.

**`pkg.osv`:** opt-in (`--osv`) supply-chain query. It maps the host distribution to an OSV ecosystem (Debian, Ubuntu, Alpine, Rocky Linux, AlmaLinux, Wolfi), enumerates installed packages (source package name/version for dpkg), batches up to 100 queries, and caches the raw response for 24h under `~/.cache/warden/osv/`. Severity comes from `database_specific.severity` (default Medium), fixed versions are extracted from `ranges[].events[].fixed`, and aliases (CVEs) are included in the finding. Package names are sent to osv.dev, so this is never enabled by default.

**`container.config`:** Docker `daemon.json` (TCP API without `tlsverify` is Critical, TLS without client verification is High, insecure registries/iptables off are Medium), containerd/CRI-O/Podman TOML (recursive `insecure_skip_verify`, plaintext endpoints, insecure registries), k3s `registries.yaml`, kubelet `config.yaml` (`anonymous.enabled`, `AlwaysAllow`, nonzero `readOnlyPort`), and non-empty `docker` group membership (root-equivalent). Config files writable by non-root are High.

**`persist.pam` / `persist.udev` / `persist.at`:** the Linux integrity pack. PAM rules are resolved against multiarch module directories and flagged for absolute modules outside them, `pam_exec` with shell/download commands, `pam_python`, and `nullok`. udev checks only `RUN+=`/`PROGRAM=` commands that match the behavioral heuristics, plus writable rule files. at jobs are parsed as text and run through the same command signals. All three skip comments/headers and report line-level evidence.

**`pkg.integrity`: opt-in package verification.** `--verify-packages` selects the live package database (dpkg/rpm/pacman), verifies checksums, and reports modified binaries/libraries as High. Config files and documentation are skipped to avoid drowning the signal; every verification walks all package-owned files, so it is off by default. It refuses to run for `--root` image scans because the manager would inspect the host, not the image.

**`host.listeners`: only suspicious processes, not a port inventory.** Criteria: executable deleted (`(deleted)`), running from a temp dir, or a non-root process on a port < 1024. System accounts (<1000) running root-owned binaries from system directories are skipped for the low-port rule: `systemd-resolved:53` and `systemd-networkd:546` rely on capabilities and are normal. Unmappable sockets produce one Info item saying root is required.

### 4.3 Severity and confidence

Severity expresses **impact**; confidence expresses **certainty**. They are independent:

- `Critical`: non-empty `ld.so.preload`, reverse shell, empty password, IOC hit, masqueraded executable
- `High`: new persistence entry, suspicious cron, unknown SUID, writable cron/sshd config
- `Medium`: permissive modes, non-standard paths, missing hardening
- `Low` / `Info`: hardening advice, coverage notes

False positives are handled by confidence, baseline, and allowlists — not by lowering severity.

## 5. Baseline, policy, and allowlists

On a production host, "which cron entries are ours" has no objective answer on first run. The baseline provides one:

1. `warden baseline save` writes the current persistence inventory (cron, systemd Exec, launchd, SSH keys, SUID, listeners) as JSON.
2. `warden scan --baseline <file>` reports **new** items as High (`baseline.drift`) and removed items as Info.
3. Snapshot keys use normalized content (path + normalized command + key fingerprint), never PIDs, timestamps, or line numbers.

Deliberate choices:

- Only structured entries whose addition is suspicious go into the baseline. Ordinary shell-rc lines do not, or every config edit would trigger drift.
- The baseline is a state snapshot, not a signed policy. Store it where only root can write (e.g. `/var/lib/warden/`).
- A new cron line can produce both "new since baseline" and "suspicious command" — one describes change, the other describes nature. Both are useful.

### 5.1 Default profile and policy file

No configuration file is required. The built-in profile is:

- `min_severity=low`, `fail_on=high`, all applicable checks, `max_file_size=64M`
- web roots auto-detected under the scan root (`var/www/html`, `var/www`, `srv/www`, `usr/share/nginx/html`, `var/lib/nginx/html`)
- YARA rule directories auto-loaded from `~/.config/warden/rules`, `/etc/warden/rules`, `/usr/share/warden/rules`
- ClamAV auto-enabled only when `clamscan` and a local `.cvd/.cld` database exist (`--no-clamav` forces off)
- package verification stays opt-in (≈35 s on the development host)
- allowlists auto-loaded from the user path or `/etc/warden/allowlist.toml`

`warden config show [--format json]` reports the effective defaults and detected paths; `warden config init` writes a commented template. Auto-detection is skipped when the corresponding CLI list or policy value is present, and an explicit empty list in the policy disables it.

Policy file:

`--policy <file>` (or auto-discovered `~/.config/warden/policy.toml`, then `/etc/warden/policy.toml`) supplies scan defaults: severity threshold, fail-on, check selection, extra paths/webroots, IOC/YARA/ClamAV settings, package verification, size limit, and allowlist path. Scalar and list options are overridden by explicit CLI values; lists use the CLI value only when non-empty. Boolean features are ORed, so a policy-enabled feature cannot be disabled from the CLI yet. `deny_unknown_fields` turns policy typos into a startup error instead of silently ignoring them.

## 6. Sandbox design (Linux)

### 6.1 Two-phase model

Downloading and executing untrusted content are different risks:

- **Download risk is content**: a malicious file, a forged extension, a weaponized archive.
- **Execution risk is behavior**: persistence, egress, dropped payloads, privilege attempts.

`warden sandbox fetch` handles the first: it downloads with protocol, redirect, size, and time limits into a quarantine directory, computes a SHA-256, inspects magic bytes and embedded commands, and **never executes**. `warden sandbox run` handles the second, **always without network**.

Why no network by default? A dropper's first action is to fetch stage 2. If the sandbox has egress, the observer only sees stage 1 and the C2 learns it is being analyzed. Egress proxying with TLS interception and allowlists is a planned tier (M2), not a flag to bolt on.

### 6.2 Isolation model (Linux local backend)

Implemented with `bubblewrap`:

- `--unshare-all`: user, PID, network, IPC, UTS, cgroup namespaces
- fresh tmpfs root; `/usr` (and `/opt` when present) read-only; `/proc` and `/dev` recreated
- `/home`, `/root`, `/mnt`, `/boot`, `/srv`, `/run`, `/sys` masked with tmpfs
- writable **copies** of `/etc`, `/usr/local`, `$HOME`, `/tmp`, `/var/tmp`, `/var/log`, `/var/spool/cron`, bound back to their real paths
- environment cleared; explicit `HOME`, `PATH`, `TMPDIR`, `USER`
- `RLIMIT_CPU`, `RLIMIT_FSIZE`, `RLIMIT_CORE`; wall-clock timeout kills the sandbox (`--die-with-parent`)
- cgroup v2 limits through a transient `systemd-run --user --scope`: `MemoryMax` (default 2 GiB), `TasksMax` (256), `CPUQuota` (200%), overridable with `--mem/--pids/--cpus` (0 disables). The scope is SIGKILLed and collected on timeout; when no systemd user session is available the run falls back to timeout + rlimits and records that in the report

The writable copies are the key design choice. They give two properties at once:

1. A sample can install a cron job, edit `~/.bashrc`, or write `/etc/ld.so.preload` and observe the effect — without touching the host.
2. A before/after hash-and-metadata snapshot of those directories produces an exact, evidence-backed list of what changed, with no root or overlayfs requirement.

`/etc` is copied per run (about 9 MB on a typical desktop). Files unreadable as non-root (`shadow`, `sudoers`) are replaced with empty placeholders so programs do not take wildly different branches; the report states that the copy is incomplete.

### 6.3 Behaviour capture and scoring

Evidence sources, ordered by reliability:

1. **Filesystem diff** — created/modified/deleted files mapped back to logical paths. Persistence paths are classified (cron ⇒ Critical, `ld.so.preload` ⇒ Critical, systemd/rc/sudoers/PAM/SSH ⇒ High, `/usr/local/bin` executables ⇒ High, other `/etc` changes ⇒ Low).
2. **IOC hashes** — every dropped file is hashed and matched against `--ioc`.
3. **strace (optional)** — `connect()` to non-loopback addresses (Critical on common C2 ports), `execve` chain (shell/downloader/encoder tools), `mount`/`ptrace`/`init_module`/`bpf`, deletion of persistence paths.
4. **Command-line heuristics** — the invoked command is checked with the same signal engine as cron/systemd.

Dropped artifacts are classified by magic bytes, not extension. Non-executable shared libraries in temp dirs are ignored (Bun/Python build caches). Generated scripts are scanned with the backdoor pattern set.

Scoring is additive and capped at 100 (Critical 50, High 25, Medium 10, Low 3); verdict is `high-risk` (High/Critical), `suspicious` (Medium), `low-risk` (Low), or `clean`. Findings are deduplicated by fingerprint and sorted stably.

### 6.4 Honest guarantees and limits

Guaranteed:

- No host write outside the disposable sandbox copy and the user-provided `--workdir`
- No network egress
- No host credential access (`/home`, `/root`, `/etc/shadow` are masked or placeholders)
- The sample runs as the invoking user, not root
- Aggregate memory and task-count bounds when cgroup v2 is available (a tmpfs-backed sandbox copy cannot exhaust host RAM; fork bombs hit `TasksMax`)

Not guaranteed:

- Kernel escape resistance. Namespaces share the kernel; a kernel exploit can break out. This is triage, not a malware-analysis VM.
- Disk quota for a user-provided `--workdir` on a real filesystem: `MemoryMax` bounds tmpfs-backed copies, but writes to an explicitly mounted host directory are not quota'd.
- Complete installers: package managers that require online repositories cannot run; pre-download dependencies into `--workdir` or wait for the proxy tier.

### 6.5 VM backend (macOS)

The local backend depends on Linux namespaces, so macOS executes the same job in a Linux VM:

- `--engine auto` resolves to `local` on Linux and `vm` on macOS; `--engine local|vm` are explicit overrides.
- The host verifies the Lima instance is running, copies the workdir plus optional YARA/IOC inputs and a **Linux** warden binary to `/tmp/warden-job`, runs `warden sandbox run --format json` in the guest, imports the `SandboxReport`, and enforces exact version equality.
- Guest binary resolution order: `--vm-guest-binary` (verified ELF) -> cached `<XDG_CACHE_HOME>/warden/guest/<host-version>/<arch>/warden` -> `--vm-guest-url`/`WARDEN_GUEST_URL` download. Downloads require a checksum (`--vm-guest-sha256`/`WARDEN_GUEST_SHA256`, or a `<url>.sha256` sidecar), are verified before caching, and are stored under the host version so upgrades cannot reuse stale binaries. `warden sandbox vm fetch-guest` pre-populates the cache.
- With `--keep`, artifacts are exported into the host workdir: the sandbox base and `/work` are staged and archived with `tar` when available, otherwise only the changed files from the report are copied individually. Archives are never auto-extracted, and the guest job directory is always removed afterwards.
- Security: the VM has its own kernel and does not share the host filesystem. Inside the guest, the normal bwrap isolation still applies (network namespace, writable copies, limits), so the sample sees no egress even if the VM has a NIC.
- Contract: `SandboxReport` JSON is the only host/guest interface. A native Virtualization.framework backend (guest agent over vsock) can replace Lima without changing the CLI or report schema.

Guest binaries are produced by `.github/workflows/release-guest.yml` (x86_64 and aarch64 Linux runners, per-file `.sha256`) or `scripts/build-guest.sh` on a Linux host. The cache is keyed by host version and architecture; there is no `--vm-arch` override yet.

Limitations: a Linux guest binary is still required (Mach-O is rejected) and must match the host version; the checksum sidecar is fetched from the same origin as the binary, so pinning `--vm-guest-sha256` is stronger than trusting the sidecar. `--clamav-db` host paths are rejected, cgroup limits inside a `limactl shell` session may fall back to timeout + rlimits (the report says so), and Docker/Colima are not wired.

### 6.6 Quarantine fetch

`warden sandbox fetch`:

- accepts only `http`/`https`, restricts redirects to the same protocols, caps redirects at 5
- enforces `--max-size` and `--max-time`
- stores as `<sha256-prefix>-<name>` and never chmods/executes
- flags native executables (Critical if disguised as a document), suspicious script content, embedded URLs, and IOC hits
- prints the exact offline `sandbox run` command as the next step

## 7. Privilege and read-only safety

| Capability | Non-root | root |
|---|---|---|
| User-scope persistence, PATH, SUID, webshells, IOC, cron config | ✅ | ✅ |
| `/etc/shadow` empty passwords | ❌ (Info explains the gap) | ✅ |
| Other users' `authorized_keys` / crontabs | partial | ✅ |
| Listener → process mapping | partial (count reported) | ✅ |
| Kernel taint / procfs details | partial | ✅ |

Code-level invariants:

- Static scanning performs only `read`, `metadata`, `read_link`; no `write`/`remove`/`chmod` on scanned paths. The only writes are `--output`, baseline files, and the sandbox's own disposable directory.
- No scanned program is executed by the static path.
- External commands are limited to `getcap`, `lsof`, `ps`, `csrutil`, `spctl`, `fdesetup`, `dscl`, `uname`, `hostname` (and `curl`/`bwrap`/`strace` for the sandbox).
- Size and traversal caps everywhere (config 4 MB, webshell 2 MB, IOC 16 MB, hashing 64 MB by default, 300k entries per snapshot).
- `--root` is a path prefix only: no chroot, no working-directory change.

## 8. Performance

Static scan, Arch Linux x86_64, 24 checks (YARA, ClamAV, package verification and OSV disabled), unprivileged, including process startup:

```
elapsed 439–531 ms
```

Hot spots and mitigations:

- SUID walk over `/usr/bin`, `/usr/lib`, `/opt` with depth limits (2–3) and a 50k-entry cap
- Suspicious-file scan limited to `/tmp`, `/var/tmp`, `/dev/shm`, `~/Downloads`, `~/Public`, depth 4
- IOC hashing parallelized with rayon and bounded by file size
- Directory walks use `filter_map(ok)` so permission errors never abort a scan

Sandbox: the dominant startup cost is copying `/etc` (~9 MB, sub-second on a desktop); the cgroup availability probe adds roughly 50 ms when limits are enabled. Execution is bounded by `--timeout`; snapshots use size + mtime + SHA-256 for files under `--max-file-size`.

## 9. Cross-platform strategy

| Capability | Linux | macOS |
|---|---|---|
| Static scan (16 checks), baseline, allowlist, JSON/SARIF | yes | yes |
| YARA-X / IOC / optional ClamAV | yes | yes |
| `sandbox fetch` (quarantine + static) | yes | yes |
| `sandbox run` (namespaces + filesystem diff) | yes | yes, inside a Lima VM (experimental) |
| cgroup v2 limits | yes (systemd user scope) | no |

- All checks compile into one binary and are enabled at runtime by `Os`; `persist.launchd` also runs on Linux for macOS images.
- OS detection prefers filesystem content: `System/Library` or `Library/LaunchDaemons` ⇒ macOS; `etc/os-release`/`etc/passwd` ⇒ Linux.
- `--root /mnt/mac-image` audits macOS persistence from Linux. launchd parsing extracts fields from XML plists directly; binary plists are converted with `plutil` when available (macOS host), otherwise skipped for image scans.
- macOS-only state (SIP, Gatekeeper, FileVault, XProtect, OpenDirectory) is read only when `root == "/"` and the platform is macOS, so image scans never make false claims.
- The local backend is Linux-only: namespaces and bubblewrap have no macOS equivalent with the same guarantees. macOS uses the VM backend (`--engine vm`), which copies the job into a Lima Linux VM and imports the same report. The next step is a native Virtualization.framework backend behind the same `Backend` trait and report contract.
- Cross-compiling from Linux to macOS is not supported because wasmtime (YARA-X) builds a C helper; build natively with Xcode Command Line Tools.

## 10. Output contract and TUI

- `Finding` is the only result unit, with fixed fields: `check, severity, confidence, title, message, path, line, evidence, remediation, mitre`.
- `path` is always the **logical** path (`--root` stripped), so image scans, baselines, and allowlists share one namespace.
- Sorting is stable: severity desc → check → path → line, so CI diffs do not churn.
- SARIF mapping: `critical/high → error`, `medium → warning`, `low/info → note`, plus a fingerprint for deduplication.
- Coverage is first-class: which checks ran, skipped, or failed and why. **"Not checked" must never look like "clean".**
- `scan --tui` is a thin ratatui layer over the same `Report`: the scan runs on a background thread; the Findings view renders evidence/remediation, and the Checks view renders every `CheckCoverage` entry (status, matches, description, platforms, skip/failure reason) with cross-navigation via Enter. It requires a TTY and is excluded from text/JSON/SARIF output paths.
- Coverage entries carry `description` and `platforms` so "what was checked" is machine-readable, not just a title. New fields use serde defaults so older guest reports still deserialize.

## 11. Signatures and threat intelligence

The current release supports IOC feeds (`--ioc`: plain text or abuse.ch CSV with SHA-256/SHA-1/MD5, URLs, domains, IPs), YARA-X rule packs (`--yara`), an optional ClamAV backend (`--clamav`, separate process), and an opt-in OSV supply-chain check (`--osv`). YARA matches are mapped into `Finding`s using rule metadata (`severity`, `description`, `reference`, `author`, `license`, `attack`), and the report records the rule pack size. ClamAV is disabled by default; when enabled it scans the same high-value targets, maps `FOUND` lines to findings, and surfaces the ClamAV/DB version in an Info item. No third-party rules are bundled; see [SIGNATURES.md](SIGNATURES.md) for source evaluation, license pitfalls, and the remaining plan (abuse.ch feeds, OSV).

## 12. Testing strategy

1. **Unit tests (73)**: cron parsing (system/user/@reboot/env), systemd prefixes, sshd judgement table, authorized_keys options, plist key boundaries, PAM rule risk/module paths, udev command extraction, at command filtering, dpkg/rpm/pacman output parsing, `/proc/net` IPv4/IPv6 decoding, webshell patterns, IOC parsing, glob, baseline diff, allowlist expiry, strace parser, bwrap argument construction, cgroup property mapping, YARA metadata mapping, ClamAV output parsing, container JSON/TOML/YAML parsing, policy parsing/unknown-key rejection/template validity, default webroot detection, IOC CSV/plain parsing, URL/IP matching and feed download, OSV ecosystem/version/vulnerability parsing and cached queries, Mach-O thin/fat signature parsing, malicious-package parsing/matching, YARA cache invalidation, ClamAV database-date parsing, VM orchestration (fake `limactl`), guest-binary download/checksum caching (fake `curl`), and check registry metadata completeness.
2. **End-to-end self-test (`warden selftest`, 23 assertions, run on Linux)**: builds a backdoored Linux fixture (including PAM, udev, and at persistence), a YARA rule pack, and a macOS launchd layout in a temp directory; verifies 17 checks fire, YARA metadata drives severity and ATT&CK ids, a legitimate cron line is not flagged, the baseline contains cron entries, and the exit code is 1. It never reads or modifies host configuration.
3. **Real-host regression**: scan the development machine, review every finding, tighten rules.
4. **Desktop UI**: `egui_kittest` renders the real layout headlessly through wgpu, with seven PNG snapshots (welcome, findings, checks, compact, dark/light, English/中文) and one test that drives the GUI's `Config` through the real engine. Run with `WGPU_BACKEND=gl cargo test -p warden-gui` on Linux.

### False-positive case studies (all observed in practice)

| Output | Root cause | Fix |
|---|---|---|
| `/etc/localtime` reported world-writable 0777 | `symlink_metadata` read the link's own mode | Follow symlinks for permission checks |
| `/tmp/.bun-*.so` reported as a trojan | Magic bytes only; exec bit and library extension ignored | Skip non-executable `.so/.node` files |
| `modprobe install libnvdimm /usr/bin/ndctl` reported as a backdoor | "Not modprobe ⇒ alert" | Only interpreters, writable paths, or behavioral matches |
| User-level systemd unit starting from `~` reported | System and user units not distinguished | No home-directory warning for user units |
| `newuidmap`/`qemu-bridge-helper` reported as privilege backdoors | SUID/capability allowlists too small | Add standard distribution components |

The lesson: **scanner quality is determined by noise-reduction rules, not rule count.**

## 13. Roadmap

**M1 (shipped):** 14 static checks, baseline, allowlist, text/JSON/SARIF, self-test, Linux sandbox with filesystem capture, quarantine fetch, optional strace.

**0.2 (shipped):** YARA-X rule packs (`--yara`) on `scan`, `sandbox run`, and `sandbox fetch` with metadata-driven severity.

**0.3 (shipped):** optional ClamAV backend (`--clamav`, separate process) on the same three entry points; shared target selection.

**0.4 (shipped):** sandbox cgroup v2 limits (memory/tasks/CPU) through a transient systemd user scope, with clean timeout/scope handling and an explicit fallback note.

**0.5 (shipped):** backend abstraction (`--engine auto|local|vm`), Lima VM backend, guest report import with version checks, VM lifecycle commands.

**0.6 (shipped):** verified guest-binary download/cache (`--vm-guest-url`, `--vm-guest-sha256`, `sandbox vm fetch-guest`), release workflow and build script for Linux guest binaries.

**0.7 (shipped):** Linux integrity pack (`persist.pam`, `persist.udev`, `persist.at`, opt-in `pkg.integrity`), expanded hardening checks (SELinux/AppArmor/Secure Boot/lockdown/ptrace/auditd), and world-writable container socket detection.

**0.8 (shipped):** `container.config` for Docker/containerd/CRI-O/Podman/k3s/kubelet and docker-group membership.

**0.9 (shipped):** operability: compiled YARA-rule cache, ClamAV database-age warnings, and a policy file with clear precedence.

**0.10 (shipped):** zero-configuration default profile (webroot/YARA/ClamAV auto-detection, system allowlist), `warden config show/init`, and `--no-clamav`/`--no-verify-packages` overrides.

**0.11 (shipped):** IOC feeds: abuse.ch CSV/plain auto-detection, SHA-1/MD5 hashes, and URL/domain/IP matching in `sandbox fetch`.

**0.12 (shipped):** feed operations (`intel fetch/show`), checksum/header support, and automatic use of `~/.config/warden/intel` by `scan`.

**0.13 (shipped):** opt-in OSV supply-chain check with package enumeration, 24h response cache, and ecosystem mapping.

**0.14 (shipped):** `macos.signature`: static Mach-O code-signature presence and live ad-hoc detection for writable locations.

**0.15 (shipped):** offline `pkg.malicious` check against ossf/malicious-packages, including project-level npm/PyPI manifests.

**0.16 (shipped):** interactive ratatui TUI (`scan --tui`) for browsing, filtering, and reading finding evidence over the same report.

**0.17 (shipped):** TUI Checks view with full coverage, per-check descriptions/platforms, skip/failure reasons, and Enter cross-navigation; coverage metadata is now part of the report.

**0.18 (this version):** native egui/eframe desktop app (`warden-gui`) for macOS and Linux: scan controls, findings, checks/coverage, JSON/SARIF export, dark/light themes, English/中文, plus Linux/macOS packaging.

**M2 — depth and signatures**

- ✓ YARA-X rule directory (`--yara`) and metadata → severity (0.2); compiled-rule cache still pending
- ✓ Optional ClamAV backend via a separate process (0.3); automated signature-age warnings still pending
- ✓ Sandbox cgroup v2 memory/CPU/task limits (0.4)
- ✓ Lima VM backend for macOS (0.5); native Virtualization.framework and egress proxy still pending
- ✓ Linux PAM/udev/at checks and package integrity (0.7)
- ✓ Container runtime configuration (0.8)
- ✓ Operability: YARA cache, ClamAV age, policy file (0.9)
- ✓ Zero-config defaults and config commands (0.10)
- ✓ IOC feeds (CSV/plain, hashes/URLs/domains/IPs) in scan and fetch (0.11)
- ✓ Feed download/show and default intel directory (0.12)
- ✓ OSV supply-chain check (0.13)
- ✓ macOS Mach-O signature presence/ad-hoc detection (0.14); Team ID/notarization, TCC and BTM still pending
- ✓ Known-malicious package dataset (0.15); scheduled dataset refresh and pre-install blocking still pending
- macOS: Mach-O code signature and Team ID checks, system/kernel extension inventory, TCC anomalies, login items (BTM)
- Linux: ✓ PAM module validation, udev rules, `at`, package integrity (0.7); `rc.local` is covered by `persist.shell_rc`; remaining: docker/containerd config

**M3 — operations**

- Abuse.ch IOC sync into SQLite; match files, listeners, and sandbox egress
- ✓ OSV query for installed packages (0.13); malicious-packages dataset and pre-install checks still pending
- JSON schema versioning, report-to-report diff, policy file for check enablement
- Performance: incremental scans, inode caching

**M4 — distribution**

- Homebrew tap, `.deb`/`.rpm`, universal macOS binary with notarization, CI cross-compile matrix
- Rule pack manager with license metadata (`warden rules add/update/verify`)

**Explicit non-goals:** automatic deletion/quarantine, cloud sample upload, family-named alerts.

## 14. Distribution and supply chain

- Single static binary for the host; Linux guest binaries for VM mode are built and published separately with per-file SHA-256 (`release-guest.yml`).
- YARA-X pulls in `wasmtime`/Cranelift for its WASM module support; this increases build time and binary size. Trimming unused YARA modules is a possible future optimization, but default modules keep third-party rule compatibility.
- Deliberately small dependency set: `clap`, `serde`, `serde_json`, `toml`, `walkdir`, `sha2`, `rayon`, `chrono`, `anyhow`, `libc`.
- Publish SHA-256 checksums and build provenance; reproducible builds are an M3 goal.
- Reports can contain sensitive configuration; treat them as sensitive data in regulated environments.

## 15. Known limitations

1. Fileless/memory-only attacks and kernel-level hiding (LKM rootkits, eBPF backdoors) are invisible to filesystem scanning.
2. Heuristics flag legitimate-but-unusual operations scripts; use baseline and allowlists.
3. macOS coverage is weaker than Linux (OpenDirectory, TCC, login items, private launchd fields, Mach-O signatures). Binary plists require `plutil`; image scans without it skip those entries. VM mode requires a Linux guest binary and a running Lima instance, and has only been exercised on Linux (Lima); a real-Mac regression run is still required.
4. No vulnerability exploitability analysis (no CVE scan), only persistence and configuration auditing.
5. Inside containers, `/proc` and `/etc` reflect the container; use `--root /host` for the host view.
6. The sandbox shares the host kernel and is not an anti-escape boundary; use a microVM for targeted kernel exploits.
7. Package verification is opt-in, host-only, skips `/etc` and documentation, and can take tens of seconds (≈35 s for `pacman -Qkk` on the development host).
8. Auto-detected web roots are scanned recursively for webshells; very large web trees may need an explicit shorter `--webroot` list. Boolean policy features are ORed, so disabling one from the CLI requires the matching `--no-*` flag.
