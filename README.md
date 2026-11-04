# Warden

Host security scanner for macOS and Linux, written in Rust. It is **not** a signature-only antivirus: it is a high-signal auditor for backdoor persistence, privilege-escalation surface, and misconfiguration — plus a Linux sandbox for observing what an untrusted installer or binary actually does.

- Enumerates and evaluates the places attackers actually use to stay resident (cron, systemd, launchd, shell rc, dynamic loader, kernel-module hooks, SSH keys)
- Checks privilege-escalation surface and hijackable paths (SUID/SGID, file capabilities, writable PATH entries)
- Detects masqueraded executables, dropped binaries, webshells, and IOC hashes
- Reviews accounts, sshd, and sudoers
- **Baseline drift**: record the known-good persistence inventory, then report only additions
- **Linux sandbox**: run a sample or installer offline, diff the filesystem, and score its behavior
- **Native desktop app** for macOS and Linux (egui/eframe): scan controls, findings, full checks/coverage, JSON/SARIF export, dark/light themes, English/中文

The scanner is strictly read-only. The sandbox never gives a sample host access, and only touches host directories that the user explicitly provides.

## Checks

| ID | What it inspects | Platforms |
|---|---|---|
| `persist.cron` | Reverse shells, download-and-execute, encoded payloads in crontab/cron.d/user crontabs | Linux, macOS |
| `persist.systemd` | Unit ownership/permissions; ExecStart pointing at temp dirs or suspicious commands | Linux |
| `persist.shell_rc` | Backdoor commands and PATH injection in `.bashrc`, `.zshrc`, `profile.d` | Linux, macOS |
| `persist.pam` | Non-standard/missing PAM modules, `pam_exec`/`pam_python`, `nullok`, writable configs | Linux, macOS |
| `persist.udev` | udev `RUN+=`/`PROGRAM=` executing suspicious commands; writable rule files | Linux |
| `persist.at` | `at` jobs with backdoor/download-and-execute commands | Linux, macOS |
| `container.config` | Docker/containerd/CRI-O/Podman/k3s/kubelet trust and auth misconfiguration, docker group membership | Linux |
| `persist.loader` | `/etc/ld.so.preload`, `LD_PRELOAD`, `ld.so.conf.d`, modprobe install hooks, `launchd.conf` | Linux, macOS |
| `persist.ssh` | `command=` backdoors in authorized_keys, dangerous sshd settings, host-key permissions | Linux, macOS |
| `persist.launchd` | LaunchDaemons/Agents pointing at `/tmp`, `/Users/Shared`, missing programs | macOS |
| `fs.suid` | Unknown SUID/SGID binaries, SUID in unusual directories, high-privilege file capabilities | Linux, macOS |
| `fs.world_writable` | Writable directories in PATH; writable files under `/etc` and `/usr/local/bin` | Linux, macOS |
| `fs.suspicious_bin` | ELF/Mach-O masquerading as documents, native binaries in temp dirs, hidden executables | Linux, macOS |
| `fs.webshell` | PHP/JSP/ASP webshell indicators (`eval($_POST)`, `base64_decode` chains, …) | Cross-platform |
| `ioc.hash` | SHA-256 matching against an IOC list | Cross-platform |
| `yara.rules` | YARA-X rule matches over persistence configs, temp dirs, web roots, and `--path` roots | Cross-platform |
| `clamav.scan` | Optional ClamAV backend (separate process) over the same high-value targets | Cross-platform |
| `host.accounts` | Extra UID 0 accounts, empty passwords, writable login shells, passwordless sudo | Linux, macOS |
| `host.listeners` | Listeners running from temp dirs, deleted executables, non-root privileged ports | Linux, macOS |
| `host.hardening` | Kernel taint, ASLR, SELinux/AppArmor, Secure Boot, lockdown, ptrace_scope, auditd; macOS SIP / Gatekeeper / FileVault / XProtect | Linux, macOS |
| `pkg.integrity` | dpkg/rpm/pacman verification of package-owned files (opt-in, `--verify-packages`) | Linux |
| `pkg.osv` | OSV vulnerabilities for installed packages (opt-in network query, cached) | Linux |
| `macos.signature` | Unsigned Mach-O, ad-hoc signatures in apps/downloads/launchd programs | macOS |
| `pkg.malicious` | Known-malicious npm/PyPI/crates.io packages from ossf/malicious-packages | Linux, macOS |

## Platform support

| Capability | Linux | macOS |
|---|---|---|
| Static scan (24 checks), baseline, allowlist, text/JSON/SARIF | ✅ | ✅ |
| YARA-X rules, IOC hashes, optional ClamAV backend | ✅ | ✅ |
| `sandbox fetch` (quarantine + static inspection) | ✅ | ✅ |
| `sandbox run` (dynamic execution, filesystem diff) | ✅ bubblewrap | ✅ via Lima VM (experimental) |
| cgroup v2 resource limits | ✅ systemd user scope | ⚠️ inside the Linux VM (may fall back) |

Local bubblewrap requires Linux namespaces (user, PID, network, mount). On macOS, `--engine vm` runs the same sandbox inside a Lima Linux VM: separate kernel, no host filesystem share, and the same report contract. Native Virtualization.framework integration is the next milestone; `sandbox-exec` is not used because it is deprecated and cannot redirect `/etc`/`$HOME`.

macOS coverage: launchd (XML plists, plus binary plists through `plutil`), SIP/Gatekeeper/FileVault/XProtect, `lsof` listeners, `dscl` UID 0 accounts, `/etc/master.passwd` empty passwords, Mach-O magic detection, and static code-signature presence (`LC_CODE_SIGNATURE`); on a live Mac, ad-hoc signatures in downloads/temp/launchd programs are detected with `codesign`. Still missing: full Team ID/notarization validation, TCC, login items (BTM), system extensions. Build natively with Xcode Command Line Tools; cross-compiling from Linux is not supported because wasmtime (a YARA-X dependency) compiles a C helper.

## Sandbox

The sandbox separates **download** from **execution** on purpose:

1. `sandbox fetch` downloads into a quarantine directory with size/time limits and inspects the content statically. It never executes anything.
2. `sandbox run` executes inside a bubblewrap sandbox with **no network**, writable copies of `/etc`, `/usr/local`, `$HOME`, `/tmp`, and `/var/spool/cron`, and a snapshot before/after execution. The diff shows exactly which persistence paths, binaries, or configs the sample touched.

```bash
# Check dependencies and kernel capabilities
warden sandbox doctor

# Download and inspect (no execution)
warden sandbox fetch https://example.com/tool.tar.gz --output ./quarantine

# Execute offline in the sandbox; capture every file change
warden sandbox run --workdir ./quarantine --keep --timeout 60 -- /work/<download>

# Run a shell installer and diff its behavior
warden sandbox run --workdir ./samples --yara ./rules -- /bin/sh /work/install.sh

# Tighter resource envelope for an untrusted installer
warden sandbox run --mem 512M --pids 128 --cpus 1 --workdir ./q -- /bin/sh /work/install.sh

# Both content scanners also work on sandbox artifacts and downloads
warden sandbox run --workdir ./samples --yara ./rules --clamav -- /bin/sh /work/install.sh
warden sandbox fetch --yara ./rules --clamav https://example.com/tool.bin --output ./q
```

### Backends

- `--engine auto` (default): Linux -> local bubblewrap; macOS -> Lima VM
- `--engine local`: force bubblewrap (Linux only)
- `--engine vm`: run the same sandbox inside a Lima VM

VM mode copies the workdir, optional YARA/IOC inputs, and a **Linux** warden binary into the guest, runs `warden sandbox run --format json` there, validates the version, and imports the report. It requires Lima, a running instance, and bubblewrap inside the guest:

```bash
warden sandbox vm up --name warden-sandbox
limactl shell warden-sandbox -- sudo apt-get update && sudo apt-get install -y bubblewrap
warden sandbox run --engine vm --vm-name warden-sandbox \
  --vm-guest-binary ./warden-linux --workdir ./q -- /bin/sh /work/install.sh
warden sandbox vm status
warden sandbox vm down --name warden-sandbox
```

`--keep` exports artifacts to `--workdir` (a `.tar.gz` when the guest has `tar`, otherwise a directory of changed files); nothing is auto-extracted. `--clamav-db` must live inside the guest (host paths are rejected).

The guest binary must be a Linux ELF matching the host warden version. Three ways to provide it:

1. `--vm-guest-binary ./warden-linux`
2. `--vm-guest-url <url> [--vm-guest-sha256 <hex>]`, or the environment variables `WARDEN_GUEST_URL` / `WARDEN_GUEST_SHA256`
3. `warden sandbox vm fetch-guest --url <url>` to pre-populate the cache

A checksum is mandatory: pin it with `--vm-guest-sha256`, or publish a `<url>.sha256` sidecar. Downloads are verified and cached at `~/.cache/warden/guest/<version>/<arch>/warden` (override with `XDG_CACHE_HOME`). Release assets named `warden-<version>-<arch>-unknown-linux-gnu` plus `.sha256` are produced by `.github/workflows/release-guest.yml` or `scripts/build-guest.sh` on Linux.

Isolation model (MVP):

- user, PID, network, IPC, UTS, and cgroup namespaces are unshared
- fresh tmpfs root with read-only `/usr`; `/home`, `/root`, `/mnt`, `/boot`, `/srv`, `/sys` masked
- `/etc`, `/usr/local`, `$HOME`, `/tmp`, `/var/tmp`, `/var/log`, `/var/spool/cron` are host-side writable copies, diffed after execution
- environment cleared; runs as the invoking user; rlimits for CPU, file size, and core dumps; wall-clock timeout kills the namespace
- cgroup v2 limits through a transient systemd user scope: 2 GiB memory, 256 tasks, 200% CPU by default (`--mem`, `--pids`, `--cpus`; 0 disables). Without a systemd user session the run falls back to timeout + rlimits and says so in the report
- optional `strace` integration observes egress attempts, the execve chain, and kernel/injection syscalls

**Escape risk:** the sandbox shares the host kernel (user namespaces). A targeted kernel exploit can escape. Use it for rapid behavior triage, not as a malware-analysis VM; for hostile kernel exploits use a microVM (Firecracker/QEMU) tier. Runtime details and evidence are in the JSON report (`--format json`).

## Install

```bash
cargo build --release
install -m755 target/release/warden /usr/local/bin/warden

# Cross-build macOS Intel from Linux (cargo-zigbuild + a macOS SDK)
SDKROOT=~/sdk/MacOSX15.5.sdk make mac-x86_64

# Apple Silicon
SDKROOT=~/sdk/MacOSX15.5.sdk make mac-arm64

# Desktop app (Linux; macOS packages with `make gui-mac-x86_64` from Linux)
cargo run --release -p warden-gui
```

Linux (x86_64/aarch64) and macOS (Intel/Apple Silicon); Rust 1.95+ to build.
The macOS cross-build needs `zig`, `cargo-zigbuild`, the matching Rust target,
and a macOS SDK in `SDKROOT` (wasmtime links CoreFoundation). See
[docs/USAGE.md](docs/USAGE.md) for the full CLI reference. On macOS install Xcode Command Line Tools first (`xcode-select --install`) because YARA-X's wasmtime dependency compiles a small C helper. `scan` auto-loads `~/.config/warden/intel`; `sandbox run`/`fetch` take `--ioc` explicitly. The scanner has no runtime dependencies. The local sandbox requires `bubblewrap` (plus a systemd user session for cgroup resource limits) and optionally `strace`/`curl`. VM mode additionally requires Lima (`brew install lima`) and a matching Linux warden binary. The optional ClamAV backend requires `clamscan` plus an updated database (`freshclam`).

## Desktop app

Warden has a native desktop app for macOS and Linux, built on egui/eframe. It runs the same scan engine and report model as the CLI — no second implementation of the checks.

<img src="apps/warden-gui/tests/snapshots/findings-dark.png" alt="Warden desktop findings view" width="760" />

- **Findings** — severity list, evidence, remediation, confidence, ATT&CK
- **Checks** — every selected check with `ran` / `skipped` / `failed`, match count, platforms, description, and the exact skip/failure reason
- Scan target and minimum severity; auto-detected webroots/YARA/IOC/ClamAV; optional OSV and package verification; policy files are honored
- Export JSON or SARIF; dark/light themes; English/中文 **interface**
- Cross-navigation: inspect a finding's check, or show a check's findings

Run it:

```bash
make gui                       # cargo run --release -p warden-gui
cargo build --release -p warden-gui
```

Linux needs the usual windowing libraries; on Debian/Ubuntu:

```bash
sudo apt install libxkbcommon-dev libxkbcommon-x11-dev libwayland-dev
```

A Vulkan-capable GPU is recommended. On headless CI, the UI snapshot tests use `WGPU_BACKEND=gl` and do not need a display server.

macOS packages can be cross-built from Linux and ad-hoc signed on the Mac:

```bash
SDKROOT=~/sdk/MacOSX15.5.sdk make gui-mac-x86_64
# → dist/Warden-<version>-macos-x86_64.zip
```

The GUI chrome is bilingual, but engine-generated finding titles/messages/remediation, evidence, and check descriptions are currently English. Full report localization is pending; raw evidence should stay verbatim. The GUI is read-only and does not include the sandbox; use the CLI for `sandbox run/fetch`. The bundled Noto Sans SC font is SIL OFL 1.1 (`apps/warden-gui/assets/fonts/OFL.txt`). On macOS the app is unsigned/not notarized unless you sign it with your Developer ID; real-Mac regression testing is still required. See [docs/GUI.md](docs/GUI.md).

## Quick start

```bash
# Local scan (unprivileged: user scope + readable system config)
warden scan

# Full scan (read-only; /etc/shadow, other users' files, and process mapping need root)
sudo warden scan --verbose

# Interactive terminal UI (findings, evidence, filter)
warden scan --tui

# Desktop GUI (macOS / Linux)
cargo run --release -p warden-gui

# High-severity only, SARIF for CI/code scanning
sudo warden scan --min-severity high --format sarif --output warden.sarif

# Webshell scan of a web root
warden scan --webroot /var/www --checks fs.webshell

# IOC hash matching
warden scan --ioc known-bad.sha256 --path /home --path /tmp

# YARA rules (bring your own pack; none are bundled)
warden scan --yara ./rules

# Optional ClamAV known-malware scan (requires clamscan + freshclam)
warden scan --clamav

# Verify package-managed files (slow; dpkg/rpm/pacman)
warden scan --verify-packages

# OSV supply-chain check (network; sends package names to osv.dev)
warden scan --osv

# Known-malicious packages (offline dataset)
git clone --depth 1 https://github.com/ossf/malicious-packages ~/.config/warden/malicious
warden scan --path ./project          # scans node_modules / *.dist-info too

# Offline image / container rootfs scan
sudo warden scan --root /mnt/image

# Baseline, then report only new persistence
sudo warden baseline save --file /var/lib/warden/baseline.json
sudo warden scan --baseline /var/lib/warden/baseline.json

# Self-test with built-in backdoor fixtures (does not touch host config)
warden selftest
```

## Output and exit codes

- `text` (default, colored terminal), `json` (full machine-readable report), `sarif` (2.1.0, GitHub Code Scanning / GitLab compatible)
- `--tui` opens an interactive view over the same report: Findings (evidence/detail/filter) plus Checks (all selected checks, status, skip/failure reason, description); it requires a TTY and is separate from the scriptable formats
- Exit codes: `0` below threshold; `1` a finding reaches `--fail-on` (default `high`); `2` usage/runtime error
- `--fail-on never` always exits 0; `--min-severity` only affects display, never exit-code calculation

## Default behavior

No policy file is required. Built-in defaults are chosen for typical hosts:

- `min_severity=low`, `fail_on=high`, all applicable checks, 64M per-file limit
- web roots are auto-detected (`/var/www/html`, `/var/www`, `/srv/www`, `/usr/share/nginx/html`, `/var/lib/nginx/html`) and scanned for webshells when they exist
- YARA rules are auto-loaded from `~/.config/warden/rules`, `/etc/warden/rules`, `/usr/share/warden/rules` when present
- ClamAV is enabled automatically only when `clamscan` **and** a local signature database exist (`--no-clamav` disables it)
- package verification remains opt-in because it is slow (`--verify-packages`)
- allowlists are auto-loaded from `~/.config/warden/allowlist.toml` or `/etc/warden/allowlist.toml`

Inspect what will apply on this host:

```bash
warden config show            # text
warden config show --format json
```

## Policy file

Most users do not need this file; only override what differs. Generate a commented template with `warden config init` (add `--output` to choose a path, `--force` to overwrite).

Defaults can live in `--policy <file>`, `~/.config/warden/policy.toml`, or `/etc/warden/policy.toml`:

```toml
min_severity = "medium"
fail_on = "high"
checks = ["persist", "fs", "container"]
exclude = ["fs.suid"]
webroots = ["/var/www"]
ioc = "/etc/warden/ioc.txt"
yara = ["/etc/warden/rules"]
clamav = true
clamav_max_db_age_days = 7
verify_packages = false
max_file_size = "64M"
allowlist = "/etc/warden/allowlist.toml"
```

Explicit CLI flags win over policy values. List options use the CLI list when non-empty, otherwise the policy list. Boolean features are ORed, so a policy-enabled scanner cannot be disabled from the CLI yet.

## Allowlist

`~/.config/warden/allowlist.toml` (or `--allowlist`):

```toml
[[allow]]
check = "fs.suid"
path  = "/usr/local/bin/vendor-agent"
reason = "Vendor monitoring agent, approved"
expires = "2027-01-31"      # ignored after this date; expired count is reported

[[allow]]
check = "persist.cron"
fingerprint = "persist.cron|/etc/cron.d/backup|*"
reason = "Operations backup job"
```

`path` and `fingerprint` accept `*` / `?`. Using only `check` suppresses the whole check (use sparingly).

## IOC format

`--ioc` accepts a file or directory and auto-detects the format:

- plain text: one SHA-256/SHA-1/MD5, URL, domain, or IP per line (`#` comments allowed; `sha256:` prefix optional)
- abuse.ch CSV exports: MalwareBazaar (`sha256_hash`/`sha1_hash`/`md5_hash`), URLhaus (`url`), ThreatFox (`ioc_value` + `ioc_type`), Feodo Tracker (`dst_ip`)
- a directory containing any mix of the above

```text
# plain text
3f786850e387550fdab836ed7e6dc881de23001b7d3c6c5b6f0f1e2a3b4c5d6e
https://malware.example/payload
*.c2.example
192.0.2.10
```

File hashes are matched by `scan`, `sandbox run`, and `sandbox fetch`; URLs, domains, and IPs are matched by `sandbox fetch` against the requested URL, embedded URLs, and the downloaded hash.

Manage feeds without writing a policy file:

```bash
# atomic download with size/time limits; optional pinned checksum and auth header
warden intel fetch https://urlhaus.abuse.ch/downloads/csv_recent/ --name urlhaus.csv
warden intel fetch https://mb-api.abuse.ch/downloads/full.csv \
  --header 'Auth-Key: $ABUSECH_AUTH_KEY' --sha256 <hex>

warden intel show              # counts + stored files
warden scan                    # auto-loads ~/.config/warden/intel
```

`scan` automatically uses `~/.config/warden/intel` when `--ioc` is not given; pass `--ioc` to point elsewhere. `$VAR` / `${VAR}` in `--header` are expanded from the environment.

## Signature cache and database age

- Compiled YARA rules are cached under `~/.cache/warden/yara/`, keyed by the warden version and every rule file's content. Editing a rule invalidates the cache automatically; corrupted caches fall back to compilation.
- `--clamav` warns (Medium) when the ClamAV database is older than `--clamav-max-db-age` days (default 7, `0` disables). The ClamAV/DB version is reported in the backend Info item.

## Open-source signatures

There is no turnkey, freely redistributable "Linux trojan signature library". The practical combination is:

- **YARA-X** (BSD-3-Clause) as the rule engine
- **Neo23x0/signature-base** (Detection Rule License) for high-quality malware/APT/webshell rules
- **ClamAV** (GPL-2.0 engine, freely usable DB) as an optional known-malware backend
- **abuse.ch** feeds (CC0) for hashes/URLs/C2 IOCs
- **OSV** + **ossf/malicious-packages** (Apache-2.0) for package/supply-chain risk

YARA-X (`--yara`) and the optional ClamAV backend (`--clamav`, invoked as a separate process) are available on `scan`, `sandbox run`, and `sandbox fetch`; no third-party rules are bundled and ClamAV is off by default. `--osv` queries osv.dev for installed package vulnerabilities (ecosystem-dependent, cached for 24h, opt-in). Licensing pitfalls, per-source evaluation, and the remaining integration plan are documented in [docs/SIGNATURES.md](docs/SIGNATURES.md).

## Safety and privacy

- Read-only by default: no writes to scanned paths, no process termination, no config changes
- The sandbox's only writable paths are disposable copies and user-provided work directories
- No network access from scanned code; `sandbox fetch` is the only network operation and it never executes content
- Evidence fields truncate long values; no private keys or password hashes are printed
- When running as root, write reports to a protected location and treat them as sensitive

## Interactive TUI

`warden scan --tui` opens a terminal UI over the same scan engine:

- **Findings**: severity-colored list on the left, evidence/remediation on the right
- **Checks**: every selected check with status (`ran` / `skipped` / `failed`), match count, platforms, one-line description, and the exact skip/failure reason. This is the answer to "what did it actually inspect?" even when there are zero findings.
- `Tab` (or `1`/`2`) switches views; `Enter` cross-references a check with its findings, or a finding with its check
- `j`/`k` or arrows move, `g`/`G` jump, `/` filters the current view, `c` clears, `PgUp`/`PgDn` scroll detail, `?` shows help, `q` quits
- scanning runs on a background thread, so package/OSV checks do not block the UI

It requires a TTY and cannot be combined with JSON/SARIF output or `--output`.

## License

Warden is released under the [MIT License](LICENSE). The bundled Noto Sans SC
font is distributed under the SIL Open Font License 1.1; see
`apps/warden-gui/assets/fonts/OFL.txt`.

## Development

```bash
cargo test --workspace  # 73 core tests + 8 GUI tests (7 UI snapshots, one real-engine wiring test)
cargo run -- selftest   # end-to-end: 23 assertions (PAM/udev/at, container config, IOC, malicious package, YARA metadata, macOS layout + Mach-O)
```

Architecture, threat model, and roadmap: [docs/DESIGN.md](docs/DESIGN.md).

## Limitations

- No memory-only/fileless detection and no real-time protection; it answers "what persistence and suspicious artifacts exist right now"
- Mach-O code-signature verification, XProtect versions, and kernel-extension signing are not implemented yet
- macOS coverage of OpenDirectory, TCC, and login items (BTM) is limited; macOS code paths still need a real-Mac regression run (unit tests and the macOS image fixture currently execute on Linux)
- Heuristic rules produce false positives; use `--baseline` and allowlists, then judge with business context
- The sandbox shares the kernel and is not an anti-escape boundary
- `sandbox run` on macOS uses a Lima VM and needs a matching Linux guest binary; the native Virtualization.framework backend is still pending

---

## 中文说明

面向 macOS / Linux 的主机安全扫描器（Rust CLI）。它不是靠特征库的通用杀毒，而是**高信号的后门持久化审计器**，并内置 Linux 沙盒用于观察不可信安装器/二进制的真实行为。

**能力**：扫描 cron/systemd/launchd/shell rc/动态链接器/内核模块钩子/SSH 公钥等持久化点；检查 SUID、file capabilities、PATH 可写目录；识别伪装可执行文件、临时目录落地物、Webshell、IOC 哈希；检查账户、sshd、sudoers；用**基线漂移**只报告新增持久化项。

**桌面 GUI**：macOS / Linux 原生 egui/eframe 应用（`warden-gui`），与 CLI 共用同一扫描引擎和报告模型。包含 Findings、完整 Checks/覆盖率（含跳过/失败原因）、JSON/SARIF 导出、深色/浅色主题与中英文界面；不包含沙盒执行。界面本身支持中文，但扫描结果中的 finding 标题/说明/修复建议、证据和检查描述目前仍由引擎输出英文，完整结果本地化尚未实现。

```bash
make gui
# 或：cargo run --release -p warden-gui
```

### 沙盒

刻意把「下载」和「执行」分开：

1. `sandbox fetch` 受控下载到隔离目录并做静态体检，**不执行**。
2. `sandbox run` 在 bubblewrap 沙盒中执行：**无网络**，`/etc`、`/usr/local`、`$HOME`、`/tmp`、`/var/spool/cron` 使用宿主上的可写副本，执行前后做快照 diff，直接看出样本写了哪些持久化位置、释放了哪些文件。

```bash
warden sandbox doctor
warden sandbox fetch https://example.com/tool.tar.gz --output ./quarantine
warden sandbox run --workdir ./quarantine --keep --timeout 60 -- /bin/sh /work/install.sh
```

默认不需要策略文件：会自动发现常见 webroot、YARA 规则目录，并在 `clamscan` 与本地病毒库都存在时自动启用 ClamAV；`warden config show` 查看当前生效默认值，`warden config init` 生成注释模板。

macOS 上可用 `--engine vm` 把同一套沙盒跑在 Lima Linux VM 中：需要 `limactl`、guest 内安装 bubblewrap、以及匹配版本的 Linux warden 二进制；宿主与 guest 通过 `SandboxReport` JSON 交换结果。guest 二进制可用 `--vm-guest-binary` 指定，或用 `--vm-guest-url` / `WARDEN_GUEST_URL` 自动下载并校验 SHA-256（也支持 `<url>.sha256` 与 `warden sandbox vm fetch-guest`），缓存位于 `~/.cache/warden/guest/<version>/<arch>/warden`。

隔离模型：user/pid/net/ipc/uts/cgroup 命名空间全部 unshare；tmpfs 根 + 只读 `/usr`；遮蔽宿主 `/home`、`/root`、`/mnt`、`/boot`、`/srv`；清空环境变量；CPU/文件大小/超时限制；通过 systemd user scope 施加 cgroup v2 配额（默认 2 GiB 内存、256 任务、200% CPU，可用 `--mem/--pids/--cpus` 调整，0 关闭；无 systemd user session 时自动降级并在报告中说明）；可选 strace 观测外联、execve 链与内核操作。报告支持 `--format json`。

扫描结果也可用 `warden scan --tui` 在交互式终端界面中查看：`Findings` 视图显示 finding 列表与证据/修复建议；`Checks` 视图列出本次所有检查项（`ran` / `skipped` / `failed`）、命中数、适用平台、检查内容，以及跳过/失败的具体原因——即使零 finding，也能看出到底查了什么。`Tab`（或 `1`/`2`）切换视图，`Enter` 在检查项与对应 findings 之间跳转；`j`/`k` 移动、`/` 过滤、`?` 帮助、`q` 退出。需要 TTY，且不能与 JSON/SARIF 输出或 `--output` 同时使用。

**限制**：与宿主共享内核，定向内核漏洞可以逃逸；它用于快速行为分级，恶意样本的强隔离请使用 microVM。沙盒内默认无网络，因此安装器所需依赖需提前下载到 `--workdir`。

### 常用命令

```bash
sudo warden scan --verbose
sudo warden scan --format sarif --output warden.sarif
warden scan --tui
cargo run --release -p warden-gui
warden scan --webroot /var/www --checks fs.webshell
warden scan --ioc known-bad.sha256 --path /home
sudo warden baseline save --file /var/lib/warden/baseline.json
sudo warden scan --baseline /var/lib/warden/baseline.json
warden selftest
```

### 开源特征库

不存在可直接商用/再分发的「Linux 木马特征库」。可行组合：YARA-X（BSD-3-Clause 引擎）+ Neo23x0/signature-base（DRL 许可的高质量规则）+ ClamAV（GPL 引擎、病毒库免费）+ abuse.ch（CC0 IOC）+ OSV / ossf-malicious-packages（供应链）。

`--ioc` 现在支持 abuse.ch CSV（MalwareBazaar/URLhaus/ThreatFox/Feodo）和混合纯文本（SHA-256/SHA-1/MD5/URL/域名/IP）；哈希用于静态扫描与沙盒产物，URL/域名/IP 用于 `sandbox fetch`。`warden intel fetch <url>` 可原子下载并校验 feed，`warden intel show` 查看库内容；`scan` 在未指定 `--ioc` 时自动加载 `~/.config/warden/intel`。

支持通过 `--malicious`（默认 `~/.config/warden/malicious`）离线比对 ossf/malicious-packages，检查全局及项目内 npm/PyPI/crates.io 包；支持通过 `--osv` 查询已安装软件包的 OSV 漏洞（需要网络，结果缓存 24 小时，默认关闭；当前支持 Debian/Ubuntu/Alpine/Rocky/AlmaLinux/Wolfi）。

当前版本已支持 **IOC 情报**、**YARA-X 规则包**与**可选 ClamAV 后端**：`warden scan --yara ./rules`、`warden scan --clamav`；沙盒与下载体检同样支持 `--yara` / `--clamav`。不内置任何第三方规则；ClamAV 通过独立进程调用，默认关闭。许可证与更新由使用者负责。各来源的许可证陷阱与后续集成方案见 [docs/SIGNATURES.md](docs/SIGNATURES.md)。

### 安全承诺

扫描只读、不联网、不自动处置。以 root 运行时建议把报告写入受保护目录，并按敏感数据管理。

### 许可证

Warden 使用 [MIT License](LICENSE)。内置的 Noto Sans SC 字体使用 SIL Open Font License 1.1，见 `apps/warden-gui/assets/fonts/OFL.txt`。
