# Warden CLI Usage

`warden` is a single binary. This page is the practical command reference; the
design and threat model live in [DESIGN.md](DESIGN.md).

## Build

```bash
# Native (Linux or macOS)
cargo build --release
install -m755 target/release/warden /usr/local/bin/warden

# macOS Intel, cross-built from Linux with cargo-zigbuild
SDKROOT=~/sdk/MacOSX15.5.sdk make mac-x86_64
# or: SDKROOT=... scripts/build-macos.sh x86_64-apple-darwin

# Apple Silicon
SDKROOT=~/sdk/MacOSX15.5.sdk make mac-arm64

# Desktop GUI (macOS / Linux); see GUI.md
cargo run --release -p warden-gui

# Verify / run the test suite
make test
make lint
```

Cross-build requirements:

- `zig` on `PATH` and `cargo-zigbuild` (`cargo install cargo-zigbuild`)
- `rustup target add x86_64-apple-darwin` (or `aarch64-apple-darwin`)
- a macOS SDK in `SDKROOT` (for example `~/sdk/MacOSX15.5.sdk`); wasmtime
  links `CoreFoundation`, which zig does not ship
- `MACOSX_DEPLOYMENT_TARGET` defaults to `11.0`

Artifacts land in `dist/warden-<version>-<target>` with a `.sha256` sidecar.

## Scan

```bash
warden scan [OPTIONS]
```

| Option | Meaning |
|---|---|
| `--root DIR` | Scan a mounted image/rootfs instead of `/` |
| `--path DIR` | Extra roots for IOC/malicious-package/local scans (repeatable) |
| `--webroot DIR` | Web roots for webshell checks (repeatable; otherwise auto-detected) |
| `--checks a,b` / `--exclude a,b` | Check selection by id or prefix (`persist`, `fs`, …) |
| `--min-severity LEVEL` | Display threshold (`info`/`low`/`medium`/`high`/`critical`) |
| `--fail-on LEVEL` | Exit 1 at/above this level, or `never` |
| `--format text\|json\|sarif` | Output format |
| `--output FILE` | Write the report to a file (summary still printed) |
| `--baseline FILE` / `--save-baseline FILE` | Baseline diff / snapshot |
| `--allowlist FILE` | Exemption list (default `~/.config/warden/allowlist.toml`) |
| `--policy FILE` | Policy defaults (auto-discovers `~/.config/warden/policy.toml`, then `/etc/warden/policy.toml`) |
| `--ioc FILE\|DIR` | IOC feed or directory (plain text or abuse.ch CSV) |
| `--yara DIR\|FILE` | YARA-X rules (repeatable; none bundled) |
| `--clamav` / `--no-clamav` | Enable/disable the optional ClamAV backend |
| `--clamav-max-db-age DAYS` | Warn when the signature DB is stale (default 7; 0 disables) |
| `--verify-packages` / `--no-verify-packages` | dpkg/rpm/pacman file verification (slow) |
| `--osv` / `--no-osv` | OSV query for installed packages (network) |
| `--malicious DIR` | ossf/malicious-packages checkout (default `~/.config/warden/malicious`) |
| `--max-file-size SIZE` | Hash/scan size limit (default `64M`) |
| `--verbose` / `--quiet` / `--no-color` | Output control |
| `--tui` | Interactive ratatui interface (TTY only; requires text output; cannot combine with `--output`) |

Examples:

```bash
# Everyday local scan, full report
sudo warden scan --verbose

# CI: fail on high, SARIF for code scanning
sudo warden scan --min-severity high --format sarif --output warden.sarif

# Baseline: report only new persistence
sudo warden baseline save --file /var/lib/warden/baseline.json
sudo warden scan --baseline /var/lib/warden/baseline.json

# Image / container rootfs
sudo warden scan --root /mnt/image --verbose

# Interactive terminal UI
warden scan --tui

# Web server
warden scan --webroot /var/www --checks fs.webshell

# Threat intel (offline feed or abuse.ch CSV)
warden intel fetch https://urlhaus.abuse.ch/downloads/csv_recent/ --name urlhaus.csv
warden scan --ioc ~/.config/warden/intel --path /home

# Supply chain
warden scan --osv
git clone --depth 1 https://github.com/ossf/malicious-packages ~/.config/warden/malicious
warden scan --path ./project
```

## TUI keys

```
Tab / 1 / 2  switch Findings / Checks
Enter        cross-reference findings and checks
q / Esc      quit (cancels filter when editing)
j / Down     next item
k / Up       previous item
g / Home     first item
G / End      last item
/            filter the current view
c            clear filter
PgUp/PgDn    scroll detail
?            help
```

The `Checks` view shows every selected check with its status, match count,
platforms, description, and skip/failure reason.

## Sandbox

```bash
warden sandbox doctor
warden sandbox fetch <URL> [--output DIR] [--max-size 100M] [--ioc FEED] [--yara DIR] [--clamav]
warden sandbox run --workdir DIR [options] -- <command> [args...]
warden sandbox vm up|status|down
warden sandbox vm fetch-guest --url URL [--sha256 HEX]
```

`run` options:

| Option | Meaning |
|---|---|
| `--engine auto\|local\|vm` | `auto` = bubblewrap on Linux, Lima VM on macOS |
| `--workdir DIR` | Host directory bound to `/work` |
| `--timeout SECS` | Wall-clock limit (default 30) |
| `--mem SIZE` / `--pids N` / `--cpus N` | cgroup v2 limits (default 2G/256/2; 0 disables) |
| `--trace auto\|off` | strace integration when available |
| `--keep` | Keep the sandbox copy (VM mode exports a tarball/artifact dir) |
| `--ioc FEED` | Hash/URL/domain/IP feed for dropped artifacts |
| `--yara DIR` / `--clamav` | Content scanners for dropped artifacts |
| `--vm-name NAME` | Lima instance (default `warden-sandbox`) |
| `--vm-guest-binary FILE` | Linux warden binary copied into the VM |
| `--vm-guest-url URL` + `--vm-guest-sha256 HEX` | Verified download instead |
| `--format text\|json` | Report format |
| `--print-command` | Print the underlying bwrap/Lima command |

Examples:

```bash
# Triage a downloaded installer offline
warden sandbox fetch https://example.com/install.sh --output ./q
warden sandbox run --workdir ./q --keep --timeout 60 -- /bin/sh /work/install.sh

# Stricter resource envelope + YARA
warden sandbox run --mem 512M --pids 128 --cpus 1 --yara ./rules \
  --workdir ./samples -- /bin/sh /work/install.sh

# macOS: enforce a Linux VM
warden sandbox vm up
limactl shell warden-sandbox -- sudo apt-get install -y bubblewrap
warden sandbox run --engine vm --vm-guest-url <release-url> \
  --workdir ./q -- /bin/sh /work/install.sh
```

The sandbox has no network by default; pre-download dependencies into the
workdir. The sample never gains host root; cgroup limits apply when a systemd
user scope is available.

## Feeds

```bash
warden intel fetch <URL> [--name FILE] [--header 'Auth-Key: $ABUSECH_AUTH_KEY'] [--sha256 HEX] [--dir DIR]
warden intel show [--dir DIR] [--format json]
```

`$VAR` and `${VAR}` in `--header` are expanded from the environment. `scan`
automatically loads `~/.config/warden/intel` when `--ioc` is absent.

## Configuration

Most hosts need no configuration:

```bash
warden config show           # built-in defaults and auto-detected paths
warden config init           # commented policy template
warden config init --output ./policy.toml --force
```

Auto-detection: web roots, YARA rule directories (`~/.config/warden/rules`,
`/etc/warden/rules`, `/usr/share/warden/rules`), ClamAV (only with a local DB),
and allowlists. Explicit flags win; lists use the CLI value when non-empty.

## Baseline and allowlist

```bash
warden baseline save --file warden-baseline.json
warden baseline show warden-baseline.json [--verbose]
```

```toml
# ~/.config/warden/allowlist.toml
[[allow]]
check = "fs.suid"
path = "/usr/local/bin/vendor-agent"
reason = "Approved vendor agent"
expires = "2027-01-31"
```

## Checks and self-test

```bash
warden checks               # ids, titles, platforms
warden checks --format json
warden selftest             # built-in fixtures, no host changes
```

## Exit codes

| Code | Meaning |
|---|---|
| 0 | No finding at or above `--fail-on` |
| 1 | Finding at or above `--fail-on` (scan) / high-risk (sandbox) |
| 2 | Usage or runtime error |

`--fail-on never` always exits 0. `--min-severity` only affects display.

## Privileges

Unprivileged scans cover user-level persistence, PATH, SUID, webshells, IOC,
container config, and readable package manifests. `sudo` is needed for
`/etc/shadow`, other users' files, and full listener/process mapping. The
scanner is read-only; `sandbox fetch` is the only network operation and never
executes downloaded content.
