# Open-Source Signature Sources

Short answer: **there is no turnkey, freely redistributable "Linux trojan signature library"** that you can drop into a product and call it detection. What exists is a set of complementary sources with different licenses, coverage, and maintenance models. This document evaluates them and defines how Warden can consume them without creating legal or engineering debt.

## 1. What each source actually gives you

| Source | Type | License | Best for | Main caveat |
|---|---|---|---|---|
| [YARA-X](https://github.com/VirusTotal/yara-x) | Rule engine (Rust) | BSD-3-Clause | Content signatures for files, scripts, webshells, memory dumps | Engine only; brings no rules |
| [yara](https://github.com/VirusTotal/yara) | Rule engine (C) | BSD-3-Clause | Same, if you need the classic engine | C dependency; YARA-X is the better Rust fit |
| [Neo23x0/signature-base](https://github.com/Neo23x0/signature-base) | YARA rules | Detection Rule License (DRL) 1.1 | High-quality malware/APT/webshell rules, Linux coverage included | Free to use, but redistribution/commercial terms must be reviewed; do not bundle blindly |
| [Yara-Rules/rules](https://github.com/Yara-Rules/rules) | YARA rules | Mixed; verify per repo/file (commonly CC BY-SA) | Broad community coverage, packers, webshells | License varies by file; attribution/share-alike obligations |
| [Elastic protections-artifacts](https://github.com/elastic/protections-artifacts) | YARA rules | Elastic License 2.0 (source-available, not OSI) | High-quality Linux/Windows malware rules | Cannot be freely redistributed in a product; no managed-service use |
| [ClamAV](https://github.com/Cisco-Talos/clamav) | AV engine + signature DB | Engine GPL-2.0; DB distributed by Cisco Talos | Known-malware hashes/patterns, archives, webshells | GPL boundary if linked; DB terms must be checked before bundling |
| [clamav-unofficial-sigs](https://github.com/extremeshok/clamav-unofficial-sigs) | Third-party ClamAV signatures | Mixed; many non-commercial | Extra coverage (Sanesecurity, SecuriteInfo, …) | Not redistributable; personal-use restrictions are common |
| [chainguard-dev/malcontent](https://github.com/chainguard-dev/malcontent) | Capability/behavior rules (own YAML format) | Apache-2.0 | Supply-chain and package malware triage on Linux | Own rule format; better as inspiration/embedded engine than YARA replacement |
| [ossf/malicious-packages](https://github.com/ossf/malicious-packages) | Dataset of malicious package versions | Apache-2.0 | Blocking known-bad npm/PyPI/Go/Ruby packages | Name/version matching, not file signatures |
| [abuse.ch](https://abuse.ch/) (MalwareBazaar, URLhaus, ThreatFox, Feodo Tracker) | IOC feeds | Free to use; most datasets CC0; API key required | SHA-256, URLs, C2 IPs/domains | Feed quality varies; rate limits; not "signatures" |
| [Google OSV](https://osv.dev/) | Vulnerability database/API | Apache-2.0 | Known CVEs in installed packages | Vulnerabilities, not malware |
| [VirusTotal](https://www.virustotal.com/) | Multi-engine reputation API | Proprietary | Hash reputation, sandbox reports | Free tier has non-commercial restrictions; never upload sensitive samples without policy |

Prior art worth reading (not signature sources): `chkrootkit` and `rkhunter` (GPL) focus on local rootkit heuristics; `Lynis` (GPLv3) focuses on host hardening audits.

## 2. Recommended architecture

Do not pick one source. Split by evidence type:

```
                    ┌──────────────────────────────┐
 file content  ───► │ YARA-X engine                │ ◄── user-supplied rule dirs
                    │ (BSD-3-Clause)               │     (signature-base, community, in-house)
                    └──────────────┬───────────────┘
                                   │
 known malware ───► ┌──────────────▼───────────────┐
 (optional)         │ ClamAV backend (separate     │
                    │ process, GPL boundary)       │
                    └──────────────┬───────────────┘
                                   │
 hashes / C2  ────► ┌──────────────▼───────────────┐
                    │ IOC store (SQLite)           │ ◄── abuse.ch feeds (CC0)
                    └──────────────┬───────────────┘
                                   │
 packages     ────► ┌──────────────▼───────────────┐
                    │ OSV + ossf/malicious-packages│
                    └──────────────────────────────┘
```

### Stage 1 — YARA-X (implemented in 0.2)

Usage:

```bash
warden scan --yara ./rules
warden sandbox run --yara ./rules --workdir ./q -- /bin/sh /work/install.sh
warden sandbox fetch --yara ./rules https://example.com/tool.bin --output ./q
```

- `yara-x` is compiled in; one rule set is compiled per invocation and reused for all scanned files.
- Metadata mapping: `severity`/`level` → finding severity (default Medium), `description`/`desc`/`info` → title, `reference`/`author`/`license` → evidence, `attack`/`mitre`/`technique` → ATT&CK ids.
- Scanning targets are deliberately narrow: persistence configs, `/tmp`, `/var/tmp`, web roots, `--path` roots, and sandbox-dropped artifacts. Whole-filesystem YARA scans are not performed.
- Compiled rules are cached under `<XDG_CACHE_HOME>/warden/yara/`; the key covers the warden version and rule content, so edits invalidate automatically.
- Ship **no third-party rules by default**. Provide `--yara <dir>` and a documented `rules/` layout. This keeps licensing with the user/operator and avoids stale bundled rules.
- Scan only high-value targets to keep runtime low: persistence configs, `/tmp`, `/var/tmp`, web roots, `--workdir` samples, and dropped artifacts found by the sandbox.
- Map rule metadata (`severity`, `description`, `reference`, `author`, `license`) into `Finding`; include the rule name and source in `evidence`.
- Rule packs are data, not code: version them, record their hash and update date in the report.

### Stage 2 — ClamAV (implemented in 0.3 as an optional process boundary)

Usage:

```bash
warden scan --clamav
warden scan --clamav --clamav-db /var/lib/clamav
warden sandbox run --clamav --workdir ./q -- /bin/sh /work/install.sh
warden sandbox fetch --clamav https://example.com/tool.bin --output ./q
```

- `clamscan` runs as a **separate process** over a file list; `libclamav` is not linked, keeping GPL-2.0 obligations at the process boundary.
- The backend is off by default and skipped when `clamscan` is missing, so the scanner works without ClamAV.
- `FOUND` lines map to High-severity findings; the ClamAV/DB version is surfaced in an Info item and `sandbox doctor`.
- An exit code above 1 (usually a missing/stale database) fails the check instead of silently reporting "clean".
- Database build dates are parsed from `clamscan --version`; a Medium finding is emitted beyond `--clamav-max-db-age` days (default 7).
- Never bundle `clamav-unofficial-sigs` datasets; they are commonly non-commercial.

### Stage 3 — IOC store

- Source: abuse.ch MalwareBazaar (SHA-256), URLhaus (URLs), ThreatFox (C2), Feodo Tracker (botnet C2).
- Store in SQLite with `source`, `fetched_at`, `expires_at`, `type`, `value`, `context`.
- `--ioc` parses abuse.ch CSV exports (MalwareBazaar/URLhaus/ThreatFox/Feodo) and plain mixed IOCs; file hashes are matched by scan/sandbox and URLs/domains/IPs by `sandbox fetch`. `warden intel fetch <url>` downloads feeds atomically with size/time limits, optional checksum and headers; `warden intel show` lists counts/files; `scan` auto-loads `~/.config/warden/intel`. A scheduler/daemon, listener matching, and sandbox `connect()` matching are still pending.
- Respect API keys and rate limits; support offline import of a downloaded feed.

### Stage 4 — Supply chain

- `OSV` API for installed package versions (dpkg/rpm/apk, npm, pip, cargo).
- `ossf/malicious-packages` for known-bad package versions before install; this pairs naturally with the sandbox's "install offline and observe" workflow.
- `chainguard-dev/malcontent` rules for capability-level triage (`/bin/sh` spawning from an installer, embedded ELF, credential access) — Apache-2.0 and designed for Linux packages.

## 3. License pitfalls (read before shipping)

1. **Engine license ≠ rule license.** YARA-X being BSD-3-Clause says nothing about the rules you load.
2. **Signature-base is DRL, not OSI.** Free use is allowed, but redistribution and commercial embedding need review. Keep it a user-installed pack.
3. **Elastic rules are source-available.** Elastic License 2.0 restricts providing the software as a hosted service and removing license notices. Do not ship them in a product binary.
4. **ClamAV is GPL-2.0.** Separate-process invocation is the pragmatic boundary; static/dynamic linking changes your obligations.
5. **Unofficial ClamAV signatures are often non-commercial.** Never bundle; document how users can add them.
6. **Community YARA repos mix licenses per file.** Preserve headers and attribution; run a license scan in CI.
7. **Threat-intel APIs have terms.** VirusTotal's free tier is non-commercial; abuse.ch requires a key and rate-limits.

## 4. What Warden should implement, in order

| Milestone | Work | Why |
|---|---|---|
| M1 (done) | `--ioc` SHA-256 matching; sandbox artifact hashing | No licensing risk, immediate value |
| 0.2 (done) | `--yara <dir>` via YARA-X on `scan`, `sandbox run`, `sandbox fetch`; metadata → severity | Biggest detection gain per engineering hour |
| 0.3 (done) | `--clamav` optional backend (separate process), shared scan targets, doctor integration | Known-malware coverage without reimplementing AV |
| 0.9 (done) | Compiled-rule cache; ClamAV database-age warnings | Faster startup; operational safety |
| 0.11 (done) | Offline abuse.ch CSV/plain feeds; SHA-1/MD5; URL/domain/IP matching in fetch | Immediate value without API keys |
| M3 | abuse.ch sync into SQLite; match listeners + sandbox egress | Live intelligence |
| 0.13 (done) | OSV query for installed packages (Debian/Ubuntu/Alpine/Rocky/AlmaLinux/Wolfi), 24h cache | Supply-chain vulnerability coverage |
| 0.15 (done) | `ossf/malicious-packages` offline dataset; global + project npm/PyPI/crates.io matching | Known-bad package versions |
| M3 | scheduled dataset refresh and pre-install blocking | Operational supply-chain control |
| M4 | Rule pack manager (`warden rules add/update/verify`) with license metadata | Operational usability without bundling restricted rules |

## 5. Realistic expectations

- YARA + curated rules catches known families, webshells, and toolkits; it will not catch a custom, lightly obfuscated dropper.
- ClamAV's Linux coverage is useful for commodity malware and webshells, not APT tooling.
- IOC feeds are precise but short-lived; they complement, not replace, behavior analysis.
- The strongest signal in this project remains **behavioral**: persistence writes, loader hijacks, and the sandbox diff. Signatures are a multiplier, not the foundation.
