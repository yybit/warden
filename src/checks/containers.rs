//! Container runtime configuration checks.
//!
//! Misconfigured runtimes are a direct host-compromise path: a Docker API on
//! TCP without client verification, disabled TLS verification for registries,
//! or `AlwaysAllow` kubelet authorization all amount to remote root.
//!
//! The check parses both JSON (Docker) and TOML (containerd/CRI-O/Podman)
//! configurations, plus line-oriented k3s/kubelet YAML.

use crate::checks::Check;
use crate::ctx::ScanContext;
use crate::model::{Confidence, Finding, Os, Severity};
use crate::util;
use anyhow::Result;
use serde_json::Value;
use std::path::Path;

const MAX_CONFIG: u64 = 4 * util::MB;

pub struct ContainerConfigCheck;

impl Check for ContainerConfigCheck {
    fn id(&self) -> &'static str {
        "container.config"
    }
    fn title(&self) -> &'static str {
        "Container runtime configuration"
    }
    fn description(&self) -> &'static str {
        "Docker/containerd/CRI-O/Podman/k3s/kubelet trust and auth settings, plus docker group membership."
    }
    fn platforms(&self) -> &'static [Os] {
        &[Os::Linux]
    }

    fn run(&self, ctx: &ScanContext) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        // Docker daemon (JSON)
        let docker = ctx.abs("/etc/docker/daemon.json");
        if let Some(text) = util::read_text(&docker, MAX_CONFIG) {
            check_permissions(ctx, self.id(), &docker, &mut findings);
            match serde_json::from_str::<Value>(&text) {
                Ok(v) => findings.extend(docker_findings(&v, &ctx.disp(&docker))),
                Err(e) => findings.push(
                    Finding::new(
                        self.id(),
                        Severity::Info,
                        "Docker daemon.json is not valid JSON",
                        format!("cannot evaluate the configuration: {e}"),
                    )
                    .at(ctx.disp(&docker), None)
                    .confidence(Confidence::Certain),
                ),
            }
        }

        // containerd main config
        let containerd = ctx.abs("/etc/containerd/config.toml");
        if let Some(text) = util::read_text(&containerd, MAX_CONFIG) {
            check_permissions(ctx, self.id(), &containerd, &mut findings);
            match toml::from_str::<toml::Value>(&text) {
                Ok(v) => {
                    let mut issues = Vec::new();
                    walk_toml(&v, "", false, &mut issues);
                    findings.extend(toml_findings(&issues, &ctx.disp(&containerd), "containerd"));
                }
                Err(e) => findings.push(
                    Finding::new(
                        self.id(),
                        Severity::Info,
                        "containerd config.toml is not valid TOML",
                        format!("cannot evaluate the configuration: {e}"),
                    )
                    .at(ctx.disp(&containerd), None)
                    .confidence(Confidence::Certain),
                ),
            }
        }

        // containerd certs.d overrides
        let certs_root = ctx.abs("/etc/containerd/certs.d");
        for dir in util::dirs_in(&certs_root) {
            let hosts = dir.join("hosts.toml");
            if let Some(text) = util::read_text(&hosts, MAX_CONFIG) {
                check_permissions(ctx, self.id(), &hosts, &mut findings);
                if let Ok(v) = toml::from_str::<toml::Value>(&text) {
                    let mut issues = Vec::new();
                    walk_toml(&v, "", true, &mut issues);
                    findings.extend(toml_findings(&issues, &ctx.disp(&hosts), "containerd"));
                }
            }
        }

        // Podman / CRI-O registry configuration
        let mut registry_files = vec![
            ctx.abs("/etc/containers/registries.conf"),
            ctx.abs("/etc/crio/crio.conf"),
        ];
        for dir in ["/etc/containers/registries.conf.d", "/etc/crio/crio.conf.d"] {
            for file in util::files_in(&ctx.abs(dir)) {
                registry_files.push(file);
            }
        }
        for file in registry_files {
            if let Some(text) = util::read_text(&file, MAX_CONFIG) {
                check_permissions(ctx, self.id(), &file, &mut findings);
                if let Ok(v) = toml::from_str::<toml::Value>(&text) {
                    let mut issues = Vec::new();
                    walk_toml(&v, "", true, &mut issues);
                    findings.extend(toml_findings(&issues, &ctx.disp(&file), "podman/crio"));
                }
            }
        }

        // k3s registry config (YAML, line-oriented)
        let k3s = ctx.abs("/etc/rancher/k3s/registries.yaml");
        if let Some(text) = util::read_text(&k3s, MAX_CONFIG) {
            check_permissions(ctx, self.id(), &k3s, &mut findings);
            findings.extend(yaml_registry_findings(&text, &ctx.disp(&k3s), "k3s"));
        }

        // kubelet config (YAML, targeted heuristics)
        let kubelet = ctx.abs("/var/lib/kubelet/config.yaml");
        if let Some(text) = util::read_text(&kubelet, MAX_CONFIG) {
            check_permissions(ctx, self.id(), &kubelet, &mut findings);
            findings.extend(kubelet_findings(&text, &ctx.disp(&kubelet)));
        }

        // docker group membership is root-equivalent
        let group = ctx.abs("/etc/group");
        if let Some(text) = util::read_text(&group, MAX_CONFIG) {
            for (line_no, line) in text.lines().enumerate() {
                if let Some(members) = docker_group_members(line) {
                    findings.push(
                        Finding::new(
                            self.id(),
                            Severity::Medium,
                            "Users have root-equivalent access via the docker group",
                            "Members of `docker` can start privileged containers and control the host",
                        )
                        .at(ctx.disp(&group), Some(line_no + 1))
                        .evidence(format!("members={}", members.join(",")))
                        .fix("Remove unnecessary members; use rootless Docker or restricted sudo rules")
                        .confidence(Confidence::Likely)
                        .mitre("T1611"),
                    );
                }
            }
        }

        Ok(findings)
    }
}

fn check_permissions(ctx: &ScanContext, check: &str, path: &Path, findings: &mut Vec<Finding>) {
    if let Some(mode) = util::mode_of(path) {
        if util::is_world_writable(mode) {
            findings.push(
                Finding::new(
                    check,
                    Severity::High,
                    "Container runtime configuration is world-writable",
                    "Any local user can change runtime behavior or registry trust",
                )
                .at(ctx.disp(path), None)
                .fix("chmod o-w and verify the configuration contents")
                .confidence(Confidence::Certain)
                .mitre("T1611"),
            );
        }
    }
}

pub fn docker_findings(v: &Value, path: &str) -> Vec<Finding> {
    let mut out = Vec::new();

    if let Some(hosts) = v.get("hosts").and_then(|h| h.as_array()) {
        let tcp: Vec<&str> = hosts
            .iter()
            .filter_map(|h| h.as_str())
            .filter(|h| h.starts_with("tcp://"))
            .collect();
        if !tcp.is_empty() {
            let verify = v
                .get("tlsverify")
                .and_then(|b| b.as_bool())
                .unwrap_or(false);
            let tls = v.get("tls").and_then(|b| b.as_bool()).unwrap_or(false);
            if !verify {
                out.push(
                    Finding::new(
                        "container.config",
                        if tls {
                            Severity::High
                        } else {
                            Severity::Critical
                        },
                        if tls {
                            "Docker API uses TLS without client certificate verification"
                        } else {
                            "Docker API is exposed over TCP without TLS"
                        },
                        "The Docker API grants host root; unauthenticated or unverified access is remote takeover",
                    )
                    .at(path, None)
                    .evidence(tcp.join(", "))
                    .fix("Remove tcp:// hosts or enable tlsverify with client certificates")
                    .confidence(Confidence::Certain)
                    .mitre("T1610"),
                );
            }
        }
    }

    if let Some(regs) = v.get("insecure-registries").and_then(|r| r.as_array()) {
        if !regs.is_empty() {
            let list: Vec<&str> = regs.iter().filter_map(|x| x.as_str()).collect();
            out.push(
                Finding::new(
                    "container.config",
                    Severity::Medium,
                    "Docker trusts insecure registries",
                    "Images can be pulled over plaintext HTTP or without verified TLS",
                )
                .at(path, None)
                .evidence(list.join(", "))
                .fix("Remove insecure-registries or deploy a trusted TLS registry")
                .confidence(Confidence::Certain)
                .mitre("T1610"),
            );
        }
    }

    if v.get("iptables").and_then(|b| b.as_bool()) == Some(false) {
        out.push(
            Finding::new(
                "container.config",
                Severity::Medium,
                "Docker iptables management is disabled",
                "Container network isolation and port publishing rules are not enforced",
            )
            .at(path, None)
            .fix("Re-enable iptables unless an external firewall fully replaces it")
            .confidence(Confidence::Likely)
            .mitre("T1611"),
        );
    }

    out
}

#[derive(Debug, Clone)]
struct TomlIssue {
    key: String,
    severity: Severity,
    title: &'static str,
}

fn walk_toml(v: &toml::Value, path: &str, registry_ctx: bool, out: &mut Vec<TomlIssue>) {
    match v {
        toml::Value::Table(table) => {
            for (key, value) in table {
                let k = key.to_ascii_lowercase();
                let here = if path.is_empty() {
                    k.clone()
                } else {
                    format!("{path}.{k}")
                };
                let in_registry = registry_ctx
                    || k.contains("registry")
                    || k.contains("mirror")
                    || k.contains("certs");

                if k.contains("insecure_skip_verify") && value.as_bool() == Some(true) {
                    out.push(TomlIssue {
                        key: here.clone(),
                        severity: Severity::High,
                        title: "Registry TLS verification is disabled",
                    });
                }
                if in_registry
                    && matches!(k.as_str(), "endpoint" | "address" | "server" | "location")
                {
                    if let Some(s) = value.as_str() {
                        if s.starts_with("http://") {
                            out.push(TomlIssue {
                                key: here.clone(),
                                severity: Severity::Medium,
                                title: "Plaintext HTTP registry endpoint",
                            });
                        }
                    }
                }
                if k == "insecure" && value.as_bool() == Some(true) {
                    out.push(TomlIssue {
                        key: here.clone(),
                        severity: Severity::Medium,
                        title: "Registry is marked insecure",
                    });
                }
                if k == "insecure_registries" {
                    if let Some(arr) = value.as_array() {
                        if !arr.is_empty() {
                            out.push(TomlIssue {
                                key: here.clone(),
                                severity: Severity::Medium,
                                title: "Insecure registries are configured",
                            });
                        }
                    }
                }
                walk_toml(value, &here, in_registry, out);
            }
        }
        toml::Value::Array(arr) => {
            for (i, value) in arr.iter().enumerate() {
                walk_toml(value, &format!("{path}[{i}]"), registry_ctx, out);
            }
        }
        _ => {}
    }
}

fn toml_findings(issues: &[TomlIssue], path: &str, runtime: &str) -> Vec<Finding> {
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::new();
    for issue in issues {
        if !seen.insert(issue.key.clone()) {
            continue;
        }
        out.push(
            Finding::new(
                "container.config",
                issue.severity,
                issue.title,
                format!("{runtime} registry configuration weakens image trust"),
            )
            .at(path, None)
            .evidence(issue.key.clone())
            .fix("Use HTTPS with certificate verification, or restrict the mirror to trusted hosts")
            .confidence(Confidence::Certain)
            .mitre("T1610"),
        );
    }
    out
}

fn yaml_registry_findings(text: &str, path: &str, runtime: &str) -> Vec<Finding> {
    let mut out = Vec::new();
    for (line_no, line) in text.lines().enumerate() {
        let t = line.trim();
        if t.starts_with('#') || t.is_empty() {
            continue;
        }
        let lower = t.to_ascii_lowercase();
        if lower.starts_with("insecure_skip_verify:") && lower.contains("true") {
            out.push(
                Finding::new(
                    "container.config",
                    Severity::High,
                    "Registry TLS verification is disabled",
                    format!("{runtime} will accept any certificate for this registry"),
                )
                .at(path, Some(line_no + 1))
                .evidence(t)
                .fix("Set insecure_skip_verify to false and install the CA")
                .confidence(Confidence::Certain)
                .mitre("T1610"),
            );
        }
        if (lower.starts_with("server:")
            || lower.starts_with("endpoint:")
            || lower.starts_with("- http://"))
            && lower.contains("http://")
        {
            out.push(
                Finding::new(
                    "container.config",
                    Severity::Medium,
                    "Plaintext HTTP registry endpoint",
                    format!("{runtime} registry traffic is unencrypted"),
                )
                .at(path, Some(line_no + 1))
                .evidence(t)
                .fix("Use https:// for registry endpoints")
                .confidence(Confidence::Certain)
                .mitre("T1610"),
            );
        }
    }
    out
}

fn kubelet_findings(text: &str, path: &str) -> Vec<Finding> {
    let mut out = Vec::new();
    let mut anonymous = false;

    for (line_no, line) in text.lines().enumerate() {
        let t = line.trim();
        if t.is_empty() || t.starts_with('#') {
            continue;
        }
        let lower = t.to_ascii_lowercase();
        if lower.starts_with("anonymous:") {
            anonymous = true;
            continue;
        }
        if anonymous {
            if lower.starts_with("enabled:") {
                if lower.contains("true") {
                    out.push(
                        Finding::new(
                            "container.config",
                            Severity::High,
                            "kubelet anonymous authentication is enabled",
                            "Unauthenticated requests can reach the kubelet API",
                        )
                        .at(path, Some(line_no + 1))
                        .evidence(t)
                        .fix("Set authentication.anonymous.enabled to false")
                        .confidence(Confidence::Certain)
                        .mitre("T1610"),
                    );
                }
                anonymous = false;
            } else if !t.starts_with('-') {
                anonymous = false;
            }
        }
        if lower.starts_with("mode:") && lower.contains("alwaysallow") {
            out.push(
                Finding::new(
                    "container.config",
                    Severity::High,
                    "kubelet authorization mode is AlwaysAllow",
                    "Any authenticated or anonymous request is authorized",
                )
                .at(path, Some(line_no + 1))
                .evidence(t)
                .fix("Use Webhook authorization mode")
                .confidence(Confidence::Certain)
                .mitre("T1610"),
            );
        }
        if let Some(rest) = lower.strip_prefix("readonlyport:") {
            if let Ok(port) = rest.trim().parse::<u16>() {
                if port > 0 {
                    out.push(
                        Finding::new(
                            "container.config",
                            Severity::Medium,
                            "kubelet read-only port is enabled",
                            "The unauthenticated read-only endpoint exposes pod and node data",
                        )
                        .at(path, Some(line_no + 1))
                        .evidence(t)
                        .fix("Set readOnlyPort to 0")
                        .confidence(Confidence::Certain)
                        .mitre("T1610"),
                    );
                }
            }
        }
    }
    out
}

fn docker_group_members(line: &str) -> Option<Vec<String>> {
    let fields: Vec<&str> = line.trim().split(':').collect();
    if fields.len() < 4 || fields[0] != "docker" {
        return None;
    }
    let members: Vec<String> = fields[3]
        .split(',')
        .map(|m| m.trim())
        .filter(|m| !m.is_empty())
        .map(|m| m.to_string())
        .collect();
    if members.is_empty() {
        None
    } else {
        Some(members)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn docker_exposure_and_tls() {
        let exposed: Value = serde_json::from_str(
            r#"{"hosts":["tcp://0.0.0.0:2375"],"insecure-registries":["http://reg"]}"#,
        )
        .unwrap();
        let findings = docker_findings(&exposed, "/etc/docker/daemon.json");
        assert!(findings.iter().any(|f| f.severity == Severity::Critical));
        assert!(findings.iter().any(|f| f.severity == Severity::Medium));

        let tls_only: Value =
            serde_json::from_str(r#"{"hosts":["tcp://0.0.0.0:2376"],"tls":true}"#).unwrap();
        let findings = docker_findings(&tls_only, "x");
        assert!(findings.iter().any(|f| f.severity == Severity::High));

        let verified: Value =
            serde_json::from_str(r#"{"hosts":["tcp://0.0.0.0:2376"],"tls":true,"tlsverify":true}"#)
                .unwrap();
        assert!(docker_findings(&verified, "x").is_empty());
    }

    #[test]
    fn containerd_and_podman_toml() {
        let text = r#"
[plugins."io.containerd.grpc.v1.cri".registry.configs."reg.local".tls]
  insecure_skip_verify = true
"#;
        let v: toml::Value = toml::from_str(text).unwrap();
        let mut issues = Vec::new();
        walk_toml(&v, "", false, &mut issues);
        assert!(issues.iter().any(|i| i.severity == Severity::High));

        let podman: toml::Value =
            toml::from_str("[[registry]]\nlocation = \"http://reg\"\ninsecure = true\n").unwrap();
        let mut issues = Vec::new();
        walk_toml(&podman, "", true, &mut issues);
        assert!(issues.iter().any(|i| i.severity == Severity::Medium));
    }

    #[test]
    fn kubelet_and_group() {
        let text = "authentication:\n  anonymous:\n    enabled: true\nauthorization:\n  mode: AlwaysAllow\nreadOnlyPort: 10255\n";
        let f = kubelet_findings(text, "/var/lib/kubelet/config.yaml");
        assert!(f.iter().any(|x| x.title.contains("anonymous")));
        assert!(f.iter().any(|x| x.title.contains("AlwaysAllow")));
        assert!(f.iter().any(|x| x.title.contains("read-only")));

        assert_eq!(
            docker_group_members("docker:x:999:alice,bob").unwrap(),
            vec!["alice".to_string(), "bob".to_string()]
        );
        assert!(docker_group_members("docker:x:999:").is_none());
        assert!(docker_group_members("wheel:x:10:alice").is_none());
    }
}
