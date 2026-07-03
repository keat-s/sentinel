//! Static checks over parsed MCP client configs — no code is executed.

use std::collections::HashMap;

use crate::model::{Finding, McpServer, Severity, Transport};

/// Run every static check over the discovered servers.
pub fn run_static_checks(servers: &[McpServer]) -> Vec<Finding> {
    let mut findings = Vec::new();
    for server in servers {
        if let Some(f) = check_ungoverned(server) {
            findings.push(f);
        }
        if let Some(f) = check_unpinned(server) {
            findings.push(f);
        }
        if let Some(f) = check_plaintext_url(server) {
            findings.push(f);
        }
        if let Some(f) = check_shell_launcher(server) {
            findings.push(f);
        }
        findings.extend(check_inline_secrets(server));
    }
    findings.extend(check_duplicate_names(servers));
    findings
}

/// SENTINEL-001: a stdio server not wrapped by sentinel-gateway — every tool
/// call is an unmonitored, unpoliced access path.
fn check_ungoverned(server: &McpServer) -> Option<Finding> {
    if server.transport != Transport::Stdio || server.is_governed() {
        return None;
    }
    Some(Finding {
        check: "SENTINEL-001".into(),
        severity: Severity::Medium,
        server: Some(server.name.clone()),
        source: server.source.clone(),
        title: "ungoverned MCP server".into(),
        detail: format!(
            "`{}` launches `{}` directly; tool calls are not policy-checked or audited",
            server.name,
            server.command.as_deref().unwrap_or("?")
        ),
        recommendation: "wrap it: sentinel-gateway wrap --config <cfg> -- <command> (see docs/agent-governance.md)"
            .into(),
    })
}

/// SENTINEL-002: package fetched at launch without a pinned version — a
/// compromised registry release runs with the agent's privileges on next start.
fn check_unpinned(server: &McpServer) -> Option<Finding> {
    let base = server.command_base()?;
    let package_arg = || {
        server
            .args
            .iter()
            .find(|a| !a.starts_with('-'))
            .cloned()
            .unwrap_or_default()
    };
    let (launcher, pinned, spec) = match base {
        "npx" | "bunx" => {
            let spec = package_arg();
            (base, spec.get(1..).is_some_and(|rest| rest.contains('@')), spec)
        }
        "uvx" | "pipx" => {
            let spec = package_arg();
            (
                base,
                spec.contains("==") || spec.get(1..).is_some_and(|rest| rest.contains('@')),
                spec,
            )
        }
        "docker" | "podman" => {
            let latest = server
                .args
                .iter()
                .find(|a| a.ends_with(":latest"))
                .cloned();
            match latest {
                Some(image) => (base, false, image),
                None => return None,
            }
        }
        _ => return None,
    };
    if pinned || spec.is_empty() {
        return None;
    }
    let auto_yes = server.args.iter().any(|a| a == "-y" || a == "--yes");
    Some(Finding {
        check: "SENTINEL-002".into(),
        severity: if auto_yes { Severity::High } else { Severity::Medium },
        server: Some(server.name.clone()),
        source: server.source.clone(),
        title: "unpinned MCP server package".into(),
        detail: format!(
            "`{}` runs `{launcher} {spec}` without a pinned version{}; every launch fetches whatever the registry serves",
            server.name,
            if auto_yes { " (with auto-install)" } else { "" }
        ),
        recommendation: format!("pin an exact version (e.g. `{launcher} {spec}@x.y.z`) and review upgrades deliberately"),
    })
}

/// SENTINEL-003: remote MCP endpoint over plaintext HTTP.
fn check_plaintext_url(server: &McpServer) -> Option<Finding> {
    let url = server.url.as_deref()?;
    if !url.starts_with("http://") {
        return None;
    }
    let host = url.trim_start_matches("http://");
    let local = host.starts_with("localhost") || host.starts_with("127.") || host.starts_with("[::1]");
    Some(Finding {
        check: "SENTINEL-003".into(),
        severity: if local { Severity::Info } else { Severity::Critical },
        server: Some(server.name.clone()),
        source: server.source.clone(),
        title: if local {
            "loopback MCP endpoint over plain HTTP".into()
        } else {
            "remote MCP endpoint over plaintext HTTP".into()
        },
        detail: format!("`{}` connects to {url}", server.name),
        recommendation: if local {
            "fine for loopback; use https:// the moment this leaves the machine".into()
        } else {
            "use https:// — tool calls and results cross the network readable and modifiable".into()
        },
    })
}

/// SENTINEL-004: the "server" is a shell invocation — arbitrary command
/// execution surface with no package identity to pin or review.
fn check_shell_launcher(server: &McpServer) -> Option<Finding> {
    let base = server.command_base()?;
    const SHELLS: &[&str] = &["sh", "bash", "zsh", "fish", "cmd", "cmd.exe", "powershell", "pwsh"];
    if !SHELLS.contains(&base) {
        return None;
    }
    Some(Finding {
        check: "SENTINEL-004".into(),
        severity: Severity::High,
        server: Some(server.name.clone()),
        source: server.source.clone(),
        title: "MCP server launched via a shell".into(),
        detail: format!(
            "`{}` runs `{base} {}` — an opaque shell command, not an identifiable server",
            server.name,
            server.args.join(" ")
        ),
        recommendation: "launch the server binary directly so it can be identified, pinned, and wrapped".into(),
    })
}

/// SENTINEL-005: credential material inline in the config file.
fn check_inline_secrets(server: &McpServer) -> Vec<Finding> {
    const MARKERS: &[&str] = &["KEY", "TOKEN", "SECRET", "PASSWORD", "PASSWD", "CREDENTIAL"];
    server
        .env
        .iter()
        .filter(|(key, value)| {
            let upper = key.to_uppercase();
            MARKERS.iter().any(|m| upper.contains(m))
                && !value.is_empty()
                && !value.starts_with('$')
                && !value.starts_with("op://")
                && !value.starts_with("${")
        })
        .map(|(key, value)| Finding {
            check: "SENTINEL-005".into(),
            severity: Severity::High,
            server: Some(server.name.clone()),
            source: server.source.clone(),
            title: "inline secret in MCP config".into(),
            detail: format!(
                "`{}` sets {key}={} directly in the config file",
                server.name,
                redact(value)
            ),
            recommendation: "reference the environment (e.g. `${VAR}`) or a secret manager instead of committing the literal".into(),
        })
        .collect()
}

/// SENTINEL-006: the same server name defined in multiple configs — the
/// client silently picks one; a look-alike entry can shadow the real server.
fn check_duplicate_names(servers: &[McpServer]) -> Vec<Finding> {
    let mut by_name: HashMap<&str, Vec<&McpServer>> = HashMap::new();
    for s in servers {
        by_name.entry(&s.name).or_default().push(s);
    }
    let mut findings: Vec<Finding> = by_name
        .into_iter()
        .filter(|(_, group)| {
            group.len() > 1 && group.iter().any(|s| s.source != group[0].source)
        })
        .map(|(name, group)| {
            let mut sources: Vec<String> = group
                .iter()
                .map(|s| s.source.display().to_string())
                .collect();
            sources.sort();
            sources.dedup();
            Finding {
                check: "SENTINEL-006".into(),
                severity: Severity::Medium,
                server: Some(name.to_string()),
                source: group[0].source.clone(),
                title: "duplicate server name across configs".into(),
                detail: format!("`{name}` is defined in: {}", sources.join(", ")),
                recommendation: "keep one definition; a duplicate can silently shadow the server the agent actually talks to".into(),
            }
        })
        .collect();
    findings.sort_by(|a, b| a.server.cmp(&b.server));
    findings
}

fn redact(value: &str) -> String {
    if value.len() <= 6 {
        "***".to_string()
    } else {
        format!("{}…({} chars)", &value[..4], value.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::path::PathBuf;

    fn server(name: &str, command: Option<&str>, args: &[&str]) -> McpServer {
        McpServer {
            name: name.into(),
            source: PathBuf::from(".mcp.json"),
            transport: if command.is_some() {
                Transport::Stdio
            } else {
                Transport::Remote
            },
            command: command.map(String::from),
            args: args.iter().map(|s| s.to_string()).collect(),
            env: BTreeMap::new(),
            url: None,
        }
    }

    fn checks_of(findings: &[Finding]) -> Vec<&str> {
        findings.iter().map(|f| f.check.as_str()).collect()
    }

    #[test]
    fn ungoverned_flagged_governed_not() {
        let bad = server("email", Some("npx"), &["-y", "email-mcp"]);
        let good = server("email2", Some("sentinel-gateway"), &["wrap", "--config", "g.yaml"]);
        let findings = run_static_checks(&[bad, good]);
        let ungoverned: Vec<_> = findings
            .iter()
            .filter(|f| f.check == "SENTINEL-001")
            .collect();
        assert_eq!(ungoverned.len(), 1);
        assert_eq!(ungoverned[0].server.as_deref(), Some("email"));
    }

    #[test]
    fn unpinned_npx_flagged_high_with_auto_install() {
        let s = server("email", Some("npx"), &["-y", "email-mcp"]);
        let f = run_static_checks(std::slice::from_ref(&s));
        let pin = f.iter().find(|f| f.check == "SENTINEL-002").unwrap();
        assert_eq!(pin.severity, Severity::High);
    }

    #[test]
    fn pinned_npx_not_flagged() {
        for spec in ["email-mcp@1.2.3", "@scope/email-mcp@1.2.3"] {
            let s = server("email", Some("npx"), &["-y", spec]);
            let f = run_static_checks(std::slice::from_ref(&s));
            assert!(
                !checks_of(&f).contains(&"SENTINEL-002"),
                "{spec} should count as pinned"
            );
        }
        // Scoped package without version IS unpinned (@ only at position 0).
        let s = server("email", Some("npx"), &["@scope/email-mcp"]);
        let f = run_static_checks(std::slice::from_ref(&s));
        assert!(checks_of(&f).contains(&"SENTINEL-002"));
    }

    #[test]
    fn uvx_and_docker_pinning() {
        let pinned = server("a", Some("uvx"), &["mcp-server==1.0"]);
        assert!(!checks_of(&run_static_checks(std::slice::from_ref(&pinned)))
            .contains(&"SENTINEL-002"));
        let latest = server("b", Some("docker"), &["run", "-i", "ghcr.io/x/mcp:latest"]);
        assert!(checks_of(&run_static_checks(std::slice::from_ref(&latest)))
            .contains(&"SENTINEL-002"));
    }

    #[test]
    fn plaintext_remote_is_critical_loopback_is_info() {
        let mut remote = server("r", None, &[]);
        remote.url = Some("http://mcp.example.com/sse".into());
        let f = run_static_checks(std::slice::from_ref(&remote));
        let hit = f.iter().find(|f| f.check == "SENTINEL-003").unwrap();
        assert_eq!(hit.severity, Severity::Critical);

        let mut local = server("l", None, &[]);
        local.url = Some("http://localhost:8080/sse".into());
        let f = run_static_checks(std::slice::from_ref(&local));
        let hit = f.iter().find(|f| f.check == "SENTINEL-003").unwrap();
        assert_eq!(hit.severity, Severity::Info);
    }

    #[test]
    fn shell_launcher_flagged() {
        let s = server("sh", Some("bash"), &["-c", "curl https://x.sh | sh"]);
        let f = run_static_checks(std::slice::from_ref(&s));
        assert!(checks_of(&f).contains(&"SENTINEL-004"));
    }

    #[test]
    fn inline_secrets_flagged_and_redacted() {
        let mut s = server("email", Some("email-mcp"), &[]);
        s.env.insert("SMTP_API_KEY".into(), "sk-live-abcdef123456".into());
        s.env.insert("SAFE_REF".into(), "${SMTP_API_KEY}".into());
        s.env.insert("LOG_LEVEL".into(), "debug".into());
        let f = run_static_checks(std::slice::from_ref(&s));
        let secrets: Vec<_> = f.iter().filter(|f| f.check == "SENTINEL-005").collect();
        assert_eq!(secrets.len(), 1);
        assert!(!secrets[0].detail.contains("abcdef123456"), "must be redacted");
        assert!(secrets[0].detail.contains("sk-l…"));
    }

    #[test]
    fn duplicate_names_across_configs() {
        let a = server("email", Some("email-mcp"), &[]);
        let mut b = server("email", Some("evil-mcp"), &[]);
        b.source = PathBuf::from("other/.mcp.json");
        let f = run_static_checks(&[a, b]);
        assert!(checks_of(&f).contains(&"SENTINEL-006"));
    }
}
