//! Discovery and parsing of MCP client configuration files.
//!
//! Supported shapes (all JSON):
//! - Claude Code / Claude Desktop / Cursor: `{"mcpServers": {name: {...}}}`
//!   in `.mcp.json`, `claude_desktop_config.json`, `.cursor/mcp.json`
//! - VS Code: `{"servers": {name: {...}}}` in `.vscode/mcp.json`

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde_json::Value;

use crate::model::{McpServer, Transport};

const CONFIG_BASENAMES: &[&str] = &[".mcp.json", "mcp.json", "claude_desktop_config.json"];
const SKIP_DIRS: &[&str] = &[
    "node_modules",
    ".git",
    "target",
    "dist",
    "build",
    "venv",
    ".venv",
    "__pycache__",
];
const MAX_DEPTH: usize = 8;

/// Expand roots into a de-duplicated list of config files: explicit files
/// are taken as-is, directories are walked, and `include_home` adds the
/// well-known per-user locations.
pub fn discover(roots: &[PathBuf], include_home: bool) -> Vec<PathBuf> {
    let mut found = Vec::new();
    for root in roots {
        if root.is_file() {
            found.push(root.clone());
        } else if root.is_dir() {
            walk(root, 0, &mut found);
        }
    }
    if include_home {
        if let Some(home) = std::env::var_os("HOME").map(PathBuf::from) {
            for candidate in [
                home.join(".cursor/mcp.json"),
                home.join(".mcp.json"),
                home.join("Library/Application Support/Claude/claude_desktop_config.json"),
                home.join(".config/Claude/claude_desktop_config.json"),
            ] {
                if candidate.is_file() {
                    found.push(candidate);
                }
            }
        }
    }
    found.sort();
    found.dedup();
    found
}

fn walk(dir: &Path, depth: usize, found: &mut Vec<PathBuf>) {
    if depth > MAX_DEPTH {
        return;
    }
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if path.is_dir() {
            if SKIP_DIRS.contains(&name.as_ref()) {
                continue;
            }
            walk(&path, depth + 1, found);
        } else if CONFIG_BASENAMES.contains(&name.as_ref()) {
            // Bare `mcp.json` is only meaningful inside a client dir.
            if name == "mcp.json" {
                let parent = dir.file_name().map(|p| p.to_string_lossy().to_string());
                if !matches!(parent.as_deref(), Some(".cursor") | Some(".vscode")) {
                    continue;
                }
            }
            found.push(path);
        }
    }
}

/// Parse one config file into server entries.
pub fn parse_config(path: &Path) -> anyhow::Result<Vec<McpServer>> {
    let text = std::fs::read_to_string(path)?;
    let value: Value = serde_json::from_str(&text)?;
    let servers = value
        .get("mcpServers")
        .or_else(|| value.get("servers"))
        .and_then(Value::as_object)
        .ok_or_else(|| anyhow::anyhow!("no `mcpServers` or `servers` object"))?;

    let mut out = Vec::new();
    for (name, entry) in servers {
        let command = entry.get("command").and_then(Value::as_str).map(String::from);
        let url = entry.get("url").and_then(Value::as_str).map(String::from);
        let args = entry
            .get("args")
            .and_then(Value::as_array)
            .map(|a| {
                a.iter()
                    .map(|v| v.as_str().map(String::from).unwrap_or_else(|| v.to_string()))
                    .collect()
            })
            .unwrap_or_default();
        let env: BTreeMap<String, String> = entry
            .get("env")
            .and_then(Value::as_object)
            .map(|m| {
                m.iter()
                    .map(|(k, v)| {
                        (
                            k.clone(),
                            v.as_str().map(String::from).unwrap_or_else(|| v.to_string()),
                        )
                    })
                    .collect()
            })
            .unwrap_or_default();
        let transport = if command.is_some() {
            Transport::Stdio
        } else {
            Transport::Remote
        };
        out.push(McpServer {
            name: name.clone(),
            source: path.to_path_buf(),
            transport,
            command,
            args,
            env,
            url,
        });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write(dir: &Path, rel: &str, content: &str) -> PathBuf {
        let path = dir.join(rel);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, content).unwrap();
        path
    }

    #[test]
    fn parses_claude_shape() {
        let dir = tempfile::tempdir().unwrap();
        let path = write(
            dir.path(),
            ".mcp.json",
            r#"{"mcpServers": {
                "email": {"command": "npx", "args": ["-y", "email-mcp"], "env": {"API_KEY": "sk-123"}},
                "remote": {"url": "http://mcp.example.com/sse"}
            }}"#,
        );
        let mut servers = parse_config(&path).unwrap();
        servers.sort_by(|a, b| a.name.cmp(&b.name));
        assert_eq!(servers.len(), 2);
        assert_eq!(servers[0].name, "email");
        assert_eq!(servers[0].transport, Transport::Stdio);
        assert_eq!(servers[0].command.as_deref(), Some("npx"));
        assert_eq!(servers[0].env["API_KEY"], "sk-123");
        assert_eq!(servers[1].transport, Transport::Remote);
        assert_eq!(servers[1].url.as_deref(), Some("http://mcp.example.com/sse"));
    }

    #[test]
    fn parses_vscode_shape() {
        let dir = tempfile::tempdir().unwrap();
        let path = write(
            dir.path(),
            ".vscode/mcp.json",
            r#"{"servers": {"db": {"command": "db-mcp", "args": []}}}"#,
        );
        let servers = parse_config(&path).unwrap();
        assert_eq!(servers.len(), 1);
        assert_eq!(servers[0].name, "db");
    }

    #[test]
    fn discovery_finds_known_names_and_skips_noise() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), ".mcp.json", "{}");
        write(dir.path(), "sub/.cursor/mcp.json", "{}");
        write(dir.path(), ".vscode/mcp.json", "{}");
        write(dir.path(), "node_modules/pkg/.mcp.json", "{}");
        write(dir.path(), "sub/other/mcp.json", "{}"); // bare mcp.json outside client dir

        let found = discover(&[dir.path().to_path_buf()], false);
        let names: Vec<String> = found
            .iter()
            .map(|p| {
                p.strip_prefix(dir.path())
                    .unwrap()
                    .to_string_lossy()
                    .to_string()
            })
            .collect();
        assert!(names.contains(&".mcp.json".to_string()));
        assert!(names.contains(&"sub/.cursor/mcp.json".to_string()));
        assert!(names.contains(&".vscode/mcp.json".to_string()));
        assert!(!names.iter().any(|n| n.contains("node_modules")));
        assert!(!names.contains(&"sub/other/mcp.json".to_string()));
    }

    #[test]
    fn governed_detection() {
        let dir = tempfile::tempdir().unwrap();
        let path = write(
            dir.path(),
            ".mcp.json",
            r#"{"mcpServers": {"email": {"command": "/usr/local/bin/sentinel-gateway", "args": ["wrap"]}}}"#,
        );
        let servers = parse_config(&path).unwrap();
        assert!(servers[0].is_governed());
    }
}
