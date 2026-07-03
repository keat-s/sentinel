//! End-to-end: run the real sentinel-scan binary against fixture configs.

use std::path::Path;
use std::process::Command;

use serde_json::Value;

fn run_scan(args: &[&str], dir: &Path) -> (bool, Value) {
    let output = Command::new(env!("CARGO_BIN_EXE_sentinel-scan"))
        .args(args)
        .current_dir(dir)
        .output()
        .expect("run sentinel-scan");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let json: Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("bad JSON output: {e}\n{stdout}"));
    (output.status.success(), json)
}

fn checks_in(report: &Value) -> Vec<(&str, &str)> {
    report["findings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| {
            (
                f["check"].as_str().unwrap(),
                f["severity"].as_str().unwrap(),
            )
        })
        .collect()
}

#[test]
fn static_scan_flags_the_classic_misconfigurations() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join(".mcp.json"),
        r#"{
  "mcpServers": {
    "email": {
      "command": "npx",
      "args": ["-y", "email-mcp"],
      "env": { "SMTP_API_KEY": "sk-live-supersecret12345" }
    },
    "remote-crm": { "url": "http://crm-mcp.example.com/sse" },
    "governed-db": {
      "command": "sentinel-gateway",
      "args": ["wrap", "--config", "gw.yaml", "--", "db-mcp"]
    }
  }
}"#,
    )
    .unwrap();

    let (success, report) = run_scan(&["--format", "json", "--fail-on", "high"], dir.path());
    assert!(!success, "critical+high findings must fail the scan");

    let checks = checks_in(&report);
    let has = |id: &str| checks.iter().any(|(c, _)| *c == id);
    assert!(has("SENTINEL-001"), "ungoverned server: {checks:?}");
    assert!(has("SENTINEL-002"), "unpinned npx: {checks:?}");
    assert!(has("SENTINEL-003"), "plaintext http: {checks:?}");
    assert!(has("SENTINEL-005"), "inline secret: {checks:?}");

    // The governed server must not be flagged as ungoverned.
    let ungoverned_servers: Vec<&str> = report["findings"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|f| f["check"] == "SENTINEL-001")
        .map(|f| f["server"].as_str().unwrap())
        .collect();
    assert!(!ungoverned_servers.contains(&"governed-db"));
    assert_eq!(report["servers_governed"], 1);

    // Secrets never appear verbatim in the report.
    let raw = report.to_string();
    assert!(!raw.contains("supersecret12345"));

    // fail-on never -> exit 0 with the same findings.
    let (success, _) = run_scan(&["--format", "json", "--fail-on", "never"], dir.path());
    assert!(success);
}

#[test]
fn probe_catches_the_poisoned_tool_and_emits_a_policy() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join(".mcp.json"),
        format!(
            r#"{{ "mcpServers": {{ "utils": {{ "command": "{}" }} }} }}"#,
            env!("CARGO_BIN_EXE_mock-injected-mcp")
        ),
    )
    .unwrap();

    let (success, report) = run_scan(
        &[
            "--format",
            "json",
            "--fail-on",
            "never",
            "--probe",
            "--emit-policy",
            "starter-policy.yaml",
        ],
        dir.path(),
    );
    assert!(success);
    assert_eq!(report["servers_probed"], 1);

    let findings = report["findings"].as_array().unwrap();
    let injection = findings
        .iter()
        .find(|f| f["check"] == "SENTINEL-101")
        .expect("prompt injection finding");
    assert_eq!(injection["severity"], "critical");
    assert!(injection["title"].as_str().unwrap().contains("send_email"));
    assert!(findings.iter().any(|f| f["check"] == "SENTINEL-103")); // delete_workspace

    // The emitted starter policy is valid and least-privilege.
    let text = std::fs::read_to_string(dir.path().join("starter-policy.yaml")).unwrap();
    let policy = sentinel_policy::Policy::from_yaml(&text).expect("valid generated policy");
    let args = serde_json::json!({});
    let eval = |tool: &str| {
        policy
            .evaluate(&sentinel_policy::CallCtx {
                server: "utils",
                tool,
                agent: "a",
                principal: "p",
                args: &args,
            })
            .effect
    };
    assert_eq!(eval("delete_workspace"), sentinel_policy::Effect::Deny);
    assert_eq!(eval("send_email"), sentinel_policy::Effect::Approve);
    assert_eq!(eval("read_notes"), sentinel_policy::Effect::Allow);
}
