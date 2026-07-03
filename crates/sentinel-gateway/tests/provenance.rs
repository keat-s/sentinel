//! End-to-end provenance tests: pin the mock server, then watch the gateway
//! catch a rug-pulled tool description and a swapped executable.

use std::path::Path;
use std::process::Stdio;
use std::time::Duration;

use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, ChildStdin, ChildStdout, Command};

const ALLOW_ALL_POLICY: &str = "version: 1\ndefault_action: allow\nrules: []\n";

fn write_config(dir: &Path, enforce: &str) {
    std::fs::write(dir.join("policy.yaml"), ALLOW_ALL_POLICY).unwrap();
    std::fs::write(
        dir.join("gateway.yaml"),
        format!(
            r#"
server: {{ name: email }}
identity: {{ agent: claude-code, principal: keat@example.com }}
policy: {{ path: policy.yaml }}
audit: {{ path: audit.jsonl, key_path: audit.key, log_args: hash }}
provenance: {{ lock: server.lock.yaml, enforce: {enforce} }}
"#
        ),
    )
    .unwrap();
    let key = sentinel_audit::generate_signing_key();
    sentinel_audit::save_keypair(
        &key,
        &dir.join("audit.key"),
        &dir.join("audit.key.pub"),
    )
    .unwrap();
}

fn pin_mock(dir: &Path) {
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_sentinel-gateway"))
        .args(["pin", "--out"])
        .arg(dir.join("server.lock.yaml"))
        .arg("--")
        .arg(env!("CARGO_BIN_EXE_mock-email-mcp"))
        .output()
        .expect("run pin");
    assert!(
        output.status.success(),
        "pin failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

struct Gw {
    child: Child,
    stdin: ChildStdin,
    reader: BufReader<ChildStdout>,
}

fn spawn_gateway(dir: &Path, rugpull: bool) -> Gw {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_sentinel-gateway"));
    cmd.arg("wrap")
        .arg("--config")
        .arg(dir.join("gateway.yaml"))
        .arg("--")
        .arg(env!("CARGO_BIN_EXE_mock-email-mcp"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit());
    if rugpull {
        cmd.env("MOCK_RUGPULL", "1");
    }
    let mut child = cmd.spawn().expect("spawn gateway");
    let stdin = child.stdin.take().unwrap();
    let reader = BufReader::new(child.stdout.take().unwrap());
    Gw {
        child,
        stdin,
        reader,
    }
}

impl Gw {
    async fn send(&mut self, msg: Value) {
        self.stdin
            .write_all(format!("{msg}\n").as_bytes())
            .await
            .unwrap();
        self.stdin.flush().await.unwrap();
    }

    async fn recv_id(&mut self, id: u64) -> Value {
        tokio::time::timeout(Duration::from_secs(20), async {
            loop {
                let mut line = String::new();
                let n = self.reader.read_line(&mut line).await.unwrap();
                assert!(n > 0, "gateway stdout closed while waiting for id {id}");
                if line.trim().is_empty() {
                    continue;
                }
                let v: Value = serde_json::from_str(&line).unwrap();
                if v.get("id").and_then(Value::as_u64) == Some(id) {
                    return v;
                }
            }
        })
        .await
        .unwrap_or_else(|_| panic!("timed out waiting for id {id}"))
    }

    async fn initialize(&mut self) {
        self.send(json!({
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {"protocolVersion": "2024-11-05", "capabilities": {},
                       "clientInfo": {"name": "test", "version": "0"}}
        }))
        .await;
        self.recv_id(1).await;
        self.send(json!({"jsonrpc": "2.0", "method": "notifications/initialized"}))
            .await;
    }

    async fn tool_names(&mut self, id: u64) -> Vec<String> {
        self.send(json!({"jsonrpc": "2.0", "id": id, "method": "tools/list"}))
            .await;
        let resp = self.recv_id(id).await;
        resp["result"]["tools"]
            .as_array()
            .unwrap()
            .iter()
            .map(|t| t["name"].as_str().unwrap().to_string())
            .collect()
    }

    async fn shutdown(mut self) {
        drop(self.stdin);
        let _ = tokio::time::timeout(Duration::from_secs(10), self.child.wait()).await;
        let _ = self.child.kill().await;
    }
}

#[tokio::test]
async fn clean_server_passes_provenance() {
    let dir = tempfile::tempdir().unwrap();
    write_config(dir.path(), "block");
    pin_mock(dir.path());

    // The lockfile captured the full surface.
    let lock: Value = serde_yaml::from_str(
        &std::fs::read_to_string(dir.path().join("server.lock.yaml")).unwrap(),
    )
    .unwrap();
    assert_eq!(lock["version"], 1);
    assert_eq!(lock["tools"].as_array().unwrap().len(), 3);
    assert_eq!(lock["executable"]["sha256"].as_str().unwrap().len(), 64);
    assert_eq!(lock["server_info"]["name"], "mock-email");

    let mut gw = spawn_gateway(dir.path(), false);
    gw.initialize().await;
    let names = gw.tool_names(2).await;
    assert!(names.contains(&"send_email".to_string()));

    // Calls flow normally.
    gw.send(json!({
        "jsonrpc": "2.0", "id": 3, "method": "tools/call",
        "params": {"name": "send_email",
                   "arguments": {"to": ["boss@example.com"], "subject": "hi", "body": "x"}}
    }))
    .await;
    let resp = gw.recv_id(3).await;
    assert!(resp["result"]["content"][0]["text"]
        .as_str()
        .unwrap()
        .starts_with("Email sent"));
    gw.shutdown().await;

    // No provenance violations on the record.
    let log = std::fs::read_to_string(dir.path().join("audit.jsonl")).unwrap();
    assert!(!log.contains("provenance_violation"));
}

#[tokio::test]
async fn rug_pulled_tool_is_stripped_and_denied() {
    let dir = tempfile::tempdir().unwrap();
    write_config(dir.path(), "block");
    pin_mock(dir.path()); // pinned CLEAN...

    // ...but the server that actually starts has a poisoned description.
    let mut gw = spawn_gateway(dir.path(), true);
    gw.initialize().await;

    // The drifted tool vanishes from the list the agent sees.
    let names = gw.tool_names(2).await;
    assert!(
        !names.contains(&"send_email".to_string()),
        "drifted tool must be stripped, saw {names:?}"
    );
    assert!(names.contains(&"list_inbox".to_string()));

    // And calling it directly is denied even though policy allows everything.
    gw.send(json!({
        "jsonrpc": "2.0", "id": 3, "method": "tools/call",
        "params": {"name": "send_email",
                   "arguments": {"to": ["boss@example.com"], "subject": "hi", "body": "x"}}
    }))
    .await;
    let resp = gw.recv_id(3).await;
    assert_eq!(resp.pointer("/result/isError"), Some(&json!(true)));
    let text = resp["result"]["content"][0]["text"].as_str().unwrap();
    assert!(text.contains("provenance"), "denial explains why: {text}");
    gw.shutdown().await;

    // The violation and the denial are both on the signed record.
    let vk = sentinel_audit::load_verifying_key(&dir.path().join("audit.key.pub")).unwrap();
    sentinel_audit::verify_file(&dir.path().join("audit.jsonl"), &vk).unwrap();
    let log = std::fs::read_to_string(dir.path().join("audit.jsonl")).unwrap();
    assert!(log.contains("\"kind\":\"tool_changed\""));
    assert!(log.contains("\"subject\":\"send_email\""));
    assert!(log.contains("\"rule_id\":\"<provenance>\""));
}

#[tokio::test]
async fn swapped_executable_refuses_to_start_in_block_mode() {
    let dir = tempfile::tempdir().unwrap();
    write_config(dir.path(), "block");
    pin_mock(dir.path());

    // Doctor the pinned hash to simulate a swapped binary.
    let lock_path = dir.path().join("server.lock.yaml");
    let doctored = std::fs::read_to_string(&lock_path)
        .unwrap()
        .lines()
        .map(|l| {
            if l.trim_start().starts_with("sha256:") {
                "  sha256: 0000000000000000000000000000000000000000000000000000000000000000"
                    .to_string()
            } else {
                l.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join("\n");
    std::fs::write(&lock_path, doctored).unwrap();

    let mut gw = spawn_gateway(dir.path(), false);
    let status = tokio::time::timeout(Duration::from_secs(15), gw.child.wait())
        .await
        .expect("gateway should exit promptly")
        .unwrap();
    assert!(!status.success(), "block mode must refuse to start");

    let log = std::fs::read_to_string(dir.path().join("audit.jsonl")).unwrap();
    assert!(log.contains("executable_mismatch"));
    assert!(log.contains("\"enforced\":\"blocked\""));
}

#[tokio::test]
async fn warn_mode_starts_but_records_the_violation() {
    let dir = tempfile::tempdir().unwrap();
    write_config(dir.path(), "warn");
    pin_mock(dir.path());

    // Same rug pull, warn mode: traffic flows, the record shows it.
    let mut gw = spawn_gateway(dir.path(), true);
    gw.initialize().await;
    let names = gw.tool_names(2).await;
    assert!(
        names.contains(&"send_email".to_string()),
        "warn mode must not strip tools"
    );
    gw.shutdown().await;

    let log = std::fs::read_to_string(dir.path().join("audit.jsonl")).unwrap();
    assert!(log.contains("\"kind\":\"tool_changed\""));
    assert!(log.contains("\"enforced\":\"warned\""));
}
