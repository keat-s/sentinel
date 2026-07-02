//! The MCP proxy: sits between an MCP client (agent) and a wrapped MCP
//! server over stdio, intercepting `tools/call` for policy enforcement and
//! `tools/list` responses for least-privilege tool filtering. Everything
//! else passes through untouched.
//!
//! Transport is MCP stdio framing: one JSON-RPC 2.0 message per line.

use std::collections::HashSet;
use std::net::SocketAddr;
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context as _;
use parking_lot::Mutex;
use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::Command;
use tokio::sync::mpsc;

use sentinel_audit::{Actor, ArgsRecord, AuditWriter, Event};
use sentinel_policy::{CallCtx, Decision, Effect, Policy};

use crate::approvals::{notify, ApprovalInfo, Broker, Resolution};
use crate::config::GatewayConfig;
use crate::util::{gen_id, now_ms};

/// Env var: when set, the gateway writes the bound control-API address to
/// this file after startup (used by tests and scripts with `listen: :0`).
pub const CONTROL_ADDR_FILE_ENV: &str = "SENTINEL_GATEWAY_CONTROL_ADDR_FILE";

struct GatewayState {
    cfg: GatewayConfig,
    policy: Policy,
    audit: Mutex<AuditWriter>,
    broker: Arc<Broker>,
    control_addr: Option<SocketAddr>,
    /// JSON-RPC ids of in-flight `tools/list` requests (stringified).
    pending_tool_lists: Mutex<HashSet<String>>,
    to_server: mpsc::Sender<String>,
    to_client: mpsc::Sender<String>,
}

impl GatewayState {
    fn actor(&self) -> Actor {
        Actor {
            agent: self.cfg.identity.agent.clone(),
            principal: self.cfg.identity.principal.clone(),
        }
    }

    fn audit(&self, event: Event) {
        if let Err(e) = self.audit.lock().append(self.actor(), event) {
            // An unwritable audit log is a serious condition; make it loud.
            tracing::error!("FAILED TO WRITE AUDIT LOG: {e}");
        }
    }
}

/// Run the gateway: spawn `command` as the real MCP server and proxy stdio.
pub async fn run(cfg: GatewayConfig, command: Vec<String>) -> anyhow::Result<()> {
    anyhow::ensure!(!command.is_empty(), "no MCP server command given");

    // Policy.
    let policy_text = std::fs::read_to_string(&cfg.policy.path)
        .with_context(|| format!("reading policy {}", cfg.policy.path.display()))?;
    let policy = Policy::from_yaml(&policy_text)
        .with_context(|| format!("loading policy {}", cfg.policy.path.display()))?;
    let policy_sha256 = hex::encode(<sha2::Sha256 as sha2::Digest>::digest(
        policy_text.as_bytes(),
    ));

    // Audit chain.
    let key = sentinel_audit::load_secret_key(&cfg.audit.key_path).with_context(|| {
        format!(
            "loading audit signing key {} (run `sentinel-gateway keygen` first)",
            cfg.audit.key_path.display()
        )
    })?;
    let audit = AuditWriter::open(&cfg.audit.path, key)
        .with_context(|| format!("opening audit log {}", cfg.audit.path.display()))?;

    // Approvals control plane.
    let broker = Arc::new(Broker::new());
    let control_addr = match cfg.control_listen() {
        Some(listen) => {
            let addr = crate::approvals::control::start(&listen, broker.clone()).await?;
            tracing::info!("control API listening on http://{addr}");
            if let Ok(path) = std::env::var(CONTROL_ADDR_FILE_ENV) {
                let _ = std::fs::write(&path, addr.to_string());
            }
            Some(addr)
        }
        None => None,
    };

    // The real MCP server.
    let mut child = Command::new(&command[0])
        .args(&command[1..])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .with_context(|| format!("spawning MCP server `{}`", command[0]))?;
    let child_stdin = child.stdin.take().expect("child stdin piped");
    let child_stdout = child.stdout.take().expect("child stdout piped");

    let (to_server, mut server_rx) = mpsc::channel::<String>(256);
    let (to_client, mut client_rx) = mpsc::channel::<String>(256);

    let state = Arc::new(GatewayState {
        cfg,
        policy,
        audit: Mutex::new(audit),
        broker,
        control_addr,
        pending_tool_lists: Mutex::new(HashSet::new()),
        to_server,
        to_client,
    });

    state.audit(Event::GatewayStarted {
        server: state.cfg.server.name.clone(),
        policy_sha256,
        command: command.clone(),
    });
    tracing::info!(
        "sentinel-gateway governing MCP server `{}` as {} for {}",
        state.cfg.server.name,
        state.cfg.identity.agent,
        state.cfg.identity.principal
    );

    // Writer: gateway -> real server.
    let mut server_writer = tokio::spawn(async move {
        let mut w = child_stdin;
        while let Some(line) = server_rx.recv().await {
            if w.write_all(line.as_bytes()).await.is_err() {
                break;
            }
            if w.write_all(b"\n").await.is_err() {
                break;
            }
            let _ = w.flush().await;
        }
    });

    // Writer: gateway -> client (our stdout).
    let mut client_writer = tokio::spawn(async move {
        let mut out = tokio::io::stdout();
        while let Some(line) = client_rx.recv().await {
            if out.write_all(line.as_bytes()).await.is_err() {
                break;
            }
            if out.write_all(b"\n").await.is_err() {
                break;
            }
            let _ = out.flush().await;
        }
    });

    // Reader: real server -> gateway.
    let st = state.clone();
    let mut server_reader = tokio::spawn(async move {
        let mut lines = BufReader::new(child_stdout).lines();
        while let Ok(Some(line)) = lines.next_line().await {
            handle_server_line(&st, line).await;
        }
    });

    // Reader: client -> gateway (our stdin).
    let st = state.clone();
    let mut client_reader = tokio::spawn(async move {
        let mut lines = BufReader::new(tokio::io::stdin()).lines();
        while let Ok(Some(line)) = lines.next_line().await {
            handle_client_line(&st, line).await;
        }
    });

    // First side to finish ends the session: client hangup or server exit.
    tokio::select! {
        _ = &mut client_reader => tracing::info!("client closed stdin; shutting down"),
        _ = &mut server_reader => tracing::info!("MCP server closed stdout; shutting down"),
        _ = &mut client_writer => {},
        _ = &mut server_writer => {},
    }
    let _ = child.kill().await;
    client_reader.abort();
    server_reader.abort();
    Ok(())
}

/// Stable map key for a JSON-RPC id (number or string).
fn id_key(id: &Value) -> String {
    id.to_string()
}

async fn handle_client_line(state: &Arc<GatewayState>, line: String) {
    let Ok(msg) = serde_json::from_str::<Value>(&line) else {
        // Not JSON we understand — never break the protocol, pass through.
        let _ = state.to_server.send(line).await;
        return;
    };
    let method = msg.get("method").and_then(Value::as_str);
    let id = msg.get("id");

    match (method, id) {
        (Some("tools/call"), Some(_)) => {
            let st = state.clone();
            tokio::spawn(async move {
                handle_tool_call(&st, msg, line).await;
            });
        }
        (Some("tools/list"), Some(id)) => {
            state.pending_tool_lists.lock().insert(id_key(id));
            let _ = state.to_server.send(line).await;
        }
        _ => {
            let _ = state.to_server.send(line).await;
        }
    }
}

async fn handle_server_line(state: &Arc<GatewayState>, line: String) {
    let Ok(mut msg) = serde_json::from_str::<Value>(&line) else {
        let _ = state.to_client.send(line).await;
        return;
    };
    // Response to a tracked tools/list? Filter statically-denied tools.
    let is_tracked_list = msg
        .get("id")
        .map(|id| state.pending_tool_lists.lock().remove(&id_key(id)))
        .unwrap_or(false);
    if is_tracked_list {
        if let Some(tools) = msg
            .pointer_mut("/result/tools")
            .and_then(Value::as_array_mut)
        {
            let mut hidden = Vec::new();
            tools.retain(|tool| {
                let name = tool.get("name").and_then(Value::as_str).unwrap_or("");
                let statically_denied = state.policy.static_effect(
                    &state.cfg.server.name,
                    name,
                    &state.cfg.identity.agent,
                    &state.cfg.identity.principal,
                ) == Some(Effect::Deny);
                if statically_denied {
                    hidden.push(name.to_string());
                }
                !statically_denied
            });
            if !hidden.is_empty() {
                tracing::info!("hiding {} statically-denied tool(s): {hidden:?}", hidden.len());
                state.audit(Event::ToolsFiltered {
                    server: state.cfg.server.name.clone(),
                    hidden,
                });
                let _ = state.to_client.send(msg.to_string()).await;
                return;
            }
        }
    }
    let _ = state.to_client.send(line).await;
}

async fn handle_tool_call(state: &Arc<GatewayState>, msg: Value, raw_line: String) {
    let id = msg.get("id").cloned().unwrap_or(Value::Null);
    let request_id = id_key(&id);
    let tool = msg
        .pointer("/params/name")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let args = msg
        .pointer("/params/arguments")
        .cloned()
        .unwrap_or_else(|| json!({}));

    let mut decision = state.policy.evaluate(&CallCtx {
        server: &state.cfg.server.name,
        tool: &tool,
        agent: &state.cfg.identity.agent,
        principal: &state.cfg.identity.principal,
        args: &args,
    });

    // Approval with no approvals channel configured degrades to deny —
    // failing open here would defeat the point.
    if decision.effect == Effect::Approve && state.cfg.approvals.is_none() {
        decision.effect = Effect::Deny;
        decision.reason = Some(match decision.reason.take() {
            Some(r) => format!("{r} (approval required, but no approvals channel is configured)"),
            None => "approval required, but no approvals channel is configured".to_string(),
        });
    }

    state.audit(Event::ToolCallEvaluated {
        server: state.cfg.server.name.clone(),
        tool: tool.clone(),
        request_id: request_id.clone(),
        decision: decision.effect.as_str().to_string(),
        rule_id: decision.rule_id.clone(),
        risk: decision.risk.map(|r| r.as_str().to_string()),
        reason: decision.reason.clone(),
        args: ArgsRecord::capture(state.cfg.audit.log_args, &args),
    });

    match decision.effect {
        Effect::Allow => {
            tracing::debug!("allow {tool} (rule {})", decision.rule_id);
            let _ = state.to_server.send(raw_line).await;
        }
        Effect::Deny => {
            tracing::warn!("DENY {tool} (rule {})", decision.rule_id);
            let _ = state
                .to_client
                .send(deny_response(&id, &decision, "blocked by policy"))
                .await;
        }
        Effect::Approve => {
            handle_approval(state, id, request_id, tool, args, decision, raw_line).await;
        }
    }
}

async fn handle_approval(
    state: &Arc<GatewayState>,
    id: Value,
    request_id: String,
    tool: String,
    args: Value,
    decision: Decision,
    raw_line: String,
) {
    let approvals = state
        .cfg
        .approvals
        .clone()
        .expect("approve effect implies approvals config");
    let approval_id = gen_id();
    let info = ApprovalInfo {
        id: approval_id.clone(),
        created_ms: now_ms(),
        server: state.cfg.server.name.clone(),
        tool: tool.clone(),
        rule_id: decision.rule_id.clone(),
        risk: decision.risk.map(|r| r.as_str().to_string()),
        reason: decision.reason.clone(),
        request_id: request_id.clone(),
        args_preview: approvals.include_args.then(|| {
            let mut s = args.to_string();
            s.truncate(512);
            s
        }),
    };

    let rx = state.broker.create(info.clone());
    state.audit(Event::ApprovalRequested {
        approval_id: approval_id.clone(),
        server: state.cfg.server.name.clone(),
        tool: tool.clone(),
        request_id,
        rule_id: decision.rule_id.clone(),
    });
    tracing::warn!(
        "APPROVAL REQUIRED for {tool} (rule {}, id {approval_id})",
        decision.rule_id
    );

    if let Some(webhook) = approvals.webhook_url.clone() {
        let info = info.clone();
        let control_addr = state.control_addr;
        let timeout_secs = approvals.timeout_secs;
        tokio::spawn(async move {
            if let Err(e) = notify::send_webhook(&webhook, &info, control_addr, timeout_secs).await
            {
                tracing::warn!("approval webhook failed (queue still active): {e}");
            }
        });
    }

    let outcome = tokio::time::timeout(Duration::from_secs(approvals.timeout_secs), rx).await;
    match outcome {
        Ok(Ok(Resolution::Approved { by })) => {
            state.audit(Event::ApprovalResolved {
                approval_id,
                resolution: "approved".to_string(),
                resolved_by: by,
            });
            tracing::info!("approved: forwarding {tool}");
            let _ = state.to_server.send(raw_line).await;
        }
        Ok(Ok(Resolution::Denied { by })) => {
            state.audit(Event::ApprovalResolved {
                approval_id,
                resolution: "denied".to_string(),
                resolved_by: by.clone(),
            });
            let detail = match by {
                Some(who) => format!("denied by {who}"),
                None => "denied by approver".to_string(),
            };
            let _ = state.to_client.send(deny_response(&id, &decision, &detail)).await;
        }
        Ok(Err(_)) | Err(_) => {
            state.broker.remove(&approval_id);
            state.audit(Event::ApprovalResolved {
                approval_id,
                resolution: "timed_out".to_string(),
                resolved_by: None,
            });
            let detail = format!(
                "approval request timed out after {}s",
                approvals.timeout_secs
            );
            let _ = state.to_client.send(deny_response(&id, &decision, &detail)).await;
        }
    }
}

/// An MCP tool-error result (not a JSON-RPC protocol error): the agent gets
/// a readable explanation it can relay, and the session stays healthy.
fn deny_response(id: &Value, decision: &Decision, detail: &str) -> String {
    let mut text = format!(
        "Sentinel {detail}: rule `{}` says {}.",
        decision.rule_id,
        decision.effect.as_str()
    );
    if let Some(reason) = &decision.reason {
        text.push_str(&format!(" Reason: {reason}."));
    }
    text.push_str(" This decision was recorded in the tamper-evident audit log.");
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "result": {
            "content": [{ "type": "text", "text": text }],
            "isError": true
        }
    })
    .to_string()
}
