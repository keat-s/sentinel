//! Approval notifications via webhook (Slack-compatible `{"text": ...}`).

use std::net::SocketAddr;

use super::ApprovalInfo;

/// Compose and POST the approval message. Errors are the caller's to log;
/// notification failure never blocks the approval flow (the queue and CLI
/// still work).
pub async fn send_webhook(
    webhook_url: &str,
    info: &ApprovalInfo,
    control_addr: Option<SocketAddr>,
    timeout_secs: u64,
) -> anyhow::Result<()> {
    let text = compose_text(info, control_addr, timeout_secs);
    let client = reqwest::Client::new();
    client
        .post(webhook_url)
        .json(&serde_json::json!({ "text": text }))
        .send()
        .await?
        .error_for_status()?;
    Ok(())
}

fn compose_text(
    info: &ApprovalInfo,
    control_addr: Option<SocketAddr>,
    timeout_secs: u64,
) -> String {
    let mut text = format!(
        ":shield: *Sentinel: agent action needs approval*\n\
         • Tool: `{server}.{tool}`\n\
         • Rule: `{rule}`",
        server = info.server,
        tool = info.tool,
        rule = info.rule_id,
    );
    if let Some(risk) = &info.risk {
        text.push_str(&format!("\n• Risk: *{risk}*"));
    }
    if let Some(reason) = &info.reason {
        text.push_str(&format!("\n• Reason: {reason}"));
    }
    if let Some(preview) = &info.args_preview {
        text.push_str(&format!("\n• Arguments: ```{preview}```"));
    }
    if let Some(addr) = control_addr {
        text.push_str(&format!(
            "\nApprove: `sentinel-gateway approvals approve {id} --addr http://{addr}`\n\
             Deny:    `sentinel-gateway approvals deny {id} --addr http://{addr}`\n\
             (or `curl -X POST http://{addr}/v1/approvals/{id}/approve`)",
            id = info.id,
        ));
    }
    text.push_str(&format!(
        "\nTimes out (denied) in {timeout_secs}s. Approval id: `{id}`",
        id = info.id
    ));
    text
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn message_contains_essentials() {
        let info = ApprovalInfo {
            id: "abc123".into(),
            created_ms: 0,
            server: "email".into(),
            tool: "send_email".into(),
            rule_id: "external-recipient".into(),
            risk: Some("high".into()),
            reason: Some("External recipient".into()),
            request_id: "7".into(),
            args_preview: None,
        };
        let text = compose_text(&info, Some("127.0.0.1:9944".parse().unwrap()), 300);
        assert!(text.contains("email.send_email"));
        assert!(text.contains("abc123"));
        assert!(text.contains("approvals approve abc123"));
        assert!(text.contains("300s"));
        // include_args off => no argument content leaks into chat.
        assert!(!text.contains("Arguments"));
    }
}
