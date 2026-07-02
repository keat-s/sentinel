//! Human-in-the-loop approvals: broker, control API, and notifications.

pub mod control;
pub mod notify;

use std::collections::HashMap;

use parking_lot::Mutex;
use serde::Serialize;
use tokio::sync::oneshot;

/// A call parked in the approval queue, as shown to approvers.
#[derive(Debug, Clone, Serialize)]
pub struct ApprovalInfo {
    pub id: String,
    pub created_ms: u64,
    pub server: String,
    pub tool: String,
    pub rule_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub risk: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    pub request_id: String,
    /// Present only when `approvals.include_args` is enabled.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub args_preview: Option<String>,
}

/// How a parked call was resolved by a human.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Resolution {
    Approved { by: Option<String> },
    Denied { by: Option<String> },
}

struct Pending {
    info: ApprovalInfo,
    tx: oneshot::Sender<Resolution>,
}

/// In-memory approval queue shared between the proxy and the control API.
#[derive(Default)]
pub struct Broker {
    pending: Mutex<HashMap<String, Pending>>,
}

impl Broker {
    pub fn new() -> Self {
        Self::default()
    }

    /// Park a call; the returned receiver resolves when a human decides.
    pub fn create(&self, info: ApprovalInfo) -> oneshot::Receiver<Resolution> {
        let (tx, rx) = oneshot::channel();
        self.pending
            .lock()
            .insert(info.id.clone(), Pending { info, tx });
        rx
    }

    /// Resolve a parked call. Returns `false` if the id is unknown (already
    /// resolved, timed out, or never existed).
    pub fn resolve(&self, id: &str, approved: bool, by: Option<String>) -> bool {
        let Some(pending) = self.pending.lock().remove(id) else {
            return false;
        };
        let resolution = if approved {
            Resolution::Approved { by }
        } else {
            Resolution::Denied { by }
        };
        // The waiter may have timed out and dropped its receiver; that's fine.
        let _ = pending.tx.send(resolution);
        true
    }

    /// Drop a parked call without resolving (timeout path).
    pub fn remove(&self, id: &str) {
        self.pending.lock().remove(id);
    }

    /// Snapshot of the queue, oldest first.
    pub fn list(&self) -> Vec<ApprovalInfo> {
        let mut items: Vec<ApprovalInfo> = self
            .pending
            .lock()
            .values()
            .map(|p| p.info.clone())
            .collect();
        items.sort_by_key(|i| i.created_ms);
        items
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn info(id: &str) -> ApprovalInfo {
        ApprovalInfo {
            id: id.to_string(),
            created_ms: 0,
            server: "email".into(),
            tool: "send_email".into(),
            rule_id: "r".into(),
            risk: Some("high".into()),
            reason: None,
            request_id: "1".into(),
            args_preview: None,
        }
    }

    #[tokio::test]
    async fn approve_resolves_waiter() {
        let broker = Broker::new();
        let rx = broker.create(info("a1"));
        assert_eq!(broker.list().len(), 1);
        assert!(broker.resolve("a1", true, Some("keat".into())));
        assert_eq!(
            rx.await.unwrap(),
            Resolution::Approved {
                by: Some("keat".into())
            }
        );
        assert!(broker.list().is_empty());
    }

    #[tokio::test]
    async fn deny_resolves_waiter() {
        let broker = Broker::new();
        let rx = broker.create(info("a2"));
        assert!(broker.resolve("a2", false, None));
        assert_eq!(rx.await.unwrap(), Resolution::Denied { by: None });
    }

    #[tokio::test]
    async fn unknown_id_is_rejected() {
        let broker = Broker::new();
        assert!(!broker.resolve("nope", true, None));
    }

    #[tokio::test]
    async fn double_resolve_is_rejected() {
        let broker = Broker::new();
        let _rx = broker.create(info("a3"));
        assert!(broker.resolve("a3", false, None));
        assert!(!broker.resolve("a3", true, None));
    }

    #[tokio::test]
    async fn timeout_path_waiter_sees_closed_channel() {
        let broker = Broker::new();
        let rx = broker.create(info("a4"));
        broker.remove("a4");
        assert!(rx.await.is_err());
    }
}
