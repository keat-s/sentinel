//! What gets recorded: the audit event vocabulary.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Who the action is attributed to.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Actor {
    /// Agent identity (e.g. `claude-code`, a service account, a bot name).
    pub agent: String,
    /// Human principal the agent acts on behalf of.
    pub principal: String,
}

/// How tool-call arguments are captured in the log.
///
/// Default is `hash`: enough to prove *what* was sent without storing the
/// content itself (GDPR data minimization).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArgsMode {
    /// Record nothing about the arguments.
    Omit,
    /// Record a SHA-256 digest of the canonical argument JSON.
    #[default]
    Hash,
    /// Record the full argument JSON (content-sensitive; opt-in).
    Full,
}

/// The captured form of a call's arguments, per [`ArgsMode`].
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "mode", rename_all = "snake_case")]
pub enum ArgsRecord {
    /// Arguments were not captured.
    Omitted,
    /// SHA-256 (hex) of the canonical (key-sorted) argument JSON.
    Hash {
        /// The digest.
        sha256: String,
    },
    /// The arguments verbatim.
    Full {
        /// The argument object.
        value: serde_json::Value,
    },
}

impl ArgsRecord {
    /// Capture `args` according to `mode`.
    pub fn capture(mode: ArgsMode, args: &serde_json::Value) -> Self {
        match mode {
            ArgsMode::Omit => ArgsRecord::Omitted,
            ArgsMode::Full => ArgsRecord::Full {
                value: args.clone(),
            },
            ArgsMode::Hash => {
                // Canonicalize through Value (sorted keys) so the same
                // arguments always hash identically.
                let canon = serde_json::to_string(args).unwrap_or_default();
                ArgsRecord::Hash {
                    sha256: hex::encode(Sha256::digest(canon.as_bytes())),
                }
            }
        }
    }
}

/// One audited occurrence.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Event {
    /// The gateway came up wrapping a server under a specific policy.
    GatewayStarted {
        /// Logical server name.
        server: String,
        /// SHA-256 (hex) of the policy file in force.
        policy_sha256: String,
        /// The command line of the wrapped MCP server.
        command: Vec<String>,
    },
    /// A tool call was evaluated against policy.
    ToolCallEvaluated {
        /// Logical server name.
        server: String,
        /// Tool invoked.
        tool: String,
        /// JSON-RPC request id (stringified).
        request_id: String,
        /// `allow` / `deny` / `approve`.
        decision: String,
        /// Rule that decided (or `<default>`).
        rule_id: String,
        /// Risk attached by the rule, if any.
        #[serde(skip_serializing_if = "Option::is_none")]
        risk: Option<String>,
        /// Reason attached by the rule, if any.
        #[serde(skip_serializing_if = "Option::is_none")]
        reason: Option<String>,
        /// Captured arguments (mode per config).
        args: ArgsRecord,
    },
    /// A call was parked pending human approval.
    ApprovalRequested {
        /// Approval queue id.
        approval_id: String,
        /// Logical server name.
        server: String,
        /// Tool awaiting approval.
        tool: String,
        /// JSON-RPC request id (stringified).
        request_id: String,
        /// Rule that routed the call to approval.
        rule_id: String,
    },
    /// A parked call was resolved.
    ApprovalResolved {
        /// Approval queue id.
        approval_id: String,
        /// `approved` / `denied` / `timed_out`.
        resolution: String,
        /// Who resolved it, when known.
        #[serde(skip_serializing_if = "Option::is_none")]
        resolved_by: Option<String>,
    },
    /// Tools hidden from `tools/list` because policy denies them statically.
    ToolsFiltered {
        /// Logical server name.
        server: String,
        /// Names of the hidden tools.
        hidden: Vec<String>,
    },
    /// The wrapped server diverged from its pinned provenance record.
    ProvenanceViolation {
        /// Logical server name.
        server: String,
        /// `executable_mismatch` / `tool_changed` / `tool_added` / `tool_removed`.
        kind: String,
        /// What diverged (executable path or tool name).
        subject: String,
        /// Human-readable detail.
        detail: String,
        /// `blocked` or `warned`, per the configured enforcement mode.
        enforced: String,
    },
}

/// The signed unit: one event plus attribution and ordering metadata.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Record {
    /// Monotonic sequence number within this log file (starts at 1).
    pub seq: u64,
    /// Wall-clock milliseconds since the Unix epoch.
    pub ts_ms: u64,
    /// Who this action is attributed to.
    pub actor: Actor,
    /// What happened.
    pub event: Event,
}
