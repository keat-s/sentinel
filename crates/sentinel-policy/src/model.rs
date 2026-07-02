//! Serde data model for policy documents.

use serde::{Deserialize, Serialize};

/// What a rule (or the policy default) tells the gateway to do with a call.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Effect {
    /// Forward the call to the MCP server.
    Allow,
    /// Reject the call; the agent receives a policy-denial tool error.
    Deny,
    /// Hold the call and route it to the human approval queue.
    Approve,
}

impl Effect {
    /// Stable lowercase name, used in audit records and CLI output.
    pub fn as_str(&self) -> &'static str {
        match self {
            Effect::Allow => "allow",
            Effect::Deny => "deny",
            Effect::Approve => "approve",
        }
    }
}

/// Risk classification a rule can attach to its decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Risk {
    /// Routine, reversible.
    Low,
    /// Worth recording, unlikely to cause harm.
    Medium,
    /// Potentially destructive or outward-facing.
    High,
    /// Data exfiltration, spend, production impact.
    Critical,
}

impl Risk {
    /// Stable lowercase name, used in audit records and notifications.
    pub fn as_str(&self) -> &'static str {
        match self {
            Risk::Low => "low",
            Risk::Medium => "medium",
            Risk::High => "high",
            Risk::Critical => "critical",
        }
    }
}

/// Top-level policy document (one YAML file).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyDoc {
    /// Schema version; must be `1`.
    pub version: u32,
    /// Action when no rule matches. Defaults to `deny` (least privilege).
    #[serde(default = "default_action")]
    pub default_action: Effect,
    /// Rules, evaluated top to bottom; first match wins.
    #[serde(default)]
    pub rules: Vec<Rule>,
}

fn default_action() -> Effect {
    Effect::Deny
}

/// A single policy rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rule {
    /// Unique identifier; recorded in every audit entry this rule decides.
    pub id: String,
    /// Human-readable summary.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// What calls this rule applies to. An empty matcher matches everything.
    #[serde(rename = "match", default)]
    pub matcher: Match,
    /// What to do when the rule matches.
    pub action: Effect,
    /// Optional risk classification, surfaced in approvals and audit records.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub risk: Option<Risk>,
    /// Why this rule exists; shown to the agent on deny and to approvers.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// Match criteria for a rule. All specified fields must match (AND).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Match {
    /// Glob over the logical MCP server name (`*` and `?` wildcards).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server: Option<String>,
    /// Globs over the tool name; the rule matches if any glob matches.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tools: Option<Vec<String>>,
    /// Globs over the agent identity; any-of semantics.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agents: Option<Vec<String>>,
    /// Globs over the human principal the agent acts for; any-of semantics.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub principals: Option<Vec<String>>,
    /// Conditions over the tool-call arguments; all must hold (AND).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub args: Vec<ArgCond>,
}

/// A condition over one location in the tool-call arguments.
///
/// `path` is a dot path into the JSON arguments (`recipients.0.address`);
/// numeric segments index into arrays. All predicates set on the condition
/// must hold. For array values, `contains` / `matches` use any-element
/// semantics and `not_matches` holds if **any** element fails the pattern —
/// i.e. it flags the presence of a non-conforming value.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArgCond {
    /// Dot path into the arguments object (empty string = whole object).
    pub path: String,
    /// Require the path to exist (`true`) or be absent (`false`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exists: Option<bool>,
    /// Require exact JSON equality with this value.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub equals: Option<serde_json::Value>,
    /// Require the string form (or any array element) to contain this substring.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub contains: Option<String>,
    /// Require the string form (or any array element) to match this regex.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub matches: Option<String>,
    /// Hold if the value (or any array element) does NOT match this regex.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub not_matches: Option<String>,
    /// Require a numeric value strictly greater than this.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gt: Option<f64>,
    /// Require a numeric value strictly less than this.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lt: Option<f64>,
}

impl ArgCond {
    /// Whether at least one predicate is set (a bare `path` is a policy bug).
    pub fn has_predicate(&self) -> bool {
        self.exists.is_some()
            || self.equals.is_some()
            || self.contains.is_some()
            || self.matches.is_some()
            || self.not_matches.is_some()
            || self.gt.is_some()
            || self.lt.is_some()
    }
}

/// Errors from parsing or validating a policy document.
#[derive(Debug, thiserror::Error)]
pub enum PolicyError {
    /// The YAML failed to parse into the policy schema.
    #[error("invalid policy YAML: {0}")]
    Yaml(#[from] serde_yaml::Error),
    /// `version` is not a supported schema version.
    #[error("unsupported policy version {0} (expected 1)")]
    UnsupportedVersion(u32),
    /// A rule has an empty `id`.
    #[error("rule with empty id")]
    EmptyRuleId,
    /// Two rules share the same `id`.
    #[error("duplicate rule id `{0}`")]
    DuplicateRuleId(String),
    /// An arg condition sets no predicate.
    #[error("rule `{rule}`: condition on `{path}` has no predicate")]
    EmptyCondition {
        /// Offending rule id.
        rule: String,
        /// Offending condition path.
        path: String,
    },
    /// A `matches` / `not_matches` pattern failed to compile.
    #[error("rule `{rule}`: invalid regex on `{path}`: {source}")]
    BadRegex {
        /// Offending rule id.
        rule: String,
        /// Offending condition path.
        path: String,
        /// The regex compile error.
        source: regex::Error,
    },
}
