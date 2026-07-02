//! # sentinel-policy
//!
//! Deterministic policy-as-code engine for governing AI agent tool calls.
//!
//! Policies are written in YAML, compiled once at load time (all regexes are
//! pre-validated), and evaluated on the hot path with zero allocation beyond
//! the decision itself. Evaluation is **first-match-wins, top to bottom**,
//! with a configurable default action (deny by default = least privilege).
//!
//! A rule matches on the logical MCP *server* name, *tool* name globs, the
//! *agent* and *principal* identities the gateway is acting for, and
//! structured conditions over the tool-call *arguments*. Every decision
//! carries the id of the rule that produced it so audit records can attribute
//! each allow/deny/approve to a specific line of policy.
//!
//! ```yaml
//! version: 1
//! default_action: deny
//! rules:
//!   - id: block-bcc-exfiltration
//!     description: Never allow a hidden BCC on outbound email
//!     match:
//!       server: email
//!       tools: ["send_email"]
//!       args:
//!         - path: bcc
//!           exists: true
//!     action: deny
//!     risk: critical
//!     reason: BCC on agent-sent email is a data-exfiltration vector
//!
//!   - id: allow-send
//!     match: { server: email, tools: ["send_email"] }
//!     action: allow
//! ```

mod eval;
mod glob;
mod model;

pub use eval::{CallCtx, Decision};
pub use glob::wildcard_match;
pub use model::{ArgCond, Effect, Match, PolicyDoc, PolicyError, Risk, Rule};

use regex::Regex;

/// A parsed and validated policy, ready for evaluation.
///
/// Construct with [`Policy::from_yaml`]; all regexes in `matches` /
/// `not_matches` conditions are compiled and validated at load time so the
/// hot path can never fail.
#[derive(Debug)]
pub struct Policy {
    doc: PolicyDoc,
    /// Per-rule, per-arg-condition compiled regexes (same shape as
    /// `doc.rules[i].matcher.args`).
    compiled: Vec<Vec<CompiledCond>>,
}

#[derive(Debug)]
pub(crate) struct CompiledCond {
    pub(crate) matches: Option<Regex>,
    pub(crate) not_matches: Option<Regex>,
}

impl Policy {
    /// Parse and validate a policy from YAML text.
    pub fn from_yaml(text: &str) -> Result<Self, PolicyError> {
        let doc: PolicyDoc = serde_yaml::from_str(text)?;
        Self::from_doc(doc)
    }

    /// Validate an already-deserialized policy document.
    pub fn from_doc(doc: PolicyDoc) -> Result<Self, PolicyError> {
        if doc.version != 1 {
            return Err(PolicyError::UnsupportedVersion(doc.version));
        }
        let mut seen = std::collections::HashSet::new();
        let mut compiled = Vec::with_capacity(doc.rules.len());
        for rule in &doc.rules {
            if rule.id.trim().is_empty() {
                return Err(PolicyError::EmptyRuleId);
            }
            if !seen.insert(rule.id.clone()) {
                return Err(PolicyError::DuplicateRuleId(rule.id.clone()));
            }
            let mut conds = Vec::with_capacity(rule.matcher.args.len());
            for cond in &rule.matcher.args {
                if !cond.has_predicate() {
                    return Err(PolicyError::EmptyCondition {
                        rule: rule.id.clone(),
                        path: cond.path.clone(),
                    });
                }
                let compile = |pat: &Option<String>| -> Result<Option<Regex>, PolicyError> {
                    pat.as_deref()
                        .map(|p| {
                            Regex::new(p).map_err(|source| PolicyError::BadRegex {
                                rule: rule.id.clone(),
                                path: cond.path.clone(),
                                source,
                            })
                        })
                        .transpose()
                };
                conds.push(CompiledCond {
                    matches: compile(&cond.matches)?,
                    not_matches: compile(&cond.not_matches)?,
                });
            }
            compiled.push(conds);
        }
        Ok(Self { doc, compiled })
    }

    /// The rules in evaluation order.
    pub fn rules(&self) -> &[Rule] {
        &self.doc.rules
    }

    /// The action taken when no rule matches.
    pub fn default_action(&self) -> Effect {
        self.doc.default_action
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_unknown_version() {
        let err = Policy::from_yaml("version: 2\nrules: []").unwrap_err();
        assert!(matches!(err, PolicyError::UnsupportedVersion(2)));
    }

    #[test]
    fn rejects_duplicate_rule_ids() {
        let yaml = r#"
version: 1
rules:
  - { id: a, action: allow }
  - { id: a, action: deny }
"#;
        assert!(matches!(
            Policy::from_yaml(yaml).unwrap_err(),
            PolicyError::DuplicateRuleId(_)
        ));
    }

    #[test]
    fn rejects_bad_regex_at_load_time() {
        let yaml = r#"
version: 1
rules:
  - id: a
    match:
      args: [{ path: to, matches: "([" }]
    action: deny
"#;
        assert!(matches!(
            Policy::from_yaml(yaml).unwrap_err(),
            PolicyError::BadRegex { .. }
        ));
    }

    #[test]
    fn rejects_condition_with_no_predicate() {
        let yaml = r#"
version: 1
rules:
  - id: a
    match:
      args: [{ path: to }]
    action: deny
"#;
        assert!(matches!(
            Policy::from_yaml(yaml).unwrap_err(),
            PolicyError::EmptyCondition { .. }
        ));
    }
}
