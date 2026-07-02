//! Policy evaluation: first-match-wins over the rule list.

use serde_json::Value;

use crate::glob::wildcard_match;
use crate::model::{ArgCond, Effect, Risk, Rule};
use crate::{CompiledCond, Policy};

/// Rule id reported when no rule matched and the default action applied.
pub const DEFAULT_RULE_ID: &str = "<default>";

/// Everything the engine knows about one tool call.
#[derive(Debug, Clone, Copy)]
pub struct CallCtx<'a> {
    /// Logical name of the MCP server (from gateway config, not the wire).
    pub server: &'a str,
    /// Tool being invoked (`params.name`).
    pub tool: &'a str,
    /// Identity of the agent making the call.
    pub agent: &'a str,
    /// Human principal the agent is acting on behalf of.
    pub principal: &'a str,
    /// Tool-call arguments (`params.arguments`).
    pub args: &'a Value,
}

/// The outcome of evaluating one call against the policy.
#[derive(Debug, Clone, PartialEq)]
pub struct Decision {
    /// What to do with the call.
    pub effect: Effect,
    /// Id of the rule that decided, or [`DEFAULT_RULE_ID`].
    pub rule_id: String,
    /// Risk attached by the deciding rule, if any.
    pub risk: Option<Risk>,
    /// Reason attached by the deciding rule, if any.
    pub reason: Option<String>,
}

impl Policy {
    /// Evaluate a tool call. First matching rule wins; if none match, the
    /// policy's `default_action` applies under [`DEFAULT_RULE_ID`].
    pub fn evaluate(&self, ctx: &CallCtx<'_>) -> Decision {
        for (rule, conds) in self.doc.rules.iter().zip(&self.compiled) {
            if rule_matches(rule, conds, ctx) {
                return Decision {
                    effect: rule.action,
                    rule_id: rule.id.clone(),
                    risk: rule.risk,
                    reason: rule.reason.clone(),
                };
            }
        }
        Decision {
            effect: self.doc.default_action,
            rule_id: DEFAULT_RULE_ID.to_string(),
            risk: None,
            reason: None,
        }
    }

    /// The effect this policy applies to `tool` regardless of arguments, for
    /// a fixed agent/principal — or `None` if the outcome depends on
    /// arguments (some argument-conditioned rule is reachable first).
    ///
    /// Used to hide unconditionally-denied tools from `tools/list` so the
    /// agent never sees capabilities it can't use (least privilege).
    pub fn static_effect(
        &self,
        server: &str,
        tool: &str,
        agent: &str,
        principal: &str,
    ) -> Option<Effect> {
        for rule in &self.doc.rules {
            let m = &rule.matcher;
            if let Some(sp) = &m.server {
                if !wildcard_match(sp, server) {
                    continue;
                }
            }
            if let Some(tools) = &m.tools {
                if !tools.iter().any(|g| wildcard_match(g, tool)) {
                    continue;
                }
            }
            if let Some(agents) = &m.agents {
                if !agents.iter().any(|g| wildcard_match(g, agent)) {
                    continue;
                }
            }
            if let Some(principals) = &m.principals {
                if !principals.iter().any(|g| wildcard_match(g, principal)) {
                    continue;
                }
            }
            if m.args.is_empty() {
                return Some(rule.action);
            }
            // An argument-conditioned rule is reachable: outcome is dynamic.
            return None;
        }
        Some(self.doc.default_action)
    }
}

fn rule_matches(rule: &Rule, conds: &[CompiledCond], ctx: &CallCtx<'_>) -> bool {
    let m = &rule.matcher;
    if let Some(sp) = &m.server {
        if !wildcard_match(sp, ctx.server) {
            return false;
        }
    }
    if let Some(tools) = &m.tools {
        if !tools.iter().any(|g| wildcard_match(g, ctx.tool)) {
            return false;
        }
    }
    if let Some(agents) = &m.agents {
        if !agents.iter().any(|g| wildcard_match(g, ctx.agent)) {
            return false;
        }
    }
    if let Some(principals) = &m.principals {
        if !principals.iter().any(|g| wildcard_match(g, ctx.principal)) {
            return false;
        }
    }
    m.args
        .iter()
        .zip(conds)
        .all(|(cond, compiled)| cond_holds(cond, compiled, ctx.args))
}

/// Walk a dot path into a JSON value. Numeric segments index arrays.
fn resolve<'a>(root: &'a Value, path: &str) -> Option<&'a Value> {
    if path.is_empty() {
        return Some(root);
    }
    let mut cur = root;
    for seg in path.split('.') {
        match cur {
            Value::Object(map) => cur = map.get(seg)?,
            Value::Array(items) => {
                let idx: usize = seg.parse().ok()?;
                cur = items.get(idx)?;
            }
            _ => return None,
        }
    }
    Some(cur)
}

/// String form used by `contains` / `matches`: strings verbatim, everything
/// else via its compact JSON serialization.
fn string_form(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

/// Apply `f` to the value's string form; for arrays, to each element
/// (any-element semantics).
fn any_str(v: &Value, mut f: impl FnMut(&str) -> bool) -> bool {
    match v {
        Value::Array(items) => items.iter().any(|e| f(&string_form(e))),
        other => f(&string_form(other)),
    }
}

fn cond_holds(cond: &ArgCond, compiled: &CompiledCond, args: &Value) -> bool {
    let value = resolve(args, &cond.path);

    if let Some(want) = cond.exists {
        if value.is_some() != want {
            return false;
        }
    }
    if let Some(expected) = &cond.equals {
        match value {
            Some(v) if v == expected => {}
            _ => return false,
        }
    }
    if let Some(needle) = &cond.contains {
        match value {
            Some(v) if any_str(v, |s| s.contains(needle.as_str())) => {}
            _ => return false,
        }
    }
    if let Some(re) = &compiled.matches {
        match value {
            Some(v) if any_str(v, |s| re.is_match(s)) => {}
            _ => return false,
        }
    }
    if let Some(re) = &compiled.not_matches {
        match value {
            Some(v) if any_str(v, |s| !re.is_match(s)) => {}
            _ => return false,
        }
    }
    if let Some(bound) = cond.gt {
        match value.and_then(Value::as_f64) {
            Some(n) if n > bound => {}
            _ => return false,
        }
    }
    if let Some(bound) = cond.lt {
        match value.and_then(Value::as_f64) {
            Some(n) if n < bound => {}
            _ => return false,
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

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

  - id: block-external-recipient
    match:
      server: email
      tools: ["send_email"]
      args:
        - path: to
          not_matches: "^[A-Za-z0-9._%+-]+@example\\.com$"
    action: approve
    risk: high
    reason: External recipient requires human approval

  - id: allow-send-internal
    match: { server: email, tools: ["send_email"] }
    action: allow

  - id: deny-delete
    match: { server: email, tools: ["delete_*"] }
    action: deny
    risk: high

  - id: cap-spend
    match:
      server: payments
      tools: ["create_charge"]
      args:
        - path: amount
          gt: 100.0
    action: approve
    risk: critical

  - id: allow-small-spend
    match: { server: payments, tools: ["create_charge"] }
    action: allow
"#;

    fn policy() -> Policy {
        Policy::from_yaml(POLICY).unwrap()
    }

    fn ctx<'a>(server: &'a str, tool: &'a str, args: &'a Value) -> CallCtx<'a> {
        CallCtx {
            server,
            tool,
            agent: "claude-code",
            principal: "keat@example.com",
            args,
        }
    }

    #[test]
    fn bcc_present_is_denied() {
        let args = json!({"to": ["boss@example.com"], "bcc": ["attacker@evil.com"], "body": "hi"});
        let d = policy().evaluate(&ctx("email", "send_email", &args));
        assert_eq!(d.effect, Effect::Deny);
        assert_eq!(d.rule_id, "block-bcc");
        assert_eq!(d.risk, Some(Risk::Critical));
    }

    #[test]
    fn external_recipient_needs_approval() {
        let args = json!({"to": ["press@rival.com"], "body": "hi"});
        let d = policy().evaluate(&ctx("email", "send_email", &args));
        assert_eq!(d.effect, Effect::Approve);
        assert_eq!(d.rule_id, "block-external-recipient");
    }

    #[test]
    fn mixed_recipients_still_flagged() {
        // Any-element semantics for not_matches: one external address among
        // internal ones must still trigger the rule.
        let args = json!({"to": ["boss@example.com", "leak@evil.com"]});
        let d = policy().evaluate(&ctx("email", "send_email", &args));
        assert_eq!(d.rule_id, "block-external-recipient");
    }

    #[test]
    fn internal_email_allowed() {
        let args = json!({"to": ["boss@example.com"], "body": "hi"});
        let d = policy().evaluate(&ctx("email", "send_email", &args));
        assert_eq!(d.effect, Effect::Allow);
        assert_eq!(d.rule_id, "allow-send-internal");
    }

    #[test]
    fn delete_glob_denied() {
        let args = json!({});
        let d = policy().evaluate(&ctx("email", "delete_all_emails", &args));
        assert_eq!(d.effect, Effect::Deny);
        assert_eq!(d.rule_id, "deny-delete");
    }

    #[test]
    fn unknown_tool_falls_to_default_deny() {
        let args = json!({});
        let d = policy().evaluate(&ctx("email", "export_mailbox", &args));
        assert_eq!(d.effect, Effect::Deny);
        assert_eq!(d.rule_id, DEFAULT_RULE_ID);
    }

    #[test]
    fn numeric_threshold_routes_to_approval() {
        let p = policy();
        let small = json!({"amount": 25.0, "currency": "usd"});
        let big = json!({"amount": 5000, "currency": "usd"});
        assert_eq!(
            p.evaluate(&ctx("payments", "create_charge", &small)).effect,
            Effect::Allow
        );
        let d = p.evaluate(&ctx("payments", "create_charge", &big));
        assert_eq!(d.effect, Effect::Approve);
        assert_eq!(d.rule_id, "cap-spend");
    }

    #[test]
    fn nested_paths_resolve() {
        let yaml = r#"
version: 1
default_action: allow
rules:
  - id: nested
    match:
      args:
        - path: recipients.0.address
          contains: "@evil.com"
    action: deny
"#;
        let p = Policy::from_yaml(yaml).unwrap();
        let bad = json!({"recipients": [{"address": "x@evil.com"}]});
        let ok = json!({"recipients": [{"address": "x@example.com"}]});
        assert_eq!(p.evaluate(&ctx("s", "t", &bad)).effect, Effect::Deny);
        assert_eq!(p.evaluate(&ctx("s", "t", &ok)).effect, Effect::Allow);
    }

    #[test]
    fn agent_and_principal_scoping() {
        let yaml = r#"
version: 1
default_action: deny
rules:
  - id: admins-only
    match:
      tools: ["restart_*"]
      principals: ["*@example.com"]
    action: allow
"#;
        let p = Policy::from_yaml(yaml).unwrap();
        let args = json!({});
        let allowed = CallCtx {
            server: "infra",
            tool: "restart_service",
            agent: "claude-code",
            principal: "ops@example.com",
            args: &args,
        };
        let denied = CallCtx {
            principal: "rando@gmail.com",
            ..allowed
        };
        assert_eq!(p.evaluate(&allowed).effect, Effect::Allow);
        assert_eq!(p.evaluate(&denied).effect, Effect::Deny);
    }

    #[test]
    fn static_effect_hides_unconditional_denies_only() {
        let p = policy();
        // delete_* is denied with no arg conditions -> statically deny.
        assert_eq!(
            p.static_effect("email", "delete_all_emails", "a", "p"),
            Some(Effect::Deny)
        );
        // send_email hits an arg-conditioned rule first -> dynamic.
        assert_eq!(p.static_effect("email", "send_email", "a", "p"), None);
        // unmatched tool -> default.
        assert_eq!(
            p.static_effect("email", "export_mailbox", "a", "p"),
            Some(Effect::Deny)
        );
    }

    #[test]
    fn first_match_wins_ordering() {
        let yaml = r#"
version: 1
default_action: deny
rules:
  - id: first
    match: { tools: ["x"] }
    action: allow
  - id: second
    match: { tools: ["x"] }
    action: deny
"#;
        let p = Policy::from_yaml(yaml).unwrap();
        let args = json!({});
        let d = p.evaluate(&ctx("s", "x", &args));
        assert_eq!(d.rule_id, "first");
        assert_eq!(d.effect, Effect::Allow);
    }

    #[test]
    fn missing_path_fails_value_predicates() {
        let yaml = r#"
version: 1
default_action: allow
rules:
  - id: needs-subject
    match:
      args: [{ path: subject, contains: "secret" }]
    action: deny
"#;
        let p = Policy::from_yaml(yaml).unwrap();
        let args = json!({"body": "no subject here"});
        assert_eq!(p.evaluate(&ctx("s", "t", &args)).effect, Effect::Allow);
    }
}
