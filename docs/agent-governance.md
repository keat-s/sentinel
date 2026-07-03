# Sentinel Gateway — the trust layer for AI agents

Give every AI agent least-privilege access, require human approval before
dangerous actions, and prove exactly what every agent did — self-hostable,
open-source, audit-ready.

`sentinel-gateway` is a governance proxy that sits between an MCP client
(Claude Code, Cursor, Copilot, any agent) and an MCP server. Every tool call
crosses the gateway, where three things happen:

1. **Authorization / least privilege** (`crates/sentinel-policy`) — the call
   is evaluated against YAML policy-as-code: which *agent*, acting for which
   *principal*, may call which *tool* on which *server*, with what
   *arguments*. First match wins; the default is deny. Tools the policy
   denies unconditionally are also **hidden from `tools/list`**, so the agent
   never sees capabilities it can't use. This addresses the confused-deputy
   problem: the server may be fully privileged, but the agent's path to it
   is not.

2. **Human-in-the-loop pre-action approval** — rules with `action: approve`
   park the call in an approval queue instead of executing it. A webhook
   (Slack-compatible) notifies your channel; a human approves or denies via
   CLI (`sentinel-gateway approvals approve <id>`) or the local HTTP control
   API. Unresolved approvals time out to **deny** — the gateway always fails
   closed.

3. **Tamper-evident audit** (`crates/sentinel-audit`) — every decision is
   appended to a hash-chained, ed25519-signed JSONL log attributing the
   action to agent + principal + policy rule. Editing, reordering, or
   deleting any entry breaks verification of everything after it.
   `sentinel-gateway audit verify` proves integrity offline with just the
   public key — evidence you can hand to an auditor (SOC 2, ISO 27001,
   EU AI Act logging obligations).

```
┌─────────────┐   tools/call    ┌──────────────────┐   (only if allowed)   ┌─────────────┐
│  MCP client  │ ──────────────▶ │ sentinel-gateway │ ────────────────────▶ │  MCP server  │
│ (the agent)  │ ◀────────────── │  policy · queue  │ ◀──────────────────── │ (email, db…) │
└─────────────┘  deny / result  └────────┬─────────┘                        └─────────────┘
                                          │
                             ┌────────────┼────────────────┐
                             ▼            ▼                ▼
                       policy.yaml   Slack webhook   audit.jsonl (signed,
                      (least-priv)   + control API    hash-chained)
```

The hot path is fully deterministic — no LLM, no network call, sub-millisecond
policy evaluation. The gateway is a single static binary.

## Quickstart

```bash
cargo build --release -p sentinel-gateway
export PATH="$PWD/target/release:$PATH"

# Scaffold config, starter policy, and audit signing keys
mkdir my-governed-server && cd my-governed-server
sentinel-gateway init

# Validate and dry-run policy without running anything
sentinel-gateway policy check
sentinel-gateway policy eval --server email --tool send_email \
    --args '{"to":["a@example.com"],"bcc":["x@evil.com"]}'
# → {"effect":"deny","rule_id":"block-bcc",...}  (exit code 1)

# Run: point your MCP client at this command instead of the real server
sentinel-gateway wrap --config sentinel-gateway.yaml -- npx your-mcp-server
```

For Claude Code, that means changing the server entry in `.mcp.json` from:

```json
{ "command": "npx", "args": ["your-mcp-server"] }
```

to:

```json
{
  "command": "sentinel-gateway",
  "args": ["wrap", "--config", "/path/to/sentinel-gateway.yaml", "--", "npx", "your-mcp-server"]
}
```

No changes to the client or the server — the gateway speaks standard MCP
stdio (one JSON-RPC message per line) on both sides and passes everything
through except what policy intercepts.

### The killer demo

```bash
./examples/gateway-demo.sh
```

Watch a prompt-injected agent try to BCC your mail to `attacker@evil.com`
(the postmark-mcp incident, made concrete), get blocked by rule `block-bcc`
before the request ever reaches the email server, and then watch log
tampering get caught by signature verification.

## Policy reference

```yaml
version: 1                # required, must be 1
default_action: deny      # deny | allow | approve — applies when no rule matches
rules:
  - id: unique-rule-id    # required; recorded in every audit entry it decides
    description: ...      # optional
    match:                # all specified fields must match (AND)
      server: email       # glob over the logical server name (config `server.name`)
      tools: ["send_*"]   # globs over tool name; any-of
      agents: ["claude-*"]        # globs over agent identity; any-of
      principals: ["*@corp.com"]  # globs over the human principal; any-of
      args:               # conditions over call arguments; all must hold
        - path: bcc               # dot path; numeric segments index arrays
          exists: true            # presence / absence
        - path: to
          not_matches: "^.*@corp\\.com$"   # regex; see semantics below
        - path: amount
          gt: 100.0               # also: lt, equals, contains, matches
    action: deny          # allow | deny | approve
    risk: critical        # low | medium | high | critical (optional)
    reason: ...           # shown to the agent on deny, and to approvers
```

Semantics worth knowing:

- **First match wins.** Order rules from most specific to most general.
- **Globs** support `*` (any run) and `?` (one char) — nothing fancier, on
  purpose: patterns should be auditable at a glance.
- **Array values**: `contains` / `matches` hold if *any* element matches;
  `not_matches` holds if *any* element fails the pattern (it flags the
  presence of a non-conforming value — one external address among ten
  internal ones still triggers).
- **Missing paths** fail value predicates (`equals`, `matches`, `gt`, …);
  use `exists: false` to require absence.
- **Regexes compile at load time** — a bad pattern is a startup error, never
  a hot-path failure.
- **`approve` without an approvals channel degrades to deny.** Fail closed.
- **Static denies hide tools**: if a rule with no argument conditions denies
  a tool for this agent/principal, the tool is stripped from `tools/list`
  responses (and an attempt to call it directly is still denied).

Dry-run any decision with
`sentinel-gateway policy eval --server S --tool T --args '{...}'`
(exit code 0 = allow, 1 = deny, 2 = approve — script-friendly).

## Approvals

```yaml
approvals:
  webhook_url: https://hooks.slack.com/services/...   # optional
  timeout_secs: 300        # unresolved → denied
  include_args: false      # keep argument content out of chat by default
control:
  listen: 127.0.0.1:9944   # local approvals API (0 port = OS-assigned)
```

When a call hits an `approve` rule, the gateway parks the JSON-RPC request
(other traffic keeps flowing), posts a notification, and waits:

```
sentinel-gateway approvals list
sentinel-gateway approvals approve <id> --by keat
sentinel-gateway approvals deny <id> --by keat
# or: curl -X POST http://127.0.0.1:9944/v1/approvals/<id>/approve
```

Approve → the original request is forwarded, the result returns to the agent
as if nothing happened. Deny or timeout → the agent receives a policy-denial
tool result naming the rule. Both the request and its resolution (including
who resolved it) are separate audit entries.

## Audit log format

One JSON object per line:

```json
{
  "record": {
    "seq": 4,
    "ts_ms": 1783003853844,
    "actor": { "agent": "claude-code", "principal": "you@example.com" },
    "event": {
      "type": "tool_call_evaluated",
      "server": "email", "tool": "send_email", "request_id": "4",
      "decision": "deny", "rule_id": "block-bcc", "risk": "critical",
      "reason": "...", "args": { "mode": "hash", "sha256": "..." }
    }
  },
  "prev": "<hex sha256 of previous entry>",
  "hash": "<hex sha256 over prev + canonical record JSON>",
  "sig":  "<hex ed25519 signature over the hash>",
  "key_id": "<first 8 bytes of sha256(pubkey)>"
}
```

Event types: `gateway_started` (with the policy file's SHA-256, so you can
prove *which* policy was in force), `tool_call_evaluated`,
`approval_requested`, `approval_resolved`, `tools_filtered`.

Verification checks sequence continuity, hash-chain linkage, recomputed
record hashes, and signatures — any edit, deletion, or reorder is detected:

```bash
sentinel-gateway audit verify --log sentinel-audit.jsonl --pub sentinel-audit.key.pub
sentinel-gateway audit tail --log sentinel-audit.jsonl -n 20
```

**Data minimization is the default**: `log_args: hash` records a SHA-256 of
the arguments — enough to prove what was sent (you can re-derive the hash
from a claimed payload) without storing content. `full` and `omit` are
opt-in. Self-hosting means none of this ever leaves your infrastructure.

## Provenance pinning & drift detection

The MCP supply chain has a signature attack: the **rug pull**. A server you
installed clean ships an update (or a compromised registry release) that
quietly rewrites a tool description to carry injected instructions — and the
agent ingests tool descriptions as trusted context. Policy alone can't catch
this: the tool name and arguments look identical.

Pin the server once, then let the gateway enforce it:

```bash
# Launch the server once in a controlled handshake; record the SHA-256 of
# the resolved executable and a digest of every tool definition.
sentinel-gateway pin --out server.lock.yaml -- npx my-mcp-server@1.4.2
```

```yaml
# gateway config
provenance:
  lock: server.lock.yaml
  enforce: block   # or `warn`
```

At `wrap` time the gateway verifies the executable hash **before running
it** — in `block` mode a swapped binary means the gateway refuses to start.
At runtime, every `tools/list` response is checked against the pinned
per-tool digests (name + description + schema, canonical JSON):

- **`block`**: drifted or newly-added tools are stripped from the list the
  agent sees, and direct calls to them are denied — even if policy would
  allow the tool. The violation and the denial are both audit entries.
- **`warn`**: traffic flows, but every divergence is on the signed record.

After a *deliberate* upgrade, review the new surface and re-pin.

Honest limitation: pinning `npx`/`uvx` hashes the launcher, not the package
it fetches — for those, the tool-surface digests are the meaningful pin
(and version-pin the package itself; `sentinel-scan` flags unpinned specs).
Package-level pinning is on the roadmap.

## MCP security scanner (`sentinel-scan`)

A standalone CLI that answers "what can agents on this machine actually
reach?" — and doubles as the on-ramp to governing it.

```bash
cargo build --release -p sentinel-scan

# Static scan: find MCP configs (Claude Code, Claude Desktop, Cursor,
# VS Code), flag the classic misconfigurations. Nothing is executed.
sentinel-scan .              # walk a directory
sentinel-scan . --home       # also check ~/.cursor, Claude Desktop, ...

# Live probe: launch each stdio server, fetch its tool surface, and analyze
# what the agent would ingest. EXECUTES the configured commands — opt-in.
sentinel-scan . --probe --emit-policy starter-policy.yaml

# CI: exit non-zero at or above a severity
sentinel-scan . --format json --fail-on high
```

Static checks: **SENTINEL-001** ungoverned server (not wrapped by
sentinel-gateway) · **002** unpinned package (`npx pkg` with no version,
`:latest` images) · **003** remote endpoint over plaintext HTTP · **004**
server launched via a shell · **005** inline secrets in config env ·
**006** duplicate server names across configs (shadowing).

Probe checks: **SENTINEL-101** prompt-injection phrases in tool metadata
(descriptions *and* schema strings) · **102** invisible/bidi characters
hiding payloads from human review · **103/104** destructive and
outward-facing tool surfaces · **105** oversized tool surface.

`--emit-policy` turns the observed tool surface into a real, loadable
starter policy: destructive tools denied, outward-facing tools routed to
approval, reads allowed, default deny. Demo: `./examples/scan-demo.sh`.

## Security model & current limitations

What the gateway defends against today:

- **Prompt-injected exfiltration / unauthorized actions** — the agent can
  only reach tools and argument shapes the policy grants; everything else is
  refused before it reaches the server.
- **Shadow capabilities** — statically denied tools are invisible to the
  agent.
- **Supply-chain rug pulls** — a pinned server that swaps its executable or
  mutates its tool definitions is blocked (or at minimum recorded), per the
  provenance section above.
- **After-the-fact log doctoring** — the signed hash chain makes silent
  edits detectable by anyone with the public key.

What it does not (yet) defend against — be honest with yourself about these:

- A client configured to talk to the real server directly bypasses the
  gateway entirely. Enforce at the deployment layer (the agent host should
  only have the gateway on PATH / in `.mcp.json`).
- An attacker with write access to the signing key can rewrite history.
  Protect the key file (created `0600`); ship logs off-host if you need
  stronger guarantees.
- Truncating the log *tail* is detectable only if you record the chain head
  elsewhere (e.g. `audit verify` output in CI). Anchoring heads to an
  external store is on the roadmap.
- stdio transport only for now; HTTP/SSE MCP servers are on the roadmap.
- One gateway instance per wrapped server (that's also its isolation model).

## Roadmap

- ~~MCP server provenance/attestation: pin and verify what you're wrapping~~
  — shipped (`sentinel-gateway pin` + `provenance:` enforcement above).
- ~~MCP security scanner~~ — shipped (`sentinel-scan`).
- HTTP/SSE MCP transport; one gateway fronting many servers.
- Package-level pinning for `npx`/`uvx`-launched servers (registry
  integrity, not just launcher hash + tool surface).
- OIDC-derived principals (Entra ID / Okta) instead of static config.
- Managed control plane: centralized policy, cross-fleet audit dashboard,
  agent inventory, SSO/SCIM.
- External chain-head anchoring, OTEL export, retention controls.

## Crate map

| Crate | What it is |
|---|---|
| `sentinel-policy` | Policy schema, validation, deterministic evaluator |
| `sentinel-audit` | Signed hash-chain writer/verifier, key management |
| `sentinel-gateway` | The `sentinel-gateway` binary: MCP proxy, approvals broker, control API, provenance pin/enforce, CLI (`wrap`, `init`, `keygen`, `pin`, `policy`, `audit`, `approvals`) + `mock-email-mcp` demo server |
| `sentinel-scan` | The `sentinel-scan` binary: MCP config scanner + live tool-surface probe + starter-policy generator, with `mock-injected-mcp` as the adversarial fixture |
