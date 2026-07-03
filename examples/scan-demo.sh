#!/usr/bin/env bash
# Sentinel scanner demo, in two parts:
#   1. static scan of a typical .mcp.json (nothing is executed)
#   2. live probe of a mock MALICIOUS server (local binary only) — catching
#      the poisoned tool description an agent would have swallowed as
#      trusted context, and generating a starter least-privilege policy.
#
# Run from the repo root:  ./examples/scan-demo.sh
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DEMO="$(mktemp -d)"
trap 'rm -rf "$DEMO"' EXIT

step() { printf '\n\033[1;36m== %s\033[0m\n' "$*"; }

step "Building sentinel-scan + a mock malicious MCP server"
cargo build -q -p sentinel-scan --bins
SCAN="$ROOT/target/debug/sentinel-scan"
MOCK="$ROOT/target/debug/mock-injected-mcp"

step "Part 1: a typical .mcp.json with the usual problems (static scan only)"
mkdir -p "$DEMO/static"
cat > "$DEMO/static/.mcp.json" <<'EOF'
{
  "mcpServers": {
    "email": {
      "command": "npx",
      "args": ["-y", "email-mcp"],
      "env": { "SMTP_API_KEY": "sk-live-supersecret12345" }
    },
    "crm": { "url": "http://crm-mcp.example.com/sse" }
  }
}
EOF
cat "$DEMO/static/.mcp.json"
echo
"$SCAN" "$DEMO/static" --fail-on never

step "Part 2: live-probe a malicious server (--probe EXECUTES the command — local mock only)"
mkdir -p "$DEMO/probe"
cat > "$DEMO/probe/.mcp.json" <<EOF
{ "mcpServers": { "utils": { "command": "$MOCK" } } }
EOF
"$SCAN" "$DEMO/probe" --probe --emit-policy "$DEMO/starter-policy.yaml" --fail-on never

step "The starter least-privilege policy it generated"
cat "$DEMO/starter-policy.yaml"

step "Done"
echo "The 'utils' server carried a prompt-injection payload in a tool"
echo "description — sentinel-scan caught it before an agent ingested it."
echo "Next: wrap what you keep with sentinel-gateway, and pin it:"
echo "  sentinel-gateway pin --out server.lock.yaml -- <command>"
