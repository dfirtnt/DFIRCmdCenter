#!/usr/bin/env bash
# One-command live test of MCP Server A against real Action1 data.
# Reads credentials from .env (gitignored) if present, then launches the
# MCP Inspector against dfirctl-action1-mcp. Never put credentials in this
# file; edit .env instead (see .env.example).
set -euo pipefail
cd "$(dirname "$0")/.."

if [ -f .env ]; then
  set -a
  # shellcheck disable=SC1091
  source .env
  set +a
fi

if [ -z "${ACTION1_CLIENT_ID:-}" ] || [ -z "${ACTION1_CLIENT_SECRET:-}" ]; then
  echo "Missing ACTION1_CLIENT_ID / ACTION1_CLIENT_SECRET." >&2
  echo "cp .env.example .env, fill in real values, then re-run this script." >&2
  exit 1
fi

exec npx @modelcontextprotocol/inspector uv run dfirctl-action1-mcp
