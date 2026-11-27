# Contributing to VPSAgent

Thank you for helping make VPSAgent safer, leaner, and easier to run.

## Project Philosophy

VPSAgent is deliberately lean: it is the secure server and Remote MCP layer that **external** AI agents connect to. Please keep PRs focused and avoid adding built-in AI chat UIs, LLM provider settings, or unrelated PaaS features.

## Non-Negotiable Security Rules

1. **Zero Docker Socket Exposure** — Core containers must never mount `/var/run/docker.sock`. All host Docker and Caddy operations must flow through the allowlisted Unix-socket Runtime Bridge (`bootstrap/runtime-bridge.py`).
2. **No Secrets in Code or Logs** — Never commit `.env`, `.env.*`, SSH keys, TLS private keys, or bearer tokens (`vpsmcp_*`). Ensure any new log or MCP response redacts secrets.

## Development Setup

Requirements: **Node.js `>=24` LTS** and **pnpm `10.x`**.

```bash
pnpm install
```

Run the full verification suite before pushing:

```bash
pnpm verify
```

This runs:
- `pnpm build`
- `pnpm typecheck`
- `pnpm test`

## Branch & Pull Request Workflow

1. Create a feature branch from `main` using `<type>/<short-kebab-description>` (e.g., `feat/backup-retention`, `fix/caddy-reload`).
2. Make your changes and run `pnpm verify`.
3. Open a pull request against `main` and fill out the PR template checklist.
