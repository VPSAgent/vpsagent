# VPSAgent

**Give your AI agent a $5 VPS, safely.**

VPSAgent is a lightweight, self-hosted control plane and **Remote MCP Gateway** for Ubuntu VPSs. Install it with one command, paste a scoped key into Claude Code, Cursor, Codex, or your personal AI agent, and let your AI deploy and manage isolated apps—without ever handing it root SSH keys or `/var/run/docker.sock`.

## Core Pillars

1. **Zero-Root Safety Wall (`runtime-bridge`)** — Every workload runs inside an isolated "Locked Apartment" container (`cap_drop: ALL`, `no-new-privileges`, isolated bridge network, CPU/RAM caps, no Docker socket).
2. **Scoped Remote MCP Gateway (`POST /mcp`)** — Connect any frontier coding or personal agent with a single URL and scoped bearer token (`read-only`, `approval-required`, or `auto-approve`).
3. **Minimal 4-Tab Dashboard** — Overview (live CPU/RAM/disk), Apps (lifecycle, logs, domains, `.env`), Approvals & Audit Log, and MCP Keys & Settings.

## v2 Scope (Deliberately Lean)

- **Included:** Ubuntu one-shot installer, Caddy Auto-TLS, Host Runtime Bridge, SQLite WAL Registry, Streamable HTTP MCP Gateway, real app & Git repo deploys (including container builds & companion DBs), and the 4-tab Dashboard.
- **Excluded by design:** Built-in chatbots, multi-provider LLM settings, Hermes gateways, or trying to rebuild Coolify/Dokploy. Bring the AI agent you already use.
