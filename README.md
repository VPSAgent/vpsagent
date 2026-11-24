# VPSAgent

**Give your AI agent a $5 VPS, safely.**

VPSAgent is a lightweight, self-hosted control plane and **Remote MCP Gateway** for Ubuntu VPSs. Install it with one command, paste a scoped key into Claude Code, Cursor, Codex, or your personal AI agent, and let your AI deploy and manage isolated apps—without ever handing it root SSH keys or `/var/run/docker.sock`.

## One-Command Ubuntu LTS Install

With a domain pointed at your server's IP (automatic `https://` from boot):

```bash
curl -fsSL https://raw.githubusercontent.com/VPSAgent/vpsagent/main/bootstrap/install.sh | sudo bash -s -- --domain vps.yourdomain.com --email you@yourdomain.com
```

Without a domain yet (uses a private SSH tunnel so passwords never travel over plaintext HTTP, then lets you bind your domain in Step 2):

```bash
curl -fsSL https://raw.githubusercontent.com/VPSAgent/vpsagent/main/bootstrap/install.sh | sudo bash
```

## Core Pillars

1. **Zero-Root Safety Wall (`runtime-bridge`)** — Every workload runs inside an isolated "Locked Apartment" container (`cap_drop: ALL`, `no-new-privileges`, isolated bridge network, CPU/RAM caps, no Docker socket).
2. **Scoped Remote MCP Gateway (`POST /mcp`)** — Connect any frontier coding or personal agent with a single HTTPS URL and scoped bearer token (`read-only`, `approval-required`, or `auto-approve`).
3. **Minimal 4-Tab Dashboard** — Overview (live CPU/RAM/disk), Apps (lifecycle, logs, domains, `.env`), Approvals & Audit Log, and MCP Keys & Settings.

## v2 Scope (Deliberately Lean)

- **Included:** Ubuntu one-shot installer, Caddy Auto-TLS, Host Runtime Bridge, SQLite WAL Registry, Streamable HTTP MCP Gateway, real app & Git repo deploys (including `Dockerfile` builds & private Postgres/Redis companions), and the 4-tab Dashboard.
- **Excluded by design:** Built-in chatbots, multi-provider LLM settings, Hermes gateways, or trying to rebuild Coolify/Dokploy. Bring the AI agent you already use.
