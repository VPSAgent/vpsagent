# VPSAgent

**Give your AI agent a $5 VPS, safely.**

VPSAgent is a lightweight, self-hosted control plane and **Remote MCP Gateway** for Ubuntu LTS servers. Install it once, paste a scoped **Visitor Pass** into **Claude Code, Cursor, Codex**, or your personal AI agent, and let your AI deploy and manage isolated apps — without ever handing it root SSH keys or `/var/run/docker.sock`.

---

## Think of It Like an Apartment Building

- **Your VPS** is the building.
- **Every app** lives in its own **Locked Apartment** container (`cap_drop: ALL`, `no-new-privileges`, isolated network, CPU/RAM caps, no Docker socket).
- **VPSAgent** is the front desk (`vpsagent-core`) plus a strictly allowlisted host handyman (`vpsagent-runtime`) connected over a Unix socket.
- **Your AI** gets a scoped **Visitor Pass** (`read-only`, `approval-required`, `safe-auto-deploy`, `auto-approve`, or `host-admin`).

```mermaid
flowchart LR
    You["You (Browser)"] -->|HTTPS| Edge["Caddy 2 Auto-TLS<br/>or Tailscale (*.ts.net)"]
    AI["AI Agent (Claude, Cursor, Codex)"] -->|HTTPS + vpsmcp_ Pass| Edge
    Edge --> Core["vpsagent-core<br/>Sidebar Dashboard + Control API + POST /mcp"]
    Core -->|Unix Socket (No Docker Socket)| Bridge["vpsagent-runtime.service"]
    Bridge --> App1["Locked Apartment: App 1<br/>+ Optional Postgres/Redis"]
    Bridge --> App2["Locked Apartment: App 2"]
```

---

## Documentation

| Guide | What You'll Learn |
| :--- | :--- |
| **[1. Getting Started & Install](docs/01-getting-started.md)** | Prerequisites, 4 install options (Domain, SSH Tunnel, Tailscale, Public 1-liner), and 2-step first-time setup. |
| **[2. Architecture & Security Model](docs/02-architecture-and-security.md)** | Zero-Root Safety Wall, Locked Apartment rules, 5 AI Visitor Pass scopes, AES-256-GCM secret encryption, and log redaction. |
| **[3. Dashboard User Guide](docs/03-dashboard-guide.md)** | Complete walkthrough of the sidebar dashboard: Overview, Apps (per-app pages, edit settings, rollback, Git auto-deploy, Postgres/Redis), Approvals, and Settings (AI access, alerts, backups, account, updates). |
| **[4. Connecting Your AI Agent](docs/04-connecting-ai-agents.md)** | Creating Visitor Passes, copy-paste configs for Claude Code, Cursor, and Codex, and the AI deploy workflow. |
| **[5. MCP Tools & Resources Reference](docs/05-mcp-reference.md)** | All **32 MCP tools** and **3 MCP resources** with parameters, defaults, and permission rules. |
| **[6. Operations, Upgrades & API](docs/06-api-and-operations.md)** | One-click SHA-256 updates, backups, Tailscale troubleshooting, `.env` variables, and REST API endpoints. |

---

## Quick Start (Ubuntu 22.04 / 24.04 LTS)

### With a Custom Domain (Public HTTPS via Caddy)

```bash
git clone git@github.com:VPSAgent/vpsagent.git "$HOME/vpsagent"
sudo bash "$HOME/vpsagent/bootstrap/install.sh" --domain vps.yourdomain.com --email you@yourdomain.com
```

### With Tailscale (Private HTTPS, No Domain Needed)

```bash
git clone git@github.com:VPSAgent/vpsagent.git "$HOME/vpsagent"
sudo bash "$HOME/vpsagent/bootstrap/install.sh" --tailscale
```

### Without a Domain Yet (Private SSH Tunnel Setup)

```bash
git clone git@github.com:VPSAgent/vpsagent.git "$HOME/vpsagent"
sudo bash "$HOME/vpsagent/bootstrap/install.sh"
```

### One-Line Public Repo Install

```bash
curl -fsSL https://raw.githubusercontent.com/VPSAgent/vpsagent/main/bootstrap/install.sh | sudo bash -s -- --domain vps.yourdomain.com --email you@yourdomain.com
```

---

## v2 Scope (Deliberately Lean)

- **Included:** Ubuntu one-shot installer, Caddy Auto-TLS, Tailscale private HTTPS, Host Runtime Bridge, SQLite WAL Registry, Streamable HTTP Remote MCP Gateway, public & private GitHub auto-build deploys (`Dockerfile`, Next.js, Vite, Node.js, Python, Static HTML), GitHub push auto-deploy webhooks, one-click rollback, private Postgres/Redis companions, one-click backups, instant alerts (Discord/Slack/Telegram/webhook), password & session management, one-click SHA-256 updates, and the sidebar Dashboard.
- **Excluded by design:** Built-in AI chatbots, LLM provider settings, Hermes integrations, or trying to rebuild Coolify/Dokploy. Bring the AI agent you already use.
