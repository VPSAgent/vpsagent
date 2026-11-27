<div align="center">

<picture>
  <source media="(prefers-color-scheme: dark)" srcset=".github/assets/hero-dark.svg">
  <source media="(prefers-color-scheme: light)" srcset=".github/assets/hero-light.svg">
  <img alt="VPSAgent — Give your AI agent a $5 VPS, safely." src=".github/assets/hero-dark.svg" width="100%">
</picture>

<br/>

[![License: AGPL-3.0](https://img.shields.io/badge/License-AGPL--3.0-111111?style=flat-square)](LICENSE)
[![Release](https://img.shields.io/github/v/release/VPSAgent/vpsagent?include_prereleases&style=flat-square&color=111111&label=Release)](https://github.com/VPSAgent/vpsagent/releases)
[![Ubuntu LTS](https://img.shields.io/badge/Ubuntu-22.04%20%7C%2024.04%20LTS-111111?style=flat-square)](docs/01-getting-started.md)
[![Node.js](https://img.shields.io/badge/Node.js-%3E%3D24%20LTS-111111?style=flat-square)](package.json)
[![MCP](https://img.shields.io/badge/MCP-Streamable%20HTTP-111111?style=flat-square)](docs/05-mcp-reference.md)

**A lean, self-hosted VPS control plane and Remote MCP Gateway for Ubuntu LTS.**
Install it once, hand a scoped **Visitor Pass** to **Claude Code, Cursor, or Codex**, and let your AI deploy and manage isolated apps — without ever giving it root SSH keys or `/var/run/docker.sock`.

[Quick Start](#quick-start) · [How It Works](#how-it-works) · [Connect Your AI](#connect-your-ai-agent) · [Documentation](#documentation) · [Contributing](CONTRIBUTING.md)

</div>

---

## How It Works

Think of VPSAgent like a well-run **apartment building**:

| Concept | Role in VPSAgent |
| :--- | :--- |
| **Your VPS** | The building itself — hardened Ubuntu 22.04 / 24.04 LTS. |
| **Every App** | Lives in a **Locked Apartment** container (`cap_drop: ALL`, `no-new-privileges`, isolated network, CPU/RAM caps, zero Docker socket). |
| **VPSAgent** | The front desk (`vpsagent-core`) paired with a strictly allowlisted host handyman (`vpsagent-runtime`) over a Unix socket. |
| **Your AI** | Carries a scoped **Visitor Pass** (`read-only`, `approval-required`, `safe-auto-deploy`, `auto-approve`, or `host-admin`). |

```mermaid
flowchart LR
    You["You (Browser)"] -->|HTTPS| Edge["Caddy 2 Auto-TLS<br/>or Tailscale (*.ts.net)"]
    AI["AI Agent (Claude, Cursor, Codex)"] -->|HTTPS + vpsmcp_ Pass| Edge
    Edge --> Core["vpsagent-core<br/>Dashboard + Control API + POST /mcp"]
    Core -->|Unix Socket (No Docker Socket)| Bridge["vpsagent-runtime.service"]
    Bridge --> App1["Locked Apartment: App 1<br/>+ Optional Postgres / Redis"]
    Bridge --> App2["Locked Apartment: App 2"]
```

---

## Why VPSAgent?

- **Zero Docker Socket Exposure** — Core containers never mount `/var/run/docker.sock`. Host Docker and Caddy actions flow strictly through an allowlisted Unix-socket Runtime Bridge.
- **5 Scoped AI Visitor Passes** — Start with `approval-required` (every mutating action waits for your **Approve** click in the dashboard) or grant `safe-auto-deploy` for trusted apps.
- **32 MCP Tools & 3 Resources** — Native Streamable HTTP Remote MCP (`POST /mcp`) for deploying from GitHub, attaching Postgres/Redis, inspecting logs, managing domains, and rolling back releases.
- **Auto-Build & GitHub Webhooks** — Deploys public or private GitHub repos (`Dockerfile`, Next.js, Vite, Node.js, Python, Static HTML) with push-to-deploy webhooks and one-click rollback.
- **Encrypted Secrets & Scrubbed Logs** — App environment secrets are encrypted at rest with `AES-256-GCM`, masked in the UI, and automatically redacted from logs and MCP responses.
- **Built-in Operations** — One-click backups, instant alerts (Discord, Slack, Telegram, webhook), Tailscale private HTTPS, and one-click SHA-256 verified updates.

---

## Quick Start

Requires a fresh **Ubuntu 22.04 or 24.04 LTS** server. Pick the setup that fits your network:

### Option 1: One-Line Public Install (Custom Domain + Auto-TLS)

```bash
curl -fsSL https://raw.githubusercontent.com/VPSAgent/vpsagent/main/bootstrap/install.sh \
  | sudo bash -s -- --domain vps.yourdomain.com --email you@yourdomain.com
```

<details>
<summary><strong>More install options (Git clone, Tailscale private HTTPS, SSH tunnel)</strong></summary>

#### Custom Domain (Public HTTPS via Caddy)

```bash
git clone git@github.com:VPSAgent/vpsagent.git "$HOME/vpsagent"
sudo bash "$HOME/vpsagent/bootstrap/install.sh" --domain vps.yourdomain.com --email you@yourdomain.com
```

#### Tailscale (Private HTTPS, No Domain Needed)

```bash
git clone git@github.com:VPSAgent/vpsagent.git "$HOME/vpsagent"
sudo bash "$HOME/vpsagent/bootstrap/install.sh" --tailscale
```

#### No Domain Yet (Private SSH Tunnel)

```bash
git clone git@github.com:VPSAgent/vpsagent.git "$HOME/vpsagent"
sudo bash "$HOME/vpsagent/bootstrap/install.sh"
```

</details>

---

## Connect Your AI Agent

After the 2-step setup in the dashboard, create a **Visitor Pass** (`vpsmcp_...`) under **Settings → AI Keys** and paste the generated config into your client:

```json
{
  "mcpServers": {
    "vpsagent": {
      "type": "http",
      "url": "https://vps.yourdomain.com/mcp",
      "headers": {
        "Authorization": "Bearer vpsmcp_your_visitor_pass_here"
      }
    }
  }
}
```

> See **[Connecting Your AI Agent](docs/04-connecting-ai-agents.md)** for copy-paste setups for **Claude Code**, **Cursor**, and **Codex**.

---

## Documentation

| Guide | What You'll Learn |
| :--- | :--- |
| **[1. Getting Started & Install](docs/01-getting-started.md)** | Prerequisites, 4 install options (Domain, SSH Tunnel, Tailscale, Public 1-liner), and 2-step first-time setup. |
| **[2. Architecture & Security Model](docs/02-architecture-and-security.md)** | Zero-Root Safety Wall, Locked Apartment rules, 5 AI Visitor Pass scopes, AES-256-GCM secret encryption, and log redaction. |
| **[3. Dashboard User Guide](docs/03-dashboard-guide.md)** | Walkthrough of the sidebar dashboard: Overview, Apps, Approvals, and Settings (AI access, alerts, backups, updates). |
| **[4. Connecting Your AI Agent](docs/04-connecting-ai-agents.md)** | Creating Visitor Passes, copy-paste configs for Claude Code, Cursor, and Codex, and the AI deploy workflow. |
| **[5. MCP Tools & Resources Reference](docs/05-mcp-reference.md)** | All **32 MCP tools** and **3 MCP resources** with parameters, defaults, and permission rules. |
| **[6. Operations, Upgrades & API](docs/06-api-and-operations.md)** | One-click SHA-256 updates, backups, Tailscale troubleshooting, `.env` variables, and REST API endpoints. |

---

## Project Structure

```text
vpsagent/
├── apps/
│   ├── api/          # Hono Control API, SQLite WAL registry, Remote MCP Gateway
│   └── web/          # React 19 + Vite + Tailwind v4 sidebar dashboard
├── packages/
│   └── shared/       # Shared types, schemas, and redaction/security helpers
├── bootstrap/        # Ubuntu LTS installer & host Python Runtime Bridge
└── docs/             # User guides, architecture docs, and MCP reference
```

---

## Deliberately Lean

VPSAgent is the secure server & MCP layer that *external* AI agents connect to. Built-in AI chat UIs, LLM provider settings, and heavy PaaS bloat are **excluded by design** — bring the AI agent you already use.

---

## Contributing & Security

- Contributions are welcome! Please read **[CONTRIBUTING.md](CONTRIBUTING.md)** before opening a pull request.
- Found a security issue? Please report it privately per **[SECURITY.md](SECURITY.md)**.
- Licensed under **[GNU Affero General Public License v3.0](LICENSE)**.
