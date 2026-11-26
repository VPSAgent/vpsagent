# VPSAgent

**Give your AI agent a $5 VPS, safely.**

VPSAgent is a lightweight, self-hosted control plane and **Remote MCP Gateway** for Ubuntu VPSs. Install it once, paste a scoped key into Claude Code, Cursor, Codex, or your personal AI agent, and let your AI deploy and manage isolated apps—without ever handing it root SSH keys or `/var/run/docker.sock`.

## Ubuntu LTS Install

### Option A — Authenticated Checkout (Works for Private or Public Repos, Standard Ubuntu User)

Clone the repository into your user home directory (using your existing SSH key or GitHub credentials), then run the local installer with `sudo`:

```bash
git clone git@github.com:VPSAgent/vpsagent.git "$HOME/vpsagent"
sudo bash "$HOME/vpsagent/bootstrap/install.sh" --domain vps.yourdomain.com --email you@yourdomain.com
```

Or install without a domain yet (uses a private SSH tunnel on `127.0.0.1:3002` so passwords never travel over plaintext HTTP, then lets you bind your domain or turn on Tailscale in Step 2):

```bash
git clone git@github.com:VPSAgent/vpsagent.git "$HOME/vpsagent"
sudo bash "$HOME/vpsagent/bootstrap/install.sh"
```

### Private HTTPS via Tailscale (No Domain or DNS Required)

If you don't want to buy a domain or set up DNS records, pass `--tailscale` to install Tailscale and enable private HTTPS for both your dashboard and AI doorway (`https://<machine>.<tailnet>.ts.net/mcp`):

```bash
git clone git@github.com:VPSAgent/vpsagent.git "$HOME/vpsagent"
sudo bash "$HOME/vpsagent/bootstrap/install.sh" --tailscale
```

(Optional for headless installs: set `VPSAGENT_TAILSCALE_AUTHKEY=tskey-auth-...` before `sudo -E bash ...` to sign the server into your tailnet automatically.)

### Option B — One-Line Public / Release Install (Public Repo Only)

When installing from a public repository or release mirror:

```bash
curl -fsSL https://raw.githubusercontent.com/VPSAgent/vpsagent/main/bootstrap/install.sh | sudo bash -s -- --domain vps.yourdomain.com --email you@yourdomain.com
```

### Upgrading an Existing Install

**One-click dashboard update (recommended):**

Open **AI Keys & Settings → VPSAgent updates** in your dashboard and click **Check for updates**. When a new GitHub Release is published, click **Update** to download, verify its SHA-256 checksum, rebuild `vpsagent-core`, restart the host Runtime Bridge, and reconnect automatically—or track your repository branch automatically if no release is published yet.

You can also check for newer releases directly from your server shell:

```bash
sudo python3 /var/lib/vpsagent/runtime-bridge.py --check-update
```

**Manual shell fallback:** pull the latest code in your checkout and re-run the installer:

```bash
git -C "$HOME/vpsagent" pull --ff-only
sudo bash "$HOME/vpsagent/bootstrap/install.sh"
```

Your existing secrets, database, apps, and sessions are preserved in every upgrade path. Even if an older install originally built from `/opt/vpsagent`, running `install.sh` from `$HOME/vpsagent` automatically updates `VPSAGENT_REPO_DIR`, restarts and health-checks `vpsagent-runtime.service`, and rebuilds `vpsagent-core` from the checkout that launched the installer.

## Core Pillars

1. **Zero-Root Safety Wall (`runtime-bridge`)** — Every workload runs inside an isolated "Locked Apartment" container (`cap_drop: ALL`, `no-new-privileges`, isolated bridge network, CPU/RAM caps, no Docker socket).
2. **Scoped Remote MCP Gateway (`POST /mcp`)** — Connect any frontier coding or personal agent with a single HTTPS URL and scoped bearer token (`read-only`, `approval-required`, or `auto-approve`).
3. **Minimal 4-Tab Dashboard** — Overview (live CPU/RAM/disk), Apps (lifecycle, logs, domains, `.env`), Approvals & Audit Log, and MCP Keys & Settings.

## v2 Scope (Deliberately Lean)

- **Included:** Ubuntu one-shot installer, Caddy Auto-TLS, Host Runtime Bridge, SQLite WAL Registry, Streamable HTTP MCP Gateway, real app & Git repo deploys (including `Dockerfile` builds & private Postgres/Redis companions), and the 4-tab Dashboard.
- **Excluded by design:** Built-in chatbots, multi-provider LLM settings, Hermes gateways, or trying to rebuild Coolify/Dokploy. Bring the AI agent you already use.
