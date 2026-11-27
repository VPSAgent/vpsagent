# Dashboard User Guide

VPSAgent's web dashboard is organized around a clean sidebar (`Overview`, `Apps`, `Approvals`, `Settings`) and dedicated per-app pages — built so you can check server health, deploy and adjust apps, review AI requests, get instant alerts, and take backups in seconds.

---

## 1. Overview

The **Overview** page is your at-a-glance health check:

- **Server Resources:** Live CPU cores & 1-minute load average, memory (RAM) usage, disk space, and server uptime.
- **HTTPS & Domain Status:** Shows whether your public domain (`https://...`) or Tailscale private HTTPS (`https://*.ts.net`) is active.
- **Quick App Summary:** Running vs. stopped apps, plus a direct jump to any waiting AI approval requests.

---

## 2. Apps

The **Apps** page lists every isolated "Locked Apartment" app on your server.

### Deploying a New App

Click **New app** to launch either:

1. **GitHub Repository (Public or Private):**
   - Paste any `https://github.com/...` URL or pick directly from your connected GitHub repositories.
   - **Auto-detection:** If your repo has a `Dockerfile`, VPSAgent uses it. Otherwise, VPSAgent automatically detects **Next.js, Vite static sites, Node.js, Python (FastAPI/Uvicorn, Gunicorn, Flask), or Static HTML**, chooses the right port, and builds a non-root container image.
   - **Auto-subdomain:** If you set a default **Apps Base Domain** (e.g. `apps.yourdomain.com`), new apps automatically get `https://<slug>.apps.yourdomain.com` unless you specify another domain or mark the app private.
2. **Docker Image:**
   - Enter any Docker image reference (e.g. `nginxinc/nginx-unprivileged:alpine` or `ghcr.io/your-org/app:latest`), internal port, and optional domain.

### Companion Databases (Postgres & Redis)

You can attach private **Postgres 16** (`postgres:16-alpine`) or **Redis 7** (`redis:7-alpine`) companions when deploying or later in the app's **Settings** tab:
- They run on the app's private `vpsagent-<slug>_app_net` network (never exposed to the internet).
- VPSAgent generates strong random passwords and injects `DATABASE_URL` / `REDIS_URL` into your app's encrypted `.env` file automatically.

### Per-App Page

Click any app card to open its full page with quick action buttons (**Start / Stop**, **Restart**, **Rebuild**, **Rollback** when a previous working version is saved, and **Delete**) plus 6 sections:

| Section | What You Can Do |
| :--- | :--- |
| **Deploys** | Watch live build phases (`queued` → `cloning` → `building` → `starting` → `verifying` → `succeeded`), view commit SHA, detected runtime, and redacted build logs. |
| **Logs** | Read recent container logs (passwords and tokens are automatically scrubbed). |
| **Address** | Connect a custom `https://` domain (Caddy provisions the TLS certificate automatically) or disconnect it to keep the app private. |
| **Variables** | Add, update, or remove environment variables. Values marked as secrets are encrypted with AES-256-GCM and shown as `••••••••`. |
| **Health** | Inspect live container health, Docker liveness vs. host HTTP probe results, and verify **Locked Apartment** isolation (`cap_drop: ALL`, `no-new-privileges`, CPU/RAM limits, no Docker socket). |
| **Settings** | Edit display name, CPU/RAM caps, internal port, HTTP health check path, Git branch/Dockerfile/image, or attach/detach Postgres & Redis; turn on **GitHub push auto-deploy**; or **Download app backup (`.tar.gz`)**. |

---

## 3. Approvals

Whenever an AI agent with an `approval-required` pass (or a `safe-auto-deploy` pass requesting `delete_app`, or a non-`host-admin` pass requesting a host action) requests a change, it appears in **Approvals**:

- **One-Click Decision:** Review the plain-English summary, risk level (`low`, `medium`, `high`), and target app, then click **Approve** or **Reject** (with an optional note).
- **Searchable Activity History:** Browse or search the full audit log of every action taken by you, your AI agents, or the system.

---

## 4. Settings

The **Settings** area has 7 sections along the top bar:

1. **AI access:** Create or revoke `vpsmcp_...` Visitor Passes (`read-only`, `approval-required`, `safe-auto-deploy`, `auto-approve`, `host-admin`), lock a pass to specific apps, copy ready-to-paste configs for **Claude Code**, **Cursor**, **Codex**, or **T3 Code / Antigravity**, and run **Test Connection**.
2. **Domains & network:** Update your dashboard domain, re-check TLS certificate status, set a default `appsBaseDomain`, or connect **Tailscale Private HTTPS**.
3. **GitHub:** Save encrypted GitHub Personal Access Tokens so both you and your AI can browse and deploy private repos without pasting tokens into chat.
4. **Alerts:** Connect **Discord**, **Slack**, **Telegram**, or a **Custom HTTPS Webhook** (all secrets encrypted at rest) to get instant alerts for pending AI approvals, offline/recovered apps, or failed builds/rollbacks.
5. **Backups:** Download a full server backup (`.tar.gz`) containing your SQLite registry snapshot, Caddy routes, app blueprints, and optionally app data + live Postgres dumps (`.env` secrets are excluded for safety).
6. **Account:** Change your login password (automatically signs out older sessions), click **Sign out all devices**, or copy the one-line server CLI recovery command if you ever get locked out.
7. **Updates:** Check GitHub Releases (with SHA-256 checksum verification) or your repository branch, and click **Update** for a one-click zero-data-loss upgrade.

---

**Next:** [Connecting Your AI Agent (Remote MCP) →](04-connecting-ai-agents.md)
