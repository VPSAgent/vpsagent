# Dashboard User Guide (All 4 Tabs)

VPSAgent's web dashboard is deliberately clean and clutter-free — just **4 tabs** designed so you can see your server's health, manage your apps, approve or reject AI requests, and manage AI visitor passes in seconds.

---

## 1. Overview Tab

The **Overview** tab is your at-a-glance health check:

- **Server Resources:** Live CPU cores & 1-minute load average, memory (RAM) usage, disk space, and server uptime.
- **HTTPS & Domain Status:** Shows whether your public domain (`https://...`) or Tailscale private HTTPS (`https://*.ts.net`) is active.
- **Quick App Summary:** Count of running vs. stopped apps, plus a quick link to pending AI approvals if any are waiting.

---

## 2. Apps Tab

The **Apps** tab is where you deploy, monitor, and manage your isolated "Locked Apartment" apps.

### Deploying a New App

Click **Deploy App** to launch either:

1. **GitHub Repository (Public or Private):**
   - Paste any `https://github.com/...` URL (or pick directly from your connected GitHub repositories).
   - **Auto-detection:** If your repo has a `Dockerfile`, VPSAgent uses it. Otherwise, VPSAgent automatically detects **Next.js, Vite static sites, Node.js, Python (FastAPI/Uvicorn, Gunicorn, Flask), or Static HTML**, picks the right port, and builds a non-root container image.
   - **Auto-subdomain:** If you configured a default **Apps Base Domain** (e.g. `apps.yourdomain.com`), new apps automatically get `https://<slug>.apps.yourdomain.com` unless you choose a custom domain or mark the app private.
2. **Prebuilt Docker Image:**
   - Enter any Docker image reference (e.g. `nginx:alpine` or `ghcr.io/your-org/app:latest`), internal port, CPU/RAM limits, and optional domain.

### Companion Databases (Postgres & Redis)

When deploying an app, you can attach private **Postgres 16** (`postgres:16-alpine`) or **Redis 7** (`redis:7-alpine`) companion containers:
- They run on the app's private `vpsagent-<slug>_app_net` bridge network (never exposed publicly).
- VPSAgent auto-generates strong random passwords and injects `DATABASE_URL` / `REDIS_URL` into your app's encrypted `.env` file.

### App Detail Drawer

Click any app card to open its detail drawer with 5 sections:

| Section | What You Can Do |
| :--- | :--- |
| **Deployments** | Watch live build phases (`queued` → `cloning` → `building` → `starting` → `verifying` → `succeeded`), view commit SHA, detected runtime, and redacted build logs. |
| **Logs** | Read recent container logs (secrets are automatically scrubbed). |
| **Domain** | Connect a custom `https://` domain (Caddy provisions the TLS certificate automatically) or unroute to keep the app private. |
| **Env & Secrets** | Add, update, or delete environment variables. Values marked as secrets are encrypted with AES-256-GCM and shown as `••••••••`. |
| **Security** | Inspect the app's live container health and verify its **Locked Apartment** compliance (`cap_drop: ALL`, `no-new-privileges`, CPU/RAM limits, no Docker socket). |

---

## 3. Approvals & History Tab

Whenever an AI agent with an `approval-required` pass (or a `safe-auto-deploy` pass requesting `delete_app`, or a non-`host-admin` pass requesting a host action) tries to make a change, it appears in the **Pending Approvals** queue.

- **One-Click Decision:** Review the plain-English summary, risk level (`low`, `medium`, `high`), and target app, then click **Approve** or **Reject** (with an optional note).
- **Searchable Activity History:** Below the queue, browse or search the full audit log of every action taken by you, your AI agents, or the system.

---

## 4. AI Keys & Settings Tab

This tab holds your AI connection passes and server-wide settings:

1. **AI Visitor Passes (`vpsmcp_...`):**
   - Create passes with one of the 5 permission levels (`read-only`, `approval-required`, `safe-auto-deploy`, `auto-approve`, `host-admin`).
   - Optionally restrict a pass to specific app slugs (`allowedSlugs`).
   - Copy ready-to-paste setup snippets for **Claude Code**, **Cursor**, and **Codex**, or run the built-in **Test Connection** button.
   - Revoke any pass instantly with one click.
2. **Private GitHub Repositories:**
   - Save one or more GitHub Personal Access Tokens (encrypted at rest) so both you and your AI can browse and deploy private repos without ever pasting tokens into AI chat.
3. **Domain, Apps Base Domain & Tailscale:**
   - Update your dashboard domain, re-check TLS certificate status, set a default `appsBaseDomain` for automatic app subdomains, or toggle **Tailscale Private HTTPS**.
4. **VPSAgent Updates:**
   - Click **Check for updates** to check GitHub Releases (with SHA-256 checksum verification) or your repository branch, and click **Update** for a one-click zero-data-loss upgrade.

---

**Next:** [Connecting Your AI Agent (Remote MCP) →](04-connecting-ai-agents.md)
