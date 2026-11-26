# Operations, Upgrades, Backups & API Reference

This guide covers day-to-day server maintenance, upgrading VPSAgent safely, backing up your data, troubleshooting Tailscale/TLS, and the complete REST API.

---

## 1. Upgrading VPSAgent

Every upgrade path preserves your `.env` secrets, SQLite database (`registry.db`), deployed apps, and active sessions.

### One-Click Dashboard Update (Recommended)

1. Open **AI Keys & Settings → VPSAgent updates**.
2. Click **Check for updates**.
   - If a GitHub Release is published, VPSAgent downloads the release archive and verifies its **SHA-256 checksum** (`SHA256SUMS`) before applying.
   - If no release is published yet, it checks your configured repository branch.
3. Click **Update** to rebuild `vpsagent-core`, restart `vpsagent-runtime.service`, and reconnect automatically.

### Check from Server Shell

```bash
sudo python3 /var/lib/vpsagent/runtime-bridge.py --check-update
```

Add `--json` for machine-readable output.

### Manual Shell Upgrade

```bash
git -C "$HOME/vpsagent" pull --ff-only
sudo bash "$HOME/vpsagent/bootstrap/install.sh"
```

---

## 2. Backups & Restore

All persistent state lives inside `/var/lib/vpsagent`:

- `/var/lib/vpsagent/.env` — Master runtime, session, and encryption secrets (losing `VPSAGENT_ENCRYPTION_SECRET` means encrypted `.env` values and GitHub tokens cannot be decrypted).
- `/var/lib/vpsagent/data/registry.db` — SQLite WAL database.
- `/var/lib/vpsagent/apps/` — Per-app Compose files, `.env` files, and `/app/data` persistent volumes.

To create a safe backup of your database and config:

```bash
sudo sqlite3 /var/lib/vpsagent/data/registry.db ".backup '/tmp/registry-backup.db'"
sudo tar -czf "$HOME/vpsagent-backup-$(date +%F).tar.gz" \
  /var/lib/vpsagent/.env \
  /tmp/registry-backup.db \
  /var/lib/vpsagent/apps
sudo rm -f /tmp/registry-backup.db
```

---

## 3. Troubleshooting Tailscale & HTTPS

- **Public Tailscale Funnel conflict on port 443:** If `tailscale funnel` was previously enabled on port 443, Tailscale Serve refuses to restrict `/mcp` to private tailnet-only traffic. Run:
  ```bash
  sudo tailscale funnel --https=443 off
  sudo tailscale serve --bg --https=443 http://127.0.0.1:3001
  ```
- **Custom Domain TLS still `pending`:** Verify your DNS `A` record points to your server's public IPv4 address and ports `80` and `443` are open in your cloud firewall. Then click **Re-check HTTPS** in **AI Keys & Settings**.
- **Check Runtime Bridge health:**
  ```bash
  sudo systemctl status vpsagent-runtime.service
  sudo curl --unix-socket /var/lib/vpsagent/run/runtime.sock http://localhost/health
  ```

---

## 4. Environment Variables (`bootstrap/.env.example`)

| Variable | Description |
| :--- | :--- |
| `VPSAGENT_DOMAIN` | Dashboard domain (`localhost` until configured). |
| `VPSAGENT_ACME_EMAIL` | Email used for Let's Encrypt TLS notices. |
| `VPSAGENT_PUBLIC_IP` | Detected public IPv4 address of the server. |
| `VPSAGENT_RUNTIME_TOKEN` | 64-char hex bearer token authenticating `vpsagent-core` → `runtime-bridge.py`. |
| `VPSAGENT_SESSION_SECRET` | 64-char hex secret signing browser session cookies. |
| `VPSAGENT_ENCRYPTION_SECRET` | 64-char hex key used for AES-256-GCM encryption of app secrets and GitHub tokens. |
| `VPSAGENT_CLAIM_TOKEN` | Single-use token for Step 1 first-time setup. |
| `VPSAGENT_RUNTIME_SOCKET` | Path to the Runtime Bridge Unix socket (`/var/lib/vpsagent/run/runtime.sock`). |
| `VPSAGENT_APPS_ROOT` | Root folder for isolated app directories (`/var/lib/vpsagent/apps`). |
| `VPSAGENT_CADDY_APPS_DIR` | Directory where per-app Caddy route files are written (`/var/lib/vpsagent/caddy/apps.d`). |

---

## 5. Control API Endpoints (`apps/api/src/app.ts`)

All `/api/*` endpoints (except `/api/health`, `/api/auth/session`, `/api/setup/claim`, and `/api/auth/login`) require an authenticated dashboard session cookie.

| Group | Method & Path | Purpose |
| :--- | :--- | :--- |
| **Health & Auth** | `GET /api/health` | Server & Runtime Bridge health check |
| | `GET /api/auth/session` | Current claim, login, and HTTPS/Tailscale state |
| | `POST /api/setup/claim` | Step 1: claim server with token & password |
| | `POST /api/auth/login` / `logout` | Sign in or sign out of the dashboard |
| **Setup & TLS** | `POST /api/setup/domain` | Set dashboard domain & trigger Caddy TLS |
| | `POST /api/setup/tls-recheck` | Actively re-verify live HTTPS certificate |
| | `POST /api/setup/apps-base-domain` | Set default base domain for auto app subdomains |
| **Overview & Apps** | `GET /api/overview` | Live CPU, RAM, disk, uptime, and app list |
| | `GET /api/apps` / `POST /api/apps` | List apps or deploy a new app |
| | `GET /api/apps/:slug` / `DELETE /api/apps/:slug` | Get app details or delete an app |
| | `POST /api/apps/:slug/{start,stop,restart,rebuild}` | App lifecycle controls |
| | `GET /api/apps/:slug/logs` | Read redacted container logs |
| | `GET /api/apps/:slug/inspect` | Inspect container health & Locked Apartment status |
| | `PUT /api/apps/:slug/domain` | Connect or remove custom domain |
| | `GET` / `PUT` / `DELETE /api/apps/:slug/env` | Manage encrypted environment variables |
| **Deployments** | `GET /api/deployments` / `GET /api/deployments/:id` | List or poll build deployments |
| **GitHub** | `POST /api/git/inspect` | Inspect a public/private GitHub repo |
| | `GET` / `POST` / `DELETE /api/git/credentials` | Manage saved GitHub tokens (`ghc_...`) |
| | `POST /api/git/credentials/:id/{default,test}` | Set default token or test token access |
| | `GET /api/git/repos` | List accessible GitHub repositories |
| **Approvals & Audit** | `GET /api/approvals` | List approval requests |
| | `POST /api/approvals/:id/{approve,reject}` | Approve or reject a pending AI request |
| | `GET /api/audit` | Search activity & audit history |
| **MCP & Passes** | `POST` / `GET` / `DELETE /mcp` | Streamable HTTP Remote MCP Gateway |
| | `GET` / `POST` / `DELETE /api/mcp/tokens` | List, create, or revoke AI Visitor Passes |
| | `GET /api/mcp/snippets` | Get Claude Code, Cursor, and Codex snippets |
| | `POST /api/mcp/test` | Run a live MCP connection test |
| **Tailscale** | `GET /api/tailscale/status` | Check Tailscale daemon, IP, and Serve status |
| | `POST /api/tailscale/serve` | Enable or disable Tailscale private HTTPS |
| | `POST /api/tailscale/connect` | Start Tailscale login or auth-key sign-in |
| **Updates** | `GET /api/system/update/status` | Current version & update check status |
| | `POST /api/system/update/check` | Check GitHub Releases / branch for updates |
| | `POST /api/system/update/apply` | Download, verify SHA-256, and apply update |
