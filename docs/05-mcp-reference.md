# Complete MCP Tools & Resources Reference

VPSAgent exposes **30 MCP tools** and **3 MCP resources** over Streamable HTTP at `POST /mcp`. Every tool respects your Visitor Pass scope (`read-only`, `approval-required`, `safe-auto-deploy`, `auto-approve`, `host-admin`) and optional `allowedSlugs` restriction.

---

## 1. MCP Resources (Read-Only Context)

| Resource URI | Name | Description |
| :--- | :--- | :--- |
| `vpsagent://server/overview` | Server Overview | Live VPS CPU, memory, disk space, uptime, domain/HTTPS status, and running app counts. |
| `vpsagent://apps/list` | Managed Apps | Live list of all apps managed by VPSAgent (scoped to `allowedSlugs` if restricted). |
| `vpsagent://audit/recent` | Recent Activity History | Latest audit events recorded on the VPS. |

---

## 2. Read-Only Inspection Tools (14 Tools)

All 14 tools below are available to **every** Visitor Pass scope, including `read-only`.

| Tool | Description | Parameters |
| :--- | :--- | :--- |
| `get_server_info` | Server capabilities, CPU/RAM/disk headroom, `appsBaseDomain`, dashboard URL, `githubConnected`, and your pass permissions. | *(none)* |
| `get_host_health` | Live server CPU, memory, uptime, disk space, and running app counts. | *(none)* |
| `get_setup_status` | Configured domain, HTTPS/TLS certificate status, and Tailscale status. | `recheckTls?: boolean` (default `false`) |
| `list_github_repos` | List public and private GitHub repos accessible via saved GitHub tokens (never exposes raw tokens). | `query?: string`, `credentialId?: string`, `limit?: integer` (`1..100`, default `30`) |
| `inspect_git_repo` | Inspect a public/private GitHub repo before deploying: detects `Dockerfile` or auto-build runtime (`nextjs`, `vite-static`, `node`, `python`, `static`), suggested port, slug, DB hints, preview domain, and `.env.example` key names. | `gitRepoUrl: string` *(required)*, `gitBranch?: string`, `gitCredentialId?: string`, `dockerfilePath?: string` |
| `list_apps` | List managed apps (filtered by `allowedSlugs`) with live status, commit SHA, and detected runtime. | *(none)* |
| `get_deployment` | Check live progress, phase, commit SHA, detected runtime, redacted build logs, live URL, and `envSettingsUrl` for a deployment. | `deploymentId: string` *(required)* |
| `list_deployments` | List recent deployments and build statuses. | `slug?: string`, `limit?: integer` (`1..50`, default `10`) |
| `get_app_logs` | Read recent container logs for an app (automatically secret-scrubbed and byte-budgeted). | `slug: string` *(required)*, `tail?: integer` (`1..500`, default `100`) |
| `inspect_app` | Inspect live container health, Locked Apartment security compliance, masked env variable names, missing `.env.example` keys, and `envSettingsUrl`. | `slug: string` *(required)*, `probeHttp?: boolean` (default `false`), `probePath?: string` (default `"/"`) |
| `list_approvals` | List pending and recent approval requests in the dashboard queue. | `status?: "pending" \| "approved" \| "rejected" \| "executed" \| "failed"` |
| `wait_for_approval` | Wait up to 60s for a queued human approval request to be decided and executed. | `approvalId: string` *(required)*, `timeoutSeconds?: integer` (`1..60`, default `30`) |
| `get_audit_history` | Search and read recent activity and audit history. | `query?: string`, `targetSlug?: string`, `limit?: integer` (`1..200`, default `50`) |
| `list_files` | List files and folders inside a directory on the VPS host. | `path: string` *(required)*, `showHidden?: boolean` (default `false`), `maxEntries?: integer` (`1..500`, default `200`) |
| `read_file` | Read a text file on the VPS host (`.env`, private keys, and DB files are blocked; embedded secrets are redacted). | `path: string` *(required)*, `startLine?: integer` (default `1`), `endLine?: integer`, `maxBytes?: integer` (`256..131072`, default `65536`) |
| `list_services` | List systemd background services on the VPS host. | `filter?: string`, `state?: "all" \| "running" \| "failed"` (default `"all"`), `limit?: integer` (`1..300`, default `100`) |

*(Note: There are 16 read-only tools above; 14 mutating tools follow below — 30 tools total.)*

---

## 3. App Lifecycle & Configuration Tools (9 Tools)

Blocked for `read-only`. Queued for approval under `approval-required`. Run immediately under `safe-auto-deploy` (except `delete_app`), `auto-approve`, and `host-admin`.

| Tool | Description | Parameters |
| :--- | :--- | :--- |
| `deploy_app` | Deploy a Docker image or public/private GitHub repo into a Locked Apartment. Long builds continue in the background and return `deploymentId`. | `slug: string` *(required)*, `name: string` *(required)*, `sourceType: "image" \| "git"` *(required)*, `image?: string`, `gitRepoUrl?: string`, `gitBranch?: string`, `gitCredentialId?: string`, `dockerfilePath?: string` (default `"auto"`), `domain?: string \| null`, `noDomain?: boolean`, `internalPort?: integer`, `probeHttp?: boolean` (default `true`), `probePath?: string` (default `"/"`), `cpuLimit?: string` (default `"0.5"`), `memoryLimitMb?: integer` (default `512`), `companions?: Array<{ type: "postgres" \| "redis", version?: string, envKey?: string }>`, `envVars?: Record<string, string>` |
| `rebuild_app` | Rebuild and restart an existing app (re-cloning Git if applicable). Returns `deploymentId` if build runs in background. | `slug: string` *(required)* |
| `update_app_env` | Set or remove encrypted environment variables for an app and re-apply its `.env` file. | `slug: string` *(required)*, `vars?: Array<{ key: string, value: string, isSecret?: boolean }>`, `deleteKeys?: string[]` |
| `set_app_domain` | Connect a public HTTPS domain to an app, or pass `null` to unroute it. | `slug: string` *(required)*, `domain: string \| null` *(required)* |
| `start_app` | Start a stopped app container. | `slug: string` *(required)* |
| `restart_app` | Restart an app container. | `slug: string` *(required)* |
| `stop_app` | Stop an app container. | `slug: string` *(required)* |
| `delete_app` | Stop and remove an app, its Caddy route, and optionally its files. **Requires approval** for `approval-required` and `safe-auto-deploy`. | `slug: string` *(required)*, `removeFiles?: boolean` (default `true`) |
| `exec_in_app` | Run a shell command inside a running app container or companion service (`postgres`, `redis`). | `slug: string` *(required)*, `command: string` *(required)*, `service?: string` (default `"app"`), `timeoutSeconds?: integer` (`1..180`, default `30`) |

---

## 4. Host Administration Tools (5 Tools)

These tools operate directly on the VPS host. They are blocked for `read-only`, **require human approval** for `approval-required`, `safe-auto-deploy`, and `auto-approve`, and run immediately **only** with a `host-admin` Visitor Pass.

| Tool | Description | Parameters |
| :--- | :--- | :--- |
| `run_host_command` | Run a shell command on the VPS host (output is secret-redacted and logged). | `command: string` *(required)*, `cwd?: string`, `timeoutSeconds?: integer` (`1..180`, default `30`) |
| `write_file` | Create, overwrite, or append to a text file on the host (up to 256 KB; secret files blocked). | `path: string` *(required)*, `content: string` *(required)*, `append?: boolean` (default `false`), `createDirs?: boolean` (default `false`) |
| `delete_file` | Delete a file or directory on the host (critical system directories and secret files protected). | `path: string` *(required)*, `recursive?: boolean` (default `false`) |
| `manage_service` | Control a systemd service on the host. | `service: string` *(required)*, `action: "start" \| "stop" \| "restart" \| "reload" \| "enable" \| "disable" \| "status"` *(required)* |
| `docker_cleanup` | Prune stopped containers and unused Docker images, build cache, or volumes. | `pruneImages?: boolean` (default `true`), `pruneBuildCache?: boolean` (default `true`), `pruneVolumes?: boolean` (default `false`) |
