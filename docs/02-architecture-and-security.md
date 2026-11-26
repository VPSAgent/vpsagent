# How It Works & Security Model

VPSAgent is built around one core promise: **let your AI agent deploy and manage real apps on your VPS without ever giving it root SSH keys or raw Docker access.**

---

## 1. The Apartment Building Analogy

Think of your server like an apartment building:

| Real-World Concept | What It Is in VPSAgent |
| :--- | :--- |
| **The Building** | Your Ubuntu VPS. |
| **Locked Apartments** | Each app runs in its own isolated Docker container (`vpsagent-app-<slug>`) with strict resource caps, no root capabilities, and its own private network. |
| **The Front Desk** | `vpsagent-core` — serves the 4-tab web dashboard, Control API, and the Remote MCP doorway (`POST /mcp`). |
| **The Trusted Handyman** | `vpsagent-runtime` (`runtime-bridge.py`) — a small host service that only accepts an allowlist of safe actions over a permissioned Unix socket. |
| **Visitor Passes** | Scoped AI bearer tokens (`vpsmcp_...`) that control whether an AI can only look, must ask you first, or can deploy automatically. |

---

## 2. System Architecture

Notice that **`vpsagent-core` never mounts `/var/run/docker.sock`**. Even if an app or the web container were ever compromised, it cannot directly control Docker or the host. All host operations pass through the Runtime Bridge over a Unix socket (`runtime.sock`) authenticated with `VPSAGENT_RUNTIME_TOKEN`.

```mermaid
flowchart TB
    subgraph External["External Clients"]
        Browser["You (Web Browser)"]
        AI["Your AI Agent<br/>(Claude Code, Cursor, Codex)"]
    end

    subgraph Edge["HTTPS Termination"]
        Caddy["Caddy 2 (vpsagent-caddy)<br/>Auto Let's Encrypt TLS (80/443)"]
        TS["Tailscale Serve (Optional)<br/>Private *.ts.net HTTPS"]
    end

    subgraph Core["vpsagent-core Container (Zero Docker Socket)"]
        Web["4-Tab React Dashboard"]
        API["Hono Control API"]
        MCP["Remote MCP Gateway (POST /mcp)"]
        DB[("SQLite WAL<br/>registry.db + AES-256-GCM Secrets")]
    end

    subgraph Host["Ubuntu Host"]
        Sock{{"Unix Socket<br/>/var/lib/vpsagent/run/runtime.sock"}}
        Bridge["vpsagent-runtime.service<br/>(runtime-bridge.py Allowlist)"]
        subgraph Apt1["Locked Apartment: app-1"]
            C1["App Container<br/>cap_drop: ALL, CPU/RAM caps"]
            PG1["Optional Postgres / Redis"]
        end
        subgraph Apt2["Locked Apartment: app-2"]
            C2["App Container"]
        end
    end

    Browser -->|HTTPS| Caddy
    Browser -.->|Private HTTPS| TS
    AI -->|HTTPS + vpsmcp_ Token| Caddy
    AI -.->|Private HTTPS + Token| TS
    Caddy --> Web
    Caddy --> API
    Caddy --> MCP
    TS --> Web
    TS --> MCP
    API <--> DB
    MCP <--> DB
    API -->|Bearer Runtime Token| Sock
    MCP -->|Bearer Runtime Token| Sock
    Sock --> Bridge
    Bridge -->|Docker Compose v2| Apt1
    Bridge -->|Docker Compose v2| Apt2
    Bridge -->|Writes route files| Caddy
```

---

## 3. "Locked Apartment" Container Isolation

Every app deployed through VPSAgent (whether from a Docker image or a GitHub repository) gets a generated `docker-compose.yml` from `packages/shared/src/compose.ts` with these mandatory guardrails:

| Guardrail | Setting | Why It Matters |
| :--- | :--- | :--- |
| **No Linux root capabilities** | `cap_drop: [ALL]` | Prevents privilege escalation inside the container. |
| **No new privileges** | `no-new-privileges:true` | Blocks `setuid` binaries or capability elevation. |
| **Zero Docker socket** | Never mounted | Apps cannot inspect, start, or escape into other containers. |
| **Isolated bridge network** | `vpsagent-<slug>_app_net` | Apps cannot talk to other apps' internal networks or databases. |
| **CPU & memory caps** | Default `0.5` CPU, `512 MB` RAM | One runaway app cannot crash your entire $5 VPS. |
| **Non-root auto-builds** | `USER appuser` (`uid 10001`) | Auto-generated Dockerfiles for Node, Python, Next.js, Vite, and Static sites run as an unprivileged user. |
| **Persistent app storage** | `/var/lib/vpsagent/apps/<slug>/data` → `/app/data` | App data survives rebuilds without touching the rest of the host. |
| **Private companion DBs** | Postgres 16 / Redis 7 on `app_net` | Databases are never exposed to the public internet and get auto-generated random passwords. |

---

## 4. AI Visitor Passes & Approval Flow

Every AI key you create is a **Visitor Pass** with one of five permission levels, plus an optional list of **allowed app slugs** (`allowedSlugs`) so you can restrict an AI to specific apps only.

| Visitor Pass Level | Read / Inspect | App Deploy / Restart / Env / Domain | Delete App | Host Admin (`run_host_command`, `write_file`, `manage_service`, `docker_cleanup`, `delete_file`) |
| :--- | :---: | :---: | :---: | :---: |
| **`read-only`** | Allowed | Blocked | Blocked | Blocked |
| **`approval-required`** *(Recommended)* | Allowed | Queued for 1-click Approval | Queued for 1-click Approval | Queued for 1-click Approval |
| **`safe-auto-deploy`** | Allowed | Runs immediately | Queued for 1-click Approval | Queued for 1-click Approval |
| **`auto-approve`** | Allowed | Runs immediately | Runs immediately | Queued for 1-click Approval |
| **`host-admin`** | Allowed | Runs immediately | Runs immediately | Runs immediately |

```mermaid
flowchart TD
    Req["AI calls an MCP Tool"] --> Auth{"Valid vpsmcp_ Token<br/>& Allowed App Slug?"}
    Auth -- No --> Deny["401 / 403 Rejected"]
    Auth -- Yes --> Type{"Is it a Read-Only tool?"}
    Type -- Yes --> RunNow["Runs immediately<br/>(secrets redacted)"]
    Type -- No --> Scope{"Check Visitor Pass Scope"}
    Scope -- "read-only" --> Block["Blocked: read-only pass"]
    Scope -- "approval-required<br/>(or action requires approval)" --> Queue["Queued in Approvals Tab<br/>AI can poll wait_for_approval"]
    Queue --> Human{"You click Approve or Reject"}
    Human -- Approve --> Exec["Executes via Runtime Bridge<br/>& logs Audit Event"]
    Human -- Reject --> Stop["Cancelled & logged"]
    Scope -- "Allowed immediately<br/>for this scope" --> Exec
```

---

## 5. Secret Protection & Safety Guards

VPSAgent enforces multiple layers of secret hygiene (`packages/shared/src/safety.ts`):

1. **At-Rest Encryption:** App environment secrets and saved GitHub personal access tokens are encrypted with **AES-256-GCM** using `VPSAGENT_ENCRYPTION_SECRET` before being written to SQLite.
2. **Automatic Log & Output Redaction:** All container logs, build logs, host command output, MCP replies, and audit summaries are scrubbed for:
   - `Bearer` / `Basic` authorization headers
   - Known token prefixes (`vpsmcp_`, `ghp_`, `github_pat_`, `sk-`, `sk-ant-`, `xoxb-`, `AIza...`, `tskey-`, etc.)
   - PEM private keys (`-----BEGIN ... PRIVATE KEY-----`)
   - Embedded URL credentials (`https://user:pass@...`)
   - Key/value secrets (`PASSWORD=...`, `SECRET=...`, `API_KEY=...`)
3. **Protected Host Files:** `read_file` and `write_file` block reading or modifying `.env`, `.env.*`, SSH keys, TLS private keys, and `/var/lib/vpsagent/.env` or `registry.db`.
4. **Forbidden App Env Keys:** Apps cannot override `VPSAGENT_*`, `VPS_OS_*`, `DOCKER_*`, `LD_*`, `PATH`, `HOME`, `HOSTALIASES`, `IFS`, `ENV`, or `BASH_ENV`.
5. **SSRF & Path Traversal Prevention:** All app slugs (`2–48` lowercase alphanumeric + hyphens), domain names, Git branches, and container paths are strictly validated. Cloud metadata IPs (`169.254.169.254`, `100.100.100.200`, `metadata.google.internal`) and private/loopback IPs are blocked for external probes.
6. **Remote MCP Transport Security:** `POST /mcp` requires `https://` (or `X-Forwarded-Proto: https`) for all non-loopback requests and validates the `Host` / `Origin` headers against your configured domain or Tailscale domain.

---

**Next:** [Dashboard User Guide (All 4 Tabs) →](03-dashboard-guide.md)
