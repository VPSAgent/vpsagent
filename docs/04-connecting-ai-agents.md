# Connecting Your AI Agent (Remote MCP)

**MCP (Model Context Protocol)** is the standard doorway that lets AI tools like **Claude Code**, **Cursor**, and **Codex** talk to external servers safely. VPSAgent includes a built-in **Remote MCP Gateway** at `POST /mcp` so you don't need to install any plugins on your laptop or hand your AI an SSH key.

---

## 1. Create an AI Visitor Pass

1. Open **Settings → AI access** in your VPSAgent dashboard.
2. Under **AI Visitor Passes**, click **Create Pass**.
3. Give it a friendly name (for example, `Laptop Claude Code` or `Cursor Staging`).
4. Choose a **Permission Level**:

| Permission Level | Best For |
| :--- | :--- |
| **`read-only`** | Auditing, checking logs, reading server health, or inspecting repos without changing anything. |
| **`approval-required`** *(Recommended)* | Everyday use — your AI can inspect everything, and any change waits for your **Approve** click. |
| **`safe-auto-deploy`** | Fast iteration — your AI can deploy, rebuild, restart, and set domains/env right away, while `delete_app` and host-level commands still wait for your approval. |
| **`auto-approve`** | Trusted app automation — all isolated app actions (including `delete_app`) run immediately; host-level commands still require approval. |
| **`host-admin`** | Full server administration — allows immediate execution of host-level tools (`run_host_command`, `write_file`, `delete_file`, `manage_service`, `docker_cleanup`). |

5. *(Optional)* Enter **Allowed Apps** (comma-separated slugs like `my-blog, api-v2`) to lock the pass to only those apps.
6. Copy the generated `vpsmcp_...` token immediately — **for your security, it is shown only once.**

---

## 2. Paste Into Your AI Client

After creating a pass, **Settings → AI access** generates copy-paste snippets with your exact server URL (`https://your-domain/mcp` or `https://your-machine.tailnet.ts.net/mcp`).

### Claude Code (CLI)

```bash
claude mcp add --transport http vpsagent https://vps.yourdomain.com/mcp \
  --header "Authorization: Bearer vpsmcp_YOUR_TOKEN_HERE"
```

### Cursor (`~/.cursor/mcp.json` or `.cursor/mcp.json`)

```json
{
  "mcpServers": {
    "vpsagent": {
      "url": "https://vps.yourdomain.com/mcp",
      "headers": {
        "Authorization": "Bearer vpsmcp_YOUR_TOKEN_HERE"
      }
    }
  }
}
```

### OpenAI Codex (`~/.codex/config.toml`)

```toml
[mcp_servers.vpsagent]
url = "https://vps.yourdomain.com/mcp"
bearer_token_env_var = "VPSAGENT_MCP_TOKEN"
```

Then export `VPSAGENT_MCP_TOKEN="vpsmcp_YOUR_TOKEN_HERE"` in your shell profile.

### Generic Streamable HTTP MCP Client

- **Endpoint:** `POST https://vps.yourdomain.com/mcp`
- **Headers:**
  - `Authorization: Bearer vpsmcp_YOUR_TOKEN_HERE`
  - `Content-Type: application/json`
  - `Accept: application/json, text/event-stream`
- **Supported Protocol Versions:** `2025-11-25`, `2025-06-18`, `2025-03-26`

---

## 3. How the AI Deploy Workflow Works

When you ask your AI to deploy a GitHub repository, VPSAgent guides it through a safe, non-blocking pipeline:

```mermaid
sequenceDiagram
    actor You
    participant AI as Your AI Agent
    participant MCP as VPSAgent /mcp
    participant Bridge as Runtime Bridge
    participant App as Locked Apartment

    You->>AI: "Deploy my GitHub repo https://github.com/me/my-app"
    AI->>MCP: get_server_info()
    MCP-->>AI: CPU/RAM headroom, appsBaseDomain, pass scope
    AI->>MCP: inspect_git_repo(gitRepoUrl)
    MCP->>Bridge: Clone & inspect
    Bridge-->>MCP: Detected runtime (e.g. nextjs), port 3000, .env.example keys
    AI->>MCP: deploy_app(slug, name, sourceType="git", ...)
    alt Scope requires approval
        MCP-->>AI: status: "pending_approval", approvalId
        AI->>MCP: wait_for_approval(approvalId)
        You->>MCP: Click "Approve" in Dashboard
    end
    MCP-->>AI: status: "deploying", deploymentId
    AI->>MCP: get_deployment(deploymentId)
    Bridge->>App: Build non-root image, start container, probe HTTP, route Caddy HTTPS
    MCP-->>AI: status: "succeeded", live URL & envSettingsUrl
    AI-->>You: "Deployed! Visit https://my-app.apps.yourdomain.com"
```

> **Security Tip for Secrets:** Never paste database passwords, API keys, or GitHub tokens into your AI chat. When an app needs `.env` values (detected from `.env.example`), VPSAgent gives your AI an encrypted dashboard link (`envSettingsUrl` or `githubSettingsUrl`) to share with you so you can enter secrets directly in your browser.

---

## 4. Example Prompts to Try

- *"Check my VPS health and tell me which apps are currently running."*
- *"Inspect `https://github.com/vercel/next-learn` and tell me what runtime and env vars it needs."*
- *"Deploy my private repo `my-org/billing-api` with a Postgres companion database and attach `api.yourdomain.com`."*
- *"Show me the last 50 log lines for `billing-api` and check if its Locked Apartment security checks pass."*
- *"Restart `billing-api` and wait for my approval in the dashboard."*

---

**Next:** [Complete MCP Tools & Resources Reference →](05-mcp-reference.md)
