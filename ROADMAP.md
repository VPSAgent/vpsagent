# VPSAgent v2 Roadmap (Plain English)

**What we are building:** A safe, simple control panel for a cheap $5 cloud server. You install it once, connect your own AI (like Claude Code, Cursor, or Codex), and let your AI launch and manage real apps for you — without ever giving it full control of your server.

**Think of it like an apartment building:**
- **Your server** is the building.
- **Every app** lives in its own locked apartment (it cannot peek into other apps or break the building).
- **VPSAgent** is the building manager at the front desk.
- **Your AI** gets a visitor pass (look only, ask you first, or trusted auto-pass).

---

## Step 1 — The Filing Cabinet & Security Rules *(Done)*
We built the foundation that keeps everything organized and safe:
- [x] **Project setup:** Created the clean folders for the server brain, the website, and the shared rules.
- [x] **Local memory (database):** A built-in file that remembers your apps, your approval requests, a full history log, and your AI visitor passes.
- [x] **Password & secret protection:** App passwords and keys are locked (encrypted) when saved, hidden as `••••••••` on screen, and automatically scrubbed from logs so they never accidentally leak.
- [x] **Safety checks built in:** Blocks unsafe web addresses, requires encrypted connections (`https://`) for remote AI access, and makes sure a "look-only" AI pass can never approve changes.

---

## Step 2 — The Locked Apartments *(Next)*
Next, we build the part that actually runs your apps safely:
- [ ] **Apartment blueprints:** Automatically creates the safety rules for each app — no master permissions, strict limits on how much power/memory it can use, and its own private room for optional databases (like Postgres or Redis).
- [ ] **The trusted handyman (Runtime Bridge):** A small, locked-down helper on the server that only does a short list of allowed jobs: starting/stopping apps, downloading code from GitHub and packaging it, checking server health, and updating web addresses. Your AI never gets raw server access.

---

## Step 3 — The Front Desk & AI Doorway
Next, we connect everything to a web server so both you and your AI can talk to it:
- [ ] **2-step first-time setup:** Right after you install VPSAgent, you open one private link to:
  1. Choose your login password.
  2. Connect your domain name (for automatic `https://` padlock security).
- [ ] **The AI doorway (Remote MCP):** Gives your AI (Claude Code, Cursor, or Codex) one secure web link and a visitor pass so it can:
  - Check server health and read app logs.
  - Launch ready-made apps or build apps directly from a GitHub link.
  - Add a private database, update app settings, connect a domain, or restart/delete an app.
  - Wait for your **Approve** click whenever you use an "ask first" pass.

---

## Step 4 — Your 4-Tab Website (Dashboard)
A clean, simple website with zero clutter — just 4 tabs:
- [ ] **First-time setup screen:** The 2-step screen from Step 3.
- [ ] **Tab 1 — Overview:** Shows how busy your server is (CPU, memory, storage) and which apps are running.
- [ ] **Tab 2 — Apps:** Start, stop, restart, rebuild, view logs, connect a domain, see attached databases, and safely edit hidden settings.
- [ ] **Tab 3 — Approvals & History:** One-click **Approve** or **Reject** for anything your AI asks to do, plus a searchable history of every action.
- [ ] **Tab 4 — AI Keys & Settings:** Create or turn off AI visitor passes, with ready-to-paste setup snippets for Claude Code, Cursor, and Codex.

---

## Step 5 — One-Command Install & Full Test
Finally, we make it effortless to install on any fresh $5 Ubuntu server and test the whole thing:
- [ ] **One-command installer:** One copy-paste command installs everything and turns on automatic `https://` security for your dashboard and every app.
- [ ] **Real-world test run:** Launch a real app and a GitHub app with secret settings and a database using an AI pass, approve it in the dashboard, check the live website, and confirm every test passes.
