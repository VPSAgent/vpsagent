# AGENTS.md

## Product Identity & Scope
- **Product:** VPSAgent — a lean, agent-native VPS control plane & Remote MCP Gateway ("Give your AI agent a $5 VPS, safely").
- **Stay Lean:** Do **not** add a built-in AI chat UI, LLM provider settings, Hermes integrations, or vision OCR. VPSAgent is the secure server & MCP layer that *external* AI agents connect to.
- **Stack:** TypeScript + `pnpm` workspaces (Node.js `>=24` LTS), Hono Control API, React 19 + Vite + Tailwind v4 Dashboard, built-in `node:sqlite` (WAL), Python host Runtime Bridge (`runtime-bridge.py`), Caddy 2 Auto-TLS, Docker Compose v2.

## Strict Boundaries (Do Not Touch)
- **Zero Docker Socket Exposure:** Core containers must never mount `/var/run/docker.sock`. All host Docker/Caddy operations flow strictly through the allowlisted Unix-socket Runtime Bridge.
- **Secrets:** Never read, print, hardcode, or commit `.env`, `.env.*`, SSH keys, TLS private keys, or bearer tokens (`vpsmcp_*`). Redact secrets in all logs, audit events, and MCP responses.
- **Git Hygiene:** Work on `<type>/<short-kebab-description>` feature branches (`feat/`, `fix/`, `refactor/`, `chore/`, `docs/`). Never commit directly to `main` after initial bootstrap.
- **Verification:** Always run build, typecheck, and tests after the final edit before reporting done.

## Communication Style
- The user is **not a developer** — always explain things in plain, everyday English.
- Avoid heavy engineering jargon; if you must use a technical term, explain it in ~5 words.
- Keep updates short and clear: what changed, why it matters, and what the user should click or approve next.
- Make sensible engineering defaults yourself instead of asking low-level technical questions.
