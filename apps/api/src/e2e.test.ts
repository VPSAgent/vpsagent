import { execFileSync, spawn } from "node:child_process";
import fs from "node:fs";
import http from "node:http";
import type { AddressInfo } from "node:net";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import {
  HttpRuntimeBridgeClient,
  RegistryStore,
} from "@vpsagent/shared";
import { createVpsAgentApp } from "./app.js";

const REPO_ROOT = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "../../..",
);
const RUNTIME_BRIDGE_SCRIPT = path.join(
  REPO_ROOT,
  "bootstrap",
  "runtime-bridge.py",
);

function createFakeDockerShim(
  tempDir: string,
  stateFile: string,
): string {
  const shimPy = path.join(tempDir, "fake_docker.py");
  fs.writeFileSync(
    shimPy,
    `import json, os, sys

state_file = ${JSON.stringify(stateFile)}
args = sys.argv[1:]

def load_state():
    if os.path.exists(state_file):
        with open(state_file, "r", encoding="utf-8") as fh:
            return json.load(fh)
    return {"projects": {}, "networks": []}

def save_state(st):
    with open(state_file, "w", encoding="utf-8") as fh:
        json.dump(st, fh)

st = load_state()

if args[:1] == ["build"]:
    print("Step 1/1 : FROM node:24-alpine")
    print("Successfully built")
    sys.exit(0)

if args[:1] == ["compose"]:
    proj = args[args.index("-p") + 1] if "-p" in args else ""
    if "up" in args:
        st["projects"][proj] = "running"
        net = f"{proj}_app_net"
        if net not in st["networks"]:
            st["networks"].append(net)
        save_state(st)
        sys.exit(0)
    if "stop" in args:
        st["projects"][proj] = "stopped"
        save_state(st)
        sys.exit(0)
    if "restart" in args:
        st["projects"][proj] = "running"
        save_state(st)
        sys.exit(0)
    if "down" in args:
        st["projects"].pop(proj, None)
        save_state(st)
        sys.exit(0)
    if "ps" in args:
        status = st["projects"].get(proj, "stopped")
        if status == "running":
            print(json.dumps({"Name": proj, "State": "running", "Health": "healthy", "ExitCode": 0}))
        sys.exit(0)
    if "logs" in args:
        print(f"Listening for {proj}")
        print("Loaded STRIPE_SECRET_KEY=sk-live-never-leak-me-123456")
        sys.exit(0)

if args[:1] == ["ps"]:
    proj = ""
    for item in args:
        if item.startswith("label=com.docker.compose.project="):
            proj = item.split("=", 2)[2]
            break
    if proj and proj in st.get("projects", {}):
        print(f"cid-{proj}")
    sys.exit(0)

if args[:1] == ["inspect"]:
    target = args[1] if len(args) > 1 else ""
    proj = target[4:] if target.startswith("cid-") else f"vpsagent-{target[13:]}"
    status = st.get("projects", {}).get(proj)
    if not status:
        sys.exit(1)
    slug = proj[len("vpsagent-"):] if proj.startswith("vpsagent-") else proj
    is_running = status == "running"
    print(json.dumps([{
        "Id": f"abcdef123456{proj}",
        "Name": f"/vpsagent-app-{slug}",
        "RestartCount": 0,
        "Config": {"Image": f"vpsagent-app-{slug}:latest"},
        "State": {
            "Status": "running" if is_running else "exited",
            "Running": is_running,
            "ExitCode": 0 if is_running else 1,
            "StartedAt": "2026-11-24T01:00:00Z",
            "Health": {"Status": "healthy" if is_running else "unhealthy"},
        },
        "HostConfig": {
            "CapDrop": ["ALL"],
            "CapAdd": None,
            "PidMode": "",
            "IpcMode": "",
            "SecurityOpt": ["no-new-privileges:true"],
            "Privileged": False,
            "Memory": 536870912,
            "NanoCpus": 500000000,
            "Binds": [],
        },
        "Mounts": [],
        "NetworkSettings": {"Networks": {f"{proj}_app_net": {"IPAddress": "127.0.0.1"}}},
    }]))
    sys.exit(0)

if args[:2] == ["network", "inspect"]:
    if args[2] not in st["networks"]:
        sys.exit(1)
    sys.exit(0)

sys.exit(0)
`,
    "utf8",
  );
  const shPath = path.join(tempDir, "fake-docker");
  fs.writeFileSync(shPath, `#!/usr/bin/env sh\nexec python3 "${shimPy}" "$@"\n`, "utf8");
  fs.chmodSync(shPath, 0o755);
  return shPath;
}

function createFakeGitShim(tempDir: string): string {
  const shimPy = path.join(tempDir, "fake_git.py");
  fs.writeFileSync(
    shimPy,
    `import os, sys
args = sys.argv[1:]
if "clone" in args:
    dst = args[-1]
    os.makedirs(dst, exist_ok=True)
    with open(os.path.join(dst, "Dockerfile"), "w", encoding="utf-8") as fh:
        fh.write("FROM alpine:3.20\\n")
    sys.exit(0)
if "rev-parse" in args:
    print("0123456789abcdef0123456789abcdef01234567")
    sys.exit(0)
sys.exit(0)
`,
    "utf8",
  );
  const shPath = path.join(tempDir, "fake-git");
  fs.writeFileSync(shPath, `#!/usr/bin/env sh\nexec python3 "${shimPy}" "$@"\n`, "utf8");
  fs.chmodSync(shPath, 0o755);
  return shPath;
}

async function startBridge(options: {
  appsRoot: string;
  caddyAppsDir: string;
  dockerBin: string;
  gitBin: string;
  runtimeToken: string;
  socketPath: string;
}): Promise<{ close: () => Promise<void> }> {
  const child = spawn(
    "python3",
    [
      RUNTIME_BRIDGE_SCRIPT,
      "--socket",
      options.socketPath,
      "--apps-root",
      options.appsRoot,
      "--caddy-apps-dir",
      options.caddyAppsDir,
      "--docker-bin",
      options.dockerBin,
      "--git-bin",
      options.gitBin,
      "--runtime-token",
      options.runtimeToken,
    ],
    { stdio: ["ignore", "pipe", "pipe"] },
  );

  await new Promise<void>((resolve, reject) => {
    let out = "";
    let err = "";
    const timer = setTimeout(() => reject(new Error(`Bridge timeout: ${err}`)), 8000);
    child.stdout.on("data", (d: Buffer) => {
      out += d.toString("utf8");
      if (out.includes("LISTENING unix://")) {
        clearTimeout(timer);
        resolve();
      }
    });
    child.stderr.on("data", (d: Buffer) => {
      err += d.toString("utf8");
    });
    child.on("exit", (code) => {
      clearTimeout(timer);
      reject(new Error(`Bridge exited early (${code}): ${err}`));
    });
  });

  return {
    close: async () => {
      if (child.exitCode === null) {
        child.kill();
        await new Promise<void>((resolve) => {
          child.once("exit", () => resolve());
          setTimeout(resolve, 2000);
        });
      }
    },
  };
}

describe("VPSAgent v2 End-to-End Flow (2-step setup, Remote MCP, Approvals, Git + DB deploy, Bootstrap hardening)", () => {
  it("completes the full real-world lifecycle from first-boot claim to approved GitHub deploy and auto-approve image deploy", async () => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "vpsagent-e2e-"));
    const appsRoot = path.join(tempDir, "apps");
    const caddyAppsDir = path.join(tempDir, "caddy-apps");
    const socketPath = path.join(tempDir, "run", "runtime.sock");
    const stateFile = path.join(tempDir, "docker-state.json");
    fs.mkdirSync(appsRoot, { recursive: true });
    fs.mkdirSync(caddyAppsDir, { recursive: true });

    const dockerBin = createFakeDockerShim(tempDir, stateFile);
    const gitBin = createFakeGitShim(tempDir);
    const runtimeToken = "e2e-runtime-bridge-secret-token-9999";

    // Live mock HTTP app server: first hit 503 (warming up), second+ hit 404 (API root!)
    let probeHits = 0;
    const liveAppServer = http.createServer((_req, res) => {
      probeHits += 1;
      res.statusCode = probeHits === 1 ? 503 : 404;
      res.end(probeHits === 1 ? "starting" : '{"ok":true}');
    });
    await new Promise<void>((resolve) =>
      liveAppServer.listen(0, "127.0.0.1", () => resolve()),
    );
    const livePort = (liveAppServer.address() as AddressInfo).port;

    const bridgeProc = await startBridge({
      appsRoot,
      caddyAppsDir,
      dockerBin,
      gitBin,
      runtimeToken,
      socketPath,
    });

    const bridge = new HttpRuntimeBridgeClient({ socketPath, runtimeToken });
    const store = new RegistryStore(path.join(tempDir, "registry.db"), {
      encryptionSecret: "e2e-encryption-secret-32-bytes-long",
    });

    const claimToken = "initial-private-claim-token-2026";
    const { app } = createVpsAgentApp({
      store,
      bridge,
      appsRoot,
      sessionSecret: "e2e-session-secret-32-bytes-long",
      claimToken,
      trustProxy: true,
      readinessTimeoutSeconds: 5,
      readinessPollIntervalMs: 25,
      lookupFn: async () => [{ address: "140.82.121.4", family: 4 }],
    });

    try {
      // 1. Unclaimed session blocks private API routes
      const unauthOverview = await app.request("http://localhost/api/overview");
      expect(unauthOverview.status).toBe(401);

      // 2. Step 1 of first-boot setup: claim with #claim= token & set password
      const claimRes = await app.request("http://localhost/api/setup/claim", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          claimToken,
          passphrase: "correct-horse-battery-staple",
        }),
      });
      expect(claimRes.status).toBe(200);
      const setCookie = claimRes.headers.get("set-cookie");
      expect(setCookie).toContain("vpsagent_session=");
      const cookieHeader = setCookie!.split(";")[0]!;

      // 3. Step 2 of first-boot setup: connect dashboard domain for automatic HTTPS
      const domainRes = await app.request("http://localhost/api/setup/domain", {
        method: "POST",
        headers: {
          "content-type": "application/json",
          cookie: cookieHeader,
        },
        body: JSON.stringify({
          domain: "vps.example.com",
          acmeEmail: "owner@example.com",
        }),
      });
      expect(domainRes.status).toBe(200);

      // Verify MCP setup snippets include the HTTPS domain
      const snippetsRes = await app.request("http://localhost/api/mcp/snippets", {
        headers: { cookie: cookieHeader },
      });
      const snippets = (await snippetsRes.json()) as {
        mcpUrl: string;
        claudeCode: string;
        cursor: string;
        codex: string;
      };
      expect(snippets.mcpUrl).toBe("https://vps.example.com/mcp");
      expect(snippets.claudeCode).toContain("claude mcp add");
      expect(snippets.cursor).toContain("mcpServers");
      expect(snippets.codex).toContain("VPSAGENT_MCP_TOKEN");

      // 4. Create 3 scoped MCP tokens: read-only, approval-required, auto-approve
      const makeToken = async (
        name: string,
        scope: "read-only" | "approval-required" | "auto-approve",
      ) => {
        const res = await app.request("http://localhost/api/mcp/tokens", {
          method: "POST",
          headers: { "content-type": "application/json", cookie: cookieHeader },
          body: JSON.stringify({ name, scope }),
        });
        expect(res.status).toBe(201);
        return (await res.json()) as { rawToken: string };
      };

      const readOnly = await makeToken("Observer AI", "read-only");
      const approvalReq = await makeToken("Claude Code", "approval-required");
      const autoApprove = await makeToken("Trusted CI", "auto-approve");

      // 5. Remote MCP enforces HTTPS-only for non-loopback hosts
      const cleartextRemote = await app.request("http://vps.example.com/mcp", {
        method: "POST",
        headers: {
          "content-type": "application/json",
          host: "vps.example.com",
          authorization: `Bearer ${readOnly.rawToken}`,
        },
        body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list" }),
      });
      expect(cleartextRemote.status).toBe(403);

      const postMcp = (rawToken: string, payload: Record<string, unknown>) =>
        app.request("http://vps.example.com/mcp", {
          method: "POST",
          headers: {
            "content-type": "application/json",
            host: "vps.example.com",
            "x-forwarded-proto": "https",
            authorization: `Bearer ${rawToken}`,
          },
          body: JSON.stringify(payload),
        });

      // 6. Read-only key can read health, CANNOT deploy or queue approvals
      const healthMcp = await postMcp(readOnly.rawToken, {
        jsonrpc: "2.0",
        id: 2,
        method: "tools/call",
        params: { name: "get_host_health", arguments: {} },
      });
      expect(healthMcp.status).toBe(200);
      const healthBody = (await healthMcp.json()) as {
        result: { isError: boolean };
      };
      expect(healthBody.result.isError).toBe(false);

      const blockedDeploy = await postMcp(readOnly.rawToken, {
        jsonrpc: "2.0",
        id: 3,
        method: "tools/call",
        params: {
          name: "deploy_app",
          arguments: {
            slug: "blocked-app",
            name: "Blocked",
            sourceType: "image",
            image: "nginxinc/nginx-unprivileged:alpine",
          },
        },
      });
      const blockedJson = (await blockedDeploy.json()) as {
        result: { isError: boolean; content: Array<{ text: string }> };
      };
      expect(blockedJson.result.isError).toBe(true);
      expect(blockedJson.result.content[0]?.text).toMatch(/read-only/i);
      expect(store.listApprovals()).toHaveLength(0);

      // 7. Approval-required key requests a GitHub Dockerfile app with a secret .env + Postgres companion
      const queuedDeploy = await postMcp(approvalReq.rawToken, {
        jsonrpc: "2.0",
        id: 4,
        method: "tools/call",
        params: {
          name: "deploy_app",
          arguments: {
            slug: "shop-api",
            name: "Shop API",
            sourceType: "git",
            gitRepoUrl: "https://140.82.121.4/acme/shop-api.git",
            gitBranch: "main",
            dockerfilePath: "Dockerfile",
            domain: "shop.example.com",
            internalPort: livePort,
            companions: [{ type: "postgres" }],
            envVars: {
              STRIPE_SECRET_KEY: "sk-live-super$secret#value",
            },
          },
        },
      });
      const queuedJson = (await queuedDeploy.json()) as {
        result: { isError: boolean; content: Array<{ text: string }> };
      };
      expect(queuedJson.result.isError).toBe(false);
      const parsedQueued = JSON.parse(queuedJson.result.content[0]!.text) as {
        status: string;
        approvalId: string;
      };
      expect(parsedQueued.status).toBe("pending_approval");

      // Visible approval payload in dashboard must NEVER contain the raw Stripe secret
      const approvalsListRes = await app.request("http://localhost/api/approvals", {
        headers: { cookie: cookieHeader },
      });
      const approvalsList = (await approvalsListRes.json()) as {
        approvals: Array<{ id: string; payload: Record<string, unknown> }>;
      };
      expect(JSON.stringify(approvalsList)).not.toContain(
        "sk-live-super$secret#value",
      );

      // 8. Owner clicks Approve in dashboard -> builds Git repo, starts app + Postgres, retries readiness (503 -> 404), binds Caddy HTTPS route!
      const approveRes = await app.request(
        `http://localhost/api/approvals/${parsedQueued.approvalId}/approve`,
        {
          method: "POST",
          headers: { cookie: cookieHeader },
        },
      );
      expect(approveRes.status).toBe(200);
      const approvedBody = (await approveRes.json()) as {
        ok: boolean;
        approval: { status: string };
      };
      expect(approvedBody.ok).toBe(true);
      expect(approvedBody.approval.status).toBe("executed");

      // Confirm literal-quoted .env on disk received the REAL unredacted secret AND DATABASE_URL
      const envOnDisk = fs.readFileSync(
        path.join(appsRoot, "shop-api", ".env"),
        "utf8",
      );
      expect(envOnDisk).toContain(
        "STRIPE_SECRET_KEY='sk-live-super$secret#value'",
      );
      expect(envOnDisk).toContain("DATABASE_URL='postgresql://");

      // Confirm Caddy route file was written
      expect(
        fs.readFileSync(path.join(caddyAppsDir, "shop-api.caddy"), "utf8"),
      ).toContain(`reverse_proxy vpsagent-app-shop-api:${livePort}`);

      // Confirm Dashboard env endpoint masks secrets
      const maskedEnvRes = await app.request(
        "http://localhost/api/apps/shop-api/env",
        { headers: { cookie: cookieHeader } },
      );
      const maskedEnvText = await maskedEnvRes.text();
      expect(maskedEnvText).toContain("••••••••");
      expect(maskedEnvText).not.toContain("sk-live-super$secret#value");

      // Confirm logs redact secrets
      const logsRes = await app.request(
        "http://localhost/api/apps/shop-api/logs",
        { headers: { cookie: cookieHeader } },
      );
      const logsText = await logsRes.text();
      expect(logsText).not.toContain("sk-live-never-leak-me-123456");

      // 9. Auto-approve token launches a prebuilt image app directly
      const autoDeploy = await postMcp(autoApprove.rawToken, {
        jsonrpc: "2.0",
        id: 5,
        method: "tools/call",
        params: {
          name: "deploy_app",
          arguments: {
            slug: "landing-site",
            name: "Landing Site",
            sourceType: "image",
            image: "nginxinc/nginx-unprivileged:alpine",
            internalPort: livePort,
          },
        },
      });
      const autoJson = (await autoDeploy.json()) as {
        result: { isError: boolean };
      };
      expect(autoJson.result.isError).toBe(false);
      expect(store.getApp("landing-site")?.status).toBe("running");

      // 10. Bootstrap security invariants: ZERO Docker socket in core compose & valid shell syntax
      const coreCompose = fs.readFileSync(
        path.join(REPO_ROOT, "bootstrap", "docker-compose.core.yml"),
        "utf8",
      );
      expect(coreCompose).not.toContain("/var/run/docker.sock");
      expect(coreCompose).toContain("cap_drop:");
      expect(coreCompose).toContain("no-new-privileges:true");

      // Validate bootstrap/install.sh syntax with bash -n
      execFileSync("bash", ["-n", path.join(REPO_ROOT, "bootstrap", "install.sh")]);
    } finally {
      store.close();
      await bridgeProc.close();
      await new Promise<void>((resolve) =>
        liveAppServer.close(() => resolve()),
      );
      fs.rmSync(tempDir, { recursive: true, force: true });
    }
  });
});
