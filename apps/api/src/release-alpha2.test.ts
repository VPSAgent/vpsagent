import { spawn } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import http from "node:http";
import type { AddressInfo } from "node:net";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { gunzipSync } from "node:zlib";
import { describe, expect, it } from "vitest";
import { HttpRuntimeBridgeClient, RegistryStore } from "@vpsagent/shared";
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

function createFakeDockerShim(tempDir: string, stateFile: string): string {
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
    return {"projects": {}, "networks": [], "images": {}, "buildSeq": 0, "failLifecycle": False}

def save_state(st):
    with open(state_file, "w", encoding="utf-8") as fh:
        json.dump(st, fh)

st = load_state()

if args[:1] == ["build"]:
    tag = args[args.index("-t") + 1]
    st["buildSeq"] = st.get("buildSeq", 0) + 1
    st.setdefault("images", {})[tag] = f"sha256:build-{st['buildSeq']}"
    save_state(st)
    print(f"Successfully built {tag} ({st['images'][tag]})")
    sys.exit(0)

if args[:2] == ["image", "inspect"]:
    ref = args[-1]
    img_id = st.get("images", {}).get(ref)
    if not img_id:
        sys.exit(1)
    print(img_id)
    sys.exit(0)

if args[:1] == ["tag"]:
    src, dst = args[1], args[2]
    resolved = src if src.startswith("sha256:") else st.get("images", {}).get(src)
    if not resolved:
        sys.exit(1)
    st.setdefault("images", {})[dst] = resolved
    save_state(st)
    sys.exit(0)

if args[:1] == ["rmi"]:
    for target in args[1:]:
        if not target.startswith("-"):
            st.get("images", {}).pop(target, None)
    save_state(st)
    sys.exit(0)

if args[:1] == ["compose"]:
    proj = args[args.index("-p") + 1] if "-p" in args else ""
    if "up" in args:
        if st.get("failLifecycle"):
            sys.stderr.write("Simulated compose up failure\\n")
            sys.exit(1)
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
    if "exec" in args:
        sys.stdout.write("-- Postgres backup\\nSELECT 42;\\n")
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
        "Id": f"abcdef{proj}",
        "Name": f"/vpsagent-app-{slug}",
        "RestartCount": 0,
        "Config": {"Image": f"vpsagent-app-{slug}:latest"},
        "State": {
            "Status": "running" if is_running else "exited",
            "Running": is_running,
            "ExitCode": 0 if is_running else 1,
            "StartedAt": "2026-11-27T01:00:00Z",
            "Health": {"Status": "healthy" if is_running else "unhealthy"},
        },
        "HostConfig": {
            "CapDrop": ["ALL"],
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
  fs.writeFileSync(
    shPath,
    `#!/usr/bin/env sh\nexec python3 "${shimPy}" "$@"\n`,
    "utf8",
  );
  fs.chmodSync(shPath, 0o755);
  return shPath;
}

function createFakeGitShim(tempDir: string, commitFile: string): string {
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
    if "--abbrev-ref" in args:
        print("main")
    else:
        with open(${JSON.stringify(commitFile)}, "r", encoding="utf-8") as cfh:
            print(cfh.read().strip())
    sys.exit(0)
sys.exit(0)
`,
    "utf8",
  );
  const shPath = path.join(tempDir, "fake-git");
  fs.writeFileSync(
    shPath,
    `#!/usr/bin/env sh\nexec python3 "${shimPy}" "$@"\n`,
    "utf8",
  );
  fs.chmodSync(shPath, 0o755);
  return shPath;
}

async function startBridge(options: {
  vpsagentRoot: string;
  appsRoot: string;
  caddyAppsDir: string;
  caddyCoreDir: string;
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
      "--vpsagent-root",
      options.vpsagentRoot,
      "--apps-root",
      options.appsRoot,
      "--caddy-apps-dir",
      options.caddyAppsDir,
      "--caddy-core-dir",
      options.caddyCoreDir,
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
    const timer = setTimeout(
      () => reject(new Error(`Bridge timeout: ${err}`)),
      8000,
    );
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

function parseTarEntryNames(tarBuffer: Buffer): string[] {
  const names: string[] = [];
  let offset = 0;
  while (offset + 512 <= tarBuffer.length) {
    const header = tarBuffer.subarray(offset, offset + 512);
    if (header.every((b) => b === 0)) break;
    const rawName = header.subarray(0, 100).toString("utf8").replace(/\0.*$/, "");
    const sizeOctal = header
      .subarray(124, 136)
      .toString("utf8")
      .replace(/\0.*$/, "")
      .trim();
    const size = sizeOctal ? Number.parseInt(sizeOctal, 8) : 0;
    if (rawName) names.push(rawName);
    const dataBlocks = Math.ceil(size / 512) * 512;
    offset += 512 + dataBlocks;
  }
  return names;
}

describe("Release v2.0.0-alpha.2 features (CSRF, Auth/CLI reset, App settings, Rollback, Webhooks, Backups, Alerts)", () => {
  it("covers all alpha.2 features end-to-end with strict security boundaries", async () => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "va2-"));
    const vpsagentRoot = path.join(tempDir, "vpsagent");
    const appsRoot = path.join(vpsagentRoot, "apps");
    const dataDir = path.join(vpsagentRoot, "data");
    const caddyAppsDir = path.join(vpsagentRoot, "caddy", "apps.d");
    const caddyCoreDir = path.join(vpsagentRoot, "caddy", "core.d");
    const socketPath = path.join(tempDir, "r.sock");
    const stateFile = path.join(tempDir, "docker-state.json");
    const commitFile = path.join(tempDir, "git-commit.txt");
    fs.mkdirSync(appsRoot, { recursive: true });
    fs.mkdirSync(dataDir, { recursive: true });
    fs.mkdirSync(caddyAppsDir, { recursive: true });
    fs.mkdirSync(caddyCoreDir, { recursive: true });
    fs.writeFileSync(
      commitFile,
      "1111111111111111111111111111111111111111",
      "utf8",
    );

    const dockerBin = createFakeDockerShim(tempDir, stateFile);
    const gitBin = createFakeGitShim(tempDir, commitFile);
    const runtimeToken = "alpha2-runtime-bridge-secret-token";

    const liveAppServer = http.createServer((_req, res) => {
      res.statusCode = 200;
      res.end("ok");
    });
    await new Promise<void>((resolve) =>
      liveAppServer.listen(0, "127.0.0.1", () => resolve()),
    );
    const livePort = (liveAppServer.address() as AddressInfo).port;

    const sentAlerts: Array<{ url: string; body: Record<string, unknown> }> = [];
    const mockFetch: typeof fetch = async (input, init) => {
      const url = typeof input === "string" ? input : input.toString();
      const body = init?.body
        ? (JSON.parse(String(init.body)) as Record<string, unknown>)
        : {};
      sentAlerts.push({ url, body });
      return new Response(JSON.stringify({ ok: true }), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    };

    const bridgeProc = await startBridge({
      vpsagentRoot,
      appsRoot,
      caddyAppsDir,
      caddyCoreDir,
      dockerBin,
      gitBin,
      runtimeToken,
      socketPath,
    });

    const bridge = new HttpRuntimeBridgeClient({ socketPath, runtimeToken });
    const dbPath = path.join(dataDir, "registry.db");
    const store = new RegistryStore(dbPath, {
      encryptionSecret: "alpha2-encryption-secret-32-bytes-ok",
    });

    const claimToken = "alpha2-claim-token";
    const { app, healthAlerter } = createVpsAgentApp({
      store,
      bridge,
      appsRoot,
      sessionSecret: "alpha2-session-secret-32-bytes-ok",
      claimToken,
      trustProxy: true,
      isLocalListener: false,
      defaultPeerIp: "172.18.0.2",
      readinessTimeoutSeconds: 5,
      readinessPollIntervalMs: 25,
      lookupFn: async () => [{ address: "140.82.121.4", family: 4 }],
      notificationFetchFn: mockFetch,
    });

    try {
      // Claim and configure HTTPS domain
      const claimRes = await app.request("https://vps.example.com/api/setup/claim", {
        method: "POST",
        headers: {
          "content-type": "application/json",
          host: "vps.example.com",
          "x-forwarded-proto": "https",
        },
        body: JSON.stringify({
          claimToken,
          passphrase: "initial-password-2026",
        }),
      });
      expect(claimRes.status).toBe(200);
      let cookieHeader = claimRes.headers.get("set-cookie")!.split(";")[0]!;
      store.updateSetupState({
        domain: "vps.example.com",
        httpsActive: true,
        tlsStatus: "active",
      });

      const httpsHeaders = (extra?: Record<string, string>) => ({
        cookie: cookieHeader,
        host: "vps.example.com",
        "x-forwarded-proto": "https",
        origin: "https://vps.example.com",
        "sec-fetch-site": "same-origin",
        ...(extra ?? {}),
      });

      // 1. Global CSRF enforcement across /api/apps, /api/approvals, /api/mcp/tokens
      for (const target of [
        "/api/apps",
        "/api/approvals/apr_123/approve",
        "/api/mcp/tokens",
      ]) {
        const crossSite = await app.request(`https://vps.example.com${target}`, {
          method: "POST",
          headers: {
            cookie: cookieHeader,
            host: "vps.example.com",
            "x-forwarded-proto": "https",
            origin: "https://evil.example",
            "sec-fetch-site": "cross-site",
            "content-type": "application/json",
          },
          body: "{}",
        });
        expect(crossSite.status).toBe(403);

        const formPost = await app.request(`https://vps.example.com${target}`, {
          method: "POST",
          headers: {
            cookie: cookieHeader,
            host: "vps.example.com",
            "x-forwarded-proto": "https",
            "content-type": "application/x-www-form-urlencoded",
          },
          body: "a=1",
        });
        expect(formPost.status).toBe(415);
      }

      const crossSiteLogout = await app.request(
        "https://vps.example.com/api/auth/logout",
        {
          method: "POST",
          headers: {
            cookie: cookieHeader,
            host: "vps.example.com",
            "x-forwarded-proto": "https",
            origin: "https://evil.example",
            "sec-fetch-site": "cross-site",
          },
        },
      );
      expect(crossSiteLogout.status).toBe(403);

      // 2. Password change invalidates old cookie while issuing fresh valid cookie
      const oldCookie = cookieHeader;
      const badChange = await app.request(
        "https://vps.example.com/api/auth/change-password",
        {
          method: "POST",
          headers: httpsHeaders({ "content-type": "application/json" }),
          body: JSON.stringify({
            currentPassword: "wrong-password",
            newPassword: "second-password-2026",
          }),
        },
      );
      expect(badChange.status).toBe(401);

      const okChange = await app.request(
        "https://vps.example.com/api/auth/change-password",
        {
          method: "POST",
          headers: httpsHeaders({ "content-type": "application/json" }),
          body: JSON.stringify({
            currentPassword: "initial-password-2026",
            newPassword: "second-password-2026",
          }),
        },
      );
      expect(okChange.status).toBe(200);
      const freshCookie = okChange.headers.get("set-cookie")!.split(";")[0]!;
      expect(
        (
          await app.request("https://vps.example.com/api/overview", {
            headers: {
              cookie: oldCookie,
              host: "vps.example.com",
              "x-forwarded-proto": "https",
            },
          })
        ).status,
      ).toBe(401);
      expect(
        (
          await app.request("https://vps.example.com/api/overview", {
            headers: {
              cookie: freshCookie,
              host: "vps.example.com",
              "x-forwarded-proto": "https",
            },
          })
        ).status,
      ).toBe(200);
      cookieHeader = freshCookie;

      // Logout-all invalidates all sessions including current
      const logoutAllRes = await app.request(
        "https://vps.example.com/api/auth/logout-all",
        {
          method: "POST",
          headers: httpsHeaders({ "content-type": "application/json" }),
          body: JSON.stringify({ keepCurrent: false }),
        },
      );
      expect(logoutAllRes.status).toBe(200);
      expect(
        (
          await app.request("https://vps.example.com/api/overview", {
            headers: {
              cookie: cookieHeader,
              host: "vps.example.com",
              "x-forwarded-proto": "https",
            },
          })
        ).status,
      ).toBe(401);

      // Cross-runtime CLI --reset-password test
      const cliReset = await new Promise<{ code: number | null; stderr: string }>(
        (resolve) => {
          const p = spawn(
            "python3",
            [
              RUNTIME_BRIDGE_SCRIPT,
              "--reset-password",
              "--db-path",
              dbPath,
              "--password-stdin",
            ],
            { stdio: ["pipe", "pipe", "pipe"] },
          );
          let stderr = "";
          p.stderr.on("data", (d: Buffer) => {
            stderr += d.toString("utf8");
          });
          p.stdin.write("cli-recovered-pass-2026\n");
          p.stdin.end();
          p.on("exit", (code) => resolve({ code, stderr }));
        },
      );
      expect(cliReset.code).toBe(0);
      expect(store.verifyAdminPassphrase("cli-recovered-pass-2026")).toBe(true);

      const relogin = await app.request("https://vps.example.com/api/auth/login", {
        method: "POST",
        headers: {
          "content-type": "application/json",
          host: "vps.example.com",
          "x-forwarded-proto": "https",
          origin: "https://vps.example.com",
          "sec-fetch-site": "same-origin",
        },
        body: JSON.stringify({ passphrase: "cli-recovered-pass-2026" }),
      });
      expect(relogin.status).toBe(200);
      cookieHeader = relogin.headers.get("set-cookie")!.split(";")[0]!;

      // 3. Configure Instant Alerts (SSRF check, save, test, approval alert, down/recovery, secret redaction)
      const ssrfAlert = await app.request(
        "https://vps.example.com/api/notifications",
        {
          method: "PUT",
          headers: httpsHeaders({ "content-type": "application/json" }),
          body: JSON.stringify({
            enabled: true,
            channel: "webhook",
            webhookUrl: "https://127.0.0.1/evil",
          }),
        },
      );
      expect(ssrfAlert.status).toBe(400);

      const saveAlerts = await app.request(
        "https://vps.example.com/api/notifications",
        {
          method: "PUT",
          headers: httpsHeaders({ "content-type": "application/json" }),
          body: JSON.stringify({
            enabled: true,
            channel: "discord",
            webhookUrl:
              "https://discord.com/api/webhooks/123456/secret-webhook-token",
            notifyOnApproval: true,
            notifyOnAppDown: true,
            notifyOnDeployFailure: true,
          }),
        },
      );
      expect(saveAlerts.status).toBe(200);
      const alertJson = (await saveAlerts.json()) as {
        settings: { hasTargetSecret: boolean; targetHint: string };
      };
      expect(alertJson.settings.hasTargetSecret).toBe(true);
      expect(JSON.stringify(alertJson)).not.toContain("secret-webhook-token");

      const testAlertRes = await app.request(
        "https://vps.example.com/api/notifications/test",
        {
          method: "POST",
          headers: httpsHeaders({ "content-type": "application/json" }),
          body: "{}",
        },
      );
      expect(testAlertRes.status).toBe(200);
      expect(sentAlerts).toHaveLength(1);
      expect(String(sentAlerts[0]!.body.content)).toContain("VPSAgent Test Alert");

      // Create tokens (approval-required & auto-approve)
      const makePass = async (name: string, scope: string) => {
        const r = await app.request("https://vps.example.com/api/mcp/tokens", {
          method: "POST",
          headers: httpsHeaders({ "content-type": "application/json" }),
          body: JSON.stringify({ name, scope }),
        });
        expect(r.status).toBe(201);
        return ((await r.json()) as { rawToken: string }).rawToken;
      };
      const approvalToken = await makePass("AskBot", "approval-required");
      const autoToken = await makePass("AutoBot", "auto-approve");

      // Approval-required MCP call triggers instant approval alert (without leaking secret values)
      const queuedMcp = await app.request("https://vps.example.com/mcp", {
        method: "POST",
        headers: {
          "content-type": "application/json",
          host: "vps.example.com",
          "x-forwarded-proto": "https",
          authorization: `Bearer ${approvalToken}`,
        },
        body: JSON.stringify({
          jsonrpc: "2.0",
          id: 1,
          method: "tools/call",
          params: {
            name: "deploy_app",
            arguments: {
              slug: "web-demo",
              name: "Web Demo",
              sourceType: "image",
              image: "nginxinc/nginx-unprivileged:alpine",
              internalPort: livePort,
              envVars: { API_KEY: "sk-live-secret-should-never-alert" },
            },
          },
        }),
      });
      expect(queuedMcp.status).toBe(200);
      await new Promise((r) => setTimeout(r, 30));
      expect(sentAlerts.length).toBeGreaterThanOrEqual(2);
      const approvalAlertText = String(sentAlerts.at(-1)!.body.content);
      expect(approvalAlertText).toContain("AI Approval Needed");
      expect(approvalAlertText).not.toContain("sk-live-secret-should-never-alert");

      // 4. Deploy Git app, edit settings (+ file rollback on failure), attach Postgres, webhook, rebuild, rollback, backup
      const deployGitRes = await app.request("https://vps.example.com/api/apps", {
        method: "POST",
        headers: httpsHeaders({ "content-type": "application/json" }),
        body: JSON.stringify({
          slug: "my-git-app",
          name: "My Git App",
          sourceType: "git",
          gitRepoUrl: "https://github.com/acme/my-git-app.git",
          gitBranch: "main",
          internalPort: livePort,
          domain: "gitapp.example.com",
          cpuLimit: "0.5",
          memoryLimitMb: 512,
          companions: [{ type: "postgres" }],
          envVars: { APP_SECRET: "super-secret-env-value" },
        }),
      });
      expect(deployGitRes.status).toBe(201);
      const pgPassBefore = store.getAppEnvMapForRuntime("my-git-app").POSTGRES_PASSWORD;
      expect(pgPassBefore).toBeTruthy();

      // Simulate compose failure on PATCH -> disk files must restore cleanly
      const stFail = JSON.parse(fs.readFileSync(stateFile, "utf8")) as Record<string, unknown>;
      stFail.failLifecycle = true;
      fs.writeFileSync(stateFile, JSON.stringify(stFail), "utf8");
      const failedPatch = await app.request(
        "https://vps.example.com/api/apps/my-git-app",
        {
          method: "PATCH",
          headers: httpsHeaders({ "content-type": "application/json" }),
          body: JSON.stringify({ memoryLimitMb: 1024 }),
        },
      );
      expect(failedPatch.status).toBe(502);
      expect(store.getApp("my-git-app")?.memoryLimitMb).toBe(512);
      stFail.failLifecycle = false;
      fs.writeFileSync(stateFile, JSON.stringify(stFail), "utf8");

      // Successful PATCH via MCP update_app_settings (changes CPU/RAM/branch, adds Redis, preserves PG password)
      const mcpPatch = await app.request("https://vps.example.com/mcp", {
        method: "POST",
        headers: {
          "content-type": "application/json",
          host: "vps.example.com",
          "x-forwarded-proto": "https",
          authorization: `Bearer ${autoToken}`,
        },
        body: JSON.stringify({
          jsonrpc: "2.0",
          id: 2,
          method: "tools/call",
          params: {
            name: "update_app_settings",
            arguments: {
              slug: "my-git-app",
              cpuLimit: "1.0",
              memoryLimitMb: 1024,
              gitBranch: "release",
              companions: [{ type: "postgres" }, { type: "redis" }],
            },
          },
        }),
      });
      const mcpPatchJson = JSON.parse(
        ((await mcpPatch.json()) as { result: { content: Array<{ text: string }> } })
          .result.content[0]!.text,
      ) as { result: { app: { cpuLimit: string; memoryLimitMb: number }; needsRebuild: boolean } };
      expect(mcpPatchJson.result.needsRebuild).toBe(true);
      expect(mcpPatchJson.result.app.cpuLimit).toBe("1.0");
      expect(mcpPatchJson.result.app.memoryLimitMb).toBe(1024);
      expect(store.getAppEnvMapForRuntime("my-git-app").POSTGRES_PASSWORD).toBe(
        pgPassBefore,
      );

      // Seed healthAlerter while app is running, then test down + recovery + intentional stop suppression
      await healthAlerter.checkOnce(); // seeds
      const stDown = JSON.parse(fs.readFileSync(stateFile, "utf8")) as {
        projects: Record<string, string>;
      };
      stDown.projects["vpsagent-my-git-app"] = "stopped";
      fs.writeFileSync(stateFile, JSON.stringify(stDown), "utf8");
      await healthAlerter.checkOnce();
      await new Promise((r) => setTimeout(r, 30));
      expect(String(sentAlerts.at(-1)!.body.content)).toContain("looks offline");

      stDown.projects["vpsagent-my-git-app"] = "running";
      fs.writeFileSync(stateFile, JSON.stringify(stDown), "utf8");
      await healthAlerter.checkOnce();
      await new Promise((r) => setTimeout(r, 30));
      expect(String(sentAlerts.at(-1)!.body.content)).toContain("is back online");

      // Intentional stop suppresses offline alert
      const alertsCountBeforeStop = sentAlerts.length;
      await app.request("https://vps.example.com/api/apps/my-git-app/stop", {
        method: "POST",
        headers: httpsHeaders(),
      });
      await healthAlerter.checkOnce();
      await new Promise((r) => setTimeout(r, 30));
      expect(sentAlerts.length).toBe(alertsCountBeforeStop);

      // Start back up
      await app.request("https://vps.example.com/api/apps/my-git-app/start", {
        method: "POST",
        headers: httpsHeaders(),
      });

      // 5. GitHub push webhook: enable, reject bad sig, handle ping, ignore wrong branch, trigger on matching branch
      const enableHook = await app.request(
        "https://vps.example.com/api/apps/my-git-app/webhook",
        {
          method: "POST",
          headers: httpsHeaders({ "content-type": "application/json" }),
          body: "{}",
        },
      );
      expect(enableHook.status).toBe(200);
      const hookInfo = (await enableHook.json()) as {
        rawSecret: string;
        webhookUrl: string;
      };
      expect(hookInfo.webhookUrl).toBe(
        "https://vps.example.com/api/webhooks/github/my-git-app",
      );

      const sign = (payload: string) =>
        `sha256=${crypto.createHmac("sha256", hookInfo.rawSecret).update(payload, "utf8").digest("hex")}`;

      const badSigRes = await app.request(
        "https://vps.example.com/api/webhooks/github/my-git-app",
        {
          method: "POST",
          headers: {
            host: "vps.example.com",
            "x-forwarded-proto": "https",
            "x-github-event": "push",
            "x-hub-signature-256": "sha256=deadbeef",
            "content-type": "application/json",
          },
          body: JSON.stringify({ ref: "refs/heads/release" }),
        },
      );
      expect(badSigRes.status).toBe(401);

      const pingBody = JSON.stringify({ zen: "Keep it logically awesome." });
      const pingRes = await app.request(
        "https://vps.example.com/api/webhooks/github/my-git-app",
        {
          method: "POST",
          headers: {
            host: "vps.example.com",
            "x-forwarded-proto": "https",
            "x-github-event": "ping",
            "x-hub-signature-256": sign(pingBody),
            "content-type": "application/json",
          },
          body: pingBody,
        },
      );
      expect(pingRes.status).toBe(200);

      const wrongBranchBody = JSON.stringify({ ref: "refs/heads/other-branch" });
      const wrongBranchRes = await app.request(
        "https://vps.example.com/api/webhooks/github/my-git-app",
        {
          method: "POST",
          headers: {
            host: "vps.example.com",
            "x-forwarded-proto": "https",
            "x-github-event": "push",
            "x-hub-signature-256": sign(wrongBranchBody),
            "content-type": "application/json",
          },
          body: wrongBranchBody,
        },
      );
      expect(wrongBranchRes.status).toBe(200);
      expect(((await wrongBranchRes.json()) as { ignored: boolean }).ignored).toBe(
        true,
      );

      // Update commit SHA for second build, then fire matching push webhook
      fs.writeFileSync(
        commitFile,
        "2222222222222222222222222222222222222222",
        "utf8",
      );
      const pushBody = JSON.stringify({ ref: "refs/heads/release" });
      const pushRes = await app.request(
        "https://vps.example.com/api/webhooks/github/my-git-app",
        {
          method: "POST",
          headers: {
            host: "vps.example.com",
            "x-forwarded-proto": "https",
            "x-github-event": "push",
            "x-hub-signature-256": sign(pushBody),
            "content-type": "application/json",
          },
          body: pushBody,
        },
      );
      expect(pushRes.status).toBe(202);
      const pushJson = (await pushRes.json()) as {
        triggered: boolean;
        deploymentId: string;
      };
      expect(pushJson.triggered).toBe(true);

      // Wait for background rebuild triggered by webhook to finish
      let rebuiltApp = store.getApp("my-git-app");
      for (let i = 0; i < 40; i++) {
        const dep = store.getDeployment(pushJson.deploymentId);
        if (dep && dep.status === "succeeded") {
          rebuiltApp = store.getApp("my-git-app");
          break;
        }
        await new Promise((r) => setTimeout(r, 100));
      }
      expect(rebuiltApp?.lastCommitSha).toBe(
        "2222222222222222222222222222222222222222",
      );
      expect(rebuiltApp?.previousCommitSha).toBe(
        "1111111111111111111111111111111111111111",
      );
      expect(rebuiltApp?.rollbackAvailable).toBe(true);

      // 6. Rollback back to commit 1111111
      const rbRes = await app.request(
        "https://vps.example.com/api/apps/my-git-app/rollback",
        {
          method: "POST",
          headers: httpsHeaders({ "content-type": "application/json" }),
          body: "{}",
        },
      );
      expect(rbRes.status).toBe(200);
      const rbJson = (await rbRes.json()) as {
        app: { lastCommitSha: string; previousCommitSha: string };
        deployment: { action: string; status: string };
      };
      expect(rbJson.deployment.action).toBe("rollback_app");
      expect(rbJson.deployment.status).toBe("succeeded");
      expect(rbJson.app.lastCommitSha).toBe(
        "1111111111111111111111111111111111111111",
      );
      expect(rbJson.app.previousCommitSha).toBe(
        "2222222222222222222222222222222222222222",
      );

      // 7. One-click App & Server Backups exclude .env secrets
      const appBakRes = await app.request(
        "https://vps.example.com/api/apps/my-git-app/backup",
        {
          method: "POST",
          headers: httpsHeaders({ "content-type": "application/json" }),
          body: "{}",
        },
      );
      expect(appBakRes.status).toBe(200);
      expect(appBakRes.headers.get("content-type")).toContain("gzip");
      const appTarNames = parseTarEntryNames(
        gunzipSync(Buffer.from(await appBakRes.arrayBuffer())),
      );
      expect(appTarNames.some((n) => n.endsWith("/manifest.json"))).toBe(true);
      expect(appTarNames.some((n) => n.endsWith("/RESTORE.txt"))).toBe(true);
      expect(appTarNames.some((n) => n.endsWith("/postgres.sql"))).toBe(true);
      expect(appTarNames.some((n) => n.includes(".env"))).toBe(false);

      const sysBakRes = await app.request(
        "https://vps.example.com/api/system/backup",
        {
          method: "POST",
          headers: httpsHeaders({ "content-type": "application/json" }),
          body: JSON.stringify({ includeAppData: true }),
        },
      );
      expect(sysBakRes.status).toBe(200);
      const sysTarNames = parseTarEntryNames(
        gunzipSync(Buffer.from(await sysBakRes.arrayBuffer())),
      );
      expect(sysTarNames.some((n) => n.endsWith("/registry.db"))).toBe(true);
      expect(sysTarNames.some((n) => n.endsWith("/apps/my-git-app/postgres.sql"))).toBe(
        true,
      );
      expect(sysTarNames.some((n) => n.includes(".env"))).toBe(false);
    } finally {
      healthAlerter.stop();
      store.close();
      await bridgeProc.close();
      await new Promise<void>((resolve) =>
        liveAppServer.close(() => resolve()),
      );
      fs.rmSync(tempDir, { recursive: true, force: true });
    }
  }, 45_000);
});
