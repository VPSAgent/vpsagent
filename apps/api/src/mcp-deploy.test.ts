import { spawn } from "node:child_process";
import fs from "node:fs";
import http from "node:http";
import type { AddressInfo } from "node:net";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
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
const PYTHON_BIN = process.platform === "win32" ? "python" : "python3";

function wrapPythonShim(tempDir: string, name: string, pyCode: string): string {
  const pyPath = path.join(tempDir, `${name}.py`);
  fs.writeFileSync(pyPath, pyCode, "utf8");
  if (process.platform === "win32") {
    const cmdPath = path.join(tempDir, `${name}.cmd`);
    fs.writeFileSync(
      cmdPath,
      `@echo off\r\n${PYTHON_BIN} "${pyPath}" %*\r\n`,
      "utf8",
    );
    return cmdPath;
  }
  const shPath = path.join(tempDir, name);
  fs.writeFileSync(
    shPath,
    `#!/usr/bin/env sh\nexec ${PYTHON_BIN} "${pyPath}" "$@"\n`,
    "utf8",
  );
  fs.chmodSync(shPath, 0o755);
  return shPath;
}

function createCrossPlatformDockerShim(
  tempDir: string,
  stateFile: string,
): string {
  return wrapPythonShim(
    tempDir,
    "fake-docker",
    `import json, os, sys, time

state_file = ${JSON.stringify(stateFile)}
args = sys.argv[1:]

def load_state():
    if os.path.exists(state_file):
        with open(state_file, "r", encoding="utf-8") as fh:
            return json.load(fh)
    return {"projects": {}, "networks": [], "buildSleepS": 0.0, "failBuild": False}

def save_state(st):
    with open(state_file, "w", encoding="utf-8") as fh:
        json.dump(st, fh)

st = load_state()

if args[:1] == ["build"]:
    sleep_s = float(st.get("buildSleepS", 0.0) or 0.0)
    if sleep_s > 0:
        time.sleep(sleep_s)
    if st.get("failBuild"):
        print("Step 1/2 : RUN pnpm build")
        sys.stderr.write("ERROR: failed with OPENAI_API_KEY=sk-secret-never-leak-999999\\n")
        sys.exit(1)
    print("Step 1/3 : Auto-detected build recipe")
    print("Successfully built app image")
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
            "StartedAt": "2026-11-25T01:00:00Z",
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
  );
}

function createCrossPlatformGitShim(tempDir: string): string {
  return wrapPythonShim(
    tempDir,
    "fake-git",
    `import json, os, sys
args = sys.argv[1:]
if "clone" in args:
    dst = args[-1]
    url = args[-2] if len(args) >= 2 else ""
    os.makedirs(dst, exist_ok=True)
    if "vite-site" in url:
        with open(os.path.join(dst, "package.json"), "w", encoding="utf-8") as fh:
            json.dump({"name": "vite-site", "dependencies": {"react": "19.0.0"}, "devDependencies": {"vite": "6.0.0"}, "scripts": {"build": "vite build"}}, fh)
    elif "py-api" in url:
        with open(os.path.join(dst, "requirements.txt"), "w", encoding="utf-8") as fh:
            fh.write("fastapi==0.115.0\\nuvicorn==0.30.0\\npsycopg2-binary==2.9.9\\nredis==5.0.0\\n")
        with open(os.path.join(dst, "main.py"), "w", encoding="utf-8") as fh:
            fh.write("app = object()\\n")
        with open(os.path.join(dst, ".env.example"), "w", encoding="utf-8") as fh:
            fh.write("DATABASE_URL=postgres://x\\nREDIS_URL=redis://x\\nSTRIPE_SECRET_KEY=sk-test-never-leak\\n")
    elif "static-html" in url:
        with open(os.path.join(dst, "index.html"), "w", encoding="utf-8") as fh:
            fh.write("<h1>Hello</h1>\\n")
    else:
        with open(os.path.join(dst, "package.json"), "w", encoding="utf-8") as fh:
            json.dump({"name": "next-demo", "dependencies": {"next": "15.0.0", "pg": "8.13.0"}, "scripts": {"build": "next build", "start": "next start"}}, fh)
        with open(os.path.join(dst, ".env.example"), "w", encoding="utf-8") as fh:
            fh.write("OPENAI_API_KEY=sk-example-never-return\\nDATABASE_URL=postgres://x\\nAPP_THEME=dark\\n")
    sys.exit(0)
if "rev-parse" in args:
    if "--abbrev-ref" in args:
        print("main")
    else:
        print("fedcba9876543210fedcba9876543210fedcba98")
    sys.exit(0)
sys.exit(0)
`,
  );
}

async function startTcpBridge(options: {
  appsRoot: string;
  caddyAppsDir: string;
  caddyCoreDir: string;
  dockerBin: string;
  gitBin: string;
  runtimeToken: string;
}): Promise<{ baseUrl: string; close: () => Promise<void> }> {
  const child = spawn(
    PYTHON_BIN,
    [
      "-u",
      RUNTIME_BRIDGE_SCRIPT,
      "--tcp",
      "127.0.0.1:0",
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

  const baseUrl = await new Promise<string>((resolve, reject) => {
    let out = "";
    let err = "";
    const timer = setTimeout(
      () => reject(new Error(`Bridge timeout: ${err}`)),
      10000,
    );
    child.stdout.on("data", (d: Buffer) => {
      out += d.toString("utf8");
      const m = out.match(/LISTENING (http:\/\/127\.0\.0\.1:\d+)/);
      if (m) {
        clearTimeout(timer);
        resolve(m[1]!);
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
    baseUrl,
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

describe("MCP GitHub Deploy Flow (Auto-Detect, Async Background Jobs, Safe Auto-Deploy, App Locks, Base Domain, Secret Handoff)", () => {
  it("runs full cross-platform MCP + REST GitHub deploy workflow", async () => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "vpsagent-mcp-flow-"));
    const appsRoot = path.join(tempDir, "apps");
    const caddyAppsDir = path.join(tempDir, "caddy", "apps.d");
    const caddyCoreDir = path.join(tempDir, "caddy", "core.d");
    const stateFile = path.join(tempDir, "docker-state.json");
    fs.mkdirSync(appsRoot, { recursive: true });
    fs.mkdirSync(caddyAppsDir, { recursive: true });
    fs.mkdirSync(caddyCoreDir, { recursive: true });

    const dockerBin = createCrossPlatformDockerShim(tempDir, stateFile);
    const gitBin = createCrossPlatformGitShim(tempDir);
    const runtimeToken = "mcp-flow-runtime-token-2026";

    const liveAppServer = http.createServer((_req, res) => {
      res.statusCode = 200;
      res.end('{"ok":true}');
    });
    await new Promise<void>((resolve) =>
      liveAppServer.listen(0, "127.0.0.1", () => resolve()),
    );
    const livePort = (liveAppServer.address() as AddressInfo).port;

    const bridgeProc = await startTcpBridge({
      appsRoot,
      caddyAppsDir,
      caddyCoreDir,
      dockerBin,
      gitBin,
      runtimeToken,
    });

    const bridge = new HttpRuntimeBridgeClient({
      baseUrl: bridgeProc.baseUrl,
      runtimeToken,
    });
    const store = new RegistryStore(path.join(tempDir, "registry.db"), {
      encryptionSecret: "mcp-flow-encryption-secret-32-bytes",
    });

    const claimToken = "mcp-flow-claim-token";
    const { app } = createVpsAgentApp({
      store,
      bridge,
      appsRoot,
      sessionSecret: "mcp-flow-session-secret-32-bytes",
      claimToken,
      trustProxy: true,
      isLocalListener: false,
      defaultPeerIp: "172.18.0.2",
      readinessTimeoutSeconds: 5,
      readinessPollIntervalMs: 25,
      mcpDeployGraceMs: 4000,
      lookupFn: async () => [{ address: "140.82.121.4", family: 4 }],
    });

    try {
      // Claim and mark HTTPS dashboard active
      store.setAdminPassphrase("correct-horse-battery");
      store.updateSetupState({
        claimed: true,
        domain: "vps.example.com",
        httpsActive: true,
        tlsStatus: "active",
        claimedAt: new Date().toISOString(),
      });

      const loginRes = await app.request("https://vps.example.com/api/auth/login", {
        method: "POST",
        headers: {
          "content-type": "application/json",
          host: "vps.example.com",
          "x-forwarded-proto": "https",
        },
        body: JSON.stringify({ passphrase: "correct-horse-battery" }),
      });
      expect(loginRes.status).toBe(200);
      const cookie = loginRes.headers.get("set-cookie")!.split(";")[0]!;

      // Configure default apps base domain
      const baseRes = await app.request(
        "https://vps.example.com/api/setup/apps-base-domain",
        {
          method: "POST",
          headers: {
            "content-type": "application/json",
            cookie,
            host: "vps.example.com",
            "x-forwarded-proto": "https",
          },
          body: JSON.stringify({ appsBaseDomain: "apps.example.com" }),
        },
      );
      expect(baseRes.status).toBe(200);

      // Create a safe-auto-deploy pass locked to ["next-demo", "slow-app", "fail-app"]
      const tokRes = await app.request("https://vps.example.com/api/mcp/tokens", {
        method: "POST",
        headers: {
          "content-type": "application/json",
          cookie,
          host: "vps.example.com",
          "x-forwarded-proto": "https",
        },
        body: JSON.stringify({
          name: "Agent Pass",
          scope: "safe-auto-deploy",
          allowedSlugs: ["next-demo", "slow-app", "fail-app"],
        }),
      });
      expect(tokRes.status).toBe(201);
      const { rawToken } = (await tokRes.json()) as { rawToken: string };

      const callMcp = async (
        method: string,
        params: Record<string, unknown> = {},
      ) => {
        const res = await app.request("https://vps.example.com/mcp", {
          method: "POST",
          headers: {
            "content-type": "application/json",
            host: "vps.example.com",
            "x-forwarded-proto": "https",
            authorization: `Bearer ${rawToken}`,
          },
          body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
        });
        expect(res.status).toBe(200);
        return (await res.json()) as {
          result: {
            instructions?: string;
            isError?: boolean;
            content?: Array<{ text: string }>;
          };
        };
      };

      // 1. initialize returns MCP instructions
      const init = await callMcp("initialize", { protocolVersion: "2025-11-25" });
      expect(init.result.instructions).toContain("inspect_git_repo");
      expect(init.result.instructions).toContain("envSettingsUrl");

      // 2. get_server_info returns base domain + pass lock details
      const infoRaw = await callMcp("tools/call", {
        name: "get_server_info",
        arguments: {},
      });
      const info = JSON.parse(infoRaw.result.content![0]!.text) as {
        server: { appsBaseDomain: string };
        visitorPass: { scope: string; allowedSlugs: string[]; deleteRequiresApproval: boolean };
      };
      expect(info.server.appsBaseDomain).toBe("apps.example.com");
      expect(info.visitorPass.scope).toBe("safe-auto-deploy");
      expect(info.visitorPass.allowedSlugs).toEqual([
        "next-demo",
        "slow-app",
        "fail-app",
      ]);
      expect(info.visitorPass.deleteRequiresApproval).toBe(true);

      // 3. inspect_git_repo detects Next.js, Vite, Python FastAPI, and static HTML cleanly
      for (const [url, expectedRuntime, expectedPort] of [
        ["https://140.82.121.4/acme/next-demo", "nextjs", 3000],
        ["https://140.82.121.4/acme/vite-site", "vite-static", 8080],
        ["https://140.82.121.4/acme/py-api", "python", 8000],
        ["https://140.82.121.4/acme/static-html", "static", 8080],
      ] as const) {
        const res = await callMcp("tools/call", {
          name: "inspect_git_repo",
          arguments: { gitRepoUrl: url },
        });
        expect(res.result.isError).toBe(false);
        const parsed = JSON.parse(res.result.content![0]!.text) as {
          detectedRuntime: string;
          suggestedPort: number;
          hasDockerfile: boolean;
        };
        expect(parsed.detectedRuntime).toBe(expectedRuntime);
        expect(parsed.suggestedPort).toBe(expectedPort);
        expect(parsed.hasDockerfile).toBe(false);
      }

      // 4. App lock strictly blocks deploying an unlisted slug
      const blocked = await callMcp("tools/call", {
        name: "deploy_app",
        arguments: {
          slug: "forbidden-app",
          name: "Forbidden",
          sourceType: "git",
          gitRepoUrl: "https://140.82.121.4/acme/next-demo",
        },
      });
      expect(blocked.result.isError).toBe(true);

      // 5. Safe Auto-Deploy launches Next.js repo with Postgres, auto-domain, and secret handoff link (excluding DATABASE_URL!)
      const depRaw = await callMcp("tools/call", {
        name: "deploy_app",
        arguments: {
          slug: "next-demo",
          name: "Next Demo",
          sourceType: "git",
          gitRepoUrl: "https://140.82.121.4/acme/next-demo",
          internalPort: livePort,
          companions: [{ type: "postgres" }],
        },
      });
      expect(depRaw.result.isError).toBe(false);
      const depRes = JSON.parse(depRaw.result.content![0]!.text) as {
        status: string;
        result: {
          app: { domain: string; detectedRuntime: string };
          deployment: { id: string; status: string; usedAutoDockerfile: boolean };
          liveUrl: string;
          missingEnvKeys: string[];
          envSettingsUrl: string;
        };
      };
      expect(depRes.status).toBe("executed");
      expect(depRes.result.app.domain).toBe("next-demo.apps.example.com");
      expect(depRes.result.app.detectedRuntime).toBe("nextjs");
      expect(depRes.result.deployment.usedAutoDockerfile).toBe(true);
      expect(depRes.result.liveUrl).toBe("https://next-demo.apps.example.com");
      // DATABASE_URL is auto-wired by Postgres companion, so only OPENAI_API_KEY and APP_THEME remain!
      expect(depRes.result.missingEnvKeys).toEqual(["OPENAI_API_KEY", "APP_THEME"]);
      expect(depRes.result.envSettingsUrl).toBe(
        "https://vps.example.com/#apps/next-demo/env",
      );

      // 6. Safe Auto-Deploy STILL requires human approval for delete_app
      const delRaw = await callMcp("tools/call", {
        name: "delete_app",
        arguments: { slug: "next-demo" },
      });
      const delRes = JSON.parse(delRaw.result.content![0]!.text) as {
        status: string;
        approvalId: string;
      };
      expect(delRes.status).toBe("pending_approval");
      expect(delRes.approvalId).toMatch(/^apr_/);

      // 7. REST async deploy (?async=true) returns 202 immediately while slow build finishes in background!
      fs.writeFileSync(
        stateFile,
        JSON.stringify({ projects: {}, networks: [], buildSleepS: 0.35, failBuild: false }),
        "utf8",
      );
      const asyncRest = await app.request(
        "https://vps.example.com/api/apps?async=true",
        {
          method: "POST",
          headers: {
            "content-type": "application/json",
            cookie,
            host: "vps.example.com",
            "x-forwarded-proto": "https",
          },
          body: JSON.stringify({
            slug: "slow-app",
            name: "Slow App",
            sourceType: "git",
            gitRepoUrl: "https://140.82.121.4/acme/vite-site",
            internalPort: livePort,
          }),
        },
      );
      expect(asyncRest.status).toBe(202);
      const asyncJson = (await asyncRest.json()) as {
        done: boolean;
        deployment: { id: string; status: string };
      };
      expect(asyncJson.done).toBe(false);

      // Poll get_deployment via MCP until background job finishes cleanly
      let finalStatus = asyncJson.deployment.status;
      for (let i = 0; i < 40; i++) {
        const pollRaw = await callMcp("tools/call", {
          name: "get_deployment",
          arguments: { deploymentId: asyncJson.deployment.id },
        });
        const polled = JSON.parse(pollRaw.result.content![0]!.text) as {
          deployment: { status: string; buildLogs: string[]; commitSha: string | null };
        };
        finalStatus = polled.deployment.status;
        if (finalStatus === "succeeded" || finalStatus === "failed") {
          expect(polled.deployment.commitSha).toBe(
            "fedcba9876543210fedcba9876543210fedcba98",
          );
          expect(polled.deployment.buildLogs.length).toBeGreaterThan(0);
          break;
        }
        await new Promise((r) => setTimeout(r, 80));
      }
      expect(finalStatus).toBe("succeeded");

      // 8. Build failure captures redacted build logs (no leaked secret!)
      fs.writeFileSync(
        stateFile,
        JSON.stringify({ projects: {}, networks: [], buildSleepS: 0, failBuild: true }),
        "utf8",
      );
      const failAsync = await app.request(
        "https://vps.example.com/api/apps?async=true",
        {
          method: "POST",
          headers: {
            "content-type": "application/json",
            cookie,
            host: "vps.example.com",
            "x-forwarded-proto": "https",
          },
          body: JSON.stringify({
            slug: "fail-app",
            name: "Fail App",
            sourceType: "git",
            gitRepoUrl: "https://140.82.121.4/acme/next-demo",
            internalPort: livePort,
          }),
        },
      );
      expect(failAsync.status).toBe(202);
      const failDepId = (
        (await failAsync.json()) as { deployment: { id: string } }
      ).deployment.id;

      let failedRecord: { status: string; buildLogs: string[]; error: string | null } | null = null;
      for (let i = 0; i < 40; i++) {
        const pollRes = await app.request(
          `https://vps.example.com/api/deployments/${failDepId}`,
          {
            headers: {
              cookie,
              host: "vps.example.com",
              "x-forwarded-proto": "https",
            },
          },
        );
        const body = (await pollRes.json()) as {
          deployment: { status: string; buildLogs: string[]; error: string | null };
        };
        if (body.deployment.status === "failed") {
          failedRecord = body.deployment;
          break;
        }
        await new Promise((r) => setTimeout(r, 50));
      }
      expect(failedRecord?.status).toBe("failed");
      expect(failedRecord?.buildLogs.join("\n")).not.toContain(
        "sk-secret-never-leak-999999",
      );
      expect(failedRecord?.buildLogs.join("\n")).toContain("[REDACTED]");
    } finally {
      store.close();
      await bridgeProc.close();
      await new Promise<void>((resolve) =>
        liveAppServer.close(() => resolve()),
      );
      fs.rmSync(tempDir, { recursive: true, force: true });
    }
  }, 30_000);
});
