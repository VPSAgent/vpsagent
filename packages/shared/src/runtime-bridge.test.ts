import { execFileSync, spawn } from "node:child_process";
import fs from "node:fs";
import http from "node:http";
import type { AddressInfo } from "node:net";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import {
  generateApartmentBlueprint,
  writeApartmentBlueprint,
} from "./compose.js";
import {
  HttpRuntimeBridgeClient,
  RuntimeBridgeError,
  RuntimeCoreUpdateStatusSchema,
  RuntimeTailscaleStatusSchema,
  createRuntimeBridgeFromEnv,
  syncAppStatuses,
} from "./runtime-bridge.js";
import { RegistryStore } from "./store.js";

const REPO_ROOT = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "../../..",
);
const RUNTIME_BRIDGE_SCRIPT = path.join(
  REPO_ROOT,
  "bootstrap",
  "runtime-bridge.py",
);

function findPythonBinary(): string | null {
  for (const bin of ["python3", "python"]) {
    try {
      execFileSync(bin, ["--version"], { stdio: "ignore" });
      return bin;
    } catch {
      // try next binary
    }
  }
  return null;
}

function createFakeDockerShim(
  tempDir: string,
  pythonBin: string,
  stateFile: string,
  callsLog: string,
  envLog: string,
): string {
  const shimPy = path.join(tempDir, "fake_docker.py");
  fs.writeFileSync(
    shimPy,
    `import json, os, sys, time

state_file = ${JSON.stringify(stateFile)}
calls_log = ${JSON.stringify(callsLog)}
env_log = ${JSON.stringify(envLog)}
args = sys.argv[1:]

with open(calls_log, "a", encoding="utf-8") as fh:
    fh.write(json.dumps(args) + "\\n")

with open(env_log, "a", encoding="utf-8") as fh:
    fh.write(json.dumps(sorted(os.environ.keys())) + "\\n")

def load_state():
    if os.path.exists(state_file):
        with open(state_file, "r", encoding="utf-8") as fh:
            return json.load(fh)
    return {
        "projects": {},
        "networks": [],
        "failValidate": False,
        "failDown": False,
        "psDelay": 0.0,
        "buildDelay": 0.0,
        "inspectOverrides": {},
    }

def save_state(st):
    with open(state_file, "w", encoding="utf-8") as fh:
        json.dump(st, fh)

st = load_state()

if args[:1] == ["build"]:
    delay = float(st.get("buildDelay", 0.0) or 0.0)
    if delay > 0:
        time.sleep(delay)
    print("Step 1/2 : FROM node:24-alpine")
    print("Using API_KEY=sk-should-be-redacted-123456789")
    print("Successfully built image")
    sys.exit(0)

if args[:1] == ["compose"]:
    proj = ""
    if "-p" in args:
        proj = args[args.index("-p") + 1]
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
        if st.get("failDown"):
            sys.stderr.write("Error: simulated compose down failure\\n")
            sys.exit(1)
        st["projects"].pop(proj, None)
        save_state(st)
        sys.exit(0)
    if "ps" in args:
        delay = float(st.get("psDelay", 0.0) or 0.0)
        if delay > 0:
            time.sleep(delay)
        status = st["projects"].get(proj, "stopped")
        if status == "running":
            print(json.dumps({"Name": proj, "State": "running", "Health": "healthy", "ExitCode": 0}))
        elif status == "error":
            print(json.dumps({"Name": proj, "State": "exited", "Health": "", "ExitCode": 1}))
        sys.exit(0)
    if "logs" in args:
        print(f"Booted {proj}")
        print("Connected with API_KEY=sk-secret1234567890")
        print("MCP token vpsmcp_supersecret1234567890abcd")
        print("-----BEGIN PRIVATE KEY-----")
        print("MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQ")
        print("-----END PRIVATE KEY-----")
        sys.stderr.write("Authorization: Bearer supersecret_token_value\\n")
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
    proj = ""
    if target.startswith("cid-"):
        proj = target[4:]
    elif target.startswith("vpsagent-app-"):
        proj = f"vpsagent-{target[13:]}"
    status = st.get("projects", {}).get(proj)
    if not status:
        sys.stderr.write(f"No such object: {target}\\n")
        sys.exit(1)
    override = st.get("inspectOverrides", {}).get(proj, {})
    non_compliant = bool(override.get("nonCompliant", False))
    ip_addr = override.get("ipAddress", "127.0.0.1")
    health_status = override.get("healthStatus", "healthy" if status == "running" else "unhealthy")
    is_running = status == "running"
    slug = proj[len("vpsagent-"):] if proj.startswith("vpsagent-") else proj
    payload = [
        {
            "Id": f"abcdef1234567890{proj}",
            "Name": f"/vpsagent-app-{slug}",
            "RestartCount": 0,
            "Config": {"Image": "nginxinc/nginx-unprivileged:alpine"},
            "State": {
                "Status": "running" if is_running else "exited",
                "Running": is_running,
                "ExitCode": 0 if is_running else 1,
                "StartedAt": "2026-11-24T01:00:00Z",
                "Health": {
                    "Status": health_status,
                    "Log": [{"Output": "GET / 200 OK token=sk-secret99999999"}],
                },
            },
            "HostConfig": {
                "CapDrop": [] if non_compliant else ["ALL"],
                "CapAdd": None,
                "PidMode": "",
                "IpcMode": "",
                "SecurityOpt": [] if non_compliant else ["no-new-privileges:true"],
                "Privileged": non_compliant,
                "Memory": 536870912,
                "NanoCpus": 500000000,
                "Binds": ["/var/run/docker.sock:/var/run/docker.sock"] if non_compliant else [],
            },
            "Mounts": (
                [{"Source": "/var/run/docker.sock", "Destination": "/var/run/docker.sock"}]
                if non_compliant
                else []
            ),
            "NetworkSettings": {
                "Networks": {
                    f"{proj}_app_net": {"IPAddress": ip_addr},
                },
            },
        }
    ]
    print(json.dumps(payload))
    sys.exit(0)

if args[:2] == ["network", "inspect"]:
    net = args[2]
    if net not in st["networks"]:
        sys.stderr.write(f"No such network: {net}\\n")
        sys.exit(1)
    sys.exit(0)

if args[:2] == ["network", "connect"] or args[:2] == ["network", "disconnect"]:
    sys.exit(0)

if args[:1] == ["exec"] and "validate" in args:
    if st.get("failValidate"):
        sys.stderr.write("Error: invalid Caddyfile directive\\n")
        sys.exit(1)
    sys.exit(0)

if args[:1] == ["exec"] and "reload" in args:
    sys.exit(0)

sys.exit(0)
`,
    "utf8",
  );

  const shPath = path.join(tempDir, "fake-docker");
  fs.writeFileSync(
    shPath,
    `#!/usr/bin/env sh\nexec "${pythonBin}" "${shimPy}" "$@"\n`,
    "utf8",
  );
  fs.chmodSync(shPath, 0o755);
  return shPath;
}

function createFakeGitShim(tempDir: string, pythonBin: string): string {
  const shimPy = path.join(tempDir, "fake_git.py");
  fs.writeFileSync(
    shimPy,
    `import os, sys

args = sys.argv[1:]
if "clone" in args:
    target_dir = args[-1]
    os.makedirs(target_dir, exist_ok=True)
    with open(os.path.join(target_dir, "Dockerfile"), "w", encoding="utf-8") as fh:
        fh.write("FROM alpine:3.20\\nCMD [\\"echo\\", \\"ok\\"]\\n")
    sys.exit(0)

if "rev-parse" in args:
    print("deadbeef1234567890abcdef1234567890abcdef")
    sys.exit(0)

sys.exit(0)
`,
    "utf8",
  );

  const shPath = path.join(tempDir, "fake-git");
  fs.writeFileSync(
    shPath,
    `#!/usr/bin/env sh\nexec "${pythonBin}" "${shimPy}" "$@"\n`,
    "utf8",
  );
  fs.chmodSync(shPath, 0o755);
  return shPath;
}

async function startPythonRuntimeBridge(options: {
  pythonBin: string;
  appsRoot: string;
  caddyAppsDir: string;
  dockerBin: string;
  gitBin: string;
  runtimeToken: string;
  socketPath?: string;
  extraEnv?: Record<string, string>;
}): Promise<{
  baseUrl?: string;
  socketPath?: string;
  close: () => Promise<void>;
}> {
  const args = [
    RUNTIME_BRIDGE_SCRIPT,
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
  ];
  if (options.socketPath) {
    args.push("--socket", options.socketPath);
  } else {
    args.push("--tcp", "127.0.0.1:0");
  }

  const child = spawn(options.pythonBin, args, {
    stdio: ["ignore", "pipe", "pipe"],
    env: {
      ...process.env,
      ...(options.extraEnv ?? {}),
    },
  });

  const listenTarget = await new Promise<string>((resolve, reject) => {
    let stdoutBuf = "";
    let stderrBuf = "";
    const timer = setTimeout(() => {
      reject(
        new Error(
          `Timed out waiting for runtime-bridge.py startup. stderr=${stderrBuf}`,
        ),
      );
    }, 8000);

    child.stdout.on("data", (chunk: Buffer) => {
      stdoutBuf += chunk.toString("utf8");
      const match = stdoutBuf.match(/LISTENING ((?:http|unix):\/\/[^\r\n]+)/);
      if (match?.[1]) {
        clearTimeout(timer);
        resolve(match[1].trim());
      }
    });

    child.stderr.on("data", (chunk: Buffer) => {
      stderrBuf += chunk.toString("utf8");
    });

    child.on("exit", (code) => {
      clearTimeout(timer);
      reject(
        new Error(
          `runtime-bridge.py exited prematurely with code ${code}: ${stderrBuf}`,
        ),
      );
    });
  });

  return {
    ...(listenTarget.startsWith("http://") ? { baseUrl: listenTarget } : {}),
    ...(listenTarget.startsWith("unix://")
      ? { socketPath: listenTarget.slice("unix://".length) }
      : {}),
    close: async () => {
      if (child.exitCode === null && child.signalCode === null) {
        child.kill();
        await new Promise<void>((resolve) => {
          child.once("exit", () => resolve());
          setTimeout(resolve, 2000);
        });
      }
    },
  };
}

describe("RuntimeBridge Unix-socket client + bootstrap/runtime-bridge.py", () => {
  it("runs full Locked Apartment lifecycle, companions, Caddy routing, Git builds, host stats, and readiness over a Unix socket", async () => {
    const pythonBin = findPythonBinary();
    expect(pythonBin).not.toBeNull();
    if (!pythonBin) return;

    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "vpsagent-bridge-"));
    const appsRoot = path.join(tempDir, "apps");
    const caddyAppsDir = path.join(tempDir, "caddy-apps");
    const socketPath = path.join(tempDir, "run", "runtime.sock");
    const stateFile = path.join(tempDir, "docker-state.json");
    const callsLog = path.join(tempDir, "docker-calls.log");
    const envLog = path.join(tempDir, "docker-env.log");
    fs.mkdirSync(appsRoot, { recursive: true });
    fs.mkdirSync(caddyAppsDir, { recursive: true });

    const dockerBin = createFakeDockerShim(
      tempDir,
      pythonBin,
      stateFile,
      callsLog,
      envLog,
    );
    const gitBin = createFakeGitShim(tempDir, pythonBin);
    const runtimeToken = "vpsagent-runtime-secret-token-1234";

    // Start a tiny local HTTP server that returns 503 on first attempt, then 404 (API root!)
    let probeHits = 0;
    const apiServer = http.createServer((_req, res) => {
      probeHits += 1;
      if (probeHits === 1) {
        res.statusCode = 503;
        res.end("warming up");
      } else {
        res.statusCode = 404;
        res.setHeader("content-type", "application/json");
        res.end(JSON.stringify({ error: "not found" }));
      }
    });
    await new Promise<void>((resolve) =>
      apiServer.listen(0, "127.0.0.1", () => resolve()),
    );
    const apiPort = (apiServer.address() as AddressInfo).port;

    const daemon = await startPythonRuntimeBridge({
      pythonBin,
      appsRoot,
      caddyAppsDir,
      dockerBin,
      gitBin,
      runtimeToken,
      socketPath,
      extraEnv: {
        VPSAGENT_ADMIN_SECRET: "host-admin-secret-must-not-leak",
      },
    });

    const store = new RegistryStore(":memory:");

    try {
      // Startup guards: short token and non-loopback --tcp must fail closed
      expect(() =>
        execFileSync(
          pythonBin,
          [
            RUNTIME_BRIDGE_SCRIPT,
            "--tcp",
            "127.0.0.1:0",
            "--runtime-token",
            "short",
          ],
          { stdio: "pipe" },
        ),
      ).toThrow();
      expect(() =>
        execFileSync(
          pythonBin,
          [
            RUNTIME_BRIDGE_SCRIPT,
            "--tcp",
            "0.0.0.0:9999",
            "--runtime-token",
            runtimeToken,
          ],
          { stdio: "pipe" },
        ),
      ).toThrow();

      const client = createRuntimeBridgeFromEnv({
        VPSAGENT_RUNTIME_SOCKET: daemon.socketPath,
        VPSAGENT_RUNTIME_TOKEN: runtimeToken,
      });
      expect(client).toBeDefined();
      if (!client) return;

      const unauthClient = new HttpRuntimeBridgeClient({
        socketPath: daemon.socketPath,
        runtimeToken: "wrong-token-value",
      });

      // Health + Host stats
      const health = await client.health();
      expect(health).toEqual({ ok: true, service: "vpsagent-runtime" });

      const stats = await client.getHostStats();
      expect(stats.metrics.cpuCount).toBeGreaterThanOrEqual(1);
      expect(stats.disk.totalGb).toBeGreaterThan(0);

      // Auth fail-closed
      await expect(unauthClient.getHostStats()).rejects.toSatisfy(
        (err: unknown) =>
          err instanceof RuntimeBridgeError && err.statusCode === 401,
      );

      // Provision a real Locked Apartment blueprint with Postgres & Redis companions
      const bp = generateApartmentBlueprint({
        slug: "crm-portal",
        sourceType: "image",
        image: "nginxinc/nginx-unprivileged:alpine",
        internalPort: apiPort,
        cpuLimit: "0.5",
        memoryLimitMb: 512,
        envVars: {
          APP_GREETING: "hello $WORLD #1",
        },
        companions: [{ type: "postgres" }, { type: "redis" }],
        companionSecrets: {
          postgresPassword: "pg$secret#password123",
          redisPassword: "redis$secret#password456",
        },
      });
      writeApartmentBlueprint(appsRoot, bp);

      // Start, inspect, readiness (retries 503 -> accepts 404 API root!)
      const started = await client.lifecycle("crm-portal", "start");
      expect(started.status).toBe("running");

      // Host secrets must never leak into docker subprocess env
      const envSnapshots = fs
        .readFileSync(envLog, "utf8")
        .trim()
        .split(/\r?\n/);
      const lastEnvKeys = JSON.parse(envSnapshots.at(-1)!) as string[];
      expect(lastEnvKeys).not.toContain("VPSAGENT_ADMIN_SECRET");

      // Inspect verifies Locked Apartment compliance
      const inspected = await client.inspectWorkload("crm-portal", {
        probeHttp: false,
      });
      expect(inspected.lockedApartmentCompliant).toBe(true);
      expect(inspected.containers[0]?.security.capDropAll).toBe(true);
      expect(inspected.containers[0]?.security.noNewPrivileges).toBe(true);
      expect(inspected.containers[0]?.security.hasDockerSocketMount).toBe(false);

      // Bounded readiness retries 503 and succeeds on 404 API root!
      const readiness = await client.waitForReadiness("crm-portal", {
        internalPort: apiPort,
        probePath: "/",
        timeoutSeconds: 5,
        pollIntervalMs: 25,
      });
      expect(readiness.ready).toBe(true);
      expect(readiness.attempts).toBe(2);
      expect(readiness.httpProbe?.statusCode).toBe(404);

      // Unhealthy container fails fast on readiness check
      const st = JSON.parse(fs.readFileSync(stateFile, "utf8")) as Record<
        string,
        unknown
      >;
      st.inspectOverrides = {
        "vpsagent-crm-portal": { healthStatus: "unhealthy" },
      };
      fs.writeFileSync(stateFile, JSON.stringify(st), "utf8");
      const unhealthyRes = await client.waitForReadiness("crm-portal", {
        internalPort: apiPort,
        timeoutSeconds: 5,
        pollIntervalMs: 25,
      });
      expect(unhealthyRes.ready).toBe(false);
      expect(unhealthyRes.attempts).toBe(1);
      expect(unhealthyRes.reason).toMatch(/unhealthy=true/);

      // Logs redact secrets including vpsmcp_ tokens and PEM keys
      const logs = await client.getLogs("crm-portal", 30);
      const joinedLogs = logs.join("\n");
      expect(joinedLogs).not.toContain("sk-secret1234567890");
      expect(joinedLogs).not.toContain("vpsmcp_supersecret1234567890abcd");
      expect(joinedLogs).not.toContain("supersecret_token_value");
      expect(joinedLogs).toContain("[REDACTED_PRIVATE_KEY]");

      // Caddy routing + uniqueness + atomic rollback
      const routed = await client.routeCaddy({
        slug: "crm-portal",
        domain: "crm.example.com",
        internalPort: apiPort,
      });
      expect(routed.routed).toBe(true);
      const caddyFile = path.join(caddyAppsDir, "crm-portal.caddy");
      expect(fs.readFileSync(caddyFile, "utf8")).toContain(
        `reverse_proxy vpsagent-app-crm-portal:${apiPort}`,
      );

      // Duplicate domain returns 409
      await expect(
        client.routeCaddy({
          slug: "other-app",
          domain: "crm.example.com",
          internalPort: 8080,
        }),
      ).rejects.toSatisfy(
        (err: unknown) =>
          err instanceof RuntimeBridgeError && err.statusCode === 409,
      );

      // Git Dockerfile build over Unix socket (using public IP literal so test is offline-safe)
      const built = await client.buildGitImage({
        slug: "git-demo",
        gitRepoUrl: "https://140.82.121.4/acme/demo.git",
        gitBranch: "main",
        dockerfilePath: "Dockerfile",
        timeoutSeconds: 30,
      });
      expect(built.ok).toBe(true);
      expect(built.image).toBe("vpsagent-app-git-demo:latest");
      expect(built.commitSha).toBe("deadbeef1234567890abcdef1234567890abcdef");
      expect(built.buildLogTail.join("\n")).not.toContain(
        "sk-should-be-redacted-123456789",
      );

      // Sync app statuses updates drifted registry status while preserving building apps
      store.upsertApp({
        slug: "crm-portal",
        name: "CRM Portal",
        sourceType: "image",
        image: "nginxinc/nginx-unprivileged:alpine",
        gitRepoUrl: null,
        gitBranch: null,
        dockerfilePath: "Dockerfile",
        domain: "crm.example.com",
        folderPath: path.join(appsRoot, "crm-portal"),
        internalPort: apiPort,
        status: "stopped",
        cpuLimit: "0.5",
        memoryLimitMb: 512,
        companions: [],
      });
      store.upsertApp({
        slug: "git-demo",
        name: "Git Demo",
        sourceType: "git",
        image: null,
        gitRepoUrl: "https://github.com/acme/demo.git",
        gitBranch: "main",
        dockerfilePath: "Dockerfile",
        domain: null,
        folderPath: path.join(appsRoot, "git-demo"),
        internalPort: 3000,
        status: "building",
        cpuLimit: "0.5",
        memoryLimitMb: 512,
        companions: [],
      });
      await syncAppStatuses(store, client);
      expect(store.getApp("crm-portal")?.status).toBe("running");
      expect(store.getApp("git-demo")?.status).toBe("building");

      // Strict Compose isolation rejects escape vectors (docker.sock, ports, build, privileged)
      const escapeAppDir = path.join(appsRoot, "unsafe-ports");
      fs.mkdirSync(escapeAppDir, { recursive: true });
      fs.writeFileSync(
        path.join(escapeAppDir, "docker-compose.yml"),
        [
          "services:",
          "  app:",
          '    image: "nginx:alpine"',
          '    cpus: "0.5"',
          '    mem_limit: "256m"',
          "    ports:",
          '      - "8080:80"',
          "    cap_drop:",
          "      - ALL",
          "    security_opt:",
          "      - no-new-privileges:true",
          "    networks:",
          "      - app_net",
          "networks:",
          "  app_net:",
          "    driver: bridge",
          "",
        ].join("\n"),
        "utf8",
      );
      await expect(client.lifecycle("unsafe-ports", "start")).rejects.toSatisfy(
        (err: unknown) =>
          err instanceof RuntimeBridgeError && err.statusCode === 400,
      );

      // Safe removal cleans up containers, Caddy route, and workspace files
      const removed = await client.removeWorkload("crm-portal", {
        removeFiles: true,
      });
      expect(removed.ok).toBe(true);
      expect(fs.existsSync(caddyFile)).toBe(false);
      expect(fs.existsSync(path.join(appsRoot, "crm-portal"))).toBe(false);
    } finally {
      store.close();
      await daemon.close();
      await new Promise<void>((resolve) => apiServer.close(() => resolve()));
      fs.rmSync(tempDir, { recursive: true, force: true });
    }
  }, 60_000);

  it("discovers Tailscale status, connects, and toggles Tailscale Serve over Unix socket", async () => {
    const pythonBin = findPythonBinary();
    expect(pythonBin).not.toBeNull();
    if (!pythonBin) return;

    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "vpsagent-ts-bridge-"));
    const appsRoot = path.join(tempDir, "apps");
    const caddyAppsDir = path.join(tempDir, "caddy-apps");
    const socketPath = path.join(tempDir, "run", "runtime.sock");
    const stateFile = path.join(tempDir, "docker-state.json");
    const callsLog = path.join(tempDir, "docker-calls.log");
    const envLog = path.join(tempDir, "docker-env.log");
    const tsStateFile = path.join(tempDir, "tailscale-state.json");
    fs.mkdirSync(appsRoot, { recursive: true });
    fs.mkdirSync(caddyAppsDir, { recursive: true });

    const targetServer = http.createServer((_req, res) => {
      res.statusCode = 200;
      res.end("ok");
    });
    await new Promise<void>((resolve) =>
      targetServer.listen(0, "127.0.0.1", () => resolve()),
    );
    const targetPort = (targetServer.address() as AddressInfo).port;

    const tsShimPy = path.join(tempDir, "fake_tailscale.py");
    fs.writeFileSync(
      tsShimPy,
      `import json, os, sys
state_file = ${JSON.stringify(tsStateFile)}
args = sys.argv[1:]

def load():
    if os.path.exists(state_file):
        with open(state_file, "r", encoding="utf-8") as fh:
            return json.load(fh)
    return {"connected": False, "serve": False, "authFileSeen": None}

def save(st):
    with open(state_file, "w", encoding="utf-8") as fh:
        json.dump(st, fh)

st = load()

if args == ["status", "--json"]:
    if not st["connected"]:
        print(json.dumps({
            "Version": "1.78.1",
            "BackendState": "NeedsLogin",
            "AuthURL": "https://login.tailscale.com/a/unit1234",
            "Self": {"HostName": "my-vps", "DNSName": "", "TailscaleIPs": []},
            "CertDomains": [],
        }))
        sys.exit(0)
    print(json.dumps({
        "Version": "1.78.1",
        "BackendState": "Running",
        "Self": {
            "HostName": "my-vps",
            "DNSName": "my-vps.tail1234.ts.net.",
            "TailscaleIPs": ["100.64.0.42", "fd7a:115c:a1e0::42"],
        },
        "CurrentTailnet": {
            "Name": "tail1234.ts.net",
            "MagicDNSSuffix": "tail1234.ts.net",
            "MagicDNSEnabled": True,
        },
        "CertDomains": ["my-vps.tail1234.ts.net"],
    }))
    sys.exit(0)

if args == ["serve", "status", "--json"]:
    if st.get("serve"):
        print(json.dumps({
            "Web": {
                "my-vps.tail1234.ts.net:443": {
                    "Handlers": {"/": {"Proxy": "http://127.0.0.1:${targetPort}"}}
                }
            }
        }))
    else:
        print("{}")
    sys.exit(0)

if args[:1] == ["up"]:
    for arg in args[1:]:
        if arg.startswith("--auth-key=file:"):
            path = arg.split(":", 1)[1]
            with open(path, "r", encoding="utf-8") as fh:
                st["authFileSeen"] = fh.read()
            st["connected"] = True
            save(st)
            sys.exit(0)
    print("https://login.tailscale.com/a/unit1234")
    sys.exit(0)

if args[:3] == ["serve", "--bg", "--https=443"]:
    st["serve"] = True
    save(st)
    sys.exit(0)

if args == ["serve", "--https=443", "--set-path=/", "off"]:
    st["serve"] = False
    save(st)
    sys.exit(0)

sys.exit(0)
`,
      "utf8",
    );
    const tsBin = path.join(tempDir, "fake-tailscale");
    fs.writeFileSync(
      tsBin,
      `#!/usr/bin/env sh\nexec "${pythonBin}" "${tsShimPy}" "$@"\n`,
      "utf8",
    );
    fs.chmodSync(tsBin, 0o755);

    const dockerBin = createFakeDockerShim(
      tempDir,
      pythonBin,
      stateFile,
      callsLog,
      envLog,
    );
    const gitBin = createFakeGitShim(tempDir, pythonBin);
    const runtimeToken = "vpsagent-runtime-ts-token-1234";

    const daemon = await startPythonRuntimeBridge({
      pythonBin,
      appsRoot,
      caddyAppsDir,
      dockerBin,
      gitBin,
      runtimeToken,
      socketPath,
      extraEnv: {
        VPSAGENT_TAILSCALE_BIN: tsBin,
        VPSAGENT_TAILSCALE_TARGET_URL: `http://127.0.0.1:${targetPort}`,
      },
    });

    try {
      const client = createRuntimeBridgeFromEnv({
        VPSAGENT_RUNTIME_SOCKET: daemon.socketPath,
        VPSAGENT_RUNTIME_TOKEN: runtimeToken,
      })!;

      const initial = await client.getTailscaleStatus();
      expect(initial.installed).toBe(true);
      expect(initial.connected).toBe(false);
      expect(initial.backendState).toBe("needs_login");
      expect(initial.loginUrl).toBe("https://login.tailscale.com/a/unit1234");

      const loginStarted = await client.connectTailscale({ mode: "login" });
      expect(loginStarted.ok).toBe(true);
      expect(loginStarted.loginUrl).toBe("https://login.tailscale.com/a/unit1234");

      const connected = await client.connectTailscale({
        mode: "authkey",
        authKey: "tskey-auth-kBridgeTest12345678",
      });
      expect(connected.ok).toBe(true);
      expect(connected.status.connected).toBe(true);
      expect(connected.status.tailscaleIp).toBe("100.64.0.42");
      expect(connected.status.dnsName).toBe("my-vps.tail1234.ts.net");

      const served = await client.setTailscaleServe({ enabled: true });
      expect(served.ok).toBe(true);
      expect(served.status.serveEnabled).toBe(true);
      expect(served.status.serveUrl).toBe("https://my-vps.tail1234.ts.net");
      expect(served.status.mcpUrl).toBe("https://my-vps.tail1234.ts.net/mcp");

      const disabled = await client.setTailscaleServe({ enabled: false });
      expect(disabled.ok).toBe(true);
      expect(disabled.status.serveEnabled).toBe(false);
      expect(disabled.status.mcpUrl).toBeNull();
      expect(disabled.status.serveConflictDetails).toBeNull();

      const legacyStatus = RuntimeTailscaleStatusSchema.parse({
        installed: true,
        serviceActive: true,
        connected: true,
        backendState: "running",
        tailscaleIp: "100.64.0.42",
        hostname: "my-vps",
        dnsName: "my-vps.tail1234.ts.net",
        tailnetName: "tail1234.ts.net",
      });
      expect(legacyStatus.serveConflictDetails).toBeNull();
    } finally {
      await daemon.close();
      await new Promise<void>((resolve) => targetServer.close(() => resolve()));
      fs.rmSync(tempDir, { recursive: true, force: true });
    }
  }, 60_000);

  it("parses legacy and release update status payloads and redacts secrets", async () => {
    const minimalParsed = RuntimeCoreUpdateStatusSchema.parse({
      state: "idle",
      canUpdate: true,
      currentVersion: "2.0.0-alpha.1",
    });
    expect(minimalParsed.updateSource).toBe("none");
    expect(minimalParsed.releaseStatus).toBe("unchecked");
    expect(minimalParsed.checksumStatus).toBe("none");
    expect(minimalParsed.installedFrom).toBe("unknown");

    let seenApplyBody: string | null = null;
    const mockServer = http.createServer((req, res) => {
      const chunks: Buffer[] = [];
      req.on("data", (c: Buffer) => chunks.push(c));
      req.on("end", () => {
        if (req.url === "/v1/core/update/status") {
          res.writeHead(200, { "content-type": "application/json" });
          res.end(
            JSON.stringify({
              state: "idle",
              canUpdate: true,
              updateSource: "release",
              releaseRepo: "VPSAgent/vpsagent",
              releaseStatus: "available",
              releaseNote: "Bearer sk-secret1234567890abcd leaked",
              installedFrom: "release",
              currentVersion: "2.0.0-alpha.1",
              latestVersion: "2.1.0",
              latestReleaseTag: "v2.1.0",
              latestReleaseName: "v2.1.0 token=vpsmcp_1234567890abcdef",
              latestReleaseUrl:
                "https://github.com/VPSAgent/vpsagent/releases/tag/v2.1.0",
              latestReleaseNotes: "Fixes github_pat_1234567890abcdef",
              checksumAvailable: true,
              checksumStatus: "available",
              updateAvailable: true,
            }),
          );
          return;
        }
        if (req.url === "/v1/core/update/apply") {
          seenApplyBody = Buffer.concat(chunks).toString("utf8");
          res.writeHead(200, { "content-type": "application/json" });
          res.end(
            JSON.stringify({
              ok: true,
              started: true,
              status: {
                state: "updating",
                phase: "downloading",
                canUpdate: true,
                updateSource: "release",
                latestReleaseTag: "v2.1.0",
              },
            }),
          );
          return;
        }
        res.writeHead(404);
        res.end();
      });
    });

    await new Promise<void>((resolve) =>
      mockServer.listen(0, "127.0.0.1", () => resolve()),
    );
    const port = (mockServer.address() as AddressInfo).port;
    try {
      const client = new HttpRuntimeBridgeClient({
        baseUrl: `http://127.0.0.1:${port}`,
      });
      const st = await client.getCoreUpdateStatus();
      expect(st.updateSource).toBe("release");
      expect(st.latestReleaseTag).toBe("v2.1.0");
      expect(st.releaseNote).not.toContain("sk-secret1234567890abcd");
      expect(st.latestReleaseName).not.toContain("vpsmcp_1234567890abcdef");
      expect(st.latestReleaseNotes).not.toContain(
        "github_pat_1234567890abcdef",
      );

      const applied = await client.applyCoreUpdate({ source: "release" });
      expect(applied.started).toBe(true);
      expect(seenApplyBody).toBe(JSON.stringify({ source: "release" }));
    } finally {
      await new Promise<void>((resolve) => mockServer.close(() => resolve()));
    }
  });

  it("parses and redacts Tailscale serveConflictDetails", async () => {
    const mockServer = http.createServer((req, res) => {
      if (req.url === "/v1/host/tailscale/status") {
        res.writeHead(200, { "content-type": "application/json" });
        res.end(
          JSON.stringify({
            installed: true,
            serviceActive: true,
            connected: true,
            backendState: "running",
            tailscaleIp: "100.64.0.42",
            hostname: "my-vps",
            dnsName: "my-vps.tail1234.ts.net",
            tailnetName: "tail1234.ts.net",
            serveConflict:
              "public Funnel sibling routes (/status -> http://user:vpsmcp_secret123456@127.0.0.1:8080); removed /mcp route (/mcp -> http://tok:sk-secret1234567890abcd@127.0.0.1:9000)",
            serveConflictDetails: {
              funnelActive: true,
              preservedFunnelSiblings: [
                "/status -> http://user:vpsmcp_secret123456@127.0.0.1:8080",
              ],
              replacedRootRoute: null,
              removedMcpRoute:
                "/mcp -> http://tok:sk-secret1234567890abcd@127.0.0.1:9000",
            },
          }),
        );
        return;
      }
      res.writeHead(404);
      res.end();
    });

    await new Promise<void>((resolve) =>
      mockServer.listen(0, "127.0.0.1", () => resolve()),
    );
    const port = (mockServer.address() as AddressInfo).port;
    try {
      const client = new HttpRuntimeBridgeClient({
        baseUrl: `http://127.0.0.1:${port}`,
      });
      const ts = await client.getTailscaleStatus();
      expect(ts.serveConflictDetails).not.toBeNull();
      expect(ts.serveConflictDetails?.funnelActive).toBe(true);
      expect(ts.serveConflictDetails?.preservedFunnelSiblings[0]).not.toContain(
        "vpsmcp_secret123456",
      );
      expect(ts.serveConflictDetails?.removedMcpRoute).not.toContain(
        "sk-secret1234567890abcd",
      );
      expect(ts.serveConflict).not.toContain("vpsmcp_secret123456");
      expect(ts.serveConflict).not.toContain("sk-secret1234567890abcd");
    } finally {
      await new Promise<void>((resolve) => mockServer.close(() => resolve()));
    }
  });
});
