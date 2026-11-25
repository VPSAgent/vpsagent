import { execFileSync, spawn } from "node:child_process";
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
    return {"projects": {}, "networks": [], "failValidate": False}

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
        if proj == "vpsagent-escape-logs":
            for i in range(120):
                print(f'line-{i:03d} ' + ('"quoted\\\\slash" ' * 60))
            sys.exit(0)
        print(f"Listening for {proj}")
        print("Loaded STRIPE_SECRET_KEY=sk-live-never-leak-me-123456")
        sys.exit(0)
    if "exec" in args:
        cmd = args[-1] if args else ""
        print(f"exec-ok:{proj}:{cmd}")
        sys.exit(0)

if args[:2] in (["container", "prune"], ["image", "prune"], ["builder", "prune"], ["volume", "prune"]):
    print("Total reclaimed space: 12.5MB")
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

if args[:1] == ["exec"] and "validate" in args:
    if st.get("failValidate"):
        sys.stderr.write("Error: simulated Caddy validate failure\\n")
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

function createFakeGitShim(tempDir: string): string {
  const shimPy = path.join(tempDir, "fake_git.py");
  fs.writeFileSync(
    shimPy,
    `import os, sys
args = sys.argv[1:]
if "clone" in args:
    dst = args[-1]
    url = args[-2] if len(args) >= 2 else ""
    os.makedirs(dst, exist_ok=True)
    if "no-dockerfile" in url:
        with open(os.path.join(dst, "package.json"), "w", encoding="utf-8") as fh:
            fh.write('{"name":"auto-app","dependencies":{"next":"15.0.0"},"scripts":{"build":"next build","start":"next start"}}')
        with open(os.path.join(dst, ".env.example"), "w", encoding="utf-8") as fh:
            fh.write("OPENAI_API_KEY=sk-example-secret-should-never-appear\\nPUBLIC_MODE=demo\\n")
    else:
        with open(os.path.join(dst, "Dockerfile"), "w", encoding="utf-8") as fh:
            fh.write("FROM alpine:3.20\\n")
    sys.exit(0)
if "rev-parse" in args:
    if "--abbrev-ref" in args:
        print("main")
    else:
        print("0123456789abcdef0123456789abcdef01234567")
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

describe("VPSAgent v2 End-to-End Flow (HTTPS Caddy reload, Security Boundaries, Streamable MCP, Approvals, Git + DB deploy)", () => {
  it("enforces HTTPS/Host/Origin, live Caddy HTTPS reload, sealed approvals, MCP version negotiation, 64KiB env caps, and full deploy flow", async () => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "vpsagent-e2e-"));
    const appsRoot = path.join(tempDir, "apps");
    const caddyAppsDir = path.join(tempDir, "caddy", "apps.d");
    const caddyCoreDir = path.join(tempDir, "caddy", "core.d");
    const socketPath = path.join(tempDir, "run", "runtime.sock");
    const stateFile = path.join(tempDir, "docker-state.json");
    fs.mkdirSync(appsRoot, { recursive: true });
    fs.mkdirSync(caddyAppsDir, { recursive: true });
    fs.mkdirSync(caddyCoreDir, { recursive: true });

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
      caddyCoreDir,
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
    // Proxied Caddy-fronted app (strictly fails closed without HTTPS or genuine loopback)
    const { app } = createVpsAgentApp({
      store,
      bridge,
      appsRoot,
      sessionSecret: "e2e-session-secret-32-bytes-long",
      claimToken,
      trustProxy: true,
      isLocalListener: false,
      defaultPeerIp: "172.18.0.2", // Docker bridge IP of Caddy container
      readinessTimeoutSeconds: 5,
      readinessPollIntervalMs: 25,
      lookupFn: async () => [{ address: "140.82.121.4", family: 4 }],
    });

    // Dedicated loopback-only local setup listener (127.0.0.1:3002 via SSH tunnel)
    const { app: localSetupApp } = createVpsAgentApp({
      store,
      bridge,
      appsRoot,
      sessionSecret: "e2e-session-secret-32-bytes-long",
      claimToken,
      trustProxy: false,
      isLocalListener: true,
      readinessTimeoutSeconds: 5,
      readinessPollIntervalMs: 25,
      lookupFn: async () => [{ address: "140.82.121.4", family: 4 }],
    });

    try {
      // 1. Spoofing Host: localhost over plaintext HTTP on Caddy-fronted listener MUST fail closed (403)
      const spoofedClaim = await app.request("http://localhost/api/setup/claim", {
        method: "POST",
        headers: {
          "content-type": "application/json",
          host: "localhost",
          "x-forwarded-for": "203.0.113.42",
          "x-forwarded-proto": "http",
        },
        body: JSON.stringify({
          claimToken,
          passphrase: "correct-horse-battery-staple",
        }),
      });
      expect(spoofedClaim.status).toBe(403);

      // Missing proxy metadata on proxied listener also fails closed (403)
      const missingProxyClaim = await app.request(
        "http://localhost/api/setup/claim",
        {
          method: "POST",
          headers: {
            "content-type": "application/json",
            host: "localhost",
          },
          body: JSON.stringify({
            claimToken,
            passphrase: "correct-horse-battery-staple",
          }),
        },
      );
      expect(missingProxyClaim.status).toBe(403);

      // 2. Step 1 over the genuine local SSH-tunnel listener succeeds!
      const claimRes = await localSetupApp.request(
        "http://localhost:3002/api/setup/claim",
        {
          method: "POST",
          headers: {
            "content-type": "application/json",
            host: "localhost:3002",
          },
          body: JSON.stringify({
            claimToken,
            passphrase: "correct-horse-battery-staple",
          }),
        },
      );
      expect(claimRes.status).toBe(200);
      const setCookie = claimRes.headers.get("set-cookie");
      expect(setCookie).toContain("vpsagent_session=");
      const cookieHeader = setCookie!.split(";")[0]!;

      // Before domain is enabled in Caddy, snippets must NOT advertise remote HTTPS yet
      const preSnippetsRes = await localSetupApp.request(
        "http://localhost:3002/api/mcp/snippets",
        { headers: { cookie: cookieHeader, host: "localhost:3002" } },
      );
      const preSnippets = (await preSnippetsRes.json()) as {
        httpsReady: boolean;
      };
      expect(preSnippets.httpsReady).toBe(false);

      // 3. Step 2: if Caddy validation fails, domain is NOT saved and httpsActive stays false
      fs.writeFileSync(
        stateFile,
        JSON.stringify({ projects: {}, networks: [], failValidate: true }),
        "utf8",
      );
      const failedDomainRes = await localSetupApp.request(
        "http://localhost:3002/api/setup/domain",
        {
          method: "POST",
          headers: { "content-type": "application/json", cookie: cookieHeader },
          body: JSON.stringify({ domain: "bad.example.com" }),
        },
      );
      expect(failedDomainRes.status).toBe(422);
      expect(store.getSetupState().domain).toBeNull();
      expect(store.getSetupState().httpsActive).toBe(false);

      // Now Caddy reloads dashboard.caddy, but because vps.example.com has no live TLS listener on :443,
      // httpsActive MUST stay false (pending/failed) and snippets must NOT advertise HTTPS yet!
      fs.writeFileSync(
        stateFile,
        JSON.stringify({ projects: {}, networks: [], failValidate: false }),
        "utf8",
      );
      const domainRes = await localSetupApp.request(
        "http://localhost:3002/api/setup/domain",
        {
          method: "POST",
          headers: { "content-type": "application/json", cookie: cookieHeader },
          body: JSON.stringify({
            domain: "vps.example.com",
            acmeEmail: "owner@example.com",
          }),
        },
      );
      expect(domainRes.status).toBe(200);
      expect(store.getSetupState().domain).toBe("vps.example.com");
      expect(store.getSetupState().httpsActive).toBe(false);
      expect(["pending", "failed"]).toContain(store.getSetupState().tlsStatus);
      const coreCaddy = fs.readFileSync(
        path.join(caddyCoreDir, "dashboard.caddy"),
        "utf8",
      );
      expect(coreCaddy).toContain("vps.example.com {");
      expect(coreCaddy).toContain("tls owner@example.com");

      // While TLS is pending/failed, snippets must NOT advertise https://vps.example.com/mcp yet
      const pendingSnippetsRes = await localSetupApp.request(
        "http://localhost:3002/api/mcp/snippets",
        { headers: { cookie: cookieHeader, host: "localhost:3002" } },
      );
      expect(((await pendingSnippetsRes.json()) as { httpsReady: boolean }).httpsReady).toBe(false);

      // Simulate TLS certificate issuance succeeding -> now snippets advertise https://vps.example.com/mcp
      store.updateSetupState({
        httpsActive: true,
        tlsStatus: "active",
        tlsError: null,
      });
      const snippetsRes = await app.request(
        "https://vps.example.com/api/mcp/snippets",
        {
          headers: {
            cookie: cookieHeader,
            host: "vps.example.com",
            "x-forwarded-proto": "https",
          },
        },
      );
      const snippets = (await snippetsRes.json()) as {
        mcpUrl: string;
        httpsReady: boolean;
      };
      expect(snippets.httpsReady).toBe(true);
      expect(snippets.mcpUrl).toBe("https://vps.example.com/mcp");

      // 4. Token creation is blocked on remote plaintext HTTP (403), succeeds over HTTPS
      const plaintextTokenRes = await app.request(
        "http://vps.example.com/api/mcp/tokens",
        {
          method: "POST",
          headers: {
            "content-type": "application/json",
            cookie: cookieHeader,
            host: "vps.example.com",
            "x-forwarded-proto": "http",
            "x-forwarded-for": "203.0.113.42",
          },
          body: JSON.stringify({ name: "Bad", scope: "read-only" }),
        },
      );
      expect(plaintextTokenRes.status).toBe(403);

      const makeToken = async (
        name: string,
        scope: "read-only" | "approval-required" | "auto-approve",
      ) => {
        const res = await app.request("https://vps.example.com/api/mcp/tokens", {
          method: "POST",
          headers: {
            "content-type": "application/json",
            cookie: cookieHeader,
            host: "vps.example.com",
            "x-forwarded-proto": "https",
          },
          body: JSON.stringify({ name, scope }),
        });
        expect(res.status).toBe(201);
        return (await res.json()) as {
          token: { id: string };
          rawToken: string;
        };
      };

      const readOnly = await makeToken("Observer AI", "read-only");
      const approvalReq = await makeToken("Claude Code", "approval-required");
      const autoApprove = await makeToken("Trusted CI", "auto-approve");

      // 5. /mcp validates Host, Origin, GET -> 405, and Streamable HTTP protocol versions
      const unexpectedHostMcp = await app.request("https://evil.example.com/mcp", {
        method: "POST",
        headers: {
          "content-type": "application/json",
          host: "evil.example.com",
          "x-forwarded-proto": "https",
          authorization: `Bearer ${readOnly.rawToken}`,
        },
        body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list" }),
      });
      expect(unexpectedHostMcp.status).toBe(403);

      const badOriginMcp = await app.request("https://vps.example.com/mcp", {
        method: "POST",
        headers: {
          "content-type": "application/json",
          host: "vps.example.com",
          origin: "https://evil-site.example",
          "x-forwarded-proto": "https",
          authorization: `Bearer ${readOnly.rawToken}`,
        },
        body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list" }),
      });
      expect(badOriginMcp.status).toBe(403);

      const getMcpRes = await app.request("https://vps.example.com/mcp", {
        method: "GET",
        headers: {
          host: "vps.example.com",
          "x-forwarded-proto": "https",
        },
      });
      expect(getMcpRes.status).toBe(405);
      expect(getMcpRes.headers.get("allow")).toBe("POST, DELETE");

      const postMcp = (
        rawToken: string,
        payload: Record<string, unknown>,
        extraHeaders?: Record<string, string>,
      ) =>
        app.request("https://vps.example.com/mcp", {
          method: "POST",
          headers: {
            "content-type": "application/json",
            host: "vps.example.com",
            "x-forwarded-proto": "https",
            authorization: `Bearer ${rawToken}`,
            ...(extraHeaders ?? {}),
          },
          body: JSON.stringify(payload),
        });

      // Streamable HTTP version negotiation & header validation
      const init202511 = await postMcp(readOnly.rawToken, {
        jsonrpc: "2.0",
        id: 10,
        method: "initialize",
        params: { protocolVersion: "2025-11-25" },
      });
      expect(init202511.status).toBe(200);
      expect(init202511.headers.get("mcp-protocol-version")).toBe("2025-11-25");
      const initBody = (await init202511.json()) as {
        result: { protocolVersion: string };
      };
      expect(initBody.result.protocolVersion).toBe("2025-11-25");

      const badProtoHeader = await postMcp(
        readOnly.rawToken,
        { jsonrpc: "2.0", id: 11, method: "tools/list" },
        { "mcp-protocol-version": "1999-01-01" },
      );
      expect(badProtoHeader.status).toBe(400);

      // Oversized JSON-RPC id is rejected with 400 so log envelope can never exceed 48 KiB
      const hugeIdRes = await postMcp(readOnly.rawToken, {
        jsonrpc: "2.0",
        id: "x".repeat(50_000),
        method: "tools/call",
        params: { name: "get_app_logs", arguments: { slug: "shop-api" } },
      });
      expect(hugeIdRes.status).toBe(400);

      // 6. Read-only key cannot deploy or queue approvals
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
        result: { isError: boolean };
      };
      expect(blockedJson.result.isError).toBe(true);
      expect(store.listApprovals()).toHaveLength(0);

      // 7. Approval-required key queues GitHub Dockerfile deploy with Postgres + secret env
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
            probePath: "/",
            companions: [{ type: "postgres" }],
            envVars: {
              MY_CUSTOM_FLAG: "arbitrary-secret-should-be-masked",
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
        approvalId: string;
      };

      // Approval persists tokenId AND masks ALL envVars in visible preview (even arbitrary key names!)
      const storedApproval = store.getApproval(parsedQueued.approvalId)!;
      expect(storedApproval.tokenId).toBe(approvalReq.token.id);
      expect(JSON.stringify(storedApproval.payload)).not.toContain(
        "arbitrary-secret-should-be-masked",
      );
      expect(JSON.stringify(storedApproval.payload)).not.toContain(
        "sk-live-super$secret#value",
      );

      // 8. Approve -> deploys Git app + Postgres + real secrets + Caddy HTTPS route
      const approveRes = await app.request(
        `https://vps.example.com/api/approvals/${parsedQueued.approvalId}/approve`,
        {
          method: "POST",
          headers: {
            cookie: cookieHeader,
            host: "vps.example.com",
            "x-forwarded-proto": "https",
          },
        },
      );
      expect(approveRes.status).toBe(200);
      const envOnDisk = fs.readFileSync(
        path.join(appsRoot, "shop-api", ".env"),
        "utf8",
      );
      expect(envOnDisk).toContain(
        "MY_CUSTOM_FLAG='arbitrary-secret-should-be-masked'",
      );
      expect(envOnDisk).toContain(
        "STRIPE_SECRET_KEY='sk-live-super$secret#value'",
      );

      // 9. Secret-marked arbitrary env update is masked in approval preview AND missing sealed payload refuses to execute (502 with error + failed status!)
      const queuedEnv = await postMcp(approvalReq.rawToken, {
        jsonrpc: "2.0",
        id: 12,
        method: "tools/call",
        params: {
          name: "update_app_env",
          arguments: {
            slug: "shop-api",
            vars: [
              {
                key: "ARBITRARY_NAME",
                value: "must-never-show-in-preview",
                isSecret: true,
              },
            ],
          },
        },
      });
      const queuedEnvParsed = JSON.parse(
        ((await queuedEnv.json()) as { result: { content: Array<{ text: string }> } })
          .result.content[0]!.text,
      ) as { approvalId: string };
      const envApproval = store.getApproval(queuedEnvParsed.approvalId)!;
      expect(JSON.stringify(envApproval.payload)).not.toContain(
        "must-never-show-in-preview",
      );

      // Simulate missing sealed payload -> approve MUST fail closed with 502 + clear error, NEVER executing "[REDACTED]"!
      store.consumeApprovalExecutionPayload(queuedEnvParsed.approvalId);
      const failedApproveRes = await app.request(
        `https://vps.example.com/api/approvals/${queuedEnvParsed.approvalId}/approve`,
        {
          method: "POST",
          headers: {
            cookie: cookieHeader,
            host: "vps.example.com",
            "x-forwarded-proto": "https",
          },
        },
      );
      expect(failedApproveRes.status).toBe(502);
      const failedApproveJson = (await failedApproveRes.json()) as {
        ok: boolean;
        error: string;
        approval: { status: string };
      };
      expect(failedApproveJson.ok).toBe(false);
      expect(failedApproveJson.error).toMatch(/Sealed execution payload/);
      expect(failedApproveJson.approval.status).toBe("failed");

      // 10. Oversized (> 64 KiB) env update is rejected BEFORE modifying SQLite or disk!
      const oversizedEnvRes = await app.request(
        "https://vps.example.com/api/apps/shop-api/env",
        {
          method: "PUT",
          headers: {
            "content-type": "application/json",
            cookie: cookieHeader,
            host: "vps.example.com",
            "x-forwarded-proto": "https",
          },
          body: JSON.stringify({
            vars: [{ key: "HUGE_BLOB", value: "a".repeat(70 * 1024) }],
            deleteKeys: [],
          }),
        },
      );
      expect(oversizedEnvRes.status).toBe(400);
      expect(store.getAppEnvMapForRuntime("shop-api").HUGE_BLOB).toBeUndefined();

      // 10b. Saving a regular env setting + rebuilding a running Postgres app succeeds without EPERM chmod
      const editEnvRes = await app.request(
        "https://vps.example.com/api/apps/shop-api/env",
        {
          method: "PUT",
          headers: {
            "content-type": "application/json",
            cookie: cookieHeader,
            host: "vps.example.com",
            "x-forwarded-proto": "https",
          },
          body: JSON.stringify({
            vars: [{ key: "TRICKY_VAR", value: "it's ${APP_PORT}\nline2" }],
            deleteKeys: [],
          }),
        },
      );
      expect(editEnvRes.status).toBe(200);
      expect(store.getAppEnvMapForRuntime("shop-api").TRICKY_VAR).toBe(
        "it's ${APP_PORT}\nline2",
      );

      // Generated compose includes recurring healthcheck for app service
      const shopCompose = fs.readFileSync(
        path.join(appsRoot, "shop-api", "docker-compose.yml"),
        "utf8",
      );
      expect(shopCompose).toContain("healthcheck:");

      // 10c. Wire byte budget on MCP get_app_logs stays strictly <= 48 KiB even with escape-heavy JSON lines!
      const escapeLogsRes = await postMcp(autoApprove.rawToken, {
        jsonrpc: "2.0",
        id: 14,
        method: "tools/call",
        params: {
          name: "deploy_app",
          arguments: {
            slug: "escape-logs",
            name: "Escape Logs",
            sourceType: "image",
            image: "nginxinc/nginx-unprivileged:alpine",
            internalPort: livePort,
          },
        },
      });
      expect(escapeLogsRes.status).toBe(200);
      const wireLogsRes = await postMcp(readOnly.rawToken, {
        jsonrpc: "2.0",
        id: 15,
        method: "tools/call",
        params: {
          name: "get_app_logs",
          arguments: { slug: "escape-logs", tail: 200 },
        },
      });
      const wireLogsText = await wireLogsRes.text();
      expect(Buffer.byteLength(wireLogsText, "utf8")).toBeLessThanOrEqual(
        48 * 1024,
      );
      const wireLogsJson = JSON.parse(wireLogsText) as {
        result: { content: Array<{ text: string }> };
      };
      const innerLogs = JSON.parse(wireLogsJson.result.content[0]!.text) as {
        truncated: boolean;
      };
      expect(innerLogs.truncated).toBe(true);

      // 11. Auto-approve deploys an image app and records actorTokenId in audit log
      const autoDeploy = await postMcp(autoApprove.rawToken, {
        jsonrpc: "2.0",
        id: 13,
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
      expect(
        ((await autoDeploy.json()) as { result: { isError: boolean } }).result
          .isError,
      ).toBe(false);
      const deployAudit = store
        .listAuditEvents({ targetSlug: "landing-site" })
        .find((e) => e.action === "deploy_app");
      expect(deployAudit?.actorTokenId).toBe(autoApprove.token.id);

      // 11b. Default apps base domain + MCP instructions + get_server_info + inspect_git_repo + safe-auto-deploy + app lock + secret handoff
      expect((initBody.result as { instructions?: string }).instructions).toContain(
        "inspect_git_repo",
      );

      const baseDomainRes = await app.request(
        "https://vps.example.com/api/setup/apps-base-domain",
        {
          method: "POST",
          headers: {
            "content-type": "application/json",
            cookie: cookieHeader,
            host: "vps.example.com",
            "x-forwarded-proto": "https",
          },
          body: JSON.stringify({ appsBaseDomain: "apps.example.com" }),
        },
      );
      expect(baseDomainRes.status).toBe(200);

      const safeScopedRes = await app.request(
        "https://vps.example.com/api/mcp/tokens",
        {
          method: "POST",
          headers: {
            "content-type": "application/json",
            cookie: cookieHeader,
            host: "vps.example.com",
            "x-forwarded-proto": "https",
          },
          body: JSON.stringify({
            name: "Safe Scoped Agent",
            scope: "safe-auto-deploy",
            allowedSlugs: ["auto-next"],
          }),
        },
      );
      expect(safeScopedRes.status).toBe(201);
      const safeScoped = (await safeScopedRes.json()) as { rawToken: string };

      const serverInfoRes = await postMcp(safeScoped.rawToken, {
        jsonrpc: "2.0",
        id: 20,
        method: "tools/call",
        params: { name: "get_server_info", arguments: {} },
      });
      const serverInfoText = (
        (await serverInfoRes.json()) as { result: { content: Array<{ text: string }> } }
      ).result.content[0]!.text;
      const serverInfo = JSON.parse(serverInfoText) as {
        server: { appsBaseDomain: string };
        visitorPass: { scope: string; allowedSlugs: string[]; deleteRequiresApproval: boolean };
      };
      expect(serverInfo.server.appsBaseDomain).toBe("apps.example.com");
      expect(serverInfo.visitorPass.scope).toBe("safe-auto-deploy");
      expect(serverInfo.visitorPass.allowedSlugs).toEqual(["auto-next"]);
      expect(serverInfo.visitorPass.deleteRequiresApproval).toBe(true);

      // App lock strictly blocks reading or acting on other apps
      const blockedCrossApp = await postMcp(safeScoped.rawToken, {
        jsonrpc: "2.0",
        id: 21,
        method: "tools/call",
        params: { name: "get_app_logs", arguments: { slug: "shop-api" } },
      });
      expect(
        ((await blockedCrossApp.json()) as { result: { isError: boolean } }).result
          .isError,
      ).toBe(true);

      // Inspecting a public repo without a Dockerfile auto-detects Next.js, port 3000, and .env.example keys
      const inspectGitRes = await postMcp(safeScoped.rawToken, {
        jsonrpc: "2.0",
        id: 22,
        method: "tools/call",
        params: {
          name: "inspect_git_repo",
          arguments: {
            gitRepoUrl: "https://140.82.121.4/acme/no-dockerfile-demo",
          },
        },
      });
      const inspectGit = JSON.parse(
        ((await inspectGitRes.json()) as { result: { content: Array<{ text: string }> } })
          .result.content[0]!.text,
      ) as {
        detectedRuntime: string;
        hasDockerfile: boolean;
        suggestedPort: number;
        suggestedDomain: string;
        envExampleKeys: Array<{ key: string }>;
      };
      expect(inspectGit.detectedRuntime).toBe("nextjs");
      expect(inspectGit.hasDockerfile).toBe(false);
      expect(inspectGit.suggestedPort).toBe(3000);
      expect(inspectGit.suggestedDomain).toBe("no-dockerfile-demo.apps.example.com");
      expect(inspectGit.envExampleKeys.map((k) => k.key)).toEqual([
        "OPENAI_API_KEY",
        "PUBLIC_MODE",
      ]);

      // Safe Auto-Deploy launches the repo without approval, assigns auto-subdomain, tracks deployment, and returns secret handoff URL
      const autoNextDeployRes = await postMcp(safeScoped.rawToken, {
        jsonrpc: "2.0",
        id: 23,
        method: "tools/call",
        params: {
          name: "deploy_app",
          arguments: {
            slug: "auto-next",
            name: "Auto Next",
            sourceType: "git",
            gitRepoUrl: "https://140.82.121.4/acme/no-dockerfile-demo",
            internalPort: livePort,
          },
        },
      });
      const autoNextPayload = JSON.parse(
        ((await autoNextDeployRes.json()) as { result: { content: Array<{ text: string }> } })
          .result.content[0]!.text,
      ) as {
        status: string;
        result: {
          app: { domain: string; detectedRuntime: string };
          deployment: { id: string; usedAutoDockerfile: boolean; status: string };
          liveUrl: string;
          missingEnvKeys: string[];
          envSettingsUrl: string;
        };
      };
      expect(autoNextPayload.status).toBe("executed");
      expect(autoNextPayload.result.app.domain).toBe("auto-next.apps.example.com");
      expect(autoNextPayload.result.app.detectedRuntime).toBe("nextjs");
      expect(autoNextPayload.result.deployment.usedAutoDockerfile).toBe(true);
      expect(autoNextPayload.result.deployment.status).toBe("succeeded");
      expect(autoNextPayload.result.liveUrl).toBe("https://auto-next.apps.example.com");
      expect(autoNextPayload.result.missingEnvKeys).toEqual([
        "OPENAI_API_KEY",
        "PUBLIC_MODE",
      ]);
      expect(autoNextPayload.result.envSettingsUrl).toBe(
        "https://vps.example.com/#apps/auto-next/env",
      );

      // get_deployment returns persisted build logs & commit info
      const getDepRes = await postMcp(safeScoped.rawToken, {
        jsonrpc: "2.0",
        id: 24,
        method: "tools/call",
        params: {
          name: "get_deployment",
          arguments: { deploymentId: autoNextPayload.result.deployment.id },
        },
      });
      const getDep = JSON.parse(
        ((await getDepRes.json()) as { result: { content: Array<{ text: string }> } })
          .result.content[0]!.text,
      ) as { deployment: { status: string; commitSha: string; buildLogs: string[] } };
      expect(getDep.deployment.status).toBe("succeeded");
      expect(getDep.deployment.commitSha).toBe("0123456789abcdef0123456789abcdef01234567");
      expect(getDep.deployment.buildLogs.length).toBeGreaterThan(0);

      // Safe Auto-Deploy MUST still queue delete_app for human approval!
      const safeDeleteRes = await postMcp(safeScoped.rawToken, {
        jsonrpc: "2.0",
        id: 25,
        method: "tools/call",
        params: { name: "delete_app", arguments: { slug: "auto-next" } },
      });
      const safeDelete = JSON.parse(
        ((await safeDeleteRes.json()) as { result: { content: Array<{ text: string }> } })
          .result.content[0]!.text,
      ) as { status: string; approvalId: string };
      expect(safeDelete.status).toBe("pending_approval");
      expect(safeDelete.approvalId).toMatch(/^apr_/);
      expect(store.getApp("auto-next")).not.toBeNull();

      // 11c. VPS Manager MCP tools: read-only, approval-required, auto-approve (app-only), and explicit host-admin
      const toolsListRes = await postMcp(readOnly.rawToken, {
        jsonrpc: "2.0",
        id: 100,
        method: "tools/list",
      });
      const toolsListBody = (await toolsListRes.json()) as {
        result: { tools: Array<{ name: string }> };
      };
      const toolNames = toolsListBody.result.tools.map((t) => t.name);
      expect(toolNames).toEqual(
        expect.arrayContaining([
          "start_app",
          "get_audit_history",
          "get_setup_status",
          "exec_in_app",
          "run_host_command",
          "list_files",
          "read_file",
          "write_file",
          "delete_file",
          "list_services",
          "manage_service",
          "docker_cleanup",
        ]),
      );

      // Read-only key can inspect audit history & setup status, but is blocked from host commands
      const auditMcpRes = await postMcp(readOnly.rawToken, {
        jsonrpc: "2.0",
        id: 101,
        method: "tools/call",
        params: { name: "get_audit_history", arguments: { limit: 10 } },
      });
      const auditMcpBody = (await auditMcpRes.json()) as {
        result: { isError: boolean; content: Array<{ text: string }> };
      };
      expect(auditMcpBody.result.isError).toBe(false);
      expect(JSON.parse(auditMcpBody.result.content[0]!.text).events.length).toBeGreaterThan(0);

      const setupMcpRes = await postMcp(readOnly.rawToken, {
        jsonrpc: "2.0",
        id: 102,
        method: "tools/call",
        params: { name: "get_setup_status", arguments: {} },
      });
      const setupMcpBody = (await setupMcpRes.json()) as {
        result: { isError: boolean; content: Array<{ text: string }> };
      };
      expect(setupMcpBody.result.isError).toBe(false);
      expect(JSON.parse(setupMcpBody.result.content[0]!.text).setup.claimed).toBe(true);

      const roHostExec = await postMcp(readOnly.rawToken, {
        jsonrpc: "2.0",
        id: 103,
        method: "tools/call",
        params: { name: "run_host_command", arguments: { command: "echo nope" } },
      });
      expect(
        ((await roHostExec.json()) as { result: { isError: boolean } }).result
          .isError,
      ).toBe(true);

      // Approval-required key queues run_host_command and executes it once owner approves
      const queuedHostCmd = await postMcp(approvalReq.rawToken, {
        jsonrpc: "2.0",
        id: 104,
        method: "tools/call",
        params: {
          name: "run_host_command",
          arguments: { command: "echo approved-host-ok", cwd: tempDir },
        },
      });
      const queuedHostCmdBody = (await queuedHostCmd.json()) as {
        result: { isError: boolean; content: Array<{ text: string }> };
      };
      expect(queuedHostCmdBody.result.isError).toBe(false);
      const queuedHostData = JSON.parse(
        queuedHostCmdBody.result.content[0]!.text,
      ) as { status: string; approvalId: string };
      expect(queuedHostData.status).toBe("pending_approval");

      const approveHostCmdRes = await app.request(
        `/api/approvals/${queuedHostData.approvalId}/approve`,
        {
          method: "POST",
          headers: {
            cookie: cookieHeader,
            "content-type": "application/json",
            "x-forwarded-proto": "https",
          },
          body: JSON.stringify({ note: "Approved host command" }),
        },
      );
      expect(approveHostCmdRes.status).toBe(200);

      // Failed command under approval MUST report HTTP 502, ok=false, status=failed, and isError=true on wait_for_approval
      const queuedFailCmd = await postMcp(approvalReq.rawToken, {
        jsonrpc: "2.0",
        id: 1041,
        method: "tools/call",
        params: {
          name: "run_host_command",
          arguments: { command: "echo boom >&2 && exit 7", cwd: tempDir },
        },
      });
      const queuedFailData = JSON.parse(
        ((await queuedFailCmd.json()) as { result: { content: Array<{ text: string }> } })
          .result.content[0]!.text,
      ) as { status: string; approvalId: string };
      const approveFailRes = await app.request(
        `/api/approvals/${queuedFailData.approvalId}/approve`,
        {
          method: "POST",
          headers: {
            cookie: cookieHeader,
            "content-type": "application/json",
            "x-forwarded-proto": "https",
          },
          body: JSON.stringify({}),
        },
      );
      expect(approveFailRes.status).toBe(502);
      const approveFailBody = (await approveFailRes.json()) as {
        ok: boolean;
        approval: { status: string };
      };
      expect(approveFailBody.ok).toBe(false);
      expect(approveFailBody.approval.status).toBe("failed");

      const waitFailRes = await postMcp(approvalReq.rawToken, {
        jsonrpc: "2.0",
        id: 1042,
        method: "tools/call",
        params: {
          name: "wait_for_approval",
          arguments: { approvalId: queuedFailData.approvalId, timeoutSeconds: 2 },
        },
      });
      const waitFailBody = (await waitFailRes.json()) as {
        result: { isError: boolean; content: Array<{ text: string }> };
      };
      expect(waitFailBody.result.isError).toBe(true);
      expect(JSON.parse(waitFailBody.result.content[0]!.text).status).toBe(
        "failed",
      );

      // Cross-pass isolation: another pass CANNOT read approvalReq's approval via wait_for_approval
      const crossPassWait = await postMcp(readOnly.rawToken, {
        jsonrpc: "2.0",
        id: 1043,
        method: "tools/call",
        params: {
          name: "wait_for_approval",
          arguments: { approvalId: queuedHostData.approvalId, timeoutSeconds: 1 },
        },
      });
      expect(
        ((await crossPassWait.json()) as { result: { isError: boolean } }).result
          .isError,
      ).toBe(true);

      // Existing auto-approve (app-only) MUST queue host-admin actions instead of running root shell silently
      const autoHostQueued = await postMcp(autoApprove.rawToken, {
        jsonrpc: "2.0",
        id: 1044,
        method: "tools/call",
        params: {
          name: "run_host_command",
          arguments: { command: "echo should-queue" },
        },
      });
      const autoHostData = JSON.parse(
        ((await autoHostQueued.json()) as { result: { content: Array<{ text: string }> } })
          .result.content[0]!.text,
      ) as { status: string };
      expect(autoHostData.status).toBe("pending_approval");

      // Explicit host-admin pass runs write_file -> list_files -> read_file -> delete_file inside appsRoot
      const hostAdminRes = await app.request(
        "https://vps.example.com/api/mcp/tokens",
        {
          method: "POST",
          headers: {
            "content-type": "application/json",
            cookie: cookieHeader,
            host: "vps.example.com",
            "x-forwarded-proto": "https",
          },
          body: JSON.stringify({
            name: "Root Host Manager",
            scope: "host-admin",
          }),
        },
      );
      expect(hostAdminRes.status).toBe(201);
      const hostAdmin = (await hostAdminRes.json()) as { rawToken: string };

      const managedFilePath = path.join(appsRoot, "vps-manager-dir", "hello.txt");
      const writeRes = await postMcp(hostAdmin.rawToken, {
        jsonrpc: "2.0",
        id: 105,
        method: "tools/call",
        params: {
          name: "write_file",
          arguments: {
            path: managedFilePath,
            content: "hello from vps manager\n",
            createDirs: true,
          },
        },
      });
      expect(
        ((await writeRes.json()) as { result: { isError: boolean } }).result
          .isError,
      ).toBe(false);

      const readRes = await postMcp(readOnly.rawToken, {
        jsonrpc: "2.0",
        id: 106,
        method: "tools/call",
        params: { name: "read_file", arguments: { path: managedFilePath } },
      });
      const readBody = (await readRes.json()) as {
        result: { isError: boolean; content: Array<{ text: string }> };
      };
      expect(readBody.result.isError).toBe(false);
      expect(JSON.parse(readBody.result.content[0]!.text).content).toContain(
        "hello from vps manager",
      );

      const listFilesRes = await postMcp(readOnly.rawToken, {
        jsonrpc: "2.0",
        id: 107,
        method: "tools/call",
        params: {
          name: "list_files",
          arguments: { path: path.dirname(managedFilePath) },
        },
      });
      const listFilesBody = (await listFilesRes.json()) as {
        result: { isError: boolean; content: Array<{ text: string }> };
      };
      expect(listFilesBody.result.isError).toBe(false);
      expect(
        JSON.parse(listFilesBody.result.content[0]!.text).entries[0].name,
      ).toBe("hello.txt");

      const deleteFileRes = await postMcp(hostAdmin.rawToken, {
        jsonrpc: "2.0",
        id: 108,
        method: "tools/call",
        params: { name: "delete_file", arguments: { path: managedFilePath } },
      });
      expect(
        ((await deleteFileRes.json()) as { result: { isError: boolean } }).result
          .isError,
      ).toBe(false);
      expect(fs.existsSync(managedFilePath)).toBe(false);

      const execAppRes = await postMcp(autoApprove.rawToken, {
        jsonrpc: "2.0",
        id: 109,
        method: "tools/call",
        params: {
          name: "exec_in_app",
          arguments: { slug: "landing-site", command: "whoami" },
        },
      });
      const execAppBody = (await execAppRes.json()) as {
        result: { isError: boolean; content: Array<{ text: string }> };
      };
      expect(execAppBody.result.isError).toBe(false);
      expect(
        JSON.parse(execAppBody.result.content[0]!.text).result.stdout,
      ).toContain("exec-ok:vpsagent-landing-site:whoami");

      const stopRes = await postMcp(autoApprove.rawToken, {
        jsonrpc: "2.0",
        id: 110,
        method: "tools/call",
        params: { name: "stop_app", arguments: { slug: "landing-site" } },
      });
      expect(
        ((await stopRes.json()) as { result: { isError: boolean } }).result
          .isError,
      ).toBe(false);

      const startRes = await postMcp(autoApprove.rawToken, {
        jsonrpc: "2.0",
        id: 111,
        method: "tools/call",
        params: { name: "start_app", arguments: { slug: "landing-site" } },
      });
      expect(
        ((await startRes.json()) as { result: { isError: boolean } }).result
          .isError,
      ).toBe(false);

      // Server-wide docker_cleanup queues for approval under auto-approve, and runs immediately under host-admin
      const autoCleanupQueued = await postMcp(autoApprove.rawToken, {
        jsonrpc: "2.0",
        id: 1120,
        method: "tools/call",
        params: { name: "docker_cleanup", arguments: { pruneVolumes: false } },
      });
      const autoCleanupData = JSON.parse(
        ((await autoCleanupQueued.json()) as { result: { content: Array<{ text: string }> } })
          .result.content[0]!.text,
      ) as { status: string };
      expect(autoCleanupData.status).toBe("pending_approval");

      const cleanupRes = await postMcp(hostAdmin.rawToken, {
        jsonrpc: "2.0",
        id: 112,
        method: "tools/call",
        params: { name: "docker_cleanup", arguments: { pruneVolumes: false } },
      });
      const cleanupBody = (await cleanupRes.json()) as {
        result: { isError: boolean; content: Array<{ text: string }> };
      };
      expect(cleanupBody.result.isError).toBe(false);
      expect(
        JSON.parse(cleanupBody.result.content[0]!.text).result.reclaimedSummary,
      ).toContain("12.5MB");

      // 11c. Agent Connection Upgrades: initialize instructions, tool annotations, MCP Resources,
      // wait_for_approval, DELETE /mcp session close, snippets (T3/AGY/curl), and /api/mcp/test
      const initUpgraded = await postMcp(approvalReq.rawToken, {
        jsonrpc: "2.0",
        id: 120,
        method: "initialize",
        params: { protocolVersion: "2025-11-25" },
      });
      expect(initUpgraded.headers.get("mcp-session-id")).toBeTruthy();
      const initUpgradedBody = (await initUpgraded.json()) as {
        result: {
          instructions: string;
          capabilities: { tools: object; resources: object };
        };
      };
      expect(initUpgradedBody.result.instructions).toContain("ASK-FIRST");
      expect(initUpgradedBody.result.capabilities.resources).toBeDefined();

      // Tool annotations are present (readOnlyHint / destructiveHint)
      const annotatedTools = (
        toolsListBody.result.tools as Array<{
          name: string;
          annotations?: { readOnlyHint: boolean; destructiveHint: boolean };
        }>
      );
      expect(
        annotatedTools.find((t) => t.name === "get_host_health")?.annotations
          ?.readOnlyHint,
      ).toBe(true);
      expect(
        annotatedTools.find((t) => t.name === "run_host_command")?.annotations
          ?.destructiveHint,
      ).toBe(true);
      expect(toolNames).toContain("wait_for_approval");

      // MCP Resources: resources/list & resources/read
      const resList = await postMcp(readOnly.rawToken, {
        jsonrpc: "2.0",
        id: 121,
        method: "resources/list",
      });
      const resListBody = (await resList.json()) as {
        result: { resources: Array<{ uri: string }> };
      };
      expect(resListBody.result.resources.map((r) => r.uri)).toEqual(
        expect.arrayContaining([
          "vpsagent://server/overview",
          "vpsagent://apps/list",
          "vpsagent://audit/recent",
        ]),
      );

      const resRead = await postMcp(readOnly.rawToken, {
        jsonrpc: "2.0",
        id: 122,
        method: "resources/read",
        params: { uri: "vpsagent://server/overview" },
      });
      const resReadBody = (await resRead.json()) as {
        result: { contents: Array<{ uri: string; text: string }> };
      };
      expect(resReadBody.result.contents[0]!.uri).toBe(
        "vpsagent://server/overview",
      );
      expect(JSON.parse(resReadBody.result.contents[0]!.text).appCount).toBeGreaterThan(0);

      // wait_for_approval returns immediately for an already-executed approval
      const waitRes = await postMcp(approvalReq.rawToken, {
        jsonrpc: "2.0",
        id: 123,
        method: "tools/call",
        params: {
          name: "wait_for_approval",
          arguments: { approvalId: queuedHostData.approvalId, timeoutSeconds: 2 },
        },
      });
      const waitBody = (await waitRes.json()) as {
        result: { isError: boolean; content: Array<{ text: string }> };
      };
      expect(waitBody.result.isError).toBe(false);
      expect(JSON.parse(waitBody.result.content[0]!.text).done).toBe(true);

      // Real MCP session lifecycle: initialize -> valid ping -> DELETE /mcp -> closed session returns 404
      const sessionId = initUpgraded.headers.get("mcp-session-id")!;
      const validPing = await app.request("/mcp", {
        method: "POST",
        headers: {
          host: "vps.example.com",
          "x-forwarded-host": "vps.example.com",
          "x-forwarded-proto": "https",
          "content-type": "application/json",
          authorization: `Bearer ${approvalReq.rawToken}`,
          "mcp-session-id": sessionId,
        },
        body: JSON.stringify({ jsonrpc: "2.0", id: 124, method: "ping" }),
      });
      expect(validPing.status).toBe(200);

      const delMcpRes = await app.request("/mcp", {
        method: "DELETE",
        headers: {
          host: "vps.example.com",
          "x-forwarded-host": "vps.example.com",
          "x-forwarded-proto": "https",
          authorization: `Bearer ${approvalReq.rawToken}`,
          "mcp-session-id": sessionId,
        },
      });
      expect(delMcpRes.status).toBe(204);

      const closedPing = await app.request("/mcp", {
        method: "POST",
        headers: {
          host: "vps.example.com",
          "x-forwarded-host": "vps.example.com",
          "x-forwarded-proto": "https",
          "content-type": "application/json",
          authorization: `Bearer ${approvalReq.rawToken}`,
          "mcp-session-id": sessionId,
        },
        body: JSON.stringify({ jsonrpc: "2.0", id: 125, method: "ping" }),
      });
      expect(closedPing.status).toBe(404);

      // Dashboard snippets include T3/AGY & curlTest, and /api/mcp/test reports ready
      const upgradedSnippetsRes = await app.request("/api/mcp/snippets", {
        headers: { cookie: cookieHeader, host: "localhost:3002" },
      });
      const upgradedSnippetsBody = (await upgradedSnippetsRes.json()) as {
        t3AndAgy: string;
        curlTest: string;
        tokenPlaceholder: string;
      };
      expect(upgradedSnippetsBody.t3AndAgy).toContain("serverUrl");
      expect(upgradedSnippetsBody.curlTest).toContain("curl");
      expect(upgradedSnippetsBody.tokenPlaceholder).toBe(
        "vpsmcp_YOUR_TOKEN_HERE",
      );

      const testConnRes = await app.request("/api/mcp/test", {
        method: "POST",
        headers: { cookie: cookieHeader, host: "localhost:3002" },
      });
      const testConnBody = (await testConnRes.json()) as {
        ok: boolean;
        toolCount: number;
      };
      expect(testConnBody.ok).toBe(true);
      expect(testConnBody.toolCount).toBe(toolsListBody.result.tools.length);

      // 11b. System self-update endpoints require owner auth and return typed status
      const unauthUpdateStatus = await app.request("/api/system/update/status", {
        headers: { host: "localhost:3002" },
      });
      expect(unauthUpdateStatus.status).toBe(401);

      const authUpdateStatus = await app.request("/api/system/update/status", {
        headers: { cookie: cookieHeader, host: "localhost:3002" },
      });
      expect(authUpdateStatus.status).toBe(200);
      const authUpdateBody = (await authUpdateStatus.json()) as {
        status: { state: string; canUpdate: boolean };
      };
      expect(authUpdateBody.status.state).toBe("idle");
      expect(typeof authUpdateBody.status.canUpdate).toBe("boolean");

      // Sibling-site / cross-origin POST to /api/system/update/apply must be blocked (CSRF)
      const siblingApplyRes = await app.request("/api/system/update/apply", {
        method: "POST",
        headers: {
          cookie: cookieHeader,
          host: "localhost:3002",
          origin: "https://evil-app.example.com",
          "sec-fetch-site": "same-site",
          "content-type": "application/json",
        },
      });
      expect(siblingApplyRes.status).toBe(403);

      // 12. Bootstrap invariants: zero docker.sock, VPSAgent/vpsagent repo URL, no plaintext public claim URL
      const coreCompose = fs.readFileSync(
        path.join(REPO_ROOT, "bootstrap", "docker-compose.core.yml"),
        "utf8",
      );
      expect(coreCompose).not.toContain("/var/run/docker.sock");
      expect(coreCompose).toContain("127.0.0.1:3002:3002");

      const installSh = fs.readFileSync(
        path.join(REPO_ROOT, "bootstrap", "install.sh"),
        "utf8",
      );
      expect(installSh).toContain("https://github.com/VPSAgent/vpsagent.git");
      expect(installSh).toContain("systemctl restart vpsagent-runtime.service");
      expect(installSh).toContain("wait_for_runtime_bridge");
      expect(installSh).not.toContain("diegosg-dev/vpsagent");
      expect(installSh).not.toContain('base_url="http://${PUBLIC_IP}"');
      execFileSync("bash", ["-n", path.join(REPO_ROOT, "bootstrap", "install.sh")]);
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
