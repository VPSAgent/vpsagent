import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";
import {
  type AppStatus,
  RegistryStore,
  type RuntimeBridge,
  RuntimeBridgeError,
  type RuntimeTailscaleStatus,
} from "@vpsagent/shared";
import { createVpsAgentApp } from "./app.js";

function createTailscaleMockBridge(options?: {
  initialStatus?: RuntimeTailscaleStatus;
  unsupported?: boolean;
}): {
  bridge: RuntimeBridge;
  state: { status: RuntimeTailscaleStatus; lastAuthKey: string | null };
} {
  const defaultStatus: RuntimeTailscaleStatus = options?.initialStatus ?? {
    installed: true,
    serviceActive: true,
    connected: false,
    backendState: "needs_login",
    tailscaleIp: null,
    tailscaleIps: [],
    hostname: "my-vps",
    dnsName: null,
    tailnetName: null,
    magicDnsEnabled: false,
    httpsCertsAvailable: false,
    loginUrl: "https://login.tailscale.com/a/initial-login",
    serveEnabled: false,
    serveTarget: null,
    serveUrl: null,
    mcpUrl: null,
    serveConflict: null,
    serveConflictDetails: null,
    cliVersion: "1.78.1",
    detail: null,
  };

  const state = {
    status: structuredClone(defaultStatus),
    lastAuthKey: null as string | null,
  };
  const statuses: Record<string, AppStatus> = {};

  const bridge: RuntimeBridge = {
    async health() {
      return { ok: true, service: "mock-bridge" };
    },
    async getHostStats() {
      return {
        metrics: {
          hostname: "my-vps",
          platform: "linux",
          uptimeSeconds: 3600,
          cpuCount: 2,
          loadAverage1m: 0.1,
          memoryTotalMb: 2048,
          memoryUsedMb: 400,
          memoryUsagePercent: 20,
          collectedAt: new Date().toISOString(),
        },
        disk: {
          totalGb: 20,
          usedGb: 4,
          freeGb: 16,
          usedPercent: 20,
          mount: "/",
        },
      };
    },
    async lifecycle(slug, action) {
      if (action === "start" || action === "restart") {
        statuses[slug] = "running";
      } else if (action === "stop") {
        statuses[slug] = "stopped";
      }
      return { slug, status: statuses[slug] ?? "running" };
    },
    async buildGitImage(input) {
      return {
        ok: true,
        slug: input.slug,
        image: `vpsagent-app-${input.slug}:latest`,
        commitSha: "abcdef123456",
        durationMs: 10,
        buildLogTail: [],
      };
    },
    async getLogs() {
      return [];
    },
    async routeCaddy({ slug, domain }) {
      return { ok: true, slug, domain, routed: Boolean(domain) };
    },
    async routeCoreDomain({ domain, acmeEmail }) {
      return {
        ok: true,
        domain,
        acmeEmail: acmeEmail ?? null,
        httpsActive: Boolean(domain),
        tlsStatus: domain ? "active" : "inactive",
        tlsError: null,
      };
    },
    async removeWorkload(slug) {
      return { ok: true, slug };
    },
    async getStatuses(slugs) {
      const out: Record<string, AppStatus> = {};
      for (const s of slugs) out[s] = statuses[s] ?? "running";
      return out;
    },
    async inspectWorkload(slug) {
      return {
        slug,
        status: "running",
        workspaceExists: true,
        composeExists: true,
        caddyRouteConfigured: false,
        caddyDomains: [],
        containers: [],
        lockedApartmentCompliant: true,
        httpProbe: null,
      };
    },
    async waitForReadiness(slug) {
      return {
        ready: true,
        slug,
        status: "running",
        attempts: 1,
        elapsedMs: 5,
        httpProbe: null,
        reason: null,
      };
    },
    async execInApp() {
      return { exitCode: 0, stdout: "", stderr: "", durationMs: 1, truncated: false };
    },
    async runHostCommand() {
      return { exitCode: 0, stdout: "", stderr: "", durationMs: 1, truncated: false };
    },
    async listHostFiles(input) {
      return { path: input.path, entries: [], truncated: false };
    },
    async readHostFile(input) {
      return {
        path: input.path,
        content: "",
        sizeBytes: 0,
        totalLines: 0,
        startLine: 1,
        endLine: 0,
        truncated: false,
      };
    },
    async writeHostFile(input) {
      return { ok: true, path: input.path, bytesWritten: 0, appended: false };
    },
    async deleteHostFile(input) {
      return { ok: true, path: input.path, deletedType: "file" };
    },
    async listHostServices() {
      return { services: [], truncated: false };
    },
    async manageHostService(input) {
      return {
        ok: true,
        service: input.service,
        action: input.action,
        activeState: "active",
        output: "",
      };
    },
    async dockerCleanup() {
      return { ok: true, output: "", reclaimedSummary: "0B" };
    },
    async getTailscaleStatus() {
      if (options?.unsupported) {
        throw new RuntimeBridgeError(404, "Not found.");
      }
      return state.status;
    },
    async connectTailscale(input) {
      if (options?.unsupported) {
        throw new RuntimeBridgeError(404, "Not found.");
      }
      if (input?.mode === "authkey") {
        state.lastAuthKey = input.authKey ?? null;
        if (input.authKey === "tskey-auth-kFailScrubTest1234") {
          throw new RuntimeBridgeError(
            422,
            `Failed with key ${input.authKey}`,
          );
        }
        state.status = {
          ...state.status,
          connected: true,
          backendState: "running",
          tailscaleIp: "100.64.0.77",
          tailscaleIps: ["100.64.0.77"],
          dnsName: "my-vps.tail1234.ts.net",
          tailnetName: "tail1234.ts.net",
          magicDnsEnabled: true,
          httpsCertsAvailable: true,
          loginUrl: null,
        };
        return { ok: true, status: state.status, loginUrl: null };
      }
      return {
        ok: true,
        status: state.status,
        loginUrl: state.status.loginUrl,
      };
    },
    async setTailscaleServe({ enabled }) {
      if (options?.unsupported) {
        throw new RuntimeBridgeError(404, "Not found.");
      }
      state.status = {
        ...state.status,
        serveEnabled: enabled,
        serveTarget: enabled ? "http://127.0.0.1:3001" : null,
        serveUrl: enabled ? `https://${state.status.dnsName}` : null,
        mcpUrl: enabled ? `https://${state.status.dnsName}/mcp` : null,
      };
      return { ok: true, status: state.status, actionUrl: null };
    },
  };

  return { bridge, state };
}

describe("Tailscale API, MCP Gateway, CSRF & Fallback", () => {
  it("supports Tailscale discovery, connect, Serve toggle, dual MCP URLs, and Tailscale /mcp boundary", async () => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "vpsagent-ts-api-"));
    const appsRoot = path.join(tempDir, "apps");
    fs.mkdirSync(appsRoot, { recursive: true });
    const store = new RegistryStore(path.join(tempDir, "registry.db"), {
      encryptionSecret: "tailscale-test-encryption-secret",
    });
    const { bridge } = createTailscaleMockBridge();

    const { app } = createVpsAgentApp({
      store,
      bridge,
      appsRoot,
      sessionSecret: "tailscale-test-session-secret",
      trustProxy: true,
      isLocalListener: false,
      defaultPeerIp: "172.18.0.2",
    });

    try {
      store.setAdminPassphrase("correct-horse-battery");
      store.updateSetupState({
        claimed: true,
        claimedAt: new Date().toISOString(),
      });

      const loginRes = await app.request("http://localhost:3002/api/auth/login", {
        method: "POST",
        headers: {
          "content-type": "application/json",
          host: "localhost:3002",
          "x-forwarded-for": "127.0.0.1",
        },
        body: JSON.stringify({ passphrase: "correct-horse-battery" }),
      });
      expect(loginRes.status).toBe(200);
      const cookie = loginRes.headers.get("set-cookie")!.split(";")[0]!;

      // Create an MCP token while connected locally
      const tokRes = await app.request("http://localhost:3002/api/mcp/tokens", {
        method: "POST",
        headers: {
          "content-type": "application/json",
          cookie,
          host: "localhost:3002",
          "x-forwarded-for": "127.0.0.1",
        },
        body: JSON.stringify({ name: "TS Agent", scope: "read-only" }),
      });
      expect(tokRes.status).toBe(201);
      const rawToken = ((await tokRes.json()) as { rawToken: string }).rawToken;

      // 1. Initial Tailscale status (needs_login) — dashboard sees loginUrl, but MCP get_setup_status redacts loginUrl
      const statusRes1 = await app.request("/api/tailscale/status", {
        headers: { cookie, host: "localhost:3002" },
      });
      expect(statusRes1.status).toBe(200);
      const statusBody1 = (await statusRes1.json()) as {
        bridgeSupported: boolean;
        status: RuntimeTailscaleStatus;
      };
      expect(statusBody1.bridgeSupported).toBe(true);
      expect(statusBody1.status.loginUrl).toBe(
        "https://login.tailscale.com/a/initial-login",
      );

      const pendingMcpStatus = await app.request("http://localhost:3002/mcp", {
        method: "POST",
        headers: {
          "content-type": "application/json",
          authorization: `Bearer ${rawToken}`,
          host: "localhost:3002",
          "x-forwarded-for": "127.0.0.1",
        },
        body: JSON.stringify({
          jsonrpc: "2.0",
          id: 9,
          method: "tools/call",
          params: { name: "get_setup_status", arguments: {} },
        }),
      });
      expect(pendingMcpStatus.status).toBe(200);
      const pendingRpc = (await pendingMcpStatus.json()) as {
        result: { content: Array<{ text: string }> };
      };
      const pendingPayload = JSON.parse(pendingRpc.result.content[0]!.text) as {
        tailscale: { loginUrl: string | null };
      };
      expect(pendingPayload.tailscale.loginUrl).toBeNull();

      // 2. Connect guard: blocked on remote HTTP & cross-origin POST, scrubs authKey on error
      const remoteHttpConnect = await app.request(
        "http://vps.example.com/api/tailscale/connect",
        {
          method: "POST",
          headers: {
            "content-type": "application/json",
            cookie,
            host: "vps.example.com",
            "x-forwarded-proto": "http",
          },
          body: JSON.stringify({ mode: "login" }),
        },
      );
      expect(remoteHttpConnect.status).toBe(403);

      const csrfBlocked = await app.request(
        "http://localhost:3002/api/tailscale/connect",
        {
          method: "POST",
          headers: {
            "content-type": "application/json",
            cookie,
            host: "localhost:3002",
            origin: "https://evil.example.com",
            "x-forwarded-for": "127.0.0.1",
          },
          body: JSON.stringify({ mode: "login" }),
        },
      );
      expect(csrfBlocked.status).toBe(403);

      const scrubRes = await app.request(
        "http://localhost:3002/api/tailscale/connect",
        {
          method: "POST",
          headers: {
            "content-type": "application/json",
            cookie,
            host: "localhost:3002",
            "x-forwarded-for": "127.0.0.1",
          },
          body: JSON.stringify({
            mode: "authkey",
            authKey: "tskey-auth-kFailScrubTest1234",
          }),
        },
      );
      expect(scrubRes.status).toBe(422);
      const scrubBody = (await scrubRes.json()) as { error: string };
      expect(scrubBody.error).not.toContain("tskey-auth-kFailScrubTest1234");

      // Valid authkey connects cleanly and does NOT store key in audit log
      const connectRes = await app.request(
        "http://localhost:3002/api/tailscale/connect",
        {
          method: "POST",
          headers: {
            "content-type": "application/json",
            cookie,
            host: "localhost:3002",
            "x-forwarded-for": "127.0.0.1",
          },
          body: JSON.stringify({
            mode: "authkey",
            authKey: "tskey-auth-kValidConnect1234",
          }),
        },
      );
      expect(connectRes.status).toBe(200);
      expect(store.getSetupState().tailscaleDomain).toBe("my-vps.tail1234.ts.net");
      expect(store.getSetupState().tailscaleServeEnabled).toBe(false);

      // Before Serve is enabled, POST /mcp over Tailscale host is rejected (403)
      const disabledMcp = await app.request("https://my-vps.tail1234.ts.net/mcp", {
        method: "POST",
        headers: {
          "content-type": "application/json",
          authorization: `Bearer ${rawToken}`,
          host: "my-vps.tail1234.ts.net",
          "x-forwarded-proto": "https",
        },
        body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "ping" }),
      });
      expect(disabledMcp.status).toBe(403);

      // 3. Enable Tailscale Serve -> updates setupState, audit log, snippets, and /api/mcp/test
      const serveOnRes = await app.request(
        "https://my-vps.tail1234.ts.net/api/tailscale/serve",
        {
          method: "POST",
          headers: {
            "content-type": "application/json",
            cookie,
            "x-forwarded-proto": "https",
            "x-forwarded-host": "my-vps.tail1234.ts.net:443",
            origin: "https://my-vps.tail1234.ts.net",
          },
          body: JSON.stringify({ enabled: true }),
        },
      );
      expect(serveOnRes.status).toBe(200);
      expect(store.getSetupState().tailscaleServeEnabled).toBe(true);
      expect(
        store
          .listAuditEvents({ limit: 10 })
          .some((ev) => ev.action === "tailscale.serve_enabled"),
      ).toBe(true);

      const tsOnlySnippets = (await (
        await app.request("https://my-vps.tail1234.ts.net/api/mcp/snippets", {
          headers: {
            cookie,
            "x-forwarded-proto": "https",
            "x-forwarded-host": "my-vps.tail1234.ts.net",
          },
        })
      ).json()) as {
        httpsReady: boolean;
        mcpUrl: string;
        primarySource: string;
        customDomain: unknown;
        tailscale: { url: string; httpsReady: boolean } | null;
      };
      expect(tsOnlySnippets.httpsReady).toBe(true);
      expect(tsOnlySnippets.primarySource).toBe("tailscale");
      expect(tsOnlySnippets.mcpUrl).toBe("https://my-vps.tail1234.ts.net/mcp");
      expect(tsOnlySnippets.customDomain).toBeNull();
      expect(tsOnlySnippets.tailscale?.url).toBe("https://my-vps.tail1234.ts.net/mcp");

      const testRes = (await (
        await app.request("https://my-vps.tail1234.ts.net/api/mcp/test", {
          method: "POST",
          headers: {
            cookie,
            "x-forwarded-proto": "https",
            "x-forwarded-host": "my-vps.tail1234.ts.net",
          },
        })
      ).json()) as {
        ok: boolean;
        httpsReady: boolean;
        mcpUrl: string;
        tailscaleMcpUrl: string | null;
      };
      expect(testRes.ok).toBe(true);
      expect(testRes.httpsReady).toBe(true);
      expect(testRes.tailscaleMcpUrl).toBe("https://my-vps.tail1234.ts.net/mcp");

      // 4. POST /mcp over Tailscale Serve HTTPS succeeds with Host, Host:443, matching Origin, rejects bad Origin
      for (const hostHdr of ["my-vps.tail1234.ts.net", "my-vps.tail1234.ts.net:443"]) {
        const mcpRes = await app.request("https://my-vps.tail1234.ts.net/mcp", {
          method: "POST",
          headers: {
            "content-type": "application/json",
            authorization: `Bearer ${rawToken}`,
            "x-forwarded-proto": "https",
            "x-forwarded-host": hostHdr,
            origin: "https://my-vps.tail1234.ts.net",
          },
          body: JSON.stringify({
            jsonrpc: "2.0",
            id: 10,
            method: "tools/call",
            params: { name: "get_setup_status", arguments: {} },
          }),
        });
        expect(mcpRes.status).toBe(200);
        const rpc = (await mcpRes.json()) as {
          result: { content: Array<{ text: string }> };
        };
        const toolPayload = JSON.parse(rpc.result.content[0]!.text) as {
          setup: { tailscaleDomain: string; tailscaleServeEnabled: boolean };
          tailscale: { serveUrl: string };
        };
        expect(toolPayload.setup.tailscaleDomain).toBe("my-vps.tail1234.ts.net");
        expect(toolPayload.setup.tailscaleServeEnabled).toBe(true);
        expect(toolPayload.tailscale.serveUrl).toBe("https://my-vps.tail1234.ts.net");
      }

      const badOriginMcp = await app.request("https://my-vps.tail1234.ts.net/mcp", {
        method: "POST",
        headers: {
          "content-type": "application/json",
          authorization: `Bearer ${rawToken}`,
          "x-forwarded-proto": "https",
          "x-forwarded-host": "my-vps.tail1234.ts.net",
          origin: "https://evil.example.com",
        },
        body: JSON.stringify({ jsonrpc: "2.0", id: 11, method: "ping" }),
      });
      expect(badOriginMcp.status).toBe(403);

      // 5. get_server_info returns tailscale metadata & tailscale dashboardUrl fallback
      const infoRes = await app.request("https://my-vps.tail1234.ts.net/mcp", {
        method: "POST",
        headers: {
          "content-type": "application/json",
          authorization: `Bearer ${rawToken}`,
          "x-forwarded-proto": "https",
          "x-forwarded-host": "my-vps.tail1234.ts.net",
        },
        body: JSON.stringify({
          jsonrpc: "2.0",
          id: 12,
          method: "tools/call",
          params: { name: "get_server_info", arguments: {} },
        }),
      });
      const infoRpc = (await infoRes.json()) as {
        result: { content: Array<{ text: string }> };
      };
      const serverInfo = JSON.parse(infoRpc.result.content[0]!.text) as {
        server: {
          dashboardUrl: string;
          tailscaleDomain: string;
          tailscaleServeEnabled: boolean;
          tailscaleUrl: string;
        };
      };
      expect(serverInfo.server.dashboardUrl).toBe("https://my-vps.tail1234.ts.net");
      expect(serverInfo.server.tailscaleDomain).toBe("my-vps.tail1234.ts.net");
      expect(serverInfo.server.tailscaleServeEnabled).toBe(true);
      expect(serverInfo.server.tailscaleUrl).toBe("https://my-vps.tail1234.ts.net");

      // 6. Both custom domain & Tailscale active -> snippets expose both endpoints
      store.updateSetupState({
        domain: "vps.example.com",
        httpsActive: true,
        tlsStatus: "active",
      });
      const bothSnippets = (await (
        await app.request("https://vps.example.com/api/mcp/snippets", {
          headers: {
            cookie,
            "x-forwarded-proto": "https",
            "x-forwarded-host": "vps.example.com",
          },
        })
      ).json()) as {
        primarySource: string;
        mcpUrl: string;
        customDomain: { url: string; httpsReady: boolean } | null;
        tailscale: { url: string; httpsReady: boolean } | null;
      };
      expect(bothSnippets.primarySource).toBe("domain");
      expect(bothSnippets.mcpUrl).toBe("https://vps.example.com/mcp");
      expect(bothSnippets.customDomain?.url).toBe("https://vps.example.com/mcp");
      expect(bothSnippets.tailscale?.url).toBe("https://my-vps.tail1234.ts.net/mcp");

      // 7. Disable Tailscale Serve -> updates setupState & rejects Tailscale /mcp again
      const serveOffRes = await app.request(
        "https://vps.example.com/api/tailscale/serve",
        {
          method: "POST",
          headers: {
            "content-type": "application/json",
            cookie,
            "x-forwarded-proto": "https",
            "x-forwarded-host": "vps.example.com",
          },
          body: JSON.stringify({ enabled: false }),
        },
      );
      expect(serveOffRes.status).toBe(200);
      expect(store.getSetupState().tailscaleServeEnabled).toBe(false);

      const disabledAfterOff = await app.request(
        "https://my-vps.tail1234.ts.net/mcp",
        {
          method: "POST",
          headers: {
            "content-type": "application/json",
            authorization: `Bearer ${rawToken}`,
            "x-forwarded-proto": "https",
            "x-forwarded-host": "my-vps.tail1234.ts.net",
          },
          body: JSON.stringify({ jsonrpc: "2.0", id: 13, method: "ping" }),
        },
      );
      expect(disabledAfterOff.status).toBe(403);

      // Verify raw Tailscale auth key never appeared in audit log
      const allAuditText = JSON.stringify(store.listAuditEvents({ limit: 50 }));
      expect(allAuditText).not.toContain("tskey-auth-kValidConnect1234");
      expect(allAuditText).not.toContain("tskey-auth-kFailScrubTest1234");
    } finally {
      store.close();
      fs.rmSync(tempDir, { recursive: true, force: true });
    }
  });

  it("reconciles live Tailscale Serve status on /mcp when store predates headless setup", async () => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "vpsagent-ts-sync-"));
    const appsRoot = path.join(tempDir, "apps");
    fs.mkdirSync(appsRoot, { recursive: true });
    const store = new RegistryStore(path.join(tempDir, "registry.db"), {
      encryptionSecret: "tailscale-sync-encryption-secret",
    });
    const { bridge } = createTailscaleMockBridge({
      initialStatus: {
        installed: true,
        serviceActive: true,
        connected: true,
        backendState: "running",
        tailscaleIp: "100.64.0.77",
        tailscaleIps: ["100.64.0.77"],
        hostname: "my-vps",
        dnsName: "my-vps.tail1234.ts.net",
        tailnetName: "tail1234.ts.net",
        magicDnsEnabled: true,
        httpsCertsAvailable: true,
        loginUrl: null,
        serveEnabled: true,
        serveTarget: "http://127.0.0.1:3001",
        serveUrl: "https://my-vps.tail1234.ts.net",
        mcpUrl: "https://my-vps.tail1234.ts.net/mcp",
        serveConflict: null,
        serveConflictDetails: null,
        cliVersion: "1.78.1",
        detail: null,
      },
    });

    const { app } = createVpsAgentApp({
      store,
      bridge,
      appsRoot,
      sessionSecret: "tailscale-sync-session-secret",
      trustProxy: true,
      isLocalListener: false,
      defaultPeerIp: "172.18.0.2",
    });

    try {
      store.setAdminPassphrase("correct-horse-battery");
      store.updateSetupState({
        claimed: true,
        claimedAt: new Date().toISOString(),
        tailscaleDomain: null,
        tailscaleServeEnabled: false,
      });
      const { rawToken } = store.createMcpToken({
        name: "Headless TS Key",
        scope: "read-only",
        allowedSlugs: [],
      });

      const reconciledMcp = await app.request(
        "https://my-vps.tail1234.ts.net/mcp",
        {
          method: "POST",
          headers: {
            "content-type": "application/json",
            authorization: `Bearer ${rawToken}`,
            "x-forwarded-proto": "https",
            "x-forwarded-host": "my-vps.tail1234.ts.net",
          },
          body: JSON.stringify({ jsonrpc: "2.0", id: 14, method: "ping" }),
        },
      );
      expect(reconciledMcp.status).toBe(200);
      expect(store.getSetupState().tailscaleServeEnabled).toBe(true);
      expect(store.getSetupState().tailscaleDomain).toBe("my-vps.tail1234.ts.net");
    } finally {
      store.close();
      fs.rmSync(tempDir, { recursive: true, force: true });
    }
  });

  it("falls back gracefully when host Runtime Bridge returns 404 for Tailscale routes", async () => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "vpsagent-ts-404-"));
    const appsRoot = path.join(tempDir, "apps");
    fs.mkdirSync(appsRoot, { recursive: true });
    const store = new RegistryStore(path.join(tempDir, "registry.db"), {
      encryptionSecret: "tailscale-404-encryption-secret",
    });
    const { bridge } = createTailscaleMockBridge({ unsupported: true });

    const { app } = createVpsAgentApp({
      store,
      bridge,
      appsRoot,
      sessionSecret: "tailscale-404-session-secret",
      trustProxy: false,
      isLocalListener: true,
    });

    try {
      store.setAdminPassphrase("correct-horse-battery");
      store.updateSetupState({
        claimed: true,
        claimedAt: new Date().toISOString(),
      });
      const loginRes = await app.request("http://localhost:3002/api/auth/login", {
        method: "POST",
        headers: {
          "content-type": "application/json",
          host: "localhost:3002",
        },
        body: JSON.stringify({ passphrase: "correct-horse-battery" }),
      });
      const cookie = loginRes.headers.get("set-cookie")!.split(";")[0]!;

      const statusRes = await app.request("/api/tailscale/status", {
        headers: { cookie, host: "localhost:3002" },
      });
      expect(statusRes.status).toBe(200);
      const statusBody = (await statusRes.json()) as {
        bridgeSupported: boolean;
        status: RuntimeTailscaleStatus;
      };
      expect(statusBody.bridgeSupported).toBe(false);
      expect(statusBody.status.detail).toContain("Runtime Bridge needs a one-time update");

      const serveRes = await app.request("/api/tailscale/serve", {
        method: "POST",
        headers: {
          "content-type": "application/json",
          cookie,
          host: "localhost:3002",
        },
        body: JSON.stringify({ enabled: true }),
      });
      expect(serveRes.status).toBe(501);
    } finally {
      store.close();
      fs.rmSync(tempDir, { recursive: true, force: true });
    }
  });
});
