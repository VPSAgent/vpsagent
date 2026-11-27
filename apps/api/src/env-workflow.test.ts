import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";
import {
  RegistryStore,
  type RuntimeBridge,
  type RuntimeBuildGitInput,
} from "@vpsagent/shared";
import { createVpsAgentApp } from "./app.js";

function createRecordingBridge() {
  const buildCalls: RuntimeBuildGitInput[] = [];
  const bridge: RuntimeBridge = {
    async health() {
      return { ok: true, service: "test-bridge" };
    },
    async getHostStats() {
      return {
        metrics: {
          hostname: "test-vps",
          platform: "linux",
          uptimeSeconds: 100,
          cpuCount: 2,
          loadAverage1m: 0.1,
          totalMemoryMb: 2048,
          freeMemoryMb: 1024,
          memoryUsagePercent: 50,
          collectedAt: new Date().toISOString(),
        },
        disk: {
          path: "/",
          totalGb: 40,
          usedGb: 10,
          availableGb: 30,
          usedPercent: 25,
        },
      };
    },
    async lifecycle(slug, action) {
      return {
        slug,
        status: action === "stop" ? "stopped" : "running",
      };
    },
    async buildGitImage(input) {
      buildCalls.push(input);
      return {
        ok: true,
        slug: input.slug,
        image: `vpsagent-app-${input.slug}:latest`,
        commitSha: "deadbeef1234",
        durationMs: 120,
        buildLogTail: ["Successfully built"],
        detectedRuntime: "nextjs",
        usedAutoDockerfile: true,
        suggestedPort: 3000,
        envExampleKeys: [],
        previousImageSaved: true,
      };
    },
    async getLogs() {
      return [];
    },
    async routeCaddy(input) {
      return { ok: true, slug: input.slug, domain: input.domain, routed: Boolean(input.domain) };
    },
    async routeCoreDomain(input) {
      return {
        ok: true,
        domain: input.domain,
        acmeEmail: input.acmeEmail ?? null,
        httpsActive: Boolean(input.domain),
        tlsStatus: input.domain ? "active" : "inactive",
        tlsError: null,
      };
    },
    async removeWorkload(slug) {
      return { ok: true, slug };
    },
    async getStatuses(slugs) {
      return Object.fromEntries(slugs.map((s) => [s, "running" as const]));
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
        httpProbe: {
          attempted: true,
          ok: true,
          statusCode: 200,
          latencyMs: 5,
          contentType: "text/html",
          error: null,
        },
      };
    },
    async waitForReadiness(slug) {
      return {
        ready: true,
        slug,
        status: "running",
        attempts: 1,
        elapsedMs: 10,
        httpProbe: {
          attempted: true,
          ok: true,
          statusCode: 200,
          latencyMs: 5,
          contentType: "text/html",
          error: null,
        },
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
      return { path: input.path, content: "", sizeBytes: 0, totalLines: 0, startLine: 1, endLine: 0, truncated: false };
    },
    async writeHostFile(input) {
      return { ok: true, path: input.path, bytesWritten: input.content.length, appended: false };
    },
    async deleteHostFile(input) {
      return { ok: true, path: input.path, deletedType: "file" };
    },
    async listHostServices() {
      return { services: [], truncated: false };
    },
    async manageHostService(input) {
      return { ok: true, service: input.service, action: input.action, activeState: "active", output: "" };
    },
    async dockerCleanup() {
      return { ok: true, output: "", reclaimedSummary: "0B" };
    },
  };
  return { bridge, buildCalls };
}

describe("App env workflow & build-time public buildArgs", () => {
  it("supports request_app_env checklist, bulk env save with auto-pruning, and forwards only public buildArgs on rebuild", async () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "vpsagent-env-wf-"));
    const dbPath = path.join(tmpDir, "registry.db");
    const appsRoot = path.join(tmpDir, "apps");
    fs.mkdirSync(appsRoot, { recursive: true });

    const store = new RegistryStore(dbPath);
    const { bridge, buildCalls } = createRecordingBridge();
    const { app } = createVpsAgentApp({
      store,
      bridge,
      appsRoot,
      sessionSecret: "test-session-secret-0123456789abcdef",
      claimToken: "test-claim-token",
      isLocalListener: true,
      lookupFn: async () => [{ address: "93.184.216.34", family: 4 }],
    });

    try {
      // Claim dashboard & obtain session cookie
      const claimRes = await app.request("http://127.0.0.1/api/setup/claim", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          claimToken: "test-claim-token",
          passphrase: "super-strong-passphrase-123",
        }),
      });
      expect(claimRes.status).toBe(200);
      const cookie = claimRes.headers.get("set-cookie")?.split(";")[0] ?? "";
      expect(cookie).toContain("vpsagent_session=");

      // Create a Git app
      store.upsertApp({
        slug: "saas-web",
        name: "SaaS Web",
        sourceType: "git",
        image: "vpsagent-app-saas-web:latest",
        gitRepoUrl: "https://github.com/acme/saas-web",
        gitBranch: "main",
        dockerfilePath: "auto",
        domain: null,
        folderPath: path.join(appsRoot, "saas-web"),
        internalPort: 3000,
        status: "running",
        cpuLimit: "0.5",
        memoryLimitMb: 512,
        companions: [],
      });

      // Create MCP tokens (read-only, approval-required, & safe-auto-deploy)
      const roToken = store.createMcpToken({
        name: "Reader",
        scope: "read-only",
      });
      const approvalToken = store.createMcpToken({
        name: "Careful Agent",
        scope: "approval-required",
      });
      const deployToken = store.createMcpToken({
        name: "Claude Builder",
        scope: "safe-auto-deploy",
      });

      const callMcp = async (
        token: string,
        toolName: string,
        args: Record<string, unknown>,
      ) => {
        const res = await app.request("http://127.0.0.1/mcp", {
          method: "POST",
          headers: {
            "content-type": "application/json",
            authorization: `Bearer ${token}`,
          },
          body: JSON.stringify({
            jsonrpc: "2.0",
            id: 1,
            method: "tools/call",
            params: { name: toolName, arguments: args },
          }),
        });
        expect(res.status).toBe(200);
        const body = (await res.json()) as {
          result: { isError?: boolean; content: Array<{ text: string }> };
        };
        const text = body.result.content[0]!.text;
        const isError = Boolean(body.result.isError);
        let data: Record<string, unknown> = {};
        if (!isError) {
          data = JSON.parse(text) as Record<string, unknown>;
        }
        return { isError, text, data };
      };

      // Read-only pass cannot create env checklists
      const roRes = await callMcp(roToken.rawToken, "request_app_env", {
        slug: "saas-web",
        keys: [{ key: "POLAR_ACCESS_TOKEN" }],
      });
      expect(roRes.isError).toBe(true);

      // Safe-auto-deploy pass creates a checklist without any secret values
      const reqRes = await callMcp(deployToken.rawToken, "request_app_env", {
        slug: "saas-web",
        note: "Needed for Supabase auth and Polar billing",
        keys: [
          {
            key: "NEXT_PUBLIC_SUPABASE_URL",
            description: "Supabase project URL",
          },
          {
            key: "NEXT_PUBLIC_SUPABASE_ANON_KEY",
            description: "Supabase anon public key",
          },
          {
            key: "SUPABASE_SERVICE_ROLE_KEY",
            description: "Supabase service role secret",
          },
          {
            key: "POLAR_ACCESS_TOKEN",
            description: "Polar organization token",
          },
        ],
      });
      expect(reqRes.isError).toBe(false);
      expect(reqRes.data.status).toBe("awaiting_user_input");
      expect(reqRes.data.rebuildRecommended).toBe(true);
      expect(String(reqRes.data.envSettingsUrl)).toContain("/#apps/saas-web/env");

      // An approval-required pass cannot overwrite an existing pending checklist
      const overwriteRes = await callMcp(
        approvalToken.rawToken,
        "request_app_env",
        {
          slug: "saas-web",
          keys: [{ key: "OTHER_KEY" }],
        },
      );
      expect(overwriteRes.isError).toBe(true);
      expect(overwriteRes.text).toMatch(/already has a pending Variables checklist/i);

      // Multiline build-time public vars fail clearly on save instead of being silently omitted
      const multilineRes = await app.request(
        "http://127.0.0.1/api/apps/saas-web/env",
        {
          method: "PUT",
          headers: { "content-type": "application/json", cookie },
          body: JSON.stringify({
            vars: [
              {
                key: "NEXT_PUBLIC_BANNER",
                value: "Hello\nWorld",
              },
            ],
            deleteKeys: [],
          }),
        },
      );
      expect(multilineRes.status).toBe(400);

      // Dashboard GET /api/apps/saas-web/env returns the pending checklist
      const getEnvRes = await app.request(
        "http://127.0.0.1/api/apps/saas-web/env",
        {
          headers: { cookie },
        },
      );
      expect(getEnvRes.status).toBe(200);
      const getEnvBody = (await getEnvRes.json()) as {
        envRequest: { keys: Array<{ key: string }>; note: string } | null;
      };
      expect(getEnvBody.envRequest?.keys.map((k) => k.key)).toEqual([
        "NEXT_PUBLIC_SUPABASE_URL",
        "NEXT_PUBLIC_SUPABASE_ANON_KEY",
        "SUPABASE_SERVICE_ROLE_KEY",
        "POLAR_ACCESS_TOKEN",
      ]);

      // Dashboard bulk PUT saves all 4 vars at once, clears checklist, and flags needsRebuild
      const putEnvRes = await app.request(
        "http://127.0.0.1/api/apps/saas-web/env",
        {
          method: "PUT",
          headers: { "content-type": "application/json", cookie },
          body: JSON.stringify({
            vars: [
              {
                key: "NEXT_PUBLIC_SUPABASE_URL",
                value: "https://demo.supabase.co",
              },
              {
                key: "NEXT_PUBLIC_SUPABASE_ANON_KEY",
                value: "sb_anon_public_123",
              },
              {
                key: "NEXT_PUBLIC_SECRET_MARKED",
                value: "do-not-bake-into-docker",
                isSecret: true,
              },
              {
                key: "SUPABASE_SERVICE_ROLE_KEY",
                value: "sb_service_secret_999",
              },
              {
                key: "POLAR_ACCESS_TOKEN",
                value: "polar_oat_secret_888",
              },
            ],
            deleteKeys: [],
          }),
        },
      );
      expect(putEnvRes.status).toBe(200);
      const putEnvBody = (await putEnvRes.json()) as {
        needsRebuild: boolean;
        changedBuildTimeKeys: string[];
        envRequest: unknown;
      };
      expect(putEnvBody.needsRebuild).toBe(true);
      expect(putEnvBody.changedBuildTimeKeys).toEqual([
        "NEXT_PUBLIC_SUPABASE_URL",
        "NEXT_PUBLIC_SUPABASE_ANON_KEY",
        "NEXT_PUBLIC_SECRET_MARKED",
      ]);
      expect(putEnvBody.envRequest).toBeNull();

      // MCP update_app_env preserves top-level slug alongside needsRebuild
      const mcpUpdateRes = await callMcp(deployToken.rawToken, "update_app_env", {
        slug: "saas-web",
        vars: [{ key: "NEXT_PUBLIC_APP_ENV", value: "production" }],
      });
      expect(mcpUpdateRes.isError).toBe(false);
      const mcpUpdateResult = mcpUpdateRes.data.result as Record<string, unknown>;
      expect(mcpUpdateResult.slug).toBe("saas-web");
      expect(mcpUpdateResult.needsRebuild).toBe(true);

      // Rebuilding the Git app passes ONLY non-secret public build-time vars as buildArgs (never secrets!)
      const rebuildRes = await app.request(
        "http://127.0.0.1/api/apps/saas-web/rebuild",
        {
          method: "POST",
          headers: { cookie },
        },
      );
      expect(rebuildRes.status).toBe(200);
      expect(buildCalls).toHaveLength(1);
      expect(buildCalls[0]?.buildArgs).toEqual({
        NEXT_PUBLIC_APP_ENV: "production",
        NEXT_PUBLIC_SUPABASE_URL: "https://demo.supabase.co",
        NEXT_PUBLIC_SUPABASE_ANON_KEY: "sb_anon_public_123",
      });
      expect(buildCalls[0]?.buildArgs).not.toHaveProperty(
        "NEXT_PUBLIC_SECRET_MARKED",
      );
      expect(buildCalls[0]?.buildArgs).not.toHaveProperty(
        "SUPABASE_SERVICE_ROLE_KEY",
      );
      expect(buildCalls[0]?.buildArgs).not.toHaveProperty("POLAR_ACCESS_TOKEN");

      // Owner can explicitly opt a secret-marked NEXT_PUBLIC_* key into build-time forwarding
      const visRes = await app.request(
        "http://127.0.0.1/api/apps/saas-web/env/NEXT_PUBLIC_SECRET_MARKED/visibility",
        {
          method: "PATCH",
          headers: { "content-type": "application/json", cookie },
          body: JSON.stringify({ isSecret: false }),
        },
      );
      expect(visRes.status).toBe(200);
      const visBody = (await visRes.json()) as { needsRebuild: boolean };
      expect(visBody.needsRebuild).toBe(true);
      expect(store.getAppPublicEnvMapForBuild("saas-web")).toHaveProperty(
        "NEXT_PUBLIC_SECRET_MARKED",
      );

      // Launching a new Git app with a multiline NEXT_PUBLIC_* var rejects synchronously with 400
      const badLaunchRes = await app.request(
        "http://127.0.0.1/api/apps?async=true",
        {
          method: "POST",
          headers: { "content-type": "application/json", cookie },
          body: JSON.stringify({
            slug: "bad-launch",
            name: "Bad Launch",
            sourceType: "git",
            gitRepoUrl: "https://github.com/acme/bad-launch",
            envVars: { NEXT_PUBLIC_BANNER: "Hello\nWorld" },
          }),
        },
      );
      expect(badLaunchRes.status).toBe(400);
      expect(store.getApp("bad-launch")).toBeNull();

      // Companion envKey with public frontend prefix is rejected to prevent leaking DB credentials
      const badCompRes = await app.request(
        "http://127.0.0.1/api/apps?async=true",
        {
          method: "POST",
          headers: { "content-type": "application/json", cookie },
          body: JSON.stringify({
            slug: "bad-comp",
            name: "Bad Comp",
            sourceType: "git",
            gitRepoUrl: "https://github.com/acme/bad-comp",
            companions: [{ type: "postgres", envKey: "NEXT_PUBLIC_DB_URL" }],
          }),
        },
      );
      expect(badCompRes.status).toBe(400);
      expect(store.getApp("bad-comp")).toBeNull();

      // Unrelated runtime env edits succeed even if a legacy multiline public var exists in DB
      store.setAppEnvVars("saas-web", [
        { key: "NEXT_PUBLIC_LEGACY_MULTI", value: "line1\nline2", isSecret: false },
      ]);
      const runtimeEditRes = await app.request(
        "http://127.0.0.1/api/apps/saas-web/env",
        {
          method: "PUT",
          headers: { "content-type": "application/json", cookie },
          body: JSON.stringify({
            vars: [{ key: "LOG_LEVEL", value: "debug" }],
            deleteKeys: [],
          }),
        },
      );
      expect(runtimeEditRes.status).toBe(200);
    } finally {
      store.close();
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });
});
