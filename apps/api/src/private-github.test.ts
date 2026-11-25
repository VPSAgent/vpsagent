import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";
import {
  type AppStatus,
  RegistryStore,
  type RuntimeBridge,
  RuntimeBridgeError,
  type RuntimeBuildGitInput,
  type RuntimeInspectGitInput,
} from "@vpsagent/shared";
import { createVpsAgentApp } from "./app.js";

function createControlledMockBridge(options: {
  publicRepos?: Set<string>;
  privateRepoTokens?: Map<string, string>;
  onInspectCall?: (input: RuntimeInspectGitInput) => void;
  onBuildCall?: (input: RuntimeBuildGitInput) => void;
}): RuntimeBridge {
  const publicRepos = options.publicRepos ?? new Set<string>();
  const privateRepoTokens = options.privateRepoTokens ?? new Map<string, string>();
  const statuses: Record<string, AppStatus> = {};

  const checkAccess = (repoUrl: string, token?: string | null) => {
    const cleanUrl = repoUrl.replace(/\/+$/, "");
    if (!token) {
      if (publicRepos.has(cleanUrl)) {
        return;
      }
      throw new RuntimeBridgeError(
        401,
        "Authentication required: this repository appears to be private or does not exist.",
      );
    }
    const expected = privateRepoTokens.get(cleanUrl);
    if (expected && expected === token) {
      return;
    }
    throw new RuntimeBridgeError(
      401,
      `GitHub authentication failed for token ${token}`,
    );
  };

  return {
    async health() {
      return { ok: true, service: "mock-bridge" };
    },
    async getHostStats() {
      return {
        metrics: {
          hostname: "vps-test",
          platform: "linux",
          uptimeSeconds: 1200,
          cpuCount: 2,
          loadAverage1m: 0.2,
          memoryTotalMb: 2048,
          memoryUsedMb: 512,
          memoryUsagePercent: 25,
          collectedAt: new Date().toISOString(),
        },
        disk: {
          totalGb: 20,
          usedGb: 5,
          freeGb: 15,
          usedPercent: 25,
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
    async inspectGitRepo(input) {
      options.onInspectCall?.(input);
      checkAccess(input.gitRepoUrl, input.gitToken);
      const repoName = input.gitRepoUrl.split("/").filter(Boolean).pop() ?? "app";
      return {
        ok: true,
        gitRepoUrl: input.gitRepoUrl,
        resolvedBranch: input.gitBranch ?? "main",
        commitSha: "abcdef1234567890abcdef1234567890abcdef12",
        hasDockerfile: false,
        dockerfilePath: "auto",
        detectedRuntime: "node",
        suggestedPort: 3000,
        suggestedSlug: repoName.toLowerCase().replace(/[^a-z0-9-]+/g, "-"),
        suggestedName: repoName,
        envExampleKeys: [],
        suggestedCompanions: [],
        buildPlanSummary: "Auto-detected Node.js (npm) — runs on port 3000.",
        notes: [],
        usedAuth: Boolean(input.gitToken),
      };
    },
    async buildGitImage(input) {
      options.onBuildCall?.(input);
      checkAccess(input.gitRepoUrl, input.gitToken);
      return {
        ok: true,
        slug: input.slug,
        image: `vpsagent-app-${input.slug}:latest`,
        commitSha: "abcdef1234567890abcdef1234567890abcdef12",
        durationMs: 25,
        buildLogTail: ["Step 1/2 : FROM node:22-alpine", "Built cleanly"],
        detectedRuntime: "node",
        usedAutoDockerfile: true,
        usedAuth: Boolean(input.gitToken),
        suggestedPort: 3000,
        envExampleKeys: [],
      };
    },
    async getLogs(slug) {
      return [`[${slug}] ok`];
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
      delete statuses[slug];
      return { ok: true, slug };
    },
    async getStatuses(slugs) {
      const out: Record<string, AppStatus> = {};
      for (const s of slugs) {
        out[s] = statuses[s] ?? "running";
      }
      return out;
    },
    async inspectWorkload(slug) {
      return {
        slug,
        status: statuses[slug] ?? "running",
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
          contentType: "application/json",
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
          contentType: "application/json",
          error: null,
        },
        reason: null,
      };
    },
    async execInApp() {
      return { exitCode: 0, stdout: "", stderr: "", durationMs: 5, truncated: false };
    },
    async runHostCommand() {
      return { exitCode: 0, stdout: "", stderr: "", durationMs: 5, truncated: false };
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
      return { ok: true, output: "", reclaimedSummary: "0B reclaimed" };
    },
  };
}

describe("Private GitHub Repositories (Credentials API, Smart Resolution, Host Pinning, and MCP)", () => {
  it("supports private GitHub credentials, repo listing, auto-auth deploy/rebuild, and zero token leakage", async () => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "vpsagent-priv-gh-"));
    const appsRoot = path.join(tempDir, "apps");
    fs.mkdirSync(appsRoot, { recursive: true });

    const TOKEN_A = "github_pat_11ALICE_PRIVATE_TOKEN_1111";
    const TOKEN_B = "ghp_ACMEORG_PRIVATE_TOKEN_2222";

    const inspectCalls: Array<{ url: string; token?: string | null }> = [];
    const buildCalls: Array<{ url: string; token?: string | null }> = [];

    const privateRepoTokens = new Map<string, string>([
      ["https://github.com/alice/secret-app", TOKEN_A],
      ["https://github.com/acme-org/billing-api", TOKEN_B],
    ]);

    const bridge = createControlledMockBridge({
      publicRepos: new Set(["https://github.com/vercel/next-demo"]),
      privateRepoTokens,
      onInspectCall: (input) =>
        inspectCalls.push({ url: input.gitRepoUrl, token: input.gitToken }),
      onBuildCall: (input) =>
        buildCalls.push({ url: input.gitRepoUrl, token: input.gitToken }),
    });

    const mockGithubFetch: typeof fetch = async (input, init) => {
      const url = typeof input === "string" ? input : input.toString();
      const headers = new Headers(init?.headers);
      const auth = headers.get("authorization") ?? "";
      const token = auth.replace(/^Bearer\s+/i, "");

      if (url.endsWith("/user")) {
        if (token === TOKEN_A) {
          return new Response(JSON.stringify({ login: "alice" }), {
            status: 200,
            headers: { "content-type": "application/json" },
          });
        }
        if (token === TOKEN_B) {
          return new Response(JSON.stringify({ login: "acme-org" }), {
            status: 200,
            headers: { "content-type": "application/json" },
          });
        }
        return new Response(JSON.stringify({ message: "Bad credentials" }), {
          status: 401,
          headers: { "content-type": "application/json" },
        });
      }

      if (url.includes("/user/repos")) {
        if (token === TOKEN_A) {
          return new Response(
            JSON.stringify([
              {
                full_name: "alice/secret-app",
                name: "secret-app",
                owner: { login: "alice" },
                private: true,
                default_branch: "main",
                html_url: "https://github.com/alice/secret-app",
                description: "Private Alice service",
                updated_at: "2026-11-25T10:00:00Z",
              },
              {
                full_name: "alice/public-blog",
                name: "public-blog",
                owner: { login: "alice" },
                private: false,
                default_branch: "main",
                html_url: "https://github.com/alice/public-blog",
                description: "Public blog",
                updated_at: "2026-11-24T10:00:00Z",
              },
            ]),
            { status: 200, headers: { "content-type": "application/json" } },
          );
        }
        if (token === TOKEN_B) {
          return new Response(
            JSON.stringify([
              {
                full_name: "acme-org/billing-api",
                name: "billing-api",
                owner: { login: "acme-org" },
                private: true,
                default_branch: "production",
                html_url: "https://github.com/acme-org/billing-api",
                description: "Acme internal billing API",
                updated_at: "2026-11-25T12:00:00Z",
              },
            ]),
            { status: 200, headers: { "content-type": "application/json" } },
          );
        }
        return new Response(JSON.stringify({ message: "Unauthorized" }), {
          status: 401,
        });
      }

      return new Response("Not Found", { status: 404 });
    };

    const store = new RegistryStore(path.join(tempDir, "registry.db"), {
      encryptionSecret: "priv-gh-encryption-secret-32-bytes",
    });

    const { app } = createVpsAgentApp({
      store,
      bridge,
      appsRoot,
      sessionSecret: "priv-gh-session-secret-32-bytes",
      trustProxy: true,
      isLocalListener: false,
      defaultPeerIp: "172.18.0.2",
      readinessTimeoutSeconds: 5,
      readinessPollIntervalMs: 10,
      mcpDeployGraceMs: 2000,
      lookupFn: async () => [{ address: "140.82.121.4", family: 4 }],
      githubFetchFn: mockGithubFetch,
    });

    try {
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
      const cookie = loginRes.headers.get("set-cookie")!.split(";")[0]!;

      // Create an unrestricted safe-auto-deploy pass + an app-locked pass + an approval-required pass
      const safeTokRes = await app.request(
        "https://vps.example.com/api/mcp/tokens",
        {
          method: "POST",
          headers: {
            "content-type": "application/json",
            cookie,
            host: "vps.example.com",
            "x-forwarded-proto": "https",
          },
          body: JSON.stringify({
            name: "Main AI Agent",
            scope: "safe-auto-deploy",
          }),
        },
      );
      const safeRawToken = ((await safeTokRes.json()) as { rawToken: string })
        .rawToken;

      const lockedTokRes = await app.request(
        "https://vps.example.com/api/mcp/tokens",
        {
          method: "POST",
          headers: {
            "content-type": "application/json",
            cookie,
            host: "vps.example.com",
            "x-forwarded-proto": "https",
          },
          body: JSON.stringify({
            name: "Locked Agent",
            scope: "safe-auto-deploy",
            allowedSlugs: ["only-this-app"],
          }),
        },
      );
      const lockedRawToken = (
        (await lockedTokRes.json()) as { rawToken: string }
      ).rawToken;

      const askTokRes = await app.request(
        "https://vps.example.com/api/mcp/tokens",
        {
          method: "POST",
          headers: {
            "content-type": "application/json",
            cookie,
            host: "vps.example.com",
            "x-forwarded-proto": "https",
          },
          body: JSON.stringify({
            name: "Ask-First Agent",
            scope: "approval-required",
          }),
        },
      );
      const askRawToken = ((await askTokRes.json()) as { rawToken: string })
        .rawToken;

      const callMcp = async (
        bearer: string,
        method: string,
        params: Record<string, unknown> = {},
      ) => {
        const res = await app.request("https://vps.example.com/mcp", {
          method: "POST",
          headers: {
            "content-type": "application/json",
            host: "vps.example.com",
            "x-forwarded-proto": "https",
            authorization: `Bearer ${bearer}`,
          },
          body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
        });
        expect(res.status).toBe(200);
        return (await res.json()) as {
          result: {
            isError?: boolean;
            content?: Array<{ text: string }>;
          };
        };
      };

      // 1. Before connecting GitHub: list_github_repos & private inspect guide user to githubSettingsUrl
      const listBefore = await callMcp(safeRawToken, "tools/call", {
        name: "list_github_repos",
        arguments: {},
      });
      const listBeforeJson = JSON.parse(listBefore.result.content![0]!.text) as {
        connected: boolean;
        githubSettingsUrl: string;
      };
      expect(listBeforeJson.connected).toBe(false);
      expect(listBeforeJson.githubSettingsUrl).toBe(
        "https://vps.example.com/#keys/github",
      );

      const inspectBefore = await callMcp(safeRawToken, "tools/call", {
        name: "inspect_git_repo",
        arguments: { gitRepoUrl: "https://github.com/alice/secret-app" },
      });
      expect(inspectBefore.result.isError).toBe(true);
      expect(inspectBefore.result.content![0]!.text).toContain(
        "https://vps.example.com/#keys/github",
      );

      // 2. Reject invalid GitHub token or cross-origin / plaintext HTTP requests
      const badTokenRes = await app.request(
        "https://vps.example.com/api/git/credentials",
        {
          method: "POST",
          headers: {
            "content-type": "application/json",
            cookie,
            host: "vps.example.com",
            "x-forwarded-proto": "https",
          },
          body: JSON.stringify({ token: "github_pat_wrong_invalid_token_0000" }),
        },
      );
      expect(badTokenRes.status).toBe(401);

      const csrfBlockedRes = await app.request(
        "https://vps.example.com/api/git/credentials",
        {
          method: "POST",
          headers: {
            "content-type": "application/json",
            cookie,
            host: "vps.example.com",
            "x-forwarded-proto": "https",
            "sec-fetch-site": "same-site",
          },
          body: JSON.stringify({ token: TOKEN_A }),
        },
      );
      expect(csrfBlockedRes.status).toBe(403);

      // 3. Connect both GitHub credentials cleanly
      const addA = await app.request(
        "https://vps.example.com/api/git/credentials",
        {
          method: "POST",
          headers: {
            "content-type": "application/json",
            cookie,
            host: "vps.example.com",
            "x-forwarded-proto": "https",
          },
          body: JSON.stringify({ token: TOKEN_A }),
        },
      );
      expect(addA.status).toBe(201);
      const addAJson = (await addA.json()) as {
        credential: { id: string; label: string; isDefault: boolean; tokenHint: string };
        accountLogin: string;
        accessibleRepoCount: number;
      };
      expect(addAJson.accountLogin).toBe("alice");
      expect(addAJson.accessibleRepoCount).toBe(2);
      expect(addAJson.credential.isDefault).toBe(true);
      expect(addAJson.credential.tokenHint).toBe("github_pat_••••1111");
      expect(JSON.stringify(addAJson)).not.toContain(TOKEN_A);

      const addB = await app.request(
        "https://vps.example.com/api/git/credentials",
        {
          method: "POST",
          headers: {
            "content-type": "application/json",
            cookie,
            host: "vps.example.com",
            "x-forwarded-proto": "https",
          },
          body: JSON.stringify({ label: "Acme Org PAT", token: TOKEN_B }),
        },
      );
      expect(addB.status).toBe(201);
      const credBId = (
        (await addB.json()) as { credential: { id: string } }
      ).credential.id;

      // Test & list credentials (never return raw tokens)
      const listCredsRes = await app.request(
        "https://vps.example.com/api/git/credentials",
        {
          headers: {
            cookie,
            host: "vps.example.com",
            "x-forwarded-proto": "https",
          },
        },
      );
      const listCredsText = await listCredsRes.text();
      expect(listCredsText).not.toContain(TOKEN_A);
      expect(listCredsText).not.toContain(TOKEN_B);

      const testCredB = await app.request(
        `https://vps.example.com/api/git/credentials/${credBId}/test`,
        {
          method: "POST",
          headers: {
            "content-type": "application/json",
            cookie,
            host: "vps.example.com",
            "x-forwarded-proto": "https",
          },
        },
      );
      expect(testCredB.status).toBe(200);
      expect(((await testCredB.json()) as { accessibleRepoCount: number }).accessibleRepoCount).toBe(1);

      // 4. REST /api/git/repos lists & filters private + public repos
      const reposRes = await app.request(
        "https://vps.example.com/api/git/repos?query=billing",
        {
          headers: {
            cookie,
            host: "vps.example.com",
            "x-forwarded-proto": "https",
          },
        },
      );
      expect(reposRes.status).toBe(200);
      const reposJson = (await reposRes.json()) as {
        connected: boolean;
        repos: Array<{ fullName: string; private: boolean; credentialId: string }>;
      };
      expect(reposJson.connected).toBe(true);
      expect(reposJson.repos).toHaveLength(1);
      expect(reposJson.repos[0]!.fullName).toBe("acme-org/billing-api");
      expect(reposJson.repos[0]!.private).toBe(true);
      expect(reposJson.repos[0]!.credentialId).toBe(credBId);

      // 5. MCP get_server_info + list_github_repos (blocked for app-locked pass)
      const infoRes = await callMcp(safeRawToken, "tools/call", {
        name: "get_server_info",
        arguments: {},
      });
      const infoRawText = infoRes.result.content![0]!.text;
      expect(infoRawText).not.toContain(TOKEN_A);
      expect(infoRawText).not.toContain(TOKEN_B);
      const infoJson = JSON.parse(infoRawText) as {
        server: {
          privateReposSupported: boolean;
          githubConnected: boolean;
          githubCredentials: Array<{ id: string }>;
          githubSettingsUrl: string;
        };
      };
      expect(infoJson.server.privateReposSupported).toBe(true);
      expect(infoJson.server.githubConnected).toBe(true);
      expect(infoJson.server.githubCredentials).toHaveLength(2);
      expect(infoJson.server.githubSettingsUrl).toBe(
        "https://vps.example.com/#keys/github",
      );

      const lockedList = await callMcp(lockedRawToken, "tools/call", {
        name: "list_github_repos",
        arguments: {},
      });
      expect(lockedList.result.isError).toBe(true);

      const mcpList = await callMcp(safeRawToken, "tools/call", {
        name: "list_github_repos",
        arguments: { limit: 10 },
      });
      const mcpListJson = JSON.parse(mcpList.result.content![0]!.text) as {
        connected: boolean;
        repos: Array<{ fullName: string }>;
      };
      expect(mcpListJson.connected).toBe(true);
      expect(mcpListJson.repos.map((r) => r.fullName)).toContain(
        "alice/secret-app",
      );

      // 6. Smart auto-auth: public GitHub repo clones anonymously first without sending PAT
      inspectCalls.length = 0;
      const pubInspect = await callMcp(safeRawToken, "tools/call", {
        name: "inspect_git_repo",
        arguments: { gitRepoUrl: "https://github.com/vercel/next-demo" },
      });
      expect(pubInspect.result.isError).toBe(false);
      expect(inspectCalls).toHaveLength(1);
      expect(inspectCalls[0]!.token).toBeUndefined();

      // 7. Non-github.com URLs NEVER receive saved GitHub tokens & reject explicit gitCredentialId
      inspectCalls.length = 0;
      const nonGhInspect = await callMcp(safeRawToken, "tools/call", {
        name: "inspect_git_repo",
        arguments: { gitRepoUrl: "https://gitlab.com/someone/private-repo" },
      });
      expect(nonGhInspect.result.isError).toBe(true);
      expect(inspectCalls).toHaveLength(1);
      expect(inspectCalls[0]!.token).toBeUndefined();

      const nonGhExplicit = await callMcp(safeRawToken, "tools/call", {
        name: "inspect_git_repo",
        arguments: {
          gitRepoUrl: "https://gitlab.com/someone/private-repo",
          gitCredentialId: credBId,
        },
      });
      expect(nonGhExplicit.result.isError).toBe(true);
      expect(nonGhExplicit.result.content![0]!.text).toContain("https://github.com");

      // 8. Private repo auto-resolves matching owner token (TOKEN_B for acme-org) and deploys + rebuilds directly!
      buildCalls.length = 0;
      const privDeploy = await callMcp(safeRawToken, "tools/call", {
        name: "deploy_app",
        arguments: {
          slug: "billing-api",
          name: "Billing API",
          sourceType: "git",
          gitRepoUrl: "https://github.com/acme-org/billing-api",
        },
      });
      expect(privDeploy.result.isError).toBe(false);
      // Should have tried anonymous -> 401 -> TOKEN_B (owner match!) first
      expect(buildCalls[0]!.token).toBeUndefined();
      expect(buildCalls[1]!.token).toBe(TOKEN_B);

      const savedApp = store.getApp("billing-api");
      expect(savedApp?.gitCredentialId).toBe(credBId);
      expect(store.getGitCredential(credBId)?.lastUsedAt).not.toBeNull();

      // Rebuild reuses stored credBId immediately (only 1 build call, directly with TOKEN_B)
      buildCalls.length = 0;
      const rebuildRes = await callMcp(safeRawToken, "tools/call", {
        name: "rebuild_app",
        arguments: { slug: "billing-api" },
      });
      expect(rebuildRes.result.isError).toBe(false);
      expect(buildCalls).toHaveLength(1);
      expect(buildCalls[0]!.token).toBe(TOKEN_B);

      // 9. Approval-required deploy never leaks GitHub token into approval queue or audit log
      const queuedDeploy = await callMcp(askRawToken, "tools/call", {
        name: "deploy_app",
        arguments: {
          slug: "alice-secret",
          name: "Alice Secret",
          sourceType: "git",
          gitRepoUrl: "https://github.com/alice/secret-app",
          gitCredentialId: addAJson.credential.id,
        },
      });
      const queuedJson = JSON.parse(queuedDeploy.result.content![0]!.text) as {
        status: string;
        approvalId: string;
      };
      expect(queuedJson.status).toBe("pending_approval");
      const allApprovalsText = JSON.stringify(store.listApprovals());
      const allAuditText = JSON.stringify(store.listAuditEvents());
      expect(allApprovalsText).not.toContain(TOKEN_A);
      expect(allAuditText).not.toContain(TOKEN_A);

      // 10. Deleting credB clears billing-api.gitCredentialId & promotes remaining default
      const setDefRes = await app.request(
        `https://vps.example.com/api/git/credentials/${credBId}/default`,
        {
          method: "POST",
          headers: {
            "content-type": "application/json",
            cookie,
            host: "vps.example.com",
            "x-forwarded-proto": "https",
          },
        },
      );
      expect(setDefRes.status).toBe(200);
      expect(store.getDefaultGitCredential()?.id).toBe(credBId);

      const delCredB = await app.request(
        `https://vps.example.com/api/git/credentials/${credBId}`,
        {
          method: "DELETE",
          headers: {
            cookie,
            host: "vps.example.com",
            "x-forwarded-proto": "https",
          },
        },
      );
      expect(delCredB.status).toBe(200);
      expect(store.getApp("billing-api")?.gitCredentialId).toBeNull();
      expect(store.getDefaultGitCredential()?.id).toBe(addAJson.credential.id);
    } finally {
      store.close();
      fs.rmSync(tempDir, { recursive: true, force: true });
    }
  });
});
