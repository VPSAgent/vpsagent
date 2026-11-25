import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { isSlugAllowedForToken, requiresApprovalForScope } from "./mcp.js";
import { RegistryStore } from "./store.js";

describe("RegistryStore (SQLite WAL)", () => {
  let store: RegistryStore;

  beforeEach(() => {
    store = new RegistryStore(":memory:", {
      encryptionSecret: "test-encryption-secret-32-bytes-long",
    });
  });

  afterEach(() => {
    store.close();
  });

  it("creates, updates, lists, and deletes apps with companions", () => {
    const app = store.upsertApp({
      slug: "blog-api",
      name: "Blog API",
      sourceType: "git",
      image: null,
      gitRepoUrl: "https://github.com/acme/blog-api.git",
      gitBranch: "main",
      dockerfilePath: "Dockerfile",
      domain: "blog.example.com",
      folderPath: "/apps/blog-api",
      internalPort: 3000,
      status: "building",
      cpuLimit: "1.0",
      memoryLimitMb: 512,
      companions: [
        { type: "postgres", version: "16-alpine" },
        { type: "redis", version: "7-alpine" },
      ],
    });

    expect(app.slug).toBe("blog-api");
    expect(app.companions).toHaveLength(2);
    expect(store.listApps()).toHaveLength(1);

    const running = store.updateAppStatus("blog-api", "running");
    expect(running?.status).toBe("running");

    const updatedDomain = store.updateAppDomain("blog-api", "api.example.com");
    expect(updatedDomain?.domain).toBe("api.example.com");

    expect(store.deleteApp("blog-api")).toBe(true);
    expect(store.getApp("blog-api")).toBeNull();
  });

  it("encrypts app .env vars at rest and masks them in list views", () => {
    store.upsertApp({
      slug: "shop",
      name: "Shop",
      sourceType: "image",
      image: "ghcr.io/acme/shop:latest",
      gitRepoUrl: null,
      gitBranch: null,
      dockerfilePath: "Dockerfile",
      domain: null,
      folderPath: "/apps/shop",
      internalPort: 8080,
      status: "running",
      cpuLimit: "0.5",
      memoryLimitMb: 256,
      companions: [],
    });

    const entries = store.setAppEnvVars("shop", [
      { key: "STRIPE_SECRET_KEY", value: "sk_live_verysecret123" },
      { key: "NODE_ENV", value: "production", isSecret: false },
    ]);

    expect(entries).toHaveLength(2);
    const secretEntry = entries.find((e) => e.key === "STRIPE_SECRET_KEY");
    expect(secretEntry?.isSecret).toBe(true);
    expect(secretEntry?.maskedValue).toBe("••••••••");
    expect(secretEntry?.maskedValue).not.toContain("verysecret");

    const runtimeMap = store.getAppEnvMapForRuntime("shop");
    expect(runtimeMap.STRIPE_SECRET_KEY).toBe("sk_live_verysecret123");
    expect(runtimeMap.NODE_ENV).toBe("production");

    expect(store.deleteAppEnvVar("shop", "NODE_ENV")).toBe(true);
    expect(store.listAppEnvVars("shop")).toHaveLength(1);
  });

  it("creates, verifies, and revokes scoped MCP tokens", () => {
    const { record, rawToken } = store.createMcpToken({
      name: "Claude Code",
      scope: "approval-required",
    });

    expect(rawToken.startsWith("vpsmcp_")).toBe(true);
    expect(record.scope).toBe("approval-required");

    const verified = store.verifyMcpToken(rawToken);
    expect(verified?.id).toBe(record.id);
    expect(verified?.lastUsedAt).not.toBeNull();

    expect(store.revokeMcpToken(record.id)).toBe(true);
    expect(store.verifyMcpToken(rawToken)).toBeNull();
  });

  it("blocks read-only tokens from creating mutation approvals and enforces single execution", () => {
    expect(() =>
      store.createApproval({
        action: "deploy_app",
        targetSlug: "demo",
        summary: "Deploy demo",
        payload: { image: "nginx:alpine" },
        requestedBy: "ReadOnlyAgent",
        tokenScope: "read-only",
      }),
    ).toThrow(/Read-only tokens are blocked/);

    const req = store.createApproval({
      action: "deploy_app",
      targetSlug: "demo",
      summary: "Deploy demo with API_KEY=secret123",
      payload: { image: "nginx:alpine", api_key: "secret123" },
      requestedBy: "Cursor",
      tokenScope: "approval-required",
      riskLevel: "medium",
    });

    expect(req.summary).not.toContain("secret123");
    expect(req.payload.api_key).toBe("[REDACTED]");
    expect(req.status).toBe("pending");

    const approved = store.decideApproval(req.id, "approved", "admin", "Looks good");
    expect(approved?.status).toBe("approved");

    const claimedFirst = store.claimApprovalForExecution(req.id, "worker-1");
    expect(claimedFirst).not.toBeNull();
    const claimedSecond = store.claimApprovalForExecution(req.id, "worker-2");
    expect(claimedSecond).toBeNull();

    const completed = store.completeApprovalExecution(
      req.id,
      "executed",
      "Deployed demo successfully",
    );
    expect(completed?.status).toBe("executed");
  });

  it("redacts secrets in audit logs", () => {
    const ev = store.recordAudit({
      actor: "agent",
      action: "deploy_app",
      targetSlug: "demo",
      summary: "Used token vpsmcp_abcdef1234567890xyz to deploy",
      riskLevel: "medium",
    });

    expect(ev.summary).not.toContain("vpsmcp_abcdef1234567890xyz");
    expect(ev.summary).toContain("[REDACTED]");
    expect(store.listAuditEvents({ query: "deploy" })).toHaveLength(1);
  });

  it("manages 2-step first-boot setup state and hashed admin passphrase", () => {
    expect(store.getSetupState().claimed).toBe(false);

    store.setAdminPassphrase("correct-horse-battery");
    expect(store.verifyAdminPassphrase("correct-horse-battery")).toBe(true);
    expect(store.verifyAdminPassphrase("wrong-passphrase")).toBe(false);

    const updated = store.updateSetupState({
      claimed: true,
      domain: "vps.example.com",
      appsBaseDomain: "apps.example.com",
      acmeEmail: "owner@example.com",
      claimedAt: new Date().toISOString(),
    });
    expect(updated.claimed).toBe(true);
    expect(updated.domain).toBe("vps.example.com");
    expect(updated.appsBaseDomain).toBe("apps.example.com");
  });

  it("supports safe-auto-deploy tokens, per-app allowlists, deployments with redacted logs, and legacy DB migration", () => {
    expect(requiresApprovalForScope("safe-auto-deploy", "deploy_app")).toBe(false);
    expect(requiresApprovalForScope("safe-auto-deploy", "delete_app")).toBe(true);
    expect(requiresApprovalForScope("auto-approve", "delete_app")).toBe(false);

    const { record, rawToken } = store.createMcpToken({
      name: "Scoped Cursor",
      scope: "safe-auto-deploy",
      allowedSlugs: ["my-blog"],
    });
    expect(record.scope).toBe("safe-auto-deploy");
    expect(record.allowedSlugs).toEqual(["my-blog"]);
    expect(isSlugAllowedForToken(record, "my-blog")).toBe(true);
    expect(isSlugAllowedForToken(record, "other-app")).toBe(false);

    const verified = store.verifyMcpToken(rawToken);
    expect(verified?.scope).toBe("safe-auto-deploy");
    expect(verified?.allowedSlugs).toEqual(["my-blog"]);

    const dep = store.createDeployment({
      slug: "my-blog",
      action: "deploy_app",
      actor: "agent",
      actorTokenId: record.id,
      sourceType: "git",
      gitRepoUrl: "https://github.com/acme/my-blog",
      gitBranch: "main",
      domain: "my-blog.apps.example.com",
    });
    expect(dep.status).toBe("queued");

    const failed = store.updateDeployment(dep.id, {
      status: "failed",
      commitSha: "abcdef1234567890",
      detectedRuntime: "nextjs",
      usedAutoDockerfile: true,
      buildLogs: ["Step 1: npm ci", "OPENAI_API_KEY=sk-secret-value-12345678"],
      error: "Build failed with Bearer topsecretbearertoken123",
    })!;
    expect(failed.status).toBe("failed");
    expect(failed.finishedAt).toBeTruthy();
    expect(failed.usedAutoDockerfile).toBe(true);
    expect(failed.buildLogs.join("\n")).not.toContain("sk-secret-value-12345678");
    expect(failed.error).not.toContain("topsecretbearertoken123");
    expect(store.listDeployments({ slug: "my-blog" })).toHaveLength(1);

    // Verify legacy DB without 'safe-auto-deploy' in CHECK constraints migrates cleanly
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "vpsagent-migrate-"));
    const legacyDbPath = path.join(tmpDir, "legacy.db");
    try {
      const legacy = new DatabaseSync(legacyDbPath);
      legacy.exec(`
        CREATE TABLE mcp_tokens (
          id TEXT PRIMARY KEY,
          name TEXT NOT NULL,
          scope TEXT NOT NULL CHECK (scope IN ('read-only', 'approval-required', 'auto-approve')),
          token_hash TEXT NOT NULL UNIQUE,
          token_prefix TEXT NOT NULL,
          created_at TEXT NOT NULL,
          last_used_at TEXT,
          revoked_at TEXT
        );
        CREATE TABLE approval_requests (
          id TEXT PRIMARY KEY,
          action TEXT NOT NULL,
          target_slug TEXT,
          summary TEXT NOT NULL,
          payload_json TEXT NOT NULL,
          requested_by TEXT NOT NULL,
          token_scope TEXT NOT NULL CHECK (token_scope IN ('read-only', 'approval-required', 'auto-approve')),
          status TEXT NOT NULL CHECK (status IN ('pending', 'approved', 'rejected', 'executed', 'failed')),
          risk_level TEXT NOT NULL CHECK (risk_level IN ('low', 'medium', 'high')),
          decided_by TEXT,
          decision_note TEXT,
          result_summary TEXT,
          created_at TEXT NOT NULL,
          decided_at TEXT,
          executed_at TEXT,
          execution_owner TEXT
        );
      `);
      legacy.close();

      const upgraded = new RegistryStore(legacyDbPath);
      try {
        const created = upgraded.createMcpToken({
          name: "Upgraded Pass",
          scope: "safe-auto-deploy",
          allowedSlugs: ["demo-app"],
        });
        expect(created.record.scope).toBe("safe-auto-deploy");
        const apr = upgraded.createApproval({
          action: "delete_app",
          targetSlug: "demo-app",
          summary: "Delete demo-app",
          payload: { slug: "demo-app" },
          requestedBy: "Upgraded Pass",
          tokenScope: "safe-auto-deploy",
          riskLevel: "high",
        });
        expect(apr.tokenScope).toBe("safe-auto-deploy");
        const hostAdmin = upgraded.createMcpToken({
          name: "Root Host Pass",
          scope: "host-admin",
        });
        expect(hostAdmin.record.scope).toBe("host-admin");
        expect(upgraded.verifyMcpToken(created.rawToken)?.scope).toBe(
          "safe-auto-deploy",
        );
        expect(upgraded.verifyMcpToken(hostAdmin.rawToken)?.scope).toBe(
          "host-admin",
        );
      } finally {
        upgraded.close();
      }
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });
});
