import { afterEach, beforeEach, describe, expect, it } from "vitest";
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
      acmeEmail: "owner@example.com",
      claimedAt: new Date().toISOString(),
    });
    expect(updated.claimed).toBe(true);
    expect(updated.domain).toBe("vps.example.com");
  });
});
