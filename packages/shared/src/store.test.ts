import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  hashMcpToken,
  isSlugAllowedForToken,
  requiresApprovalForScope,
} from "./mcp.js";
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

      // Also verify upgrading a PR #2-format DB that ALREADY has a saved safe-auto-deploy pass + app lock
      const pr2DbPath = path.join(tmpDir, "pr2-registry.db");
      const pr2Db = new DatabaseSync(pr2DbPath);
      const seededRawToken = "vpsmcp_seeded_safe_auto_deploy_token_1234567890";
      const seededHash = hashMcpToken(seededRawToken);
      pr2Db.exec(`
        CREATE TABLE mcp_tokens (
          id TEXT PRIMARY KEY,
          name TEXT NOT NULL,
          scope TEXT NOT NULL CHECK (scope IN ('read-only', 'approval-required', 'safe-auto-deploy', 'auto-approve')),
          allowed_slugs_json TEXT NOT NULL DEFAULT '[]',
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
          token_id TEXT,
          token_scope TEXT NOT NULL CHECK (token_scope IN ('read-only', 'approval-required', 'safe-auto-deploy', 'auto-approve')),
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
      pr2Db
        .prepare(
          `INSERT INTO mcp_tokens (id, name, scope, allowed_slugs_json, token_hash, token_prefix, created_at)
           VALUES ('tok_seeded', 'Existing Safe Deploy', 'safe-auto-deploy', '["demo-app"]', ?, 'vpsmcp_seeded', '2026-11-24T00:00:00.000Z')`,
        )
        .run(seededHash);
      pr2Db.close();

      const migratedPr2 = new RegistryStore(pr2DbPath);
      try {
        const verified = migratedPr2.verifyMcpToken(seededRawToken);
        expect(verified).not.toBeNull();
        expect(verified?.scope).toBe("safe-auto-deploy");
        expect(verified?.allowedSlugs).toEqual(["demo-app"]);
        const listed = migratedPr2.listMcpTokens();
        expect(listed.some((t) => t.id === "tok_seeded")).toBe(true);
        const newHostAdmin = migratedPr2.createMcpToken({
          name: "New Host Admin",
          scope: "host-admin",
        });
        expect(newHostAdmin.record.scope).toBe("host-admin");
      } finally {
        migratedPr2.close();
      }
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  it("encrypts GitHub credentials at rest, manages defaults, and links/clears app gitCredentialId", () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "vpsagent-gitcred-"));
    const dbFile = path.join(tmpDir, "registry.db");
    const credStore = new RegistryStore(dbFile, {
      encryptionSecret: "git-cred-test-encryption-secret-32b",
    });

    try {
      const firstToken = "github_pat_11FIRSTTOKEN_00001111";
      const secondToken = "ghp_SECONDTOKEN_22223333";

      const first = credStore.createGitCredential({
        label: "Personal GitHub",
        token: firstToken,
        accountLogin: "alice",
      });
      expect(first.isDefault).toBe(true);
      expect(first.tokenHint).toBe("github_pat_••••1111");
      expect(first.accountLogin).toBe("alice");

      // Verify raw SQLite row stores AES-256-GCM ciphertext and never plaintext token
      const rawDb = new DatabaseSync(dbFile);
      const rawRow = rawDb
        .prepare("SELECT token_enc FROM git_credentials WHERE id = ?")
        .get(first.id) as { token_enc: string };
      rawDb.close();
      expect(rawRow.token_enc.startsWith("gcm:")).toBe(true);
      expect(rawRow.token_enc).not.toContain(firstToken);

      const second = credStore.createGitCredential({
        label: "Work Org",
        token: secondToken,
        accountLogin: "acme-bot",
      });
      expect(second.isDefault).toBe(false);
      expect(second.tokenHint).toBe("ghp_••••3333");

      // Switch default to second credential
      const promoted = credStore.setDefaultGitCredential(second.id);
      expect(promoted?.isDefault).toBe(true);
      expect(credStore.getDefaultGitCredential()?.id).toBe(second.id);
      expect(credStore.getGitCredential(first.id)?.isDefault).toBe(false);

      // Decrypt secret for runtime bridge & touch lastUsedAt
      const decrypted = credStore.getGitCredentialSecretForRuntime(second.id);
      expect(decrypted?.token).toBe(secondToken);
      credStore.touchGitCredentialLastUsed(second.id);
      expect(credStore.getGitCredential(second.id)?.lastUsedAt).not.toBeNull();

      // Link app to second credential and verify persistence
      const app = credStore.upsertApp({
        slug: "private-api",
        name: "Private API",
        sourceType: "git",
        image: null,
        gitRepoUrl: "https://github.com/acme/private-api",
        gitBranch: "main",
        dockerfilePath: "Dockerfile",
        domain: null,
        folderPath: "/apps/private-api",
        internalPort: 3000,
        status: "running",
        cpuLimit: "0.5",
        memoryLimitMb: 512,
        companions: [],
        gitCredentialId: second.id,
      });
      expect(app.gitCredentialId).toBe(second.id);

      // Deleting default credential promotes remaining credential and clears app.gitCredentialId
      expect(credStore.deleteGitCredential(second.id)).toBe(true);
      expect(credStore.getApp("private-api")?.gitCredentialId).toBeNull();
      expect(credStore.getDefaultGitCredential()?.id).toBe(first.id);
      expect(credStore.listGitCredentials()).toHaveLength(1);
    } finally {
      credStore.close();
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  it("migrates legacy deployments CHECK constraint for rollback_app and manages sessions, webhooks, rollback, and encrypted alerts", () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "vpsagent-alpha2-"));
    const legacyDbFile = path.join(tmpDir, "legacy-deploy.db");
    try {
      const legacy = new DatabaseSync(legacyDbFile);
      legacy.exec(`
        CREATE TABLE deployments (
          id TEXT PRIMARY KEY,
          slug TEXT NOT NULL,
          action TEXT NOT NULL CHECK (action IN ('deploy_app', 'rebuild_app')),
          status TEXT NOT NULL CHECK (status IN ('queued', 'cloning', 'building', 'starting', 'verifying', 'succeeded', 'failed')),
          actor TEXT NOT NULL CHECK (actor IN ('user', 'agent', 'system')),
          actor_token_id TEXT,
          source_type TEXT NOT NULL CHECK (source_type IN ('image', 'git')),
          git_repo_url TEXT,
          git_branch TEXT,
          commit_sha TEXT,
          detected_runtime TEXT,
          used_auto_dockerfile INTEGER NOT NULL DEFAULT 0,
          domain TEXT,
          phase_detail TEXT,
          build_logs_json TEXT NOT NULL DEFAULT '[]',
          error_message TEXT,
          created_at TEXT NOT NULL,
          updated_at TEXT NOT NULL,
          finished_at TEXT
        );
        INSERT INTO deployments (
          id, slug, action, status, actor, source_type, created_at, updated_at
        ) VALUES (
          'dep_existing', 'demo', 'deploy_app', 'succeeded', 'user', 'git',
          '2026-11-26T00:00:00.000Z', '2026-11-26T00:00:00.000Z'
        );
      `);
      legacy.close();

      const migrated = new RegistryStore(legacyDbFile, {
        encryptionSecret: "alpha2-store-encryption-secret-32b",
      });
      try {
        expect(migrated.getDeployment("dep_existing")?.action).toBe("deploy_app");
        const rbDep = migrated.createDeployment({
          slug: "demo",
          action: "rollback_app",
          actor: "user",
          sourceType: "git",
        });
        expect(rbDep.action).toBe("rollback_app");

        // Session version starts at 1 and increments atomically
        expect(migrated.getSessionVersion()).toBe(1);
        expect(migrated.bumpSessionVersion()).toBe(2);
        expect(migrated.getSessionVersion()).toBe(2);

        // App webhook + rollback metadata persist across upsertApp
        migrated.upsertApp({
          slug: "git-demo",
          name: "Git Demo",
          sourceType: "git",
          image: "vpsagent-app-git-demo:latest",
          gitRepoUrl: "https://github.com/acme/git-demo",
          gitBranch: "main",
          dockerfilePath: "Dockerfile",
          domain: null,
          folderPath: "/apps/git-demo",
          internalPort: 3000,
          status: "running",
          cpuLimit: "0.5",
          memoryLimitMb: 512,
          companions: [],
        });

        const { app: hooked, rawSecret } = migrated.enableAppWebhook("git-demo");
        expect(hooked.webhookEnabled).toBe(true);
        expect(rawSecret.startsWith("whsec_")).toBe(true);
        expect(migrated.getAppWebhookSecretForRuntime("git-demo")).toBe(rawSecret);

        migrated.updateAppRollbackState("git-demo", {
          previousCommitSha: "1111222233334444",
          rollbackAvailable: true,
        });

        // Ordinary upsertApp preserves webhook secret & rollback metadata
        const reUpserted = migrated.upsertApp({
          slug: "git-demo",
          name: "Git Demo Renamed",
          sourceType: "git",
          image: "vpsagent-app-git-demo:latest",
          gitRepoUrl: "https://github.com/acme/git-demo",
          gitBranch: "main",
          dockerfilePath: "Dockerfile",
          domain: null,
          folderPath: "/apps/git-demo",
          internalPort: 3000,
          status: "running",
          cpuLimit: "1.0",
          memoryLimitMb: 1024,
          companions: [],
        });
        expect(reUpserted.webhookEnabled).toBe(true);
        expect(reUpserted.rollbackAvailable).toBe(true);
        expect(reUpserted.previousCommitSha).toBe("1111222233334444");
        expect(migrated.getAppWebhookSecretForRuntime("git-demo")).toBe(rawSecret);

        const disabled = migrated.disableAppWebhook("git-demo");
        expect(disabled?.webhookEnabled).toBe(false);
        expect(migrated.getAppWebhookSecretForRuntime("git-demo")).toBeNull();

        // Encrypted notification settings mask secrets in public view
        const webhookUrl = "https://discord.com/api/webhooks/12345/super-secret-token";
        const savedAlerts = migrated.updateNotificationSettings({
          enabled: true,
          channel: "discord",
          webhookUrl,
          notifyOnApproval: true,
          notifyOnAppDown: false,
        });
        expect(savedAlerts.enabled).toBe(true);
        expect(savedAlerts.hasTargetSecret).toBe(true);
        expect(savedAlerts.targetHint).not.toContain("super-secret-token");
        expect(JSON.stringify(savedAlerts)).not.toContain("super-secret-token");
        expect(migrated.getNotificationConfigForRuntime().webhookUrl).toBe(
          webhookUrl,
        );

        migrated.recordNotificationDelivery(false, "Failed with Bearer secret999");
        expect(migrated.getNotificationSettings().lastError).not.toContain(
          "secret999",
        );
      } finally {
        migrated.close();
      }
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });
});
