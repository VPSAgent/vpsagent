import fs from "node:fs";
import path from "node:path";
import { Hono } from "hono";
import type { ContentfulStatusCode } from "hono/utils/http-status";
import { z } from "zod";
import {
  CreateMcpTokenInputSchema,
  type HostLookupFn,
  type RegistryStore,
  type RuntimeBridge,
  RuntimeBridgeError,
  redactSecrets,
  syncAppStatuses,
  validateDomain,
} from "@vpsagent/shared";
import {
  SessionManager,
  type TransportContextOptions,
  assertSecureTransport,
  getRequestHost,
  getRequestProtocol,
} from "./auth.js";
import {
  AppExecutor,
  DeployAppInputSchema,
  InspectGitInputSchema,
  UpdateAppEnvInputSchema,
} from "./executor.js";
import {
  buildMcpSetupSnippets,
  createMcpPostHandler,
  enforceMcpBoundary,
} from "./mcp-gateway.js";

export interface VpsAgentAppOptions {
  store: RegistryStore;
  bridge: RuntimeBridge;
  appsRoot: string;
  sessionSecret: string;
  claimToken?: string | undefined;
  webDistDir?: string | undefined;
  publicIp?: string | undefined;
  trustProxy?: boolean | undefined;
  /** Set true ONLY for the loopback-only local setup server (127.0.0.1:3002). */
  isLocalListener?: boolean | undefined;
  /** Optional default peer IP for unit tests without a real Node TCP socket. */
  defaultPeerIp?: string | undefined;
  lookupFn?: HostLookupFn | undefined;
  readinessTimeoutSeconds?: number | undefined;
  readinessPollIntervalMs?: number | undefined;
  buildTimeoutSeconds?: number | undefined;
  mcpDeployGraceMs?: number | undefined;
}

const ClaimInputSchema = z.object({
  claimToken: z.string().min(1),
  passphrase: z
    .string()
    .min(8, "Password must be at least 8 characters long.")
    .max(256),
});

const LoginInputSchema = z.object({
  passphrase: z.string().min(1).max(256),
});

const SetupDomainInputSchema = z.object({
  domain: z.string().trim().min(1).max(253).nullable(),
  acmeEmail: z.string().trim().email().nullable().optional(),
});

const SetupAppsBaseDomainSchema = z.object({
  appsBaseDomain: z.string().trim().min(1).max(253).nullable(),
});

const SetAppDomainBodySchema = z.object({
  domain: z.string().trim().min(1).max(253).nullable(),
});

const DecisionBodySchema = z.object({
  note: z.string().max(400).optional(),
  async: z.boolean().optional(),
});

const MIME_TYPES: Record<string, string> = {
  ".html": "text/html; charset=utf-8",
  ".js": "application/javascript; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".svg": "image/svg+xml",
  ".png": "image/png",
  ".ico": "image/x-icon",
  ".json": "application/json; charset=utf-8",
  ".woff2": "font/woff2",
};

function toStatusCode(code: number): ContentfulStatusCode {
  if (code >= 400 && code <= 599) {
    return code as ContentfulStatusCode;
  }
  return 500;
}

function handleError(err: unknown): {
  status: ContentfulStatusCode;
  error: string;
} {
  if (err instanceof RuntimeBridgeError) {
    return { status: toStatusCode(err.statusCode), error: err.message };
  }
  if (err instanceof z.ZodError) {
    const first = err.issues[0];
    return {
      status: 400,
      error: first
        ? `${first.path.join(".") || "input"}: ${first.message}`
        : "Invalid request payload.",
    };
  }
  const message = redactSecrets(
    err instanceof Error ? err.message : String(err),
  );
  const status: ContentfulStatusCode = /not found/i.test(message)
    ? 404
    : /invalid|reserved|blocked|cannot|must|required|duplicate|exceeds/i.test(
          message,
        )
      ? 400
      : 500;
  return { status, error: message };
}

export function createVpsAgentApp(options: VpsAgentAppOptions): {
  app: Hono;
  sessions: SessionManager;
  executor: AppExecutor;
  generatedClaimToken: string | null;
} {
  const { store, bridge } = options;
  const trustProxy = Boolean(options.trustProxy);
  const transportOptions: TransportContextOptions = {
    trustProxy,
    isLocalListener: options.isLocalListener,
    defaultPeerIp: options.defaultPeerIp,
  };

  const sessions = new SessionManager({
    store,
    sessionSecret: options.sessionSecret,
    claimToken: options.claimToken,
  });
  const generatedClaimToken = sessions.ensureClaimToken();

  const executor = new AppExecutor({
    store,
    bridge,
    appsRoot: options.appsRoot,
    lookupFn: options.lookupFn,
    readinessTimeoutSeconds: options.readinessTimeoutSeconds,
    readinessPollIntervalMs: options.readinessPollIntervalMs,
    buildTimeoutSeconds: options.buildTimeoutSeconds,
  });

  const app = new Hono();

  // Security headers on all responses
  app.use("*", async (c, next) => {
    await next();
    c.header("X-Content-Type-Options", "nosniff");
    c.header("X-Frame-Options", "DENY");
    c.header("Referrer-Policy", "no-referrer");
  });

  // ---------------------------------------------------------------------------
  // Public Health & Session State
  // ---------------------------------------------------------------------------

  app.get("/api/health", async (c) => {
    let bridgeOk = false;
    try {
      bridgeOk = (await bridge.health()).ok;
    } catch {
      bridgeOk = false;
    }
    return c.json({
      ok: true,
      service: "vpsagent-api",
      bridgeOk,
      claimed: store.getSetupState().claimed,
    });
  });

  app.get("/api/auth/session", (c) => {
    const setup = store.getSetupState();
    const authenticated = sessions.isAuthenticatedRequest(c);
    return c.json({
      claimed: setup.claimed,
      authenticated,
      setup,
      publicIp: options.publicIp ?? null,
    });
  });

  // ---------------------------------------------------------------------------
  // 2-Step First-Boot Setup + Login / Logout (HTTPS or genuine local loopback)
  // ---------------------------------------------------------------------------

  app.post("/api/setup/claim", async (c) => {
    let transport: { isHttps: boolean; isLocalLoopback: boolean };
    try {
      transport = assertSecureTransport(c, transportOptions);
    } catch (err) {
      return c.json(
        { error: err instanceof Error ? err.message : "HTTPS required." },
        403,
      );
    }

    if (store.getSetupState().claimed) {
      return c.json(
        { error: "This VPSAgent server has already been claimed." },
        409,
      );
    }
    try {
      const body = ClaimInputSchema.parse(await c.req.json());
      if (!sessions.verifyClaimToken(body.claimToken)) {
        return c.json(
          {
            error:
              "Invalid setup link token. Check the link printed by the installer.",
          },
          401,
        );
      }
      store.setAdminPassphrase(body.passphrase);
      sessions.clearStoredClaimToken();
      const setup = store.updateSetupState({
        claimed: true,
        claimedAt: new Date().toISOString(),
      });
      store.recordAudit({
        actor: "user",
        action: "setup.claimed",
        summary: "Server claimed and owner login password set",
        riskLevel: "high",
      });

      const token = sessions.createSessionToken();
      c.header(
        "Set-Cookie",
        sessions.buildSetSessionCookie(token, transport.isHttps),
      );
      return c.json({ ok: true, setup });
    } catch (err) {
      const { status, error } = handleError(err);
      return c.json({ error }, status);
    }
  });

  app.post("/api/auth/login", async (c) => {
    let transport: { isHttps: boolean; isLocalLoopback: boolean };
    try {
      transport = assertSecureTransport(c, transportOptions);
    } catch (err) {
      return c.json(
        { error: err instanceof Error ? err.message : "HTTPS required." },
        403,
      );
    }

    if (!store.getSetupState().claimed) {
      return c.json(
        { error: "Complete first-time setup before logging in." },
        409,
      );
    }
    const clientKey =
      c.req.header("x-forwarded-for")?.split(",")[0]?.trim() || "local";
    if (!sessions.checkLoginRateLimit(clientKey)) {
      return c.json(
        { error: "Too many failed login attempts. Please wait 5 minutes." },
        429,
      );
    }
    try {
      const body = LoginInputSchema.parse(await c.req.json());
      if (!store.verifyAdminPassphrase(body.passphrase)) {
        sessions.recordLoginFailure(clientKey);
        return c.json({ error: "Incorrect password." }, 401);
      }
      sessions.clearLoginFailures(clientKey);
      const token = sessions.createSessionToken();
      c.header(
        "Set-Cookie",
        sessions.buildSetSessionCookie(token, transport.isHttps),
      );
      return c.json({ ok: true, setup: store.getSetupState() });
    } catch (err) {
      const { status, error } = handleError(err);
      return c.json({ error }, status);
    }
  });

  app.post("/api/auth/logout", (c) => {
    const isSecure = getRequestProtocol(c, trustProxy) === "https";
    c.header("Set-Cookie", sessions.buildClearSessionCookie(isSecure));
    return c.json({ ok: true });
  });

  // ---------------------------------------------------------------------------
  // Remote MCP Gateway (`POST /mcp` — bearer token auth + HTTPS/Host/Origin)
  // ---------------------------------------------------------------------------

  app.post(
    "/mcp",
    createMcpPostHandler({
      store,
      bridge,
      executor,
      transportOptions,
      mcpDeployGraceMs: options.mcpDeployGraceMs,
    }),
  );

  // Streamable HTTP spec: return 405 Method Not Allowed on GET /mcp when SSE is not offered
  app.get("/mcp", (c) => {
    const guard = enforceMcpBoundary(c, store, transportOptions);
    if (!guard.ok) {
      return guard.response;
    }
    c.header("Allow", "POST");
    return c.json(
      { error: "Method Not Allowed: /mcp only accepts POST JSON-RPC requests." },
      405,
    );
  });

  // ---------------------------------------------------------------------------
  // Authenticated Owner Dashboard API (`/api/*`)
  // ---------------------------------------------------------------------------

  const requireOwner = async (
    c: Parameters<Parameters<typeof app.use>[1]>[0],
    next: () => Promise<void>,
  ) => {
    if (!sessions.isAuthenticatedRequest(c)) {
      return c.json({ error: "Authentication required." }, 401);
    }
    await next();
  };

  app.use("/api/setup/domain", requireOwner);
  app.use("/api/setup/apps-base-domain", requireOwner);
  app.use("/api/setup/tls-recheck", requireOwner);
  app.use("/api/overview", requireOwner);
  app.use("/api/git/*", requireOwner);
  app.use("/api/deployments/*", requireOwner);
  app.use("/api/deployments", requireOwner);
  app.use("/api/apps/*", requireOwner);
  app.use("/api/apps", requireOwner);
  app.use("/api/approvals/*", requireOwner);
  app.use("/api/approvals", requireOwner);
  app.use("/api/audit", requireOwner);
  app.use("/api/mcp/*", requireOwner);

  // Step 2 of first-boot setup (applies directly to Caddy via Runtime Bridge!)
  app.post("/api/setup/domain", async (c) => {
    try {
      const body = SetupDomainInputSchema.parse(await c.req.json());
      const safeDomain = body.domain ? validateDomain(body.domain) : null;
      const acmeEmail = body.acmeEmail ?? null;

      // Apply to Caddy and validate+reload BEFORE persisting setup state!
      const applied = await bridge.routeCoreDomain({
        domain: safeDomain,
        acmeEmail,
      });

      const setup = store.updateSetupState({
        domain: applied.domain,
        acmeEmail: applied.acmeEmail,
        httpsActive: applied.httpsActive,
        tlsStatus: applied.tlsStatus,
        tlsError: applied.tlsError,
      });
      store.recordAudit({
        actor: "user",
        action: "setup.domain_updated",
        summary: applied.domain
          ? `Configured Caddy for ${applied.domain} (TLS status: ${applied.tlsStatus})`
          : "Cleared dashboard custom domain (reverted to local-only mode)",
        riskLevel: "medium",
      });
      return c.json({ ok: true, setup });
    } catch (err) {
      const { status, error } = handleError(err);
      return c.json({ error }, status);
    }
  });

  app.post("/api/setup/tls-recheck", async (c) => {
    try {
      const current = store.getSetupState();
      if (!current.domain) {
        return c.json({ ok: true, setup: current });
      }
      if (!bridge.checkCoreTls) {
        return c.json({ ok: true, setup: current });
      }
      const checked = await bridge.checkCoreTls(current.domain);
      const setup = store.updateSetupState({
        httpsActive: checked.httpsActive,
        tlsStatus: checked.tlsStatus,
        tlsError: checked.tlsError,
      });
      return c.json({ ok: true, setup });
    } catch (err) {
      const { status, error } = handleError(err);
      return c.json({ error }, status);
    }
  });

  app.post("/api/setup/apps-base-domain", async (c) => {
    try {
      const body = SetupAppsBaseDomainSchema.parse(await c.req.json());
      const safeBase = body.appsBaseDomain
        ? validateDomain(body.appsBaseDomain)
        : null;
      const setup = store.updateSetupState({ appsBaseDomain: safeBase });
      store.recordAudit({
        actor: "user",
        action: "setup.apps_base_domain_updated",
        summary: safeBase
          ? `Set default apps base domain to *.${safeBase}`
          : "Cleared default apps base domain",
        riskLevel: "low",
      });
      return c.json({ ok: true, setup });
    } catch (err) {
      const { status, error } = handleError(err);
      return c.json({ error }, status);
    }
  });

  app.post("/api/git/inspect", async (c) => {
    try {
      const body = InspectGitInputSchema.parse(await c.req.json());
      const inspect = await executor.inspectGitRepo(body);
      return c.json({ inspect });
    } catch (err) {
      const { status, error } = handleError(err);
      return c.json({ error }, status);
    }
  });

  app.get("/api/deployments", (c) => {
    const slug = c.req.query("slug")?.trim() || undefined;
    const rawLimit = Number.parseInt(c.req.query("limit") ?? "20", 10);
    const limit = Number.isFinite(rawLimit)
      ? Math.min(Math.max(rawLimit, 1), 100)
      : 20;
    const deployments = store.listDeployments({
      ...(slug ? { slug } : {}),
      limit,
    });
    return c.json({ deployments });
  });

  app.get("/api/deployments/:id", (c) => {
    const deployment = store.getDeployment(c.req.param("id"));
    if (!deployment) {
      return c.json({ error: "Deployment not found." }, 404);
    }
    const appRecord = store.getApp(deployment.slug);
    return c.json({
      deployment,
      app: appRecord,
      missingEnvKeys: executor.getMissingEnvKeys(deployment.slug),
    });
  });

  // Tab 1 — Overview
  app.get("/api/overview", async (c) => {
    try {
      const [hostStats, apps] = await Promise.all([
        bridge.getHostStats(),
        syncAppStatuses(store, bridge),
      ]);
      const pendingApprovals = store.listApprovals({
        status: "pending",
        limit: 50,
      }).length;
      const tokens = store.listMcpTokens().filter((t) => !t.revokedAt).length;
      return c.json({
        ...hostStats,
        apps,
        pendingApprovals,
        activeMcpTokens: tokens,
        setup: store.getSetupState(),
      });
    } catch (err) {
      const { status, error } = handleError(err);
      return c.json({ error }, status);
    }
  });

  // Tab 2 — Apps
  app.get("/api/apps", async (c) => {
    const apps = await syncAppStatuses(store, bridge);
    return c.json({ apps });
  });

  app.post("/api/apps", async (c) => {
    try {
      const body = DeployAppInputSchema.parse(await c.req.json());
      const runAsync = c.req.query("async") === "true";
      if (runAsync) {
        const started = await executor.startDeployApp(body, "user", {
          waitMs: 0,
        });
        return c.json(started, 202);
      }
      const result = await executor.deployApp(body, "user");
      return c.json(result, 201);
    } catch (err) {
      const { status, error } = handleError(err);
      return c.json({ error }, status);
    }
  });

  app.get("/api/apps/:slug", (c) => {
    const appRecord = store.getApp(c.req.param("slug"));
    if (!appRecord) {
      return c.json({ error: "App not found." }, 404);
    }
    return c.json({
      app: appRecord,
      envVars: store.listAppEnvVars(appRecord.slug),
    });
  });

  app.post("/api/apps/:slug/start", async (c) => {
    try {
      const updated = await executor.lifecycleApp(
        c.req.param("slug"),
        "start",
        "user",
      );
      return c.json({ app: updated });
    } catch (err) {
      const { status, error } = handleError(err);
      return c.json({ error }, status);
    }
  });

  app.post("/api/apps/:slug/stop", async (c) => {
    try {
      const updated = await executor.lifecycleApp(
        c.req.param("slug"),
        "stop",
        "user",
      );
      return c.json({ app: updated });
    } catch (err) {
      const { status, error } = handleError(err);
      return c.json({ error }, status);
    }
  });

  app.post("/api/apps/:slug/restart", async (c) => {
    try {
      const updated = await executor.lifecycleApp(
        c.req.param("slug"),
        "restart",
        "user",
      );
      return c.json({ app: updated });
    } catch (err) {
      const { status, error } = handleError(err);
      return c.json({ error }, status);
    }
  });

  app.post("/api/apps/:slug/rebuild", async (c) => {
    try {
      const runAsync = c.req.query("async") === "true";
      if (runAsync) {
        const started = await executor.startRebuildApp(
          c.req.param("slug"),
          "user",
          { waitMs: 0 },
        );
        return c.json(started, 202);
      }
      const updated = await executor.rebuildApp(c.req.param("slug"), "user");
      return c.json({ app: updated });
    } catch (err) {
      const { status, error } = handleError(err);
      return c.json({ error }, status);
    }
  });

  app.delete("/api/apps/:slug", async (c) => {
    try {
      const removeFiles = c.req.query("removeFiles") !== "false";
      const res = await executor.deleteApp(
        c.req.param("slug"),
        removeFiles,
        "user",
      );
      return c.json(res);
    } catch (err) {
      const { status, error } = handleError(err);
      return c.json({ error }, status);
    }
  });

  app.get("/api/apps/:slug/logs", async (c) => {
    try {
      const rawTail = Number.parseInt(c.req.query("tail") ?? "100", 10);
      const tail = Number.isFinite(rawTail)
        ? Math.min(Math.max(rawTail, 1), 500)
        : 100;
      const slug = c.req.param("slug");
      const detailed = bridge.getLogsDetailed
        ? await bridge.getLogsDetailed(slug, tail)
        : { slug, lines: await bridge.getLogs(slug, tail), truncated: false };
      return c.json(detailed);
    } catch (err) {
      const { status, error } = handleError(err);
      return c.json({ error }, status);
    }
  });

  app.get("/api/apps/:slug/inspect", async (c) => {
    try {
      const slug = c.req.param("slug");
      const appRecord = store.getApp(slug);
      const inspect = await bridge.inspectWorkload(slug, {
        probeHttp:
          c.req.query("probe") === "false"
            ? false
            : (appRecord?.probeHttp ?? true),
        internalPort: appRecord?.internalPort ?? 8080,
        probePath: appRecord?.probePath ?? "/",
      });
      return c.json({ inspect });
    } catch (err) {
      const { status, error } = handleError(err);
      return c.json({ error }, status);
    }
  });

  app.put("/api/apps/:slug/domain", async (c) => {
    try {
      const body = SetAppDomainBodySchema.parse(await c.req.json());
      const updated = await executor.setAppDomain(
        c.req.param("slug"),
        body.domain,
        "user",
      );
      return c.json({ app: updated });
    } catch (err) {
      const { status, error } = handleError(err);
      return c.json({ error }, status);
    }
  });

  app.get("/api/apps/:slug/env", (c) => {
    const slug = c.req.param("slug");
    if (!store.getApp(slug)) {
      return c.json({ error: "App not found." }, 404);
    }
    return c.json({
      envVars: store.listAppEnvVars(slug),
      missingEnvKeys: executor.getMissingEnvKeys(slug),
    });
  });

  app.put("/api/apps/:slug/env", async (c) => {
    try {
      const slug = c.req.param("slug");
      const body = UpdateAppEnvInputSchema.parse(await c.req.json());
      const updated = await executor.updateAppEnv(slug, body, "user");
      return c.json({
        app: updated,
        envVars: store.listAppEnvVars(slug),
        missingEnvKeys: executor.getMissingEnvKeys(slug),
      });
    } catch (err) {
      const { status, error } = handleError(err);
      return c.json({ error }, status);
    }
  });

  app.delete("/api/apps/:slug/env/:key", async (c) => {
    try {
      const slug = c.req.param("slug");
      const key = c.req.param("key");
      const updated = await executor.updateAppEnv(
        slug,
        { vars: [], deleteKeys: [key] },
        "user",
      );
      return c.json({
        app: updated,
        envVars: store.listAppEnvVars(slug),
        missingEnvKeys: executor.getMissingEnvKeys(slug),
      });
    } catch (err) {
      const { status, error } = handleError(err);
      return c.json({ error }, status);
    }
  });

  // Tab 3 — Approvals & History
  app.get("/api/approvals", (c) => {
    const rawStatus = c.req.query("status");
    const status =
      rawStatus &&
      ["pending", "approved", "rejected", "executed", "failed"].includes(
        rawStatus,
      )
        ? (rawStatus as
            | "pending"
            | "approved"
            | "rejected"
            | "executed"
            | "failed")
        : undefined;
    const approvals = store.listApprovals(
      status ? { status, limit: 100 } : { limit: 100 },
    );
    return c.json({ approvals });
  });

  app.post("/api/approvals/:id/approve", async (c) => {
    try {
      const id = c.req.param("id");
      let note: string | undefined;
      let asyncDeploy = c.req.query("async") === "true";
      try {
        const parsed = DecisionBodySchema.parse(await c.req.json());
        note = parsed.note;
        if (parsed.async) {
          asyncDeploy = true;
        }
      } catch {
        // Optional body
      }

      const decided = store.decideApproval(id, "approved", "owner", note);
      if (!decided) {
        return c.json({ error: "Approval request not found." }, 404);
      }

      store.recordAudit({
        actor: "user",
        actorTokenId: decided.tokenId,
        action: "approval.approved",
        targetSlug: decided.targetSlug,
        summary: `Approved ${decided.action} (${decided.id}) requested by ${decided.requestedBy}`,
        riskLevel: decided.riskLevel,
      });

      const execution = await executor.executeApprovedRequest(id, {
        asyncDeploy,
      });
      const finalRecord = store.getApproval(id);
      return c.json(
        {
          ok: execution.ok,
          approval: finalRecord,
          summary: execution.summary,
          ...(execution.deployment ? { deployment: execution.deployment } : {}),
          ...(execution.ok ? {} : { error: execution.summary }),
        },
        execution.ok ? 200 : 502,
      );
    } catch (err) {
      const { status, error } = handleError(err);
      return c.json({ error }, status);
    }
  });

  app.post("/api/approvals/:id/reject", async (c) => {
    try {
      const id = c.req.param("id");
      let note: string | undefined;
      try {
        const parsed = DecisionBodySchema.parse(await c.req.json());
        note = parsed.note;
      } catch {
        // Optional body
      }

      const decided = store.decideApproval(id, "rejected", "owner", note);
      if (!decided) {
        return c.json({ error: "Approval request not found." }, 404);
      }
      store.recordAudit({
        actor: "user",
        actorTokenId: decided.tokenId,
        action: "approval.rejected",
        targetSlug: decided.targetSlug,
        summary: `Rejected ${decided.action} (${decided.id}) requested by ${decided.requestedBy}`,
        riskLevel: "low",
      });
      return c.json({ ok: true, approval: decided });
    } catch (err) {
      const { status, error } = handleError(err);
      return c.json({ error }, status);
    }
  });

  app.get("/api/audit", (c) => {
    const query = c.req.query("query")?.trim() || undefined;
    const targetSlug = c.req.query("targetSlug")?.trim() || undefined;
    const rawLimit = Number.parseInt(c.req.query("limit") ?? "100", 10);
    const limit = Number.isFinite(rawLimit)
      ? Math.min(Math.max(rawLimit, 1), 500)
      : 100;
    const events = store.listAuditEvents({
      limit,
      ...(query ? { query } : {}),
      ...(targetSlug ? { targetSlug } : {}),
    });
    return c.json({ events });
  });

  // Tab 4 — AI Keys & Settings (creating raw keys requires HTTPS or genuine local loopback)
  app.get("/api/mcp/tokens", (c) => {
    return c.json({ tokens: store.listMcpTokens() });
  });

  app.post("/api/mcp/tokens", async (c) => {
    try {
      assertSecureTransport(c, transportOptions);
    } catch (err) {
      return c.json(
        { error: err instanceof Error ? err.message : "HTTPS required." },
        403,
      );
    }
    try {
      const input = CreateMcpTokenInputSchema.parse(await c.req.json());
      const { record, rawToken } = store.createMcpToken(input);
      store.recordAudit({
        actor: "user",
        actorTokenId: record.id,
        action: "mcp.token_created",
        summary: `Created ${record.scope} AI pass "${record.name}" (${record.tokenPrefix}...)`,
        riskLevel: record.scope === "auto-approve" ? "high" : "medium",
      });
      return c.json({ token: record, rawToken }, 201);
    } catch (err) {
      const { status, error } = handleError(err);
      return c.json({ error }, status);
    }
  });

  app.delete("/api/mcp/tokens/:id", (c) => {
    const id = c.req.param("id");
    const revoked = store.revokeMcpToken(id);
    if (!revoked) {
      return c.json({ error: "Token not found or already revoked." }, 404);
    }
    store.recordAudit({
      actor: "user",
      actorTokenId: id,
      action: "mcp.token_revoked",
      summary: `Revoked AI pass (${id})`,
      riskLevel: "medium",
    });
    return c.json({ ok: true });
  });

  app.get("/api/mcp/snippets", (c) => {
    const setup = store.getSetupState();
    const httpsReady = Boolean(
      setup.domain && setup.httpsActive && setup.tlsStatus === "active",
    );
    const host = getRequestHost(c, trustProxy) || "localhost:3002";
    const mcpUrl = httpsReady
      ? `https://${setup.domain}/mcp`
      : `http://${host}/mcp`;
    return c.json(buildMcpSetupSnippets(mcpUrl, httpsReady));
  });

  // ---------------------------------------------------------------------------
  // Static Dashboard Serving (production single-container bundle)
  // ---------------------------------------------------------------------------

  const webDistDir = options.webDistDir
    ? path.resolve(options.webDistDir)
    : undefined;
  if (webDistDir && fs.existsSync(webDistDir)) {
    app.get("*", (c) => {
      const reqPath = c.req.path;
      if (reqPath.startsWith("/api/") || reqPath === "/mcp") {
        return c.json({ error: "Not found." }, 404);
      }

      const rel = reqPath === "/" ? "index.html" : reqPath.replace(/^\/+/, "");
      const candidate = path.resolve(webDistDir, rel);
      const isInside =
        candidate === webDistDir ||
        candidate.startsWith(`${webDistDir}${path.sep}`);

      const fileToServe =
        isInside && fs.existsSync(candidate) && fs.statSync(candidate).isFile()
          ? candidate
          : path.join(webDistDir, "index.html");

      if (!fs.existsSync(fileToServe)) {
        return c.text("Dashboard build not found.", 404);
      }

      const ext = path.extname(fileToServe).toLowerCase();
      const contentType = MIME_TYPES[ext] ?? "application/octet-stream";
      const content = fs.readFileSync(fileToServe);
      return c.body(content, 200, { "Content-Type": contentType });
    });
  }

  return { app, sessions, executor, generatedClaimToken };
}
