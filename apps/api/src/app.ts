import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { Hono } from "hono";
import type { ContentfulStatusCode } from "hono/utils/http-status";
import { z } from "zod";
import {
  CreateMcpTokenInputSchema,
  type HostLookupFn,
  type RegistryStore,
  type RuntimeBridge,
  RuntimeBridgeError,
  type RuntimeTailscaleStatus,
  type SetupState,
  redactSecrets,
  scrubTokenFromText,
  syncAppStatuses,
  validateDomain,
  validateTailscaleAuthKey,
} from "@vpsagent/shared";
import {
  SessionManager,
  type TransportContextOptions,
  assertSecureTransport,
  getRequestHost,
  getRequestProtocol,
  normalizeHostWithoutDefaultPort,
} from "./auth.js";
import {
  AppExecutor,
  DeployAppInputSchema,
  InspectGitInputSchema,
  UpdateAppEnvInputSchema,
} from "./executor.js";
import { verifyGithubToken } from "./github.js";
import {
  MCP_TOOLS,
  McpSessionStore,
  SUPPORTED_MCP_PROTOCOL_VERSIONS,
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
  githubApiBaseUrl?: string | undefined;
  githubFetchFn?: typeof fetch | undefined;
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

const CreateGitCredentialBodySchema = z.object({
  label: z.string().trim().max(80).optional(),
  token: z.string().trim().min(1, "GitHub token is required.").max(512),
  isDefault: z.boolean().optional(),
});

const TailscaleServeBodySchema = z.object({
  enabled: z.boolean(),
  force: z.boolean().optional(),
});

const TailscaleConnectBodySchema = z.object({
  mode: z.enum(["login", "authkey"]).default("login"),
  authKey: z.string().trim().min(1).max(300).optional(),
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

function readInstalledPackageVersion(): string | null {
  const dir = path.dirname(fileURLToPath(import.meta.url));
  const candidates = [
    path.resolve(dir, "..", "..", "..", "package.json"),
    path.resolve(dir, "..", "package.json"),
  ];
  for (const pkgPath of candidates) {
    try {
      if (!fs.existsSync(pkgPath)) continue;
      const parsed = JSON.parse(fs.readFileSync(pkgPath, "utf8")) as {
        version?: unknown;
      };
      if (typeof parsed.version === "string" && parsed.version.trim()) {
        return parsed.version.trim();
      }
    } catch {
      continue;
    }
  }
  return null;
}

const ApplySystemUpdateBodySchema = z.object({
  source: z.enum(["auto", "release", "git"]).optional(),
});

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
    githubApiBaseUrl: options.githubApiBaseUrl,
    githubFetchFn: options.githubFetchFn,
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

  const mcpSessions = new McpSessionStore();

  app.post(
    "/mcp",
    createMcpPostHandler({
      store,
      bridge,
      executor,
      transportOptions,
      mcpDeployGraceMs: options.mcpDeployGraceMs,
      sessions: mcpSessions,
    }),
  );

  // Streamable HTTP spec: return 405 Method Not Allowed on GET /mcp when SSE is not offered
  app.get("/mcp", async (c) => {
    const guard = await enforceMcpBoundary(c, store, transportOptions, bridge);
    if (!guard.ok) {
      return guard.response;
    }
    c.header("Allow", "POST, DELETE");
    return c.json(
      { error: "Method Not Allowed: /mcp only accepts POST JSON-RPC requests." },
      405,
    );
  });

  // Streamable HTTP spec: close & invalidate a server-issued session via DELETE /mcp
  app.delete("/mcp", async (c) => {
    const guard = await enforceMcpBoundary(c, store, transportOptions, bridge);
    if (!guard.ok) {
      return guard.response;
    }
    const authHeader = c.req.header("authorization") ?? "";
    const match = authHeader.match(/^Bearer\s+(.+)$/i);
    const rawToken = match?.[1]?.trim();
    const token = rawToken ? store.verifyMcpToken(rawToken) : null;
    if (!token) {
      return c.json({ error: "Invalid or missing Bearer token." }, 401);
    }
    const sessionId = c.req.header("mcp-session-id")?.trim();
    if (sessionId && !mcpSessions.close(sessionId, token.id)) {
      return c.json({ error: "MCP session not found." }, 404);
    }
    return c.body(null, 204);
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
  app.use("/api/system/*", requireOwner);
  app.use("/api/tailscale/*", requireOwner);

  const assertSameOriginPost = (
    c: Parameters<Parameters<typeof app.use>[1]>[0],
  ): Response | null => {
    const fetchSite = c.req.header("sec-fetch-site")?.trim().toLowerCase();
    if (fetchSite && fetchSite !== "same-origin" && fetchSite !== "none") {
      return c.json(
        { error: "Cross-origin or sibling-site request blocked." },
        403,
      );
    }
    const origin = c.req.header("origin")?.trim();
    if (origin) {
      let parsedOrigin: URL;
      try {
        parsedOrigin = new URL(origin);
      } catch {
        return c.json({ error: "Invalid Origin header." }, 403);
      }
      const expectedProto = getRequestProtocol(c, trustProxy);
      const isHttps = expectedProto === "https";
      const expectedHost = normalizeHostWithoutDefaultPort(
        getRequestHost(c, trustProxy) || "",
        isHttps,
      );
      const originHost = normalizeHostWithoutDefaultPort(
        parsedOrigin.host,
        parsedOrigin.protocol.toLowerCase() === "https:",
      );
      if (!expectedHost || originHost !== expectedHost) {
        return c.json({ error: "Cross-origin request blocked." }, 403);
      }
      if (isHttps && parsedOrigin.protocol.toLowerCase() !== "https:") {
        return c.json(
          { error: "HTTPS Origin is required for this request." },
          403,
        );
      }
    }
    const contentType = (c.req.header("content-type") || "").toLowerCase();
    if (!contentType.includes("application/json")) {
      return c.json(
        { error: "Content-Type: application/json is required." },
        415,
      );
    }
    return null;
  };

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

  app.get("/api/git/credentials", (c) => {
    return c.json({ credentials: store.listGitCredentials() });
  });

  app.post("/api/git/credentials", async (c) => {
    try {
      assertSecureTransport(c, transportOptions);
    } catch (err) {
      return c.json(
        { error: err instanceof Error ? err.message : "HTTPS required." },
        403,
      );
    }
    const csrfBlocked = assertSameOriginPost(c);
    if (csrfBlocked) {
      return csrfBlocked;
    }

    let rawToken = "";
    try {
      const body = CreateGitCredentialBodySchema.parse(await c.req.json());
      rawToken = body.token;
      const verified = await verifyGithubToken(rawToken, {
        apiBaseUrl: options.githubApiBaseUrl,
        fetchFn: options.githubFetchFn,
      });
      const label =
        body.label?.trim() ||
        (verified.accountLogin
          ? `GitHub (@${verified.accountLogin})`
          : "GitHub Token");
      const record = store.createGitCredential({
        provider: "github",
        label,
        token: rawToken,
        accountLogin: verified.accountLogin,
        ...(body.isDefault !== undefined ? { isDefault: body.isDefault } : {}),
      });
      store.recordAudit({
        actor: "user",
        action: "git.credential_added",
        summary: `Connected GitHub access token "${record.label}" (${record.tokenHint})`,
        riskLevel: "medium",
      });
      return c.json(
        {
          credential: record,
          accountLogin: verified.accountLogin,
          accessibleRepoCount: verified.accessibleRepoCount,
          warning: verified.warning,
        },
        201,
      );
    } catch (err) {
      const { status, error } = handleError(err);
      return c.json({ error: scrubTokenFromText(error, rawToken) }, status);
    }
  });

  app.post("/api/git/credentials/:id/default", (c) => {
    const csrfBlocked = assertSameOriginPost(c);
    if (csrfBlocked) {
      return csrfBlocked;
    }
    const id = c.req.param("id");
    const updated = store.setDefaultGitCredential(id);
    if (!updated) {
      return c.json({ error: "GitHub access token not found." }, 404);
    }
    store.recordAudit({
      actor: "user",
      action: "git.credential_default_updated",
      summary: `Set "${updated.label}" (${updated.tokenHint}) as default GitHub token`,
      riskLevel: "low",
    });
    return c.json({ ok: true, credential: updated });
  });

  app.post("/api/git/credentials/:id/test", async (c) => {
    const csrfBlocked = assertSameOriginPost(c);
    if (csrfBlocked) {
      return csrfBlocked;
    }
    const id = c.req.param("id");
    const secret = store.getGitCredentialSecretForRuntime(id);
    if (!secret) {
      return c.json({ error: "GitHub access token not found." }, 404);
    }
    try {
      const verified = await verifyGithubToken(secret.token, {
        apiBaseUrl: options.githubApiBaseUrl,
        fetchFn: options.githubFetchFn,
      });
      store.touchGitCredentialLastUsed(id);
      if (
        verified.accountLogin &&
        verified.accountLogin !== secret.record.accountLogin
      ) {
        store.updateGitCredentialMeta(id, {
          accountLogin: verified.accountLogin,
        });
      }
      const latest = store.getGitCredential(id)!;
      return c.json({
        ok: true,
        credential: latest,
        accountLogin: verified.accountLogin,
        accessibleRepoCount: verified.accessibleRepoCount,
        warning: verified.warning,
      });
    } catch (err) {
      const { status, error } = handleError(err);
      return c.json(
        { error: scrubTokenFromText(error, secret.token) },
        status,
      );
    }
  });

  app.delete("/api/git/credentials/:id", (c) => {
    const id = c.req.param("id");
    const existing = store.getGitCredential(id);
    if (!existing) {
      return c.json({ error: "GitHub access token not found." }, 404);
    }
    store.deleteGitCredential(id);
    store.recordAudit({
      actor: "user",
      action: "git.credential_deleted",
      summary: `Removed GitHub access token "${existing.label}" (${existing.tokenHint})`,
      riskLevel: "medium",
    });
    return c.json({ ok: true });
  });

  app.get("/api/git/repos", async (c) => {
    try {
      const credentialId = c.req.query("credentialId")?.trim() || undefined;
      const query = c.req.query("query")?.trim() || undefined;
      const rawLimit = Number.parseInt(c.req.query("limit") ?? "50", 10);
      const limit = Number.isFinite(rawLimit)
        ? Math.min(Math.max(rawLimit, 1), 100)
        : 50;
      const result = await executor.listGithubRepos({
        ...(credentialId ? { credentialId } : {}),
        ...(query ? { query } : {}),
        limit,
      });
      return c.json(result);
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
        githubConnected: store.listGitCredentials().length > 0,
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
    const domainHttpsReady = Boolean(
      setup.domain && setup.httpsActive && setup.tlsStatus === "active",
    );
    const tailscaleHttpsReady = Boolean(
      setup.tailscaleDomain && setup.tailscaleServeEnabled,
    );
    const domainMcpUrl = setup.domain ? `https://${setup.domain}/mcp` : null;
    const tailscaleMcpUrl = tailscaleHttpsReady
      ? `https://${setup.tailscaleDomain}/mcp`
      : null;
    const primarySource: "domain" | "tailscale" | "local" = domainHttpsReady
      ? "domain"
      : tailscaleHttpsReady
        ? "tailscale"
        : "local";
    const httpsReady = domainHttpsReady || tailscaleHttpsReady;
    const host = getRequestHost(c, trustProxy) || "localhost:3002";
    const mcpUrl = domainHttpsReady
      ? domainMcpUrl!
      : tailscaleHttpsReady
        ? tailscaleMcpUrl!
        : `http://${host}/mcp`;
    return c.json({
      ...buildMcpSetupSnippets(mcpUrl, httpsReady),
      primarySource,
      customDomain: domainMcpUrl
        ? {
            url: domainMcpUrl,
            httpsReady: domainHttpsReady,
            snippets: buildMcpSetupSnippets(domainMcpUrl, domainHttpsReady),
          }
        : null,
      tailscale: tailscaleMcpUrl
        ? {
            url: tailscaleMcpUrl,
            httpsReady: true,
            snippets: buildMcpSetupSnippets(tailscaleMcpUrl, true),
          }
        : null,
    });
  });

  app.post("/api/mcp/test", async (c) => {
    const setup = store.getSetupState();
    const domainHttpsReady = Boolean(
      setup.domain && setup.httpsActive && setup.tlsStatus === "active",
    );
    const tailscaleHttpsReady = Boolean(
      setup.tailscaleDomain && setup.tailscaleServeEnabled,
    );
    const domainMcpUrl = setup.domain ? `https://${setup.domain}/mcp` : null;
    const tailscaleMcpUrl = tailscaleHttpsReady
      ? `https://${setup.tailscaleDomain}/mcp`
      : null;
    const httpsReady = domainHttpsReady || tailscaleHttpsReady;
    const host = getRequestHost(c, trustProxy) || "localhost:3002";
    const mcpUrl = domainHttpsReady
      ? domainMcpUrl!
      : tailscaleHttpsReady
        ? tailscaleMcpUrl!
        : `http://${host}/mcp`;

    let bridgeOk = false;
    try {
      bridgeOk = (await bridge.health()).ok;
    } catch {
      bridgeOk = false;
    }

    const activeTokens = store
      .listMcpTokens()
      .filter((t) => !t.revokedAt).length;
    const ok = bridgeOk && activeTokens > 0;
    const message = !bridgeOk
      ? "The server handyman (Runtime Bridge) is not responding right now."
      : activeTokens === 0
        ? "Gateway is healthy, but you haven't created an AI visitor pass yet."
        : domainHttpsReady && tailscaleHttpsReady
          ? `Server-side gateway check OK: bridge healthy, HTTPS active on both your custom domain and Tailscale, ${MCP_TOOLS.length} tools loaded, ${activeTokens} active pass(es). Use the Curl tab to run a live client handshake.`
          : domainHttpsReady
            ? `Server-side gateway check OK: bridge healthy, HTTPS active, ${MCP_TOOLS.length} tools loaded, ${activeTokens} active pass(es). Use the Curl Test tab to run a live client handshake.`
            : tailscaleHttpsReady
              ? `Server-side gateway check OK: bridge healthy, Tailscale private HTTPS active (${tailscaleMcpUrl}), ${MCP_TOOLS.length} tools loaded, ${activeTokens} active pass(es). Use the Curl tab to run a live client handshake from a device on your tailnet.`
              : `Server-side gateway check OK locally (${MCP_TOOLS.length} tools loaded, ${activeTokens} active pass(es)). Connect a domain or enable Tailscale private HTTPS below for remote access.`;

    return c.json({
      ok,
      mcpUrl,
      domainMcpUrl,
      tailscaleMcpUrl,
      httpsReady,
      bridgeOk,
      toolCount: MCP_TOOLS.length,
      activeTokens,
      protocolVersion: SUPPORTED_MCP_PROTOCOL_VERSIONS[0],
      message,
    });
  });

  // ---------------------------------------------------------------------------
  // Tailscale Private HTTPS Access (Owner-only + strict CSRF/HTTPS guards)
  // ---------------------------------------------------------------------------

  const unavailableTailscaleDetail =
    "The host Runtime Bridge needs a one-time update before Tailscale management can run. Re-run the installer once on your server.";

  const unavailableTailscaleStatus: RuntimeTailscaleStatus = {
    installed: false,
    serviceActive: false,
    connected: false,
    backendState: "not_installed",
    tailscaleIp: null,
    tailscaleIps: [],
    hostname: null,
    dnsName: null,
    tailnetName: null,
    magicDnsEnabled: false,
    httpsCertsAvailable: false,
    loginUrl: null,
    serveEnabled: false,
    serveTarget: null,
    serveUrl: null,
    mcpUrl: null,
    serveConflict: null,
    cliVersion: null,
    detail: unavailableTailscaleDetail,
  };

  const syncSetupWithTailscaleStatus = (
    tsStatus: RuntimeTailscaleStatus,
  ): SetupState => {
    const nextDomain = tsStatus.dnsName || null;
    const nextEnabled = Boolean(tsStatus.serveEnabled && tsStatus.dnsName);
    const current = store.getSetupState();
    if (
      current.tailscaleDomain === nextDomain &&
      current.tailscaleServeEnabled === nextEnabled
    ) {
      return current;
    }
    return store.updateSetupState({
      tailscaleDomain: nextDomain,
      tailscaleServeEnabled: nextEnabled,
    });
  };

  app.get("/api/tailscale/status", async (c) => {
    try {
      if (!bridge.getTailscaleStatus) {
        return c.json({
          status: unavailableTailscaleStatus,
          bridgeSupported: false,
          setup: store.getSetupState(),
        });
      }
      const status = await bridge.getTailscaleStatus();
      const setup = syncSetupWithTailscaleStatus(status);
      return c.json({
        status,
        bridgeSupported: true,
        setup,
      });
    } catch (err) {
      if (err instanceof RuntimeBridgeError && err.statusCode === 404) {
        return c.json({
          status: unavailableTailscaleStatus,
          bridgeSupported: false,
          setup: store.getSetupState(),
        });
      }
      const { status, error } = handleError(err);
      return c.json({ error }, status);
    }
  });

  app.post("/api/tailscale/serve", async (c) => {
    const csrfBlocked = assertSameOriginPost(c);
    if (csrfBlocked) {
      return csrfBlocked;
    }
    try {
      const body = TailscaleServeBodySchema.parse(await c.req.json());
      if (!bridge.setTailscaleServe) {
        return c.json({ error: unavailableTailscaleDetail }, 501);
      }
      const res = await bridge.setTailscaleServe({
        enabled: body.enabled,
        ...(body.force !== undefined ? { force: body.force } : {}),
      });
      const setup = syncSetupWithTailscaleStatus(res.status);
      store.recordAudit({
        actor: "user",
        action: body.enabled
          ? "tailscale.serve_enabled"
          : "tailscale.serve_disabled",
        summary: body.enabled
          ? `Enabled Tailscale private HTTPS access (${res.status.serveUrl || res.status.dnsName || "port 443"})`
          : "Disabled Tailscale private HTTPS access",
        riskLevel: "medium",
      });
      return c.json({
        ok: res.ok,
        status: res.status,
        actionUrl: res.actionUrl,
        setup,
      });
    } catch (err) {
      if (err instanceof RuntimeBridgeError && err.statusCode === 404) {
        return c.json({ error: unavailableTailscaleDetail }, 501);
      }
      const { status, error } = handleError(err);
      return c.json({ error }, status);
    }
  });

  app.post("/api/tailscale/connect", async (c) => {
    try {
      assertSecureTransport(c, transportOptions);
    } catch (err) {
      return c.json(
        { error: err instanceof Error ? err.message : "HTTPS required." },
        403,
      );
    }
    const csrfBlocked = assertSameOriginPost(c);
    if (csrfBlocked) {
      return csrfBlocked;
    }

    let rawAuthKey: string | undefined;
    try {
      const body = TailscaleConnectBodySchema.parse(await c.req.json());
      if (body.mode === "authkey") {
        if (!body.authKey) {
          return c.json(
            { error: "A Tailscale auth key (tskey-auth-...) is required." },
            400,
          );
        }
        rawAuthKey = validateTailscaleAuthKey(body.authKey);
      }
      if (!bridge.connectTailscale) {
        return c.json({ error: unavailableTailscaleDetail }, 501);
      }
      const res = await bridge.connectTailscale({
        mode: body.mode,
        ...(rawAuthKey !== undefined ? { authKey: rawAuthKey } : {}),
      });
      const setup = syncSetupWithTailscaleStatus(res.status);
      store.recordAudit({
        actor: "user",
        action: res.status.connected
          ? "tailscale.connected"
          : "tailscale.login_started",
        summary: res.status.connected
          ? `Connected Tailscale (${res.status.dnsName || res.status.tailscaleIp || "tailnet"})`
          : "Started Tailscale interactive sign-in",
        riskLevel: "medium",
      });
      return c.json({
        ok: res.ok,
        status: res.status,
        loginUrl: res.loginUrl,
        setup,
      });
    } catch (err) {
      if (err instanceof RuntimeBridgeError && err.statusCode === 404) {
        return c.json({ error: unavailableTailscaleDetail }, 501);
      }
      const { status, error } = handleError(err);
      return c.json({ error: scrubTokenFromText(error, rawAuthKey) }, status);
    }
  });

  // ---------------------------------------------------------------------------
  // VPSAgent Self-Update (Owner-only + strict same-origin CSRF guard)
  // ---------------------------------------------------------------------------

  const installedVersion = readInstalledPackageVersion();
  const unavailableUpdateStatus = {
    state: "idle" as const,
    phase: null,
    canUpdate: false,
    unavailableReason:
      "The host Runtime Bridge needs a one-time update before dashboard updates can run. Re-run the installer once on your server.",
    repoDir: null,
    branch: null,
    updateSource: "none" as const,
    releaseRepo: null,
    releaseStatus: "unchecked" as const,
    releaseNote: null,
    installedFrom: "unknown" as const,
    currentVersion: installedVersion,
    currentReleaseTag: null,
    currentCommit: null,
    latestVersion: null,
    latestReleaseTag: null,
    latestReleaseName: null,
    latestReleaseUrl: null,
    latestReleaseNotes: null,
    latestReleasePublishedAt: null,
    latestReleasePrerelease: false,
    latestReleaseAssetName: null,
    checksumAvailable: false,
    checksumStatus: "none" as const,
    checksumSha256: null,
    latestCommit: null,
    latestCommitSubject: null,
    latestCommitDate: null,
    commitsBehind: 0,
    updateAvailable: false,
    dirtyWorkingTree: false,
    checkedAt: null,
    startedAt: null,
    finishedAt: null,
    message: null,
    error: null,
    logs: [] as string[],
  };

  app.get("/api/system/update/status", async (c) => {
    try {
      if (!bridge.getCoreUpdateStatus) {
        return c.json({ status: unavailableUpdateStatus });
      }
      const status = await bridge.getCoreUpdateStatus();
      return c.json({
        status: {
          ...status,
          currentVersion: status.currentVersion ?? installedVersion,
        },
      });
    } catch (err) {
      if (err instanceof RuntimeBridgeError && err.statusCode === 404) {
        return c.json({ status: unavailableUpdateStatus });
      }
      const { status, error } = handleError(err);
      return c.json({ error }, status);
    }
  });

  app.post("/api/system/update/check", async (c) => {
    const csrfBlocked = assertSameOriginPost(c);
    if (csrfBlocked) {
      return csrfBlocked;
    }
    try {
      if (!bridge.checkCoreUpdate) {
        return c.json({ status: unavailableUpdateStatus });
      }
      const status = await bridge.checkCoreUpdate();
      return c.json({
        status: {
          ...status,
          currentVersion: status.currentVersion ?? installedVersion,
        },
      });
    } catch (err) {
      if (err instanceof RuntimeBridgeError && err.statusCode === 404) {
        return c.json({ status: unavailableUpdateStatus });
      }
      const { status, error } = handleError(err);
      return c.json({ error }, status);
    }
  });

  app.post("/api/system/update/apply", async (c) => {
    const csrfBlocked = assertSameOriginPost(c);
    if (csrfBlocked) {
      return csrfBlocked;
    }
    try {
      if (!bridge.applyCoreUpdate) {
        return c.json(
          { error: unavailableUpdateStatus.unavailableReason },
          501,
        );
      }
      let applyInput: { source?: "auto" | "release" | "git" | undefined } | undefined;
      const rawBody = await c.req.text();
      if (rawBody.trim()) {
        let parsedJson: unknown;
        try {
          parsedJson = JSON.parse(rawBody);
        } catch {
          return c.json({ error: "Invalid JSON body." }, 400);
        }
        const parsedBody = ApplySystemUpdateBodySchema.parse(parsedJson);
        if (parsedBody.source !== undefined) {
          applyInput = { source: parsedBody.source };
        }
      }
      const result = await bridge.applyCoreUpdate(applyInput);
      const releaseSummary =
        result.status.updateSource === "release" &&
        result.status.latestReleaseTag
          ? `Started VPSAgent self-update to release ${result.status.latestReleaseTag}`
          : null;
      store.recordAudit({
        actor: "user",
        action: "system.update_started",
        summary:
          releaseSummary ??
          (result.status.branch
            ? `Started VPSAgent self-update from branch ${result.status.branch}`
            : "Started VPSAgent self-update"),
        riskLevel: "high",
      });
      return c.json(result, 202);
    } catch (err) {
      if (err instanceof RuntimeBridgeError && err.statusCode === 404) {
        return c.json(
          { error: unavailableUpdateStatus.unavailableReason },
          501,
        );
      }
      const { status, error } = handleError(err);
      return c.json({ error }, status);
    }
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
