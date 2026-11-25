import type { Context } from "hono";
import { z } from "zod";
import {
  type ApprovalActionType,
  type McpTokenRecord,
  type RegistryStore,
  type RiskLevel,
  type RuntimeBridge,
  canScopeMutate,
  isSlugAllowedForToken,
  redactSecrets,
  redactStructuredValue,
  requiresApprovalForScope,
  syncAppStatuses,
  validateAppSlug,
} from "@vpsagent/shared";
import {
  type TransportContextOptions,
  assertSecureTransport,
  validateMcpHostAndOrigin,
} from "./auth.js";
import {
  type AppExecutor,
  DeployAppInputSchema,
  InspectGitInputSchema,
  UpdateAppEnvInputSchema,
} from "./executor.js";

export const SUPPORTED_MCP_PROTOCOL_VERSIONS = [
  "2025-11-25",
  "2025-06-18",
  "2025-03-26",
] as const;
const DEFAULT_MCP_PROTOCOL_VERSION = SUPPORTED_MCP_PROTOCOL_VERSIONS[0];
const MAX_MCP_LOG_REPLY_BYTES = 48 * 1024;
const DEFAULT_MCP_DEPLOY_GRACE_MS = 10_000;

export const MCP_SERVER_INSTRUCTIONS = [
  "VPSAgent runs every app inside an isolated Locked Apartment container (no root capabilities, no Docker socket, isolated network, automatic HTTPS via Caddy).",
  "Recommended workflow for deploying a public GitHub repo:",
  "1. Call get_server_info to check available server resources, default apps base domain (if configured), and your pass permissions / allowed apps.",
  "2. Call inspect_git_repo first to preview the repo's detected runtime (Dockerfile, Next.js, Vite, Node.js, Python, or static HTML), suggested port, database companion hints, and .env.example key names.",
  "3. Call deploy_app (sourceType: 'git'). If no Dockerfile exists, VPSAgent auto-generates a safe non-root build recipe and detects the internal port automatically. If an appsBaseDomain is configured and you omit domain, VPSAgent assigns https://<slug>.<appsBaseDomain> automatically (pass noDomain: true or domain: null for a private app).",
  "4. Long builds continue safely in the background and return status 'deploying' with a deploymentId so your tool call never times out. Poll get_deployment(deploymentId) until status is 'succeeded' or 'failed' and inspect buildLogs if anything fails.",
  "5. Security rule for secrets: NEVER ask the user to paste secret API keys or passwords into chat if envSettingsUrl is provided. Share envSettingsUrl so the user can enter secrets directly into the encrypted VPSAgent dashboard.",
].join("\n");

const JsonRpcRequestSchema = z.object({
  jsonrpc: z.literal("2.0"),
  id: z.union([z.string().max(256), z.number().finite(), z.null()]).optional(),
  method: z.string().min(1),
  params: z.record(z.string(), z.unknown()).optional(),
});

interface McpToolDefinition {
  name: string;
  description: string;
  inputSchema: Record<string, unknown>;
}

export const MCP_TOOLS: McpToolDefinition[] = [
  {
    name: "get_server_info",
    description:
      "Read VPSAgent server capabilities, live CPU/RAM/disk headroom, configured default apps base domain, dashboard URL, and your current visitor pass permissions and app restrictions.",
    inputSchema: { type: "object", properties: {}, additionalProperties: false },
  },
  {
    name: "get_host_health",
    description:
      "Read live server CPU, memory, uptime, disk space, and running app counts.",
    inputSchema: { type: "object", properties: {}, additionalProperties: false },
  },
  {
    name: "inspect_git_repo",
    description:
      "Inspect a public HTTPS GitHub repository before deploying. Detects Dockerfile or auto-build runtime (Next.js, Vite, Node.js, Python, static HTML), suggested port, slug/name, database hints, preview domain, and .env.example key names (never values).",
    inputSchema: {
      type: "object",
      properties: {
        gitRepoUrl: {
          type: "string",
          description: "Public HTTPS GitHub repository URL",
        },
        gitBranch: {
          type: "string",
          description: "Optional branch name (defaults to repository default branch)",
        },
        dockerfilePath: {
          type: "string",
          description: "Optional Dockerfile path (defaults to Dockerfile / auto-detect)",
        },
      },
      required: ["gitRepoUrl"],
    },
  },
  {
    name: "list_apps",
    description:
      "List apps managed by VPSAgent (scoped to your visitor pass's allowed apps if restricted) with live status, commit SHA, and detected runtime.",
    inputSchema: { type: "object", properties: {}, additionalProperties: false },
  },
  {
    name: "get_deployment",
    description:
      "Check live progress, phase, commit SHA, detected runtime, redacted build logs, live URL, and missing secret settings link for a deployment ID.",
    inputSchema: {
      type: "object",
      properties: {
        deploymentId: {
          type: "string",
          description: "Deployment ID returned by deploy_app or rebuild_app (e.g. dep_...)",
        },
      },
      required: ["deploymentId"],
    },
  },
  {
    name: "list_deployments",
    description:
      "List recent deployments and build statuses, optionally filtered by app slug.",
    inputSchema: {
      type: "object",
      properties: {
        slug: { type: "string", description: "Optional app slug filter" },
        limit: {
          type: "integer",
          minimum: 1,
          maximum: 50,
          default: 10,
        },
      },
    },
  },
  {
    name: "get_app_logs",
    description:
      "Read recent container logs for an app (all secrets are automatically scrubbed and output is byte-budgeted).",
    inputSchema: {
      type: "object",
      properties: {
        slug: { type: "string", description: "App slug identifier" },
        tail: {
          type: "integer",
          minimum: 1,
          maximum: 500,
          default: 100,
          description: "Number of recent log lines to return",
        },
      },
      required: ["slug"],
    },
  },
  {
    name: "inspect_app",
    description:
      "Inspect an app's live container health, Locked Apartment security compliance, masked env variable names, missing .env.example keys, and direct dashboard secrets link.",
    inputSchema: {
      type: "object",
      properties: {
        slug: { type: "string" },
        probeHttp: { type: "boolean", default: false },
        probePath: { type: "string", default: "/" },
      },
      required: ["slug"],
    },
  },
  {
    name: "list_approvals",
    description: "List pending and recent approval requests in the dashboard queue.",
    inputSchema: {
      type: "object",
      properties: {
        status: {
          type: "string",
          enum: ["pending", "approved", "rejected", "executed", "failed"],
        },
      },
    },
  },
  {
    name: "deploy_app",
    description:
      "Deploy a prebuilt Docker image or a public HTTPS GitHub repo (with a Dockerfile OR auto-detected Next.js/Vite/Node/Python/static site) into a Locked Apartment. Long builds continue in the background and return a deploymentId to poll via get_deployment.",
    inputSchema: {
      type: "object",
      properties: {
        slug: { type: "string" },
        name: { type: "string" },
        sourceType: { type: "string", enum: ["image", "git"] },
        image: { type: "string" },
        gitRepoUrl: { type: "string" },
        gitBranch: { type: "string" },
        dockerfilePath: {
          type: "string",
          default: "auto",
          description:
            "Relative Dockerfile path, or 'auto' to use repo Dockerfile if present and auto-detect otherwise.",
        },
        domain: {
          type: ["string", "null"],
          description:
            "Custom domain, omit to auto-use <slug>.<appsBaseDomain> when configured, or pass null for private app.",
        },
        noDomain: {
          type: "boolean",
          description: "Set true to keep app private with no public domain even if appsBaseDomain is configured.",
        },
        internalPort: {
          type: "integer",
          description:
            "Container internal port (optional for GitHub repos — auto-detected when omitted).",
        },
        probeHttp: { type: "boolean", default: true },
        probePath: { type: "string", default: "/" },
        cpuLimit: { type: "string", default: "0.5" },
        memoryLimitMb: { type: "integer", default: 512 },
        companions: {
          type: "array",
          items: {
            type: "object",
            properties: {
              type: { type: "string", enum: ["postgres", "redis"] },
              version: { type: "string" },
              envKey: { type: "string" },
            },
            required: ["type"],
          },
        },
        envVars: {
          type: "object",
          additionalProperties: { type: "string" },
        },
      },
      required: ["slug", "name", "sourceType"],
    },
  },
  {
    name: "rebuild_app",
    description:
      "Rebuild and restart an existing app (re-cloning Git if applicable). Returns a deploymentId if the build continues in the background.",
    inputSchema: {
      type: "object",
      properties: { slug: { type: "string" } },
      required: ["slug"],
    },
  },
  {
    name: "update_app_env",
    description:
      "Set or remove encrypted environment variables for an app and re-apply its .env file.",
    inputSchema: {
      type: "object",
      properties: {
        slug: { type: "string" },
        vars: {
          type: "array",
          items: {
            type: "object",
            properties: {
              key: { type: "string" },
              value: { type: "string" },
              isSecret: { type: "boolean" },
            },
            required: ["key", "value"],
          },
        },
        deleteKeys: { type: "array", items: { type: "string" } },
      },
      required: ["slug"],
    },
  },
  {
    name: "set_app_domain",
    description: "Connect a public HTTPS domain to an app, or pass null to unroute it.",
    inputSchema: {
      type: "object",
      properties: {
        slug: { type: "string" },
        domain: { type: ["string", "null"] },
      },
      required: ["slug", "domain"],
    },
  },
  {
    name: "restart_app",
    description: "Restart an app container.",
    inputSchema: {
      type: "object",
      properties: { slug: { type: "string" } },
      required: ["slug"],
    },
  },
  {
    name: "stop_app",
    description: "Stop an app container.",
    inputSchema: {
      type: "object",
      properties: { slug: { type: "string" } },
      required: ["slug"],
    },
  },
  {
    name: "delete_app",
    description:
      "Stop and remove an app, its web route, and optionally its files. Always requires human approval for safe-auto-deploy and approval-required passes.",
    inputSchema: {
      type: "object",
      properties: {
        slug: { type: "string" },
        removeFiles: { type: "boolean", default: true },
      },
      required: ["slug"],
    },
  },
];

function jsonRpcResult(id: string | number | null, result: unknown) {
  return { jsonrpc: "2.0", id, result };
}

function jsonRpcError(
  id: string | number | null,
  code: number,
  message: string,
) {
  return {
    jsonrpc: "2.0",
    id,
    error: { code, message: redactSecrets(message) },
  };
}

function toolOk(data: unknown) {
  const safe = redactStructuredValue(data);
  return {
    content: [{ type: "text", text: JSON.stringify(safe, null, 2) }],
    isError: false,
  };
}

function toolErr(message: string) {
  return {
    content: [{ type: "text", text: redactSecrets(message) }],
    isError: true,
  };
}

/**
 * Builds a dedicated, safe approval preview for the dashboard UI so environment
 * values marked secret (regardless of key name) or deploy env values never leak.
 */
export function buildSafeApprovalPreview(
  action: ApprovalActionType,
  rawPayload: Record<string, unknown>,
): Record<string, unknown> {
  if (action === "update_env") {
    const vars = Array.isArray(rawPayload.vars) ? rawPayload.vars : [];
    const safeVars = vars.map((entry) => {
      if (!entry || typeof entry !== "object") return entry;
      const item = entry as {
        key?: unknown;
        value?: unknown;
        isSecret?: unknown;
      };
      const key = String(item.key ?? "");
      const markedSecret = item.isSecret !== false;
      const rawVal = typeof item.value === "string" ? item.value : "";
      return {
        key,
        isSecret: markedSecret,
        value: markedSecret ? "[REDACTED]" : redactSecrets(rawVal),
      };
    });
    return {
      slug: rawPayload.slug,
      vars: safeVars,
      deleteKeys: Array.isArray(rawPayload.deleteKeys)
        ? rawPayload.deleteKeys
        : [],
    };
  }

  if (action === "deploy_app") {
    const copy = { ...rawPayload };
    if (copy.envVars && typeof copy.envVars === "object") {
      const maskedEnv: Record<string, string> = {};
      for (const key of Object.keys(copy.envVars as Record<string, unknown>)) {
        maskedEnv[key] = "[REDACTED]";
      }
      copy.envVars = maskedEnv;
    }
    return redactStructuredValue(copy) as Record<string, unknown>;
  }

  return redactStructuredValue(rawPayload) as Record<string, unknown>;
}

/**
 * Budgets the ACTUAL FINAL WIRE JSON-RPC RESPONSE bytes (including double JSON
 * escaping when `toolOk` serializes the text payload inside the JSON-RPC envelope),
 * keeping the newest lines and setting `truncated: true` if anything was trimmed.
 */
function budgetWireLogsResponse(
  rpcId: string | number | null,
  slug: string,
  lines: string[],
  alreadyTruncated: boolean,
  maxWireBytes = MAX_MCP_LOG_REPLY_BYTES,
): { slug: string; lines: string[]; truncated: boolean } {
  const measureWireBytes = (
    candidateLines: string[],
    truncated: boolean,
  ): number =>
    Buffer.byteLength(
      JSON.stringify(
        jsonRpcResult(
          rpcId,
          toolOk({ slug, lines: candidateLines, truncated }),
        ),
      ),
      "utf8",
    );

  if (measureWireBytes(lines, alreadyTruncated) <= maxWireBytes) {
    return { slug, lines, truncated: alreadyTruncated };
  }

  // Binary search for the largest suffix (newest lines) that fits within maxWireBytes
  let lo = 0;
  let hi = lines.length;
  while (lo < hi) {
    const mid = Math.ceil((lo + hi) / 2);
    const slice = lines.slice(lines.length - mid);
    if (measureWireBytes(slice, true) <= maxWireBytes) {
      lo = mid;
    } else {
      hi = mid - 1;
    }
  }

  if (lo > 0) {
    return { slug, lines: lines.slice(lines.length - lo), truncated: true };
  }

  // Even the single newest line exceeds the budget once JSON-escaped -> trim it safely
  const newest = lines.at(-1) ?? "";
  let charLo = 0;
  let charHi = newest.length;
  while (charLo < charHi) {
    const mid = Math.ceil((charLo + charHi) / 2);
    const trimmed = [`${newest.slice(0, mid)}...`];
    if (measureWireBytes(trimmed, true) <= maxWireBytes) {
      charLo = mid;
    } else {
      charHi = mid - 1;
    }
  }
  const finalLines = charLo > 0 ? [`${newest.slice(0, charLo)}...`] : [];
  if (measureWireBytes(finalLines, true) > maxWireBytes) {
    throw new Error(
      `Log response envelope exceeds maximum allowed wire budget (${maxWireBytes} bytes).`,
    );
  }
  return {
    slug,
    lines: finalLines,
    truncated: true,
  };
}

export interface McpSetupSnippets {
  mcpUrl: string;
  httpsReady: boolean;
  claudeCode: string;
  cursor: string;
  codex: string;
  genericHttp: string;
}

/** Builds ready-to-paste client setup snippets for Claude Code, Cursor, Codex, and generic MCP clients (e.g. T3 Code). */
export function buildMcpSetupSnippets(
  mcpUrl: string,
  httpsReady: boolean,
): McpSetupSnippets {
  const cleanUrl = mcpUrl.replace(/\/+$/, "");
  const tokenPlaceholder = "vpsmcp_YOUR_TOKEN_HERE";

  return {
    mcpUrl: cleanUrl,
    httpsReady,
    claudeCode: `claude mcp add --transport http vpsagent ${cleanUrl} \\\n  --header "Authorization: Bearer ${tokenPlaceholder}"`,
    cursor: JSON.stringify(
      {
        mcpServers: {
          vpsagent: {
            url: cleanUrl,
            headers: {
              Authorization: `Bearer ${tokenPlaceholder}`,
            },
          },
        },
      },
      null,
      2,
    ),
    codex: `[mcp_servers.vpsagent]\nurl = "${cleanUrl}"\nbearer_token_env_var = "VPSAGENT_MCP_TOKEN"\n\n# In your shell:\n# export VPSAGENT_MCP_TOKEN="${tokenPlaceholder}"`,
    genericHttp: JSON.stringify(
      {
        name: "vpsagent",
        transport: "streamable-http",
        url: cleanUrl,
        headers: {
          Authorization: `Bearer ${tokenPlaceholder}`,
        },
      },
      null,
      2,
    ),
  };
}

export interface McpGatewayDeps {
  store: RegistryStore;
  bridge: RuntimeBridge;
  executor: AppExecutor;
  transportOptions: TransportContextOptions;
  mcpDeployGraceMs?: number | undefined;
}

function buildDashboardBaseUrl(store: RegistryStore): string | null {
  const setup = store.getSetupState();
  if (setup.domain && setup.httpsActive && setup.tlsStatus === "active") {
    return `https://${setup.domain}`;
  }
  if (setup.domain) {
    return `https://${setup.domain}`;
  }
  return null;
}

function buildEnvSettingsUrl(store: RegistryStore, slug: string): string {
  const base = buildDashboardBaseUrl(store);
  const hash = `/#apps/${encodeURIComponent(slug)}/env`;
  return base ? `${base}${hash}` : hash;
}

function buildDeploymentsUrl(store: RegistryStore, slug: string): string {
  const base = buildDashboardBaseUrl(store);
  const hash = `/#apps/${encodeURIComponent(slug)}/deployments`;
  return base ? `${base}${hash}` : hash;
}

export function enforceMcpBoundary(
  c: Context,
  store: RegistryStore,
  transportOptions: TransportContextOptions,
): { ok: true } | { ok: false; response: Response } {
  const setup = store.getSetupState();
  try {
    const transport = assertSecureTransport(c, transportOptions);
    validateMcpHostAndOrigin(c, {
      setupDomain: setup.domain,
      httpsActive: setup.httpsActive,
      transport,
      trustProxy: transportOptions.trustProxy,
    });
    return { ok: true };
  } catch (err) {
    return {
      ok: false,
      response: c.json(
        {
          error:
            err instanceof Error
              ? err.message
              : "Forbidden MCP request host, origin, or transport.",
        },
        403,
      ),
    };
  }
}

export function createMcpPostHandler(deps: McpGatewayDeps) {
  const { store, bridge, executor, transportOptions } = deps;
  const deployGraceMs = deps.mcpDeployGraceMs ?? DEFAULT_MCP_DEPLOY_GRACE_MS;

  function checkSlugAccess(
    token: McpTokenRecord,
    slug: string,
    toolName: string,
  ): ReturnType<typeof toolErr> | null {
    if (isSlugAllowedForToken(token, slug)) {
      return null;
    }
    store.recordAudit({
      actor: "agent",
      actorTokenId: token.id,
      action: "mcp.blocked_app_scope",
      targetSlug: slug,
      summary: `Blocked AI pass "${token.name}" from running ${toolName} on app "${slug}" (allowed: ${token.allowedSlugs.join(", ")})`,
      riskLevel: "high",
    });
    return toolErr(
      `Permission denied: visitor pass "${token.name}" is locked to [${token.allowedSlugs.join(", ")}] and cannot access app "${slug}".`,
    );
  }

  async function handleMutation(
    token: McpTokenRecord,
    input: {
      action: ApprovalActionType;
      targetSlug: string | null;
      summary: string;
      payload: Record<string, unknown>;
      riskLevel: RiskLevel;
      run: () => Promise<unknown>;
    },
  ) {
    if (input.targetSlug) {
      const denied = checkSlugAccess(token, input.targetSlug, input.action);
      if (denied) {
        return denied;
      }
    }

    if (!canScopeMutate(token.scope)) {
      store.recordAudit({
        actor: "agent",
        actorTokenId: token.id,
        action: "mcp.blocked_mutation",
        targetSlug: input.targetSlug,
        summary: `Blocked read-only key "${token.name}" from running ${input.action}`,
        riskLevel: "high",
      });
      return toolErr(
        `Permission denied: key "${token.name}" is read-only and cannot perform or queue "${input.action}".`,
      );
    }

    if (requiresApprovalForScope(token.scope, input.action)) {
      const safePreview = buildSafeApprovalPreview(input.action, input.payload);
      const approval = store.createApproval({
        action: input.action,
        targetSlug: input.targetSlug,
        summary: input.summary,
        payload: safePreview,
        executionPayload: input.payload,
        requestedBy: token.name,
        tokenId: token.id,
        tokenScope: token.scope,
        riskLevel: input.riskLevel,
      });
      store.recordAudit({
        actor: "agent",
        actorTokenId: token.id,
        action: "approval.requested",
        targetSlug: input.targetSlug,
        summary: `AI key "${token.name}" requested approval (${approval.id}): ${input.summary}`,
        riskLevel: input.riskLevel,
      });
      return toolOk({
        status: "pending_approval",
        approvalId: approval.id,
        action: approval.action,
        targetSlug: approval.targetSlug,
        message:
          input.action === "delete_app" && token.scope === "safe-auto-deploy"
            ? "Deleting an app always requires human confirmation under Safe Auto-Deploy. Ask the server owner to review and click Approve in the VPSAgent dashboard."
            : "Action queued for human approval. Ask the server owner to click Approve in the VPSAgent dashboard.",
      });
    }

    const result = await input.run();
    if (
      result &&
      typeof result === "object" &&
      "status" in result &&
      (result as { status: unknown }).status === "deploying"
    ) {
      return toolOk(result);
    }
    return toolOk({ status: "executed", result });
  }

  return async (c: Context) => {
    const guard = enforceMcpBoundary(c, store, transportOptions);
    if (!guard.ok) {
      return guard.response;
    }

    const authHeader = c.req.header("authorization") ?? "";
    const match = authHeader.match(/^Bearer\s+(.+)$/i);
    const rawToken = match?.[1]?.trim();
    if (!rawToken) {
      return c.json({ error: "Missing Bearer token." }, 401);
    }

    const token = store.verifyMcpToken(rawToken);
    if (!token) {
      return c.json({ error: "Invalid or revoked MCP token." }, 401);
    }

    let body: unknown;
    try {
      body = await c.req.json();
    } catch {
      return c.json(jsonRpcError(null, -32700, "Invalid JSON payload."), 400);
    }

    const parsed = JsonRpcRequestSchema.safeParse(body);
    if (!parsed.success) {
      return c.json(
        jsonRpcError(null, -32600, "Invalid JSON-RPC 2.0 request."),
        400,
      );
    }

    const { id = null, method, params = {} } = parsed.data;

    // Validate MCP-Protocol-Version header on post-initialize requests (Streamable HTTP spec)
    const headerVersion = c.req.header("mcp-protocol-version")?.trim();
    if (method !== "initialize" && headerVersion) {
      if (
        !(SUPPORTED_MCP_PROTOCOL_VERSIONS as readonly string[]).includes(
          headerVersion,
        )
      ) {
        return c.json(
          {
            error: `Unsupported MCP-Protocol-Version "${headerVersion}". Supported: ${SUPPORTED_MCP_PROTOCOL_VERSIONS.join(", ")}.`,
          },
          400,
        );
      }
      c.header("MCP-Protocol-Version", headerVersion);
    }

    if (method === "notifications/initialized") {
      return c.body(null, 202);
    }

    if (method === "ping") {
      return c.json(jsonRpcResult(id, {}));
    }

    if (method === "initialize") {
      const requestedVersion =
        typeof params.protocolVersion === "string"
          ? params.protocolVersion.trim()
          : "";
      const negotiatedVersion = (
        SUPPORTED_MCP_PROTOCOL_VERSIONS as readonly string[]
      ).includes(requestedVersion)
        ? requestedVersion
        : DEFAULT_MCP_PROTOCOL_VERSION;
      c.header("MCP-Protocol-Version", negotiatedVersion);
      return c.json(
        jsonRpcResult(id, {
          protocolVersion: negotiatedVersion,
          serverInfo: {
            name: "vpsagent",
            version: "2.1.0",
          },
          capabilities: {
            tools: {},
          },
          instructions: MCP_SERVER_INSTRUCTIONS,
        }),
      );
    }

    if (method === "tools/list") {
      return c.json(jsonRpcResult(id, { tools: MCP_TOOLS }));
    }

    if (method !== "tools/call") {
      return c.json(
        jsonRpcError(id, -32601, `Method "${method}" not found.`),
        200,
      );
    }

    const toolName = typeof params.name === "string" ? params.name : "";
    const args =
      params.arguments && typeof params.arguments === "object"
        ? (params.arguments as Record<string, unknown>)
        : {};

    try {
      let callResult: ReturnType<typeof toolOk>;

      switch (toolName) {
        case "get_server_info": {
          const [stats, allApps] = await Promise.all([
            bridge.getHostStats(),
            syncAppStatuses(store, bridge),
          ]);
          const visibleApps = allApps.filter((a) =>
            isSlugAllowedForToken(token, a.slug),
          );
          const setup = store.getSetupState();
          callResult = toolOk({
            server: {
              dashboardUrl: buildDashboardBaseUrl(store),
              appsBaseDomain: setup.appsBaseDomain,
              httpsActive: setup.httpsActive,
              tlsStatus: setup.tlsStatus,
              publicReposSupported: true,
              privateReposSupported: false,
              autoDetectedRuntimes: [
                "dockerfile",
                "nextjs",
                "vite-static",
                "node",
                "python",
                "static",
              ],
              supportedCompanions: ["postgres", "redis"],
              defaultLimits: { cpuLimit: "0.5", memoryLimitMb: 512 },
            },
            visitorPass: {
              name: token.name,
              scope: token.scope,
              allowedSlugs: token.allowedSlugs,
              restrictedToSpecificApps: token.allowedSlugs.length > 0,
              deleteRequiresApproval:
                token.scope === "approval-required" ||
                token.scope === "safe-auto-deploy",
            },
            host: stats,
            apps: {
              totalVisible: visibleApps.length,
              running: visibleApps.filter((a) => a.status === "running").length,
            },
          });
          break;
        }

        case "get_host_health": {
          const [stats, allApps] = await Promise.all([
            bridge.getHostStats(),
            syncAppStatuses(store, bridge),
          ]);
          const apps = allApps.filter((a) =>
            isSlugAllowedForToken(token, a.slug),
          );
          callResult = toolOk({
            ...stats,
            appCount: apps.length,
            runningApps: apps.filter((a) => a.status === "running").length,
          });
          break;
        }

        case "inspect_git_repo": {
          const parsedInput = InspectGitInputSchema.parse(args);
          const inspected = await executor.inspectGitRepo(parsedInput);
          callResult = toolOk({
            ...inspected,
            canDeployWithCurrentPass:
              canScopeMutate(token.scope) &&
              isSlugAllowedForToken(token, inspected.suggestedSlug),
            secretHandlingHint:
              inspected.envExampleKeys.length > 0
                ? "This repository lists settings in .env.example. After deploying, share the returned envSettingsUrl with the server owner so they can enter private API keys directly in the encrypted dashboard instead of pasting secrets into chat."
                : null,
          });
          break;
        }

        case "list_apps": {
          const allApps = await syncAppStatuses(store, bridge);
          const apps = allApps.filter((a) =>
            isSlugAllowedForToken(token, a.slug),
          );
          callResult = toolOk({ apps });
          break;
        }

        case "get_deployment": {
          const deploymentId = String(args.deploymentId ?? "").trim();
          if (!deploymentId) {
            callResult = toolErr("Field 'deploymentId' is required.");
            break;
          }
          const deployment = store.getDeployment(deploymentId);
          if (!deployment) {
            callResult = toolErr(`Deployment "${deploymentId}" not found.`);
            break;
          }
          const denied = checkSlugAccess(token, deployment.slug, toolName);
          if (denied) {
            callResult = denied;
            break;
          }
          const app = store.getApp(deployment.slug);
          const missingEnvKeys = executor.getMissingEnvKeys(deployment.slug);
          callResult = toolOk({
            deployment,
            app,
            liveUrl: app?.domain ? `https://${app.domain}` : null,
            missingEnvKeys,
            envSettingsUrl:
              missingEnvKeys.length > 0
                ? buildEnvSettingsUrl(store, deployment.slug)
                : null,
            deploymentsUrl: buildDeploymentsUrl(store, deployment.slug),
          });
          break;
        }

        case "list_deployments": {
          const rawSlug =
            typeof args.slug === "string" && args.slug.trim()
              ? validateAppSlug(args.slug.trim())
              : undefined;
          if (rawSlug) {
            const denied = checkSlugAccess(token, rawSlug, toolName);
            if (denied) {
              callResult = denied;
              break;
            }
          }
          const rawLimit =
            typeof args.limit === "number"
              ? Math.min(Math.max(Math.trunc(args.limit), 1), 50)
              : 10;
          const deployments = store
            .listDeployments({
              ...(rawSlug ? { slug: rawSlug } : {}),
              limit: rawLimit,
            })
            .filter((d) => isSlugAllowedForToken(token, d.slug));
          callResult = toolOk({ deployments });
          break;
        }

        case "get_app_logs": {
          const slug = validateAppSlug(String(args.slug ?? ""));
          const denied = checkSlugAccess(token, slug, toolName);
          if (denied) {
            callResult = denied;
            break;
          }
          const tail =
            typeof args.tail === "number"
              ? Math.min(Math.max(Math.trunc(args.tail), 1), 500)
              : 100;
          const detailed = bridge.getLogsDetailed
            ? await bridge.getLogsDetailed(slug, tail)
            : { slug, lines: await bridge.getLogs(slug, tail), truncated: false };
          const budgeted = budgetWireLogsResponse(
            id,
            slug,
            detailed.lines,
            Boolean(detailed.truncated),
          );
          callResult = toolOk(budgeted);
          break;
        }

        case "inspect_app": {
          const slug = validateAppSlug(String(args.slug ?? ""));
          const denied = checkSlugAccess(token, slug, toolName);
          if (denied) {
            callResult = denied;
            break;
          }
          const app = store.getApp(slug);
          const inspect = await bridge.inspectWorkload(slug, {
            probeHttp:
              typeof args.probeHttp === "boolean"
                ? args.probeHttp
                : (app?.probeHttp ?? false),
            internalPort: app?.internalPort ?? 8080,
            probePath:
              typeof args.probePath === "string"
                ? args.probePath
                : (app?.probePath ?? "/"),
          });
          const envVars = store.listAppEnvVars(slug);
          const missingEnvKeys = executor.getMissingEnvKeys(slug);
          callResult = toolOk({
            app,
            inspect,
            envVars,
            liveUrl: app?.domain ? `https://${app.domain}` : null,
            missingEnvKeys,
            envSettingsUrl:
              missingEnvKeys.length > 0 ? buildEnvSettingsUrl(store, slug) : null,
            recentDeployments: store.listDeployments({ slug, limit: 5 }),
          });
          break;
        }

        case "list_approvals": {
          const status =
            typeof args.status === "string"
              ? (args.status as
                  | "pending"
                  | "approved"
                  | "rejected"
                  | "executed"
                  | "failed")
              : undefined;
          const approvals = store
            .listApprovals(status ? { status, limit: 50 } : { limit: 50 })
            .filter(
              (a) =>
                !a.targetSlug || isSlugAllowedForToken(token, a.targetSlug),
            );
          callResult = toolOk({ approvals });
          break;
        }

        case "deploy_app": {
          const input = DeployAppInputSchema.parse(args);
          const slug = validateAppSlug(input.slug);
          callResult = await handleMutation(token, {
            action: "deploy_app",
            targetSlug: slug,
            summary: `Deploy ${input.sourceType} app "${input.name}" (${slug})`,
            payload: input as unknown as Record<string, unknown>,
            riskLevel: "medium",
            run: async () => {
              const started = await executor.startDeployApp(input, "agent", {
                actorTokenId: token.id,
                waitMs: deployGraceMs,
                throwOnImmediateFailure: true,
              });
              if (!started.done) {
                return {
                  status: "deploying",
                  deploymentId: started.deployment.id,
                  deployment: started.deployment,
                  slug,
                  deploymentsUrl: buildDeploymentsUrl(store, slug),
                  nextStep:
                    "Build is continuing in the background so your tool call does not time out. Poll get_deployment with this deploymentId to check live progress and build logs.",
                };
              }
              return {
                app: started.app,
                deployment: started.deployment,
                readinessAttempts: started.readinessAttempts ?? 1,
                liveUrl: started.app?.domain
                  ? `https://${started.app.domain}`
                  : null,
                missingEnvKeys: started.missingEnvKeys,
                envSettingsUrl:
                  started.missingEnvKeys.length > 0
                    ? buildEnvSettingsUrl(store, slug)
                    : null,
              };
            },
          });
          break;
        }

        case "rebuild_app": {
          const slug = validateAppSlug(String(args.slug ?? ""));
          callResult = await handleMutation(token, {
            action: "rebuild_app",
            targetSlug: slug,
            summary: `Rebuild and restart app "${slug}"`,
            payload: { slug },
            riskLevel: "medium",
            run: async () => {
              const started = await executor.startRebuildApp(slug, "agent", {
                actorTokenId: token.id,
                waitMs: deployGraceMs,
                throwOnImmediateFailure: true,
              });
              if (!started.done) {
                return {
                  status: "deploying",
                  deploymentId: started.deployment.id,
                  deployment: started.deployment,
                  slug,
                  deploymentsUrl: buildDeploymentsUrl(store, slug),
                  nextStep:
                    "Rebuild is continuing in the background. Poll get_deployment with this deploymentId to track live progress and build logs.",
                };
              }
              return {
                app: started.app,
                deployment: started.deployment,
                liveUrl: started.app?.domain
                  ? `https://${started.app.domain}`
                  : null,
                missingEnvKeys: started.missingEnvKeys,
                envSettingsUrl:
                  started.missingEnvKeys.length > 0
                    ? buildEnvSettingsUrl(store, slug)
                    : null,
              };
            },
          });
          break;
        }

        case "update_app_env": {
          const slug = validateAppSlug(String(args.slug ?? ""));
          const envInput = UpdateAppEnvInputSchema.parse(args);
          callResult = await handleMutation(token, {
            action: "update_env",
            targetSlug: slug,
            summary: `Update environment variables for "${slug}" (${envInput.vars.map((v) => v.key).join(", ") || "delete only"})`,
            payload: { slug, ...envInput },
            riskLevel: "medium",
            run: () => executor.updateAppEnv(slug, envInput, "agent", token.id),
          });
          break;
        }

        case "set_app_domain": {
          const slug = validateAppSlug(String(args.slug ?? ""));
          const domain =
            args.domain === null || args.domain === undefined
              ? null
              : String(args.domain);
          callResult = await handleMutation(token, {
            action: "set_domain",
            targetSlug: slug,
            summary: domain
              ? `Connect domain ${domain} to "${slug}"`
              : `Remove domain from "${slug}"`,
            payload: { slug, domain },
            riskLevel: "medium",
            run: () => executor.setAppDomain(slug, domain, "agent", token.id),
          });
          break;
        }

        case "restart_app": {
          const slug = validateAppSlug(String(args.slug ?? ""));
          callResult = await handleMutation(token, {
            action: "restart_app",
            targetSlug: slug,
            summary: `Restart app "${slug}"`,
            payload: { slug },
            riskLevel: "low",
            run: () => executor.lifecycleApp(slug, "restart", "agent", token.id),
          });
          break;
        }

        case "stop_app": {
          const slug = validateAppSlug(String(args.slug ?? ""));
          callResult = await handleMutation(token, {
            action: "stop_app",
            targetSlug: slug,
            summary: `Stop app "${slug}"`,
            payload: { slug },
            riskLevel: "medium",
            run: () => executor.lifecycleApp(slug, "stop", "agent", token.id),
          });
          break;
        }

        case "delete_app": {
          const slug = validateAppSlug(String(args.slug ?? ""));
          const removeFiles = args.removeFiles !== false;
          callResult = await handleMutation(token, {
            action: "delete_app",
            targetSlug: slug,
            summary: `Delete app "${slug}"`,
            payload: { slug, removeFiles },
            riskLevel: "high",
            run: () => executor.deleteApp(slug, removeFiles, "agent", token.id),
          });
          break;
        }

        default:
          return c.json(
            jsonRpcError(id, -32601, `Unknown MCP tool "${toolName}".`),
            200,
          );
      }

      return c.json(jsonRpcResult(id, callResult));
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      return c.json(jsonRpcResult(id, toolErr(msg)));
    }
  };
}
