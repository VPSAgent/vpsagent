import type { Context } from "hono";
import { z } from "zod";
import {
  type ApprovalActionType,
  type McpTokenRecord,
  type RegistryStore,
  type RiskLevel,
  type RuntimeBridge,
  canScopeMutate,
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
  UpdateAppEnvInputSchema,
} from "./executor.js";

export const SUPPORTED_MCP_PROTOCOL_VERSIONS = [
  "2025-11-25",
  "2025-06-18",
  "2025-03-26",
] as const;
const DEFAULT_MCP_PROTOCOL_VERSION = SUPPORTED_MCP_PROTOCOL_VERSIONS[0];
const MAX_MCP_LOG_REPLY_BYTES = 48 * 1024;

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
    name: "get_host_health",
    description:
      "Read live server CPU, memory, uptime, disk space, and running app counts.",
    inputSchema: { type: "object", properties: {}, additionalProperties: false },
  },
  {
    name: "list_apps",
    description: "List all apps managed by VPSAgent with live running status.",
    inputSchema: { type: "object", properties: {}, additionalProperties: false },
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
      "Inspect an app's live container health, Locked Apartment security compliance, and masked env variable names.",
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
      "Deploy a prebuilt Docker image or an HTTPS GitHub repo with a Dockerfile into a Locked Apartment, optionally with private Postgres/Redis companions and a public HTTPS domain.",
    inputSchema: {
      type: "object",
      properties: {
        slug: { type: "string" },
        name: { type: "string" },
        sourceType: { type: "string", enum: ["image", "git"] },
        image: { type: "string" },
        gitRepoUrl: { type: "string" },
        gitBranch: { type: "string" },
        dockerfilePath: { type: "string", default: "Dockerfile" },
        domain: { type: ["string", "null"] },
        internalPort: { type: "integer", default: 8080 },
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
    description: "Rebuild and restart an existing app (re-cloning Git if applicable).",
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
    description: "Stop and remove an app, its web route, and optionally its files.",
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
}

/** Builds ready-to-paste client setup snippets for Claude Code, Cursor, and Codex. */
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
  };
}

export interface McpGatewayDeps {
  store: RegistryStore;
  bridge: RuntimeBridge;
  executor: AppExecutor;
  transportOptions: TransportContextOptions;
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

    if (requiresApprovalForScope(token.scope)) {
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
          "Action queued for human approval. Ask the server owner to click Approve in the VPSAgent dashboard.",
      });
    }

    const result = await input.run();
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
            version: "2.0.0",
          },
          capabilities: {
            tools: {},
          },
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
        case "get_host_health": {
          const [stats, apps] = await Promise.all([
            bridge.getHostStats(),
            syncAppStatuses(store, bridge),
          ]);
          callResult = toolOk({
            ...stats,
            appCount: apps.length,
            runningApps: apps.filter((a) => a.status === "running").length,
          });
          break;
        }

        case "list_apps": {
          const apps = await syncAppStatuses(store, bridge);
          callResult = toolOk({ apps });
          break;
        }

        case "get_app_logs": {
          const slug = validateAppSlug(String(args.slug ?? ""));
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
          callResult = toolOk({ app, inspect, envVars });
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
          const approvals = store.listApprovals(
            status ? { status, limit: 50 } : { limit: 50 },
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
            run: () => executor.deployApp(input, "agent", token.id),
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
            run: () => executor.rebuildApp(slug, "agent", token.id),
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
