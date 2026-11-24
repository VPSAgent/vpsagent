import type { Context } from "hono";
import { z } from "zod";
import {
  type ApprovalActionType,
  type McpTokenRecord,
  type RegistryStore,
  type RiskLevel,
  type RuntimeBridge,
  assertHttpsForRemoteHost,
  canScopeMutate,
  redactSecrets,
  redactStructuredValue,
  requiresApprovalForScope,
  syncAppStatuses,
  validateAppSlug,
} from "@vpsagent/shared";
import { getRequestHost, getRequestProtocol } from "./auth.js";
import {
  type AppExecutor,
  DeployAppInputSchema,
  UpdateAppEnvInputSchema,
} from "./executor.js";

const MCP_PROTOCOL_VERSION = "2025-03-26";

const JsonRpcRequestSchema = z.object({
  jsonrpc: z.literal("2.0"),
  id: z.union([z.string(), z.number(), z.null()]).optional(),
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
      "Read recent container logs for an app (all secrets are automatically scrubbed).",
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

export interface McpSetupSnippets {
  mcpUrl: string;
  claudeCode: string;
  cursor: string;
  codex: string;
}

/** Builds ready-to-paste client setup snippets for Claude Code, Cursor, and Codex. */
export function buildMcpSetupSnippets(mcpUrl: string): McpSetupSnippets {
  const cleanUrl = mcpUrl.replace(/\/+$/, "");
  const tokenPlaceholder = "vpsmcp_YOUR_TOKEN_HERE";

  return {
    mcpUrl: cleanUrl,
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
  trustProxy: boolean;
}

export function createMcpPostHandler(deps: McpGatewayDeps) {
  const { store, bridge, executor, trustProxy } = deps;

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
      const approval = store.createApproval({
        action: input.action,
        targetSlug: input.targetSlug,
        summary: input.summary,
        payload: input.payload,
        executionPayload: input.payload,
        requestedBy: token.name,
        tokenScope: token.scope,
        riskLevel: input.riskLevel,
      });
      store.recordAudit({
        actor: "agent",
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
    const host = getRequestHost(c, trustProxy);
    const proto = getRequestProtocol(c, trustProxy);
    try {
      assertHttpsForRemoteHost(host, proto);
    } catch (err) {
      return c.json(
        {
          error:
            err instanceof Error
              ? err.message
              : "HTTPS is required for remote MCP access.",
        },
        403,
      );
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

    if (method === "notifications/initialized") {
      return c.body(null, 202);
    }

    if (method === "ping") {
      return c.json(jsonRpcResult(id, {}));
    }

    if (method === "initialize") {
      return c.json(
        jsonRpcResult(id, {
          protocolVersion: MCP_PROTOCOL_VERSION,
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
          const lines = await bridge.getLogs(slug, tail);
          callResult = toolOk({ slug, lines });
          break;
        }

        case "inspect_app": {
          const slug = validateAppSlug(String(args.slug ?? ""));
          const app = store.getApp(slug);
          const inspect = await bridge.inspectWorkload(slug, {
            probeHttp: Boolean(args.probeHttp),
            internalPort: app?.internalPort ?? 8080,
            probePath:
              typeof args.probePath === "string" ? args.probePath : "/",
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
            run: () => executor.deployApp(input, "agent"),
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
            run: () => executor.rebuildApp(slug, "agent"),
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
            run: () => executor.updateAppEnv(slug, envInput, "agent"),
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
            run: () => executor.setAppDomain(slug, domain, "agent"),
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
            run: () => executor.lifecycleApp(slug, "restart", "agent"),
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
            run: () => executor.lifecycleApp(slug, "stop", "agent"),
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
            run: () => executor.deleteApp(slug, removeFiles, "agent"),
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
