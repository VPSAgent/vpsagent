import crypto from "node:crypto";
import type { Context } from "hono";
import { z } from "zod";
import {
  type ApprovalActionType,
  type McpTokenRecord,
  type RegistryStore,
  type RiskLevel,
  type RuntimeBridge,
  RuntimeBridgeError,
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
  getRequestHost,
  normalizeHostWithoutDefaultPort,
  validateMcpHostAndOrigin,
} from "./auth.js";
import {
  type AppExecutor,
  DeleteHostFileInputSchema,
  DeployAppInputSchema,
  InspectGitInputSchema,
  DockerCleanupInputSchema,
  ExecInAppInputSchema,
  ManageHostServiceInputSchema,
  RunHostCommandInputSchema,
  UpdateAppEnvInputSchema,
  WriteHostFileInputSchema,
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
  "Recommended workflow for deploying a public or private GitHub repo:",
  "1. Call get_server_info to check available server resources, default apps base domain (if configured), whether private GitHub access is connected, and your pass permissions / allowed apps.",
  "2. If deploying a private GitHub repo, call list_github_repos first to find the exact repo URL, default branch, and gitCredentialId. If githubConnected is false, share githubSettingsUrl so the owner can paste a read-only GitHub token directly into the encrypted dashboard.",
  "3. Call inspect_git_repo first to preview the repo's detected runtime (Dockerfile, Next.js, Vite, Node.js, Python, or static HTML), suggested port, database companion hints, and .env.example key names.",
  "4. Call deploy_app (sourceType: 'git'). If no Dockerfile exists, VPSAgent auto-generates a safe non-root build recipe and detects the internal port automatically. If an appsBaseDomain is configured and you omit domain, VPSAgent assigns https://<slug>.<appsBaseDomain> automatically (pass noDomain: true or domain: null for a private app).",
  "5. Long builds continue safely in the background and return status 'deploying' with a deploymentId so your tool call never times out. Poll get_deployment(deploymentId) until status is 'succeeded' or 'failed' and inspect buildLogs if anything fails.",
  "6. Security rule for secrets: NEVER ask the user to paste secret API keys, database passwords, or GitHub tokens into chat when envSettingsUrl or githubSettingsUrl is provided. Share those encrypted dashboard links instead.",
].join("\n");

const JsonRpcRequestSchema = z.object({
  jsonrpc: z.literal("2.0"),
  id: z.union([z.string().max(256), z.number().finite(), z.null()]).optional(),
  method: z.string().min(1),
  params: z.record(z.string(), z.unknown()).optional(),
});

export interface McpToolAnnotations {
  title: string;
  readOnlyHint: boolean;
  destructiveHint: boolean;
  idempotentHint: boolean;
  openWorldHint: boolean;
}

interface McpToolDefinition {
  name: string;
  description: string;
  inputSchema: Record<string, unknown>;
  annotations?: McpToolAnnotations;
}

const TOOL_ANNOTATIONS: Record<string, McpToolAnnotations> = {
  get_host_health: {
    title: "Get Server Health",
    readOnlyHint: true,
    destructiveHint: false,
    idempotentHint: true,
    openWorldHint: false,
  },
  list_github_repos: {
    title: "List Accessible GitHub Repositories",
    readOnlyHint: true,
    destructiveHint: false,
    idempotentHint: true,
    openWorldHint: true,
  },
  list_apps: {
    title: "List Managed Apps",
    readOnlyHint: true,
    destructiveHint: false,
    idempotentHint: true,
    openWorldHint: false,
  },
  get_app_logs: {
    title: "Read App Logs",
    readOnlyHint: true,
    destructiveHint: false,
    idempotentHint: true,
    openWorldHint: false,
  },
  inspect_app: {
    title: "Inspect App & Security",
    readOnlyHint: true,
    destructiveHint: false,
    idempotentHint: true,
    openWorldHint: false,
  },
  list_approvals: {
    title: "List Approval Requests",
    readOnlyHint: true,
    destructiveHint: false,
    idempotentHint: true,
    openWorldHint: false,
  },
  wait_for_approval: {
    title: "Wait for Human Approval",
    readOnlyHint: true,
    destructiveHint: false,
    idempotentHint: true,
    openWorldHint: false,
  },
  get_audit_history: {
    title: "Search Activity History",
    readOnlyHint: true,
    destructiveHint: false,
    idempotentHint: true,
    openWorldHint: false,
  },
  get_setup_status: {
    title: "Check Domain & HTTPS Status",
    readOnlyHint: true,
    destructiveHint: false,
    idempotentHint: true,
    openWorldHint: false,
  },
  list_files: {
    title: "List Server Files",
    readOnlyHint: true,
    destructiveHint: false,
    idempotentHint: true,
    openWorldHint: false,
  },
  read_file: {
    title: "Read Server File",
    readOnlyHint: true,
    destructiveHint: false,
    idempotentHint: true,
    openWorldHint: false,
  },
  list_services: {
    title: "List System Services",
    readOnlyHint: true,
    destructiveHint: false,
    idempotentHint: true,
    openWorldHint: false,
  },
  deploy_app: {
    title: "Deploy App",
    readOnlyHint: false,
    destructiveHint: false,
    idempotentHint: false,
    openWorldHint: true,
  },
  rebuild_app: {
    title: "Rebuild App",
    readOnlyHint: false,
    destructiveHint: false,
    idempotentHint: false,
    openWorldHint: true,
  },
  update_app_env: {
    title: "Update App Environment",
    readOnlyHint: false,
    destructiveHint: false,
    idempotentHint: true,
    openWorldHint: false,
  },
  set_app_domain: {
    title: "Set App Domain",
    readOnlyHint: false,
    destructiveHint: false,
    idempotentHint: true,
    openWorldHint: false,
  },
  start_app: {
    title: "Start App",
    readOnlyHint: false,
    destructiveHint: false,
    idempotentHint: true,
    openWorldHint: false,
  },
  restart_app: {
    title: "Restart App",
    readOnlyHint: false,
    destructiveHint: false,
    idempotentHint: true,
    openWorldHint: false,
  },
  stop_app: {
    title: "Stop App",
    readOnlyHint: false,
    destructiveHint: true,
    idempotentHint: true,
    openWorldHint: false,
  },
  delete_app: {
    title: "Delete App",
    readOnlyHint: false,
    destructiveHint: true,
    idempotentHint: false,
    openWorldHint: false,
  },
  exec_in_app: {
    title: "Run Command Inside App",
    readOnlyHint: false,
    destructiveHint: true,
    idempotentHint: false,
    openWorldHint: true,
  },
  run_host_command: {
    title: "Run Server Command",
    readOnlyHint: false,
    destructiveHint: true,
    idempotentHint: false,
    openWorldHint: true,
  },
  write_file: {
    title: "Write Server File",
    readOnlyHint: false,
    destructiveHint: true,
    idempotentHint: false,
    openWorldHint: false,
  },
  delete_file: {
    title: "Delete Server File",
    readOnlyHint: false,
    destructiveHint: true,
    idempotentHint: false,
    openWorldHint: false,
  },
  manage_service: {
    title: "Manage System Service",
    readOnlyHint: false,
    destructiveHint: true,
    idempotentHint: false,
    openWorldHint: false,
  },
  docker_cleanup: {
    title: "Clean Up Unused Docker Space",
    readOnlyHint: false,
    destructiveHint: true,
    idempotentHint: false,
    openWorldHint: false,
  },
};

export const MCP_RESOURCES = [
  {
    uri: "vpsagent://server/overview",
    name: "Server Overview",
    description:
      "Live VPS CPU, memory, disk space, uptime, domain/HTTPS status, and running app counts.",
    mimeType: "application/json",
  },
  {
    uri: "vpsagent://apps/list",
    name: "Managed Apps",
    description: "Live list of all apps managed by VPSAgent and their current status.",
    mimeType: "application/json",
  },
  {
    uri: "vpsagent://audit/recent",
    name: "Recent Activity History",
    description: "The 30 most recent actions recorded on this VPS.",
    mimeType: "application/json",
  },
] as const;

const RAW_MCP_TOOLS: McpToolDefinition[] = [
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
    name: "list_github_repos",
    description:
      "List public and private GitHub repositories accessible via the owner's saved GitHub access token(s) in VPSAgent (never exposes raw tokens).",
    inputSchema: {
      type: "object",
      properties: {
        query: {
          type: "string",
          description: "Optional text filter matching repository name or description",
        },
        credentialId: {
          type: "string",
          description:
            "Optional saved GitHub credential ID (ghc_...) to list repos for",
        },
        limit: {
          type: "integer",
          minimum: 1,
          maximum: 100,
          default: 30,
        },
      },
    },
  },
  {
    name: "inspect_git_repo",
    description:
      "Inspect a public or private HTTPS GitHub repository before deploying. Automatically uses saved GitHub access tokens when needed (or an optional gitCredentialId). Detects Dockerfile or auto-build runtime (Next.js, Vite, Node.js, Python, static HTML), suggested port, slug/name, database hints, preview domain, and .env.example key names (never values).",
    inputSchema: {
      type: "object",
      properties: {
        gitRepoUrl: {
          type: "string",
          description: "HTTPS GitHub repository URL (public or private)",
        },
        gitBranch: {
          type: "string",
          description: "Optional branch name (defaults to repository default branch)",
        },
        gitCredentialId: {
          type: "string",
          description:
            "Optional saved GitHub credential ID (ghc_...) to use for private repos",
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
      "Deploy a prebuilt Docker image or a public/private HTTPS GitHub repo (with a Dockerfile OR auto-detected Next.js/Vite/Node/Python/static site) into a Locked Apartment. Long builds continue in the background and return a deploymentId to poll via get_deployment.",
    inputSchema: {
      type: "object",
      properties: {
        slug: { type: "string" },
        name: { type: "string" },
        sourceType: { type: "string", enum: ["image", "git"] },
        image: { type: "string" },
        gitRepoUrl: { type: "string" },
        gitBranch: { type: "string" },
        gitCredentialId: {
          type: "string",
          description:
            "Optional saved GitHub credential ID (ghc_...) to use when cloning a private GitHub repository",
        },
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
  {
    name: "start_app",
    description: "Start a stopped app container.",
    inputSchema: {
      type: "object",
      properties: { slug: { type: "string" } },
      required: ["slug"],
    },
  },
  {
    name: "get_audit_history",
    description:
      "Search and read recent activity and audit history recorded on the VPS.",
    inputSchema: {
      type: "object",
      properties: {
        query: {
          type: "string",
          description: "Optional text filter matching action or summary",
        },
        targetSlug: {
          type: "string",
          description: "Optional app slug to filter history for",
        },
        limit: {
          type: "integer",
          minimum: 1,
          maximum: 200,
          default: 50,
        },
      },
    },
  },
  {
    name: "get_setup_status",
    description:
      "Read the server's configured domain, HTTPS/TLS certificate status, and setup state.",
    inputSchema: {
      type: "object",
      properties: {
        recheckTls: {
          type: "boolean",
          default: false,
          description: "Set true to actively re-verify live HTTPS certificate status",
        },
      },
    },
  },
  {
    name: "exec_in_app",
    description:
      "Run a shell command inside a running app container or one of its companion services (e.g., postgres or redis) for migrations, debugging, or admin tasks.",
    inputSchema: {
      type: "object",
      properties: {
        slug: { type: "string", description: "App slug identifier" },
        command: {
          type: "string",
          description: "Shell command to execute inside the container",
        },
        service: {
          type: "string",
          default: "app",
          description: "Compose service name (default: app, or e.g. postgres, redis)",
        },
        timeoutSeconds: {
          type: "integer",
          minimum: 1,
          maximum: 180,
          default: 30,
        },
      },
      required: ["slug", "command"],
    },
  },
  {
    name: "run_host_command",
    description:
      "Run a shell command directly on the VPS host for full server management (installing packages, checking ports/processes/firewall/cron, debugging, running scripts). Output is automatically secret-redacted and logged.",
    inputSchema: {
      type: "object",
      properties: {
        command: {
          type: "string",
          description: "Shell command to execute on the VPS host",
        },
        cwd: {
          type: "string",
          description: "Optional absolute working directory path on the host",
        },
        timeoutSeconds: {
          type: "integer",
          minimum: 1,
          maximum: 180,
          default: 30,
        },
      },
      required: ["command"],
    },
  },
  {
    name: "list_files",
    description: "List files and folders inside a directory on the VPS host.",
    inputSchema: {
      type: "object",
      properties: {
        path: {
          type: "string",
          description: "Absolute directory path on the host",
        },
        showHidden: { type: "boolean", default: false },
        maxEntries: {
          type: "integer",
          minimum: 1,
          maximum: 500,
          default: 200,
        },
      },
      required: ["path"],
    },
  },
  {
    name: "read_file",
    description:
      "Read a text file on the VPS host (sensitive secret files like .env and private keys are blocked; embedded secrets are redacted).",
    inputSchema: {
      type: "object",
      properties: {
        path: { type: "string", description: "Absolute file path on the host" },
        startLine: { type: "integer", minimum: 1, default: 1 },
        endLine: { type: "integer", minimum: 1 },
        maxBytes: {
          type: "integer",
          minimum: 256,
          maximum: 131072,
          default: 65536,
        },
      },
      required: ["path"],
    },
  },
  {
    name: "write_file",
    description:
      "Create, overwrite, or append to a text file on the VPS host (up to 256 KB; protected secret files are blocked).",
    inputSchema: {
      type: "object",
      properties: {
        path: { type: "string", description: "Absolute file path on the host" },
        content: { type: "string", description: "Text content to write" },
        append: { type: "boolean", default: false },
        createDirs: {
          type: "boolean",
          default: false,
          description: "Create missing parent directories if needed",
        },
      },
      required: ["path", "content"],
    },
  },
  {
    name: "delete_file",
    description:
      "Delete a file or directory on the VPS host (critical system directories and secret files are protected).",
    inputSchema: {
      type: "object",
      properties: {
        path: { type: "string", description: "Absolute file or folder path" },
        recursive: {
          type: "boolean",
          default: false,
          description: "Set true to delete a non-empty directory recursively",
        },
      },
      required: ["path"],
    },
  },
  {
    name: "list_services",
    description: "List systemd background services on the VPS host.",
    inputSchema: {
      type: "object",
      properties: {
        filter: {
          type: "string",
          description: "Optional substring to filter service names or descriptions",
        },
        state: {
          type: "string",
          enum: ["all", "running", "failed"],
          default: "all",
        },
        limit: { type: "integer", minimum: 1, maximum: 300, default: 100 },
      },
    },
  },
  {
    name: "manage_service",
    description:
      "Start, stop, restart, reload, enable, disable, or check status of a systemd service on the VPS host.",
    inputSchema: {
      type: "object",
      properties: {
        service: {
          type: "string",
          description: "Systemd service unit name (e.g. nginx, caddy, cron)",
        },
        action: {
          type: "string",
          enum: [
            "start",
            "stop",
            "restart",
            "reload",
            "enable",
            "disable",
            "status",
          ],
        },
      },
      required: ["service", "action"],
    },
  },
  {
    name: "docker_cleanup",
    description:
      "Reclaim VPS disk space by pruning stopped containers and unused Docker images, build cache, or volumes.",
    inputSchema: {
      type: "object",
      properties: {
        pruneImages: { type: "boolean", default: true },
        pruneBuildCache: { type: "boolean", default: true },
        pruneVolumes: { type: "boolean", default: false },
      },
    },
  },
  {
    name: "wait_for_approval",
    description:
      "Wait for a queued human approval request to be approved, rejected, or finished executing, and return its final status and result summary.",
    inputSchema: {
      type: "object",
      properties: {
        approvalId: {
          type: "string",
          description: "The approvalId returned when an action was queued",
        },
        timeoutSeconds: {
          type: "integer",
          minimum: 1,
          maximum: 60,
          default: 30,
          description: "How long to wait before returning current status",
        },
      },
      required: ["approvalId"],
    },
  },
];

export const MCP_TOOLS: McpToolDefinition[] = RAW_MCP_TOOLS.map((tool) => ({
  ...tool,
  ...(TOOL_ANNOTATIONS[tool.name]
    ? { annotations: TOOL_ANNOTATIONS[tool.name] }
    : {}),
}));

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

  if (action === "write_file") {
    const rawContent =
      typeof rawPayload.content === "string" ? rawPayload.content : "";
    const redactedContent = redactSecrets(rawContent);
    const preview =
      redactedContent.length > 500
        ? `${redactedContent.slice(0, 500)}... (${Buffer.byteLength(rawContent, "utf8")} bytes total)`
        : redactedContent;
    return {
      path: rawPayload.path,
      append: Boolean(rawPayload.append),
      createDirs: Boolean(rawPayload.createDirs),
      bytes: Buffer.byteLength(rawContent, "utf8"),
      contentPreview: preview,
    };
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

export const MCP_TOKEN_PLACEHOLDER = "vpsmcp_YOUR_TOKEN_HERE";

export interface McpSetupSnippets {
  mcpUrl: string;
  httpsReady: boolean;
  tokenPlaceholder: string;
  claudeCode: string;
  t3AndAgy: string;
  cursor: string;
  codex: string;
  genericHttp: string;
  curlTest: string;
}

/** Builds ready-to-paste client setup snippets for Claude Code, T3 Code / Antigravity, Cursor, Codex, generic HTTP, and curl. */
export function buildMcpSetupSnippets(
  mcpUrl: string,
  httpsReady: boolean,
): McpSetupSnippets {
  const cleanUrl = mcpUrl.replace(/\/+$/, "");
  const tokenPlaceholder = MCP_TOKEN_PLACEHOLDER;

  const standardJson = JSON.stringify(
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
  );

  return {
    mcpUrl: cleanUrl,
    httpsReady,
    tokenPlaceholder,
    claudeCode: `claude mcp add --transport http vpsagent ${cleanUrl} \\\n  --header "Authorization: Bearer ${tokenPlaceholder}"`,
    t3AndAgy: JSON.stringify(
      {
        mcpServers: {
          vpsagent: {
            serverUrl: cleanUrl,
            headers: {
              Authorization: `Bearer ${tokenPlaceholder}`,
            },
          },
        },
      },
      null,
      2,
    ),
    cursor: standardJson,
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
    curlTest: `curl -sS -X POST "${cleanUrl}" \\\n  -H "Content-Type: application/json" \\\n  -H "Authorization: Bearer ${tokenPlaceholder}" \\\n  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"curl-test","version":"1.0"}}}'`,
  };
}

const MAX_MCP_SESSIONS = 1000;

/** Server-side MCP Streamable HTTP session registry so closed sessions are actually rejected. */
export class McpSessionStore {
  private readonly sessions = new Map<string, string>();

  create(tokenId: string): string {
    if (this.sessions.size >= MAX_MCP_SESSIONS) {
      const oldest = this.sessions.keys().next().value;
      if (oldest) this.sessions.delete(oldest);
    }
    const id = `vpsagent-${crypto.randomBytes(16).toString("hex")}`;
    this.sessions.set(id, tokenId);
    return id;
  }

  isValid(sessionId: string, tokenId: string): boolean {
    return this.sessions.get(sessionId) === tokenId;
  }

  close(sessionId: string, tokenId: string): boolean {
    if (this.sessions.get(sessionId) !== tokenId) {
      return false;
    }
    this.sessions.delete(sessionId);
    return true;
  }
}

function buildServerInstructions(
  token: McpTokenRecord,
  dashboardUrl: string | null,
): string {
  const scopeDesc =
    token.scope === "read-only"
      ? "LOOK-ONLY (read-only): you can inspect server health, apps, logs, allowed files, services, and history, but you cannot make changes or run commands."
      : token.scope === "approval-required"
        ? `ASK-FIRST (approval-required): read-only tools run immediately; mutating tools queue an approval request in the owner's dashboard${dashboardUrl ? ` (${dashboardUrl})` : ""}. When a tool returns status "pending_approval", share the dashboard link with the owner and call wait_for_approval with the approvalId if you want to wait for their decision.`
        : token.scope === "safe-auto-deploy"
          ? `SAFE AUTO-DEPLOY (safe-auto-deploy): app deploys, rebuilds, restarts, env updates, and domains run right away; deleting apps and host-level admin actions queue for human approval${dashboardUrl ? ` (${dashboardUrl})` : ""}.`
          : token.scope === "auto-approve"
            ? `TRUSTED AUTO-PASS (auto-approve): all isolated app actions run right away; host-level admin tools (run_host_command, write_file, delete_file, manage_service, docker_cleanup) still queue for human approval${dashboardUrl ? ` (${dashboardUrl})` : ""}.`
            : "FULL SERVER ADMIN (host-admin): explicit root-level host administration access; both app and host tools run immediately and are logged in History.";

  return [
    `You are connected to VPSAgent as AI pass "${token.name}".`,
    `Permission level: ${scopeDesc}`,
    MCP_SERVER_INSTRUCTIONS,
    "Tool boundaries: structured file tools (list_files/read_file/write_file/delete_file) are restricted to explicitly allowed directories and block secret files (.env, private keys, VPSAgent DB); manage_service protects vpsagent-runtime. Note: run_host_command executes directly on the host with full shell privileges (gated by approval unless this pass has explicit host-admin scope).",
  ].join("\n");
}

export interface McpGatewayDeps {
  store: RegistryStore;
  bridge: RuntimeBridge;
  executor: AppExecutor;
  transportOptions: TransportContextOptions;
  mcpDeployGraceMs?: number | undefined;
  sessions?: McpSessionStore | undefined;
}

function buildActiveHttpsDashboardUrl(store: RegistryStore): string | null {
  const setup = store.getSetupState();
  if (setup.domain && setup.httpsActive && setup.tlsStatus === "active") {
    return `https://${setup.domain}`;
  }
  if (setup.tailscaleDomain && setup.tailscaleServeEnabled) {
    return `https://${setup.tailscaleDomain}`;
  }
  return null;
}

function buildDashboardBaseUrl(store: RegistryStore): string | null {
  const active = buildActiveHttpsDashboardUrl(store);
  if (active) {
    return active;
  }
  const setup = store.getSetupState();
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

function buildGithubSettingsUrl(store: RegistryStore): string {
  const base = buildDashboardBaseUrl(store);
  const hash = "/#keys/github";
  return base ? `${base}${hash}` : hash;
}

function normalizeGitUrlForComparison(rawUrl: string): string {
  return rawUrl
    .trim()
    .replace(/\/+$/, "")
    .replace(/\.git$/i, "")
    .toLowerCase();
}

function isRepoBoundToAllowedApp(
  store: RegistryStore,
  token: McpTokenRecord,
  rawRepoUrl: string,
): boolean {
  const target = normalizeGitUrlForComparison(rawRepoUrl);
  for (const allowedSlug of token.allowedSlugs) {
    const existing = store.getApp(allowedSlug);
    if (
      existing?.gitRepoUrl &&
      normalizeGitUrlForComparison(existing.gitRepoUrl) === target
    ) {
      return true;
    }
  }
  return false;
}

const tailscaleReconcileLastCheck = new WeakMap<RegistryStore, number>();
const TAILSCALE_RECONCILE_COOLDOWN_MS = 5_000;

export async function enforceMcpBoundary(
  c: Context,
  store: RegistryStore,
  transportOptions: TransportContextOptions,
  bridge?: RuntimeBridge,
): Promise<{ ok: true } | { ok: false; response: Response }> {
  let setup = store.getSetupState();
  try {
    const transport = assertSecureTransport(c, transportOptions);
    const checkHostAndOrigin = (currentSetup: typeof setup) =>
      validateMcpHostAndOrigin(c, {
        setupDomain: currentSetup.domain,
        httpsActive: currentSetup.httpsActive,
        additionalAllowedHttpsHosts:
          currentSetup.tailscaleServeEnabled && currentSetup.tailscaleDomain
            ? [currentSetup.tailscaleDomain]
            : [],
        transport,
        trustProxy: transportOptions.trustProxy,
      });

    try {
      checkHostAndOrigin(setup);
      return { ok: true };
    } catch (firstErr) {
      if (
        transport.isHttps &&
        !setup.tailscaleServeEnabled &&
        bridge?.getTailscaleStatus
      ) {
        const rawHost = getRequestHost(c, transportOptions.trustProxy);
        const normalizedHost = normalizeHostWithoutDefaultPort(rawHost, true);
        if (normalizedHost.endsWith(".ts.net")) {
          const now = Date.now();
          const lastCheck = tailscaleReconcileLastCheck.get(store) ?? 0;
          if (now - lastCheck >= TAILSCALE_RECONCILE_COOLDOWN_MS) {
            tailscaleReconcileLastCheck.set(store, now);
            try {
              const ts = await bridge.getTailscaleStatus();
              const nextDomain = ts.dnsName || null;
              const nextEnabled = Boolean(ts.serveEnabled && ts.dnsName);
              if (
                setup.tailscaleDomain !== nextDomain ||
                setup.tailscaleServeEnabled !== nextEnabled
              ) {
                setup = store.updateSetupState({
                  tailscaleDomain: nextDomain,
                  tailscaleServeEnabled: nextEnabled,
                });
              }
            } catch {
              // Ignore bridge errors and fall through to original rejection
            }
          }
          checkHostAndOrigin(setup);
          return { ok: true };
        }
      }
      throw firstErr;
    }
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
      const dashboardUrl = buildActiveHttpsDashboardUrl(store);
      return toolOk({
        status: "pending_approval",
        approvalId: approval.id,
        action: approval.action,
        targetSlug: approval.targetSlug,
        dashboardUrl,
        message:
          input.action === "delete_app" && token.scope === "safe-auto-deploy"
            ? `Deleting an app always requires human confirmation under Safe Auto-Deploy. Ask the server owner to review and click Approve in the VPSAgent dashboard${dashboardUrl ? ` (${dashboardUrl})` : ""} — you can call wait_for_approval with approvalId "${approval.id}".`
            : `Action queued for human approval. Ask the server owner to click Approve in the VPSAgent dashboard${dashboardUrl ? ` (${dashboardUrl})` : ""} — you can call wait_for_approval with approvalId "${approval.id}" to wait for their decision.`,
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
    const failedExit =
      result &&
      typeof result === "object" &&
      "exitCode" in result &&
      typeof (result as { exitCode: unknown }).exitCode === "number" &&
      (result as { exitCode: number }).exitCode !== 0;
    const failedOk =
      result &&
      typeof result === "object" &&
      "ok" in result &&
      (result as { ok: unknown }).ok === false;
    if (failedExit || failedOk) {
      const safe = redactStructuredValue({ status: "failed", result });
      return {
        content: [{ type: "text", text: JSON.stringify(safe, null, 2) }],
        isError: true,
      };
    }
    return toolOk({ status: "executed", result });
  }

  return async (c: Context) => {
    const guard = await enforceMcpBoundary(c, store, transportOptions, bridge);
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
    } else if (method !== "initialize") {
      c.header("MCP-Protocol-Version", DEFAULT_MCP_PROTOCOL_VERSION);
    }

    const sessionStore = deps.sessions;
    const incomingSessionId = c.req.header("mcp-session-id")?.trim();
    if (method !== "initialize" && incomingSessionId) {
      if (sessionStore && !sessionStore.isValid(incomingSessionId, token.id)) {
        return c.json(
          { error: "MCP session not found or has been closed." },
          404,
        );
      }
      c.header("Mcp-Session-Id", incomingSessionId);
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
      const dashboardUrl = buildActiveHttpsDashboardUrl(store);
      c.header("MCP-Protocol-Version", negotiatedVersion);
      if (sessionStore) {
        c.header("Mcp-Session-Id", sessionStore.create(token.id));
      }
      return c.json(
        jsonRpcResult(id, {
          protocolVersion: negotiatedVersion,
          serverInfo: {
            name: "vpsagent",
            version: "2.1.0",
          },
          capabilities: {
            tools: {},
            resources: {},
          },
          instructions: buildServerInstructions(token, dashboardUrl),
        }),
      );
    }

    if (method === "tools/list") {
      return c.json(jsonRpcResult(id, { tools: MCP_TOOLS }));
    }

    if (method === "resources/list") {
      return c.json(jsonRpcResult(id, { resources: MCP_RESOURCES }));
    }

    if (method === "resources/read") {
      const uri = typeof params.uri === "string" ? params.uri.trim() : "";
      try {
        let data: unknown;
        if (uri === "vpsagent://server/overview") {
          const [stats, apps] = await Promise.all([
            bridge.getHostStats(),
            syncAppStatuses(store, bridge),
          ]);
          data = {
            ...stats,
            setup: store.getSetupState(),
            appCount: apps.length,
            runningApps: apps.filter((a) => a.status === "running").length,
            pendingApprovals: store.listApprovals({
              status: "pending",
              limit: 50,
            }).length,
          };
        } else if (uri === "vpsagent://apps/list") {
          const apps = await syncAppStatuses(store, bridge);
          data = { apps };
        } else if (uri === "vpsagent://audit/recent") {
          const events = store.listAuditEvents({ limit: 30 });
          data = { events };
        } else {
          return c.json(
            jsonRpcError(id, -32602, `Unknown MCP resource URI "${uri}".`),
            200,
          );
        }
        return c.json(
          jsonRpcResult(id, {
            contents: [
              {
                uri,
                mimeType: "application/json",
                text: JSON.stringify(redactStructuredValue(data), null, 2),
              },
            ],
          }),
        );
      } catch (err) {
        return c.json(
          jsonRpcError(
            id,
            -32000,
            err instanceof Error ? err.message : String(err),
          ),
          200,
        );
      }
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
          const gitCredentials = store.listGitCredentials();
          const isAppLocked = token.allowedSlugs.length > 0;
          callResult = toolOk({
            server: {
              dashboardUrl: buildDashboardBaseUrl(store),
              appsBaseDomain: setup.appsBaseDomain,
              httpsActive: setup.httpsActive,
              tlsStatus: setup.tlsStatus,
              tailscaleDomain: setup.tailscaleDomain,
              tailscaleServeEnabled: setup.tailscaleServeEnabled,
              tailscaleUrl:
                setup.tailscaleServeEnabled && setup.tailscaleDomain
                  ? `https://${setup.tailscaleDomain}`
                  : null,
              publicReposSupported: true,
              privateReposSupported: true,
              githubConnected: gitCredentials.length > 0,
              githubCredentials: isAppLocked
                ? []
                : gitCredentials.map((c) => ({
                    id: c.id,
                    label: c.label,
                    accountLogin: c.accountLogin,
                    isDefault: c.isDefault,
                  })),
              githubSettingsUrl: buildGithubSettingsUrl(store),
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

        case "list_github_repos": {
          if (token.allowedSlugs.length > 0) {
            store.recordAudit({
              actor: "agent",
              actorTokenId: token.id,
              action: "mcp.blocked_app_scope",
              targetSlug: null,
              summary: `Blocked AI pass "${token.name}" from listing GitHub repos (locked to ${token.allowedSlugs.join(", ")})`,
              riskLevel: "high",
            });
            callResult = toolErr(
              `Permission denied: visitor pass "${token.name}" is locked to [${token.allowedSlugs.join(", ")}] and cannot list the owner's GitHub repositories.`,
            );
            break;
          }
          const query =
            typeof args.query === "string" && args.query.trim()
              ? args.query.trim()
              : undefined;
          const credentialId =
            typeof args.credentialId === "string" && args.credentialId.trim()
              ? args.credentialId.trim()
              : undefined;
          const limit =
            typeof args.limit === "number"
              ? Math.min(Math.max(Math.trunc(args.limit), 1), 100)
              : 30;
          const res = await executor.listGithubRepos({
            ...(credentialId ? { credentialId } : {}),
            ...(query ? { query } : {}),
            limit,
          });
          const githubSettingsUrl = buildGithubSettingsUrl(store);
          if (!res.connected) {
            callResult = toolOk({
              connected: false,
              repos: [],
              githubSettingsUrl,
              message:
                "No GitHub access token is connected yet. Share githubSettingsUrl with the owner so they can paste a Read-only Contents token directly into the encrypted VPSAgent dashboard.",
            });
            break;
          }
          callResult = toolOk({
            connected: true,
            repos: res.repos,
            hasMore: res.hasMore,
            errors: res.errors,
            githubSettingsUrl,
          });
          break;
        }

        case "inspect_git_repo": {
          const parsedInput = InspectGitInputSchema.parse(args);
          const allowSavedGitCredentials =
            token.allowedSlugs.length === 0 ||
            isRepoBoundToAllowedApp(store, token, parsedInput.gitRepoUrl);
          if (!allowSavedGitCredentials && parsedInput.gitCredentialId) {
            store.recordAudit({
              actor: "agent",
              actorTokenId: token.id,
              action: "mcp.blocked_app_scope",
              targetSlug: null,
              summary: `Blocked app-locked pass "${token.name}" from inspecting unrelated repo with saved GitHub credentials`,
              riskLevel: "high",
            });
            callResult = toolErr(
              `Permission denied: visitor pass "${token.name}" is locked to [${token.allowedSlugs.join(", ")}] and cannot use saved GitHub credentials for an unrelated repository.`,
            );
            break;
          }
          try {
            const inspected = await executor.inspectGitRepo(parsedInput, {
              allowSavedGitCredentials,
            });
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
          } catch (err) {
            if (err instanceof RuntimeBridgeError && err.statusCode === 401) {
              if (!allowSavedGitCredentials) {
                callResult = toolErr(
                  `Permission denied: visitor pass "${token.name}" is locked to [${token.allowedSlugs.join(", ")}] and cannot access unrelated private repositories using the owner's saved GitHub credentials.`,
                );
                break;
              }
              callResult = toolErr(
                `${err.message} Connect or update a GitHub token at ${buildGithubSettingsUrl(store)}.`,
              );
              break;
            }
            throw err;
          }
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
          let allowSavedGitCredentials = true;
          if (token.allowedSlugs.length > 0 && input.sourceType === "git") {
            const existingForSlug = store.getApp(slug);
            allowSavedGitCredentials = Boolean(
              existingForSlug?.gitRepoUrl &&
                input.gitRepoUrl &&
                normalizeGitUrlForComparison(existingForSlug.gitRepoUrl) ===
                  normalizeGitUrlForComparison(input.gitRepoUrl),
            );
            if (!allowSavedGitCredentials && input.gitCredentialId) {
              store.recordAudit({
                actor: "agent",
                actorTokenId: token.id,
                action: "mcp.blocked_app_scope",
                targetSlug: slug,
                summary: `Blocked app-locked pass "${token.name}" from deploying unrelated private repo into "${slug}"`,
                riskLevel: "high",
              });
              callResult = toolErr(
                `Permission denied: visitor pass "${token.name}" is locked to [${token.allowedSlugs.join(", ")}] and cannot deploy an unrelated private repository using the owner's saved GitHub credentials.`,
              );
              break;
            }
          }
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
                allowSavedGitCredentials,
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

        case "start_app": {
          const slug = validateAppSlug(String(args.slug ?? ""));
          callResult = await handleMutation(token, {
            action: "start_app",
            targetSlug: slug,
            summary: `Start app "${slug}"`,
            payload: { slug },
            riskLevel: "low",
            run: () => executor.lifecycleApp(slug, "start", "agent", token.id),
          });
          break;
        }

        case "get_audit_history": {
          const query =
            typeof args.query === "string" && args.query.trim()
              ? args.query.trim()
              : undefined;
          const targetSlug =
            typeof args.targetSlug === "string" && args.targetSlug.trim()
              ? validateAppSlug(args.targetSlug.trim())
              : undefined;
          const limit =
            typeof args.limit === "number"
              ? Math.min(Math.max(Math.trunc(args.limit), 1), 200)
              : 50;
          const events = store.listAuditEvents({
            limit,
            ...(query ? { query } : {}),
            ...(targetSlug ? { targetSlug } : {}),
          });
          callResult = toolOk({ events });
          break;
        }

        case "get_setup_status": {
          let setup = store.getSetupState();
          if (args.recheckTls === true && setup.domain && bridge.checkCoreTls) {
            const checked = await bridge.checkCoreTls(setup.domain);
            setup = store.updateSetupState({
              httpsActive: checked.httpsActive,
              tlsStatus: checked.tlsStatus,
              tlsError: checked.tlsError,
            });
          }
          let tailscale = null;
          if (bridge.getTailscaleStatus) {
            try {
              const rawTs = await bridge.getTailscaleStatus();
              const nextDomain = rawTs.dnsName || null;
              const nextEnabled = Boolean(
                rawTs.serveEnabled && rawTs.dnsName,
              );
              if (
                setup.tailscaleDomain !== nextDomain ||
                setup.tailscaleServeEnabled !== nextEnabled
              ) {
                setup = store.updateSetupState({
                  tailscaleDomain: nextDomain,
                  tailscaleServeEnabled: nextEnabled,
                });
              }
              tailscale = {
                ...rawTs,
                loginUrl: null,
              };
            } catch {
              tailscale = null;
            }
          }
          callResult = toolOk({ setup, tailscale });
          break;
        }

        case "exec_in_app": {
          const input = ExecInAppInputSchema.parse(args);
          const slug = validateAppSlug(input.slug);
          const cmdPreview = redactSecrets(input.command).slice(0, 120);
          callResult = await handleMutation(token, {
            action: "exec_in_app",
            targetSlug: slug,
            summary: `Run command in "${slug}" (${input.service ?? "app"}): ${cmdPreview}`,
            payload: input as unknown as Record<string, unknown>,
            riskLevel: "medium",
            run: () => executor.execInApp(input, "agent", token.id),
          });
          break;
        }

        case "run_host_command": {
          const input = RunHostCommandInputSchema.parse(args);
          const cmdPreview = redactSecrets(input.command).slice(0, 140);
          callResult = await handleMutation(token, {
            action: "run_host_command",
            targetSlug: null,
            summary: `Run host command: ${cmdPreview}`,
            payload: input as unknown as Record<string, unknown>,
            riskLevel: "high",
            run: () => executor.runHostCommand(input, "agent", token.id),
          });
          break;
        }

        case "list_files": {
          const targetPath = z.string().trim().min(1).max(1024).parse(args.path);
          const res = await bridge.listHostFiles({
            path: targetPath,
            showHidden:
              typeof args.showHidden === "boolean"
                ? args.showHidden
                : undefined,
            maxEntries:
              typeof args.maxEntries === "number"
                ? Math.min(Math.max(Math.trunc(args.maxEntries), 1), 500)
                : undefined,
          });
          callResult = toolOk(res);
          break;
        }

        case "read_file": {
          const targetPath = z.string().trim().min(1).max(1024).parse(args.path);
          const res = await bridge.readHostFile({
            path: targetPath,
            startLine:
              typeof args.startLine === "number"
                ? Math.max(Math.trunc(args.startLine), 1)
                : undefined,
            endLine:
              typeof args.endLine === "number"
                ? Math.max(Math.trunc(args.endLine), 1)
                : undefined,
            maxBytes:
              typeof args.maxBytes === "number"
                ? Math.min(Math.max(Math.trunc(args.maxBytes), 256), 131072)
                : undefined,
          });
          callResult = toolOk(res);
          break;
        }

        case "write_file": {
          const input = WriteHostFileInputSchema.parse(args);
          callResult = await handleMutation(token, {
            action: "write_file",
            targetSlug: null,
            summary: `${input.append ? "Append to" : "Write"} file ${input.path}`,
            payload: input as unknown as Record<string, unknown>,
            riskLevel: "high",
            run: () => executor.writeHostFile(input, "agent", token.id),
          });
          break;
        }

        case "delete_file": {
          const input = DeleteHostFileInputSchema.parse(args);
          callResult = await handleMutation(token, {
            action: "delete_file",
            targetSlug: null,
            summary: `Delete ${input.recursive ? "path recursively" : "path"} ${input.path}`,
            payload: input as unknown as Record<string, unknown>,
            riskLevel: "high",
            run: () => executor.deleteHostFile(input, "agent", token.id),
          });
          break;
        }

        case "list_services": {
          const res = await bridge.listHostServices({
            filter: typeof args.filter === "string" ? args.filter : undefined,
            state:
              args.state === "running" ||
              args.state === "failed" ||
              args.state === "all"
                ? args.state
                : undefined,
            limit:
              typeof args.limit === "number"
                ? Math.min(Math.max(Math.trunc(args.limit), 1), 300)
                : undefined,
          });
          callResult = toolOk(res);
          break;
        }

        case "manage_service": {
          const input = ManageHostServiceInputSchema.parse(args);
          if (input.action === "status") {
            const res = await bridge.manageHostService(input);
            if (!res.ok) {
              const safe = redactStructuredValue(res);
              callResult = {
                content: [{ type: "text", text: JSON.stringify(safe, null, 2) }],
                isError: true,
              };
            } else {
              callResult = toolOk(res);
            }
            break;
          }
          callResult = await handleMutation(token, {
            action: "manage_service",
            targetSlug: null,
            summary: `Run systemctl ${input.action} on ${input.service}`,
            payload: input as unknown as Record<string, unknown>,
            riskLevel: "high",
            run: () => executor.manageHostService(input, "agent", token.id),
          });
          break;
        }

        case "docker_cleanup": {
          const input = DockerCleanupInputSchema.parse(args);
          callResult = await handleMutation(token, {
            action: "docker_cleanup",
            targetSlug: null,
            summary: `Prune unused Docker resources (images=${String(input.pruneImages)}, cache=${String(input.pruneBuildCache)}, volumes=${String(input.pruneVolumes)})`,
            payload: input as unknown as Record<string, unknown>,
            riskLevel: "medium",
            run: () => executor.dockerCleanup(input, "agent", token.id),
          });
          break;
        }

        case "wait_for_approval": {
          const approvalId = z.string().trim().min(1).max(128).parse(args.approvalId);
          const timeoutSeconds =
            typeof args.timeoutSeconds === "number"
              ? Math.min(Math.max(Math.trunc(args.timeoutSeconds), 1), 60)
              : 30;
          const deadline = Date.now() + timeoutSeconds * 1000;
          let approval = store.getApproval(approvalId);
          if (!approval || approval.tokenId !== token.id) {
            callResult = toolErr(`Approval request "${approvalId}" not found.`);
            break;
          }
          while (
            (approval.status === "pending" || approval.status === "approved") &&
            Date.now() < deadline
          ) {
            await new Promise((resolve) => setTimeout(resolve, 400));
            const latest = store.getApproval(approvalId);
            if (!latest || latest.tokenId !== token.id) break;
            approval = latest;
          }
          const done =
            approval.status === "executed" ||
            approval.status === "rejected" ||
            approval.status === "failed";
          const safeOutcome = redactStructuredValue({
            done,
            status: approval.status,
            approvalId: approval.id,
            action: approval.action,
            targetSlug: approval.targetSlug,
            resultSummary: approval.resultSummary,
            decisionNote: approval.decisionNote,
            message: done
              ? `Approval ${approval.id} finished with status "${approval.status}": ${approval.resultSummary ?? approval.decisionNote ?? approval.summary}`
              : `Approval ${approval.id} is still "${approval.status}" after waiting ${timeoutSeconds}s. Ask the server owner to approve it in the dashboard and call wait_for_approval again.`,
          });
          callResult = {
            content: [{ type: "text", text: JSON.stringify(safeOutcome, null, 2) }],
            isError: approval.status === "failed",
          };
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
