import http from "node:http";
import https from "node:https";
import { z } from "zod";
import {
  redactSecrets,
  validateAppSlug,
  validateDockerfilePath,
  validateDomain,
  validateGitBranch,
  validateHttpBaseUrl,
} from "./safety.js";
import type { RegistryStore } from "./store.js";
import {
  type AppRecord,
  type AppStatus,
  AppStatusSchema,
  DiskMetricsSchema,
  SystemMetricsSchema,
  TlsStatusSchema,
} from "./types.js";

export const RuntimeLifecycleActionSchema = z.enum([
  "start",
  "stop",
  "restart",
  "status",
]);
export type RuntimeLifecycleAction = z.infer<
  typeof RuntimeLifecycleActionSchema
>;

export const RuntimeLifecycleResultSchema = z.object({
  slug: z.string(),
  status: AppStatusSchema,
  detail: z.string().optional(),
});
export type RuntimeLifecycleResult = z.infer<
  typeof RuntimeLifecycleResultSchema
>;

export const RuntimeLogsResultSchema = z.object({
  slug: z.string(),
  lines: z.array(z.string()),
  truncated: z.boolean().optional(),
});
export type RuntimeLogsResult = z.infer<typeof RuntimeLogsResultSchema>;

export const RuntimeRouteCaddyResultSchema = z.object({
  ok: z.boolean(),
  slug: z.string(),
  domain: z.string().nullable(),
  routed: z.boolean(),
});
export type RuntimeRouteCaddyResult = z.infer<
  typeof RuntimeRouteCaddyResultSchema
>;

export const RuntimeCoreDomainResultSchema = z.object({
  ok: z.boolean(),
  domain: z.string().nullable(),
  acmeEmail: z.string().nullable(),
  httpsActive: z.boolean(),
  tlsStatus: TlsStatusSchema.default("inactive"),
  tlsError: z.string().nullable().default(null),
});
export type RuntimeCoreDomainResult = z.infer<
  typeof RuntimeCoreDomainResultSchema
>;

export const RuntimeTlsCheckResultSchema = z.object({
  domain: z.string(),
  httpsActive: z.boolean(),
  tlsStatus: TlsStatusSchema,
  tlsError: z.string().nullable(),
});
export type RuntimeTlsCheckResult = z.infer<typeof RuntimeTlsCheckResultSchema>;

export const RuntimeRemoveResultSchema = z.object({
  ok: z.boolean(),
  slug: z.string(),
});
export type RuntimeRemoveResult = z.infer<typeof RuntimeRemoveResultSchema>;

export const RuntimeStatusesResultSchema = z.object({
  statuses: z.record(z.string(), AppStatusSchema),
});
export type RuntimeStatusesResult = z.infer<typeof RuntimeStatusesResultSchema>;

export const RuntimeHealthResultSchema = z.object({
  ok: z.boolean(),
  service: z.string().optional(),
});
export type RuntimeHealthResult = z.infer<typeof RuntimeHealthResultSchema>;

export const RuntimeHostStatsResultSchema = z.object({
  metrics: SystemMetricsSchema,
  disk: DiskMetricsSchema,
});
export type RuntimeHostStatsResult = z.infer<
  typeof RuntimeHostStatsResultSchema
>;

export const RuntimeBuildGitResultSchema = z.object({
  ok: z.boolean(),
  slug: z.string(),
  image: z.string(),
  commitSha: z.string().nullable(),
  durationMs: z.number().nonnegative(),
  buildLogTail: z.array(z.string()),
  detectedRuntime: z.string().nullable().optional(),
  usedAutoDockerfile: z.boolean().optional(),
  suggestedPort: z.number().int().min(1).max(65535).nullable().optional(),
  envExampleKeys: z.array(z.string()).optional(),
});
export type RuntimeBuildGitResult = z.infer<typeof RuntimeBuildGitResultSchema>;

export const GitEnvExampleKeySchema = z.object({
  key: z.string().min(1).max(128),
  isSecret: z.boolean(),
});
export type GitEnvExampleKey = z.infer<typeof GitEnvExampleKeySchema>;

export const RuntimeInspectGitResultSchema = z.object({
  ok: z.boolean(),
  gitRepoUrl: z.string(),
  resolvedBranch: z.string().nullable(),
  commitSha: z.string().nullable(),
  hasDockerfile: z.boolean(),
  dockerfilePath: z.string(),
  detectedRuntime: z.string(),
  suggestedPort: z.number().int().min(1).max(65535),
  suggestedSlug: z.string().min(2).max(48),
  suggestedName: z.string().min(1).max(100),
  envExampleKeys: z.array(GitEnvExampleKeySchema).default([]),
  suggestedCompanions: z.array(z.enum(["postgres", "redis"])).default([]),
  buildPlanSummary: z.string(),
  notes: z.array(z.string()).default([]),
});
export type RuntimeInspectGitResult = z.infer<
  typeof RuntimeInspectGitResultSchema
>;

export const ContainerSecurityAuditSchema = z.object({
  capDropAll: z.boolean(),
  noNewPrivileges: z.boolean(),
  privileged: z.boolean(),
  hasDockerSocketMount: z.boolean(),
  isolatedNetworkOnly: z.boolean(),
  memoryLimitMb: z.number().int().nonnegative().nullable(),
  nanoCpus: z.number().int().nonnegative().nullable(),
  lockedApartmentCompliant: z.boolean(),
});
export type ContainerSecurityAudit = z.infer<
  typeof ContainerSecurityAuditSchema
>;

export const InspectedContainerSchema = z.object({
  id: z.string(),
  name: z.string(),
  image: z.string(),
  state: z.string(),
  running: z.boolean(),
  exitCode: z.number().int(),
  restartCount: z.number().int().nonnegative(),
  startedAt: z.string().nullable(),
  healthStatus: z.enum(["healthy", "unhealthy", "starting", "none"]),
  lastHealthOutput: z.string().nullable(),
  networks: z.array(z.string()),
  ipAddress: z.string().nullable(),
  security: ContainerSecurityAuditSchema,
});
export type InspectedContainer = z.infer<typeof InspectedContainerSchema>;

export const HttpProbeResultSchema = z.object({
  attempted: z.boolean(),
  ok: z.boolean(),
  statusCode: z.number().int().nullable(),
  latencyMs: z.number().nonnegative().nullable(),
  contentType: z.string().nullable(),
  error: z.string().nullable(),
});
export type HttpProbeResult = z.infer<typeof HttpProbeResultSchema>;

export const HostHttpHealthSchema = z.object({
  status: z.enum(["healthy", "unhealthy", "starting", "none"]),
  consecutiveFailures: z.number().int().nonnegative(),
  lastOutput: z.string().nullable(),
});
export type HostHttpHealth = z.infer<typeof HostHttpHealthSchema>;

export const RuntimeInspectResultSchema = z.object({
  slug: z.string(),
  status: AppStatusSchema,
  workspaceExists: z.boolean(),
  composeExists: z.boolean(),
  caddyRouteConfigured: z.boolean(),
  caddyDomains: z.array(z.string()),
  containers: z.array(InspectedContainerSchema),
  lockedApartmentCompliant: z.boolean(),
  httpProbe: HttpProbeResultSchema.nullable(),
  hostHttpHealth: HostHttpHealthSchema.nullable().optional(),
});
export type RuntimeInspectResult = z.infer<typeof RuntimeInspectResultSchema>;

export const RuntimeReadinessResultSchema = z.object({
  ready: z.boolean(),
  slug: z.string(),
  status: AppStatusSchema,
  attempts: z.number().int().nonnegative(),
  elapsedMs: z.number().nonnegative(),
  httpProbe: HttpProbeResultSchema.nullable(),
  reason: z.string().nullable(),
});
export type RuntimeReadinessResult = z.infer<
  typeof RuntimeReadinessResultSchema
>;

export const RuntimeCommandResultSchema = z.object({
  exitCode: z.number().int(),
  stdout: z.string(),
  stderr: z.string(),
  durationMs: z.number().nonnegative(),
  truncated: z.boolean().default(false),
});
export type RuntimeCommandResult = z.infer<typeof RuntimeCommandResultSchema>;

export const RuntimeFileEntrySchema = z.object({
  name: z.string(),
  path: z.string(),
  type: z.enum(["file", "dir", "symlink", "other"]),
  sizeBytes: z.number().int().nonnegative(),
  modifiedAt: z.string().nullable(),
});
export type RuntimeFileEntry = z.infer<typeof RuntimeFileEntrySchema>;

export const RuntimeListFilesResultSchema = z.object({
  path: z.string(),
  entries: z.array(RuntimeFileEntrySchema),
  truncated: z.boolean().default(false),
});
export type RuntimeListFilesResult = z.infer<
  typeof RuntimeListFilesResultSchema
>;

export const RuntimeReadFileResultSchema = z.object({
  path: z.string(),
  content: z.string(),
  sizeBytes: z.number().int().nonnegative(),
  totalLines: z.number().int().nonnegative(),
  startLine: z.number().int().positive(),
  endLine: z.number().int().nonnegative(),
  truncated: z.boolean().default(false),
});
export type RuntimeReadFileResult = z.infer<typeof RuntimeReadFileResultSchema>;

export const RuntimeWriteFileResultSchema = z.object({
  ok: z.boolean(),
  path: z.string(),
  bytesWritten: z.number().int().nonnegative(),
  appended: z.boolean().default(false),
});
export type RuntimeWriteFileResult = z.infer<
  typeof RuntimeWriteFileResultSchema
>;

export const RuntimeDeleteFileResultSchema = z.object({
  ok: z.boolean(),
  path: z.string(),
  deletedType: z.enum(["file", "dir", "symlink"]),
});
export type RuntimeDeleteFileResult = z.infer<
  typeof RuntimeDeleteFileResultSchema
>;

export const RuntimeServiceEntrySchema = z.object({
  name: z.string(),
  loadState: z.string(),
  activeState: z.string(),
  subState: z.string(),
  description: z.string(),
});
export type RuntimeServiceEntry = z.infer<typeof RuntimeServiceEntrySchema>;

export const RuntimeListServicesResultSchema = z.object({
  services: z.array(RuntimeServiceEntrySchema),
  truncated: z.boolean().default(false),
});
export type RuntimeListServicesResult = z.infer<
  typeof RuntimeListServicesResultSchema
>;

export const RuntimeServiceActionSchema = z.enum([
  "start",
  "stop",
  "restart",
  "reload",
  "enable",
  "disable",
  "status",
]);
export type RuntimeServiceAction = z.infer<typeof RuntimeServiceActionSchema>;

export const RuntimeManageServiceResultSchema = z.object({
  ok: z.boolean(),
  service: z.string(),
  action: RuntimeServiceActionSchema,
  activeState: z.string(),
  output: z.string(),
});
export type RuntimeManageServiceResult = z.infer<
  typeof RuntimeManageServiceResultSchema
>;

export const RuntimeDockerCleanupResultSchema = z.object({
  ok: z.boolean(),
  output: z.string(),
  reclaimedSummary: z.string(),
});
export type RuntimeDockerCleanupResult = z.infer<
  typeof RuntimeDockerCleanupResultSchema
>;

export const RuntimeCoreUpdateStateSchema = z.enum([
  "idle",
  "updating",
  "succeeded",
  "failed",
]);
export type RuntimeCoreUpdateState = z.infer<
  typeof RuntimeCoreUpdateStateSchema
>;

export const RuntimeCoreUpdateStatusSchema = z.object({
  state: RuntimeCoreUpdateStateSchema,
  phase: z.string().nullable().default(null),
  canUpdate: z.boolean(),
  unavailableReason: z.string().nullable().default(null),
  repoDir: z.string().nullable().default(null),
  branch: z.string().nullable().default(null),
  currentVersion: z.string().nullable().default(null),
  currentCommit: z.string().nullable().default(null),
  latestCommit: z.string().nullable().default(null),
  latestCommitSubject: z.string().nullable().default(null),
  latestCommitDate: z.string().nullable().default(null),
  commitsBehind: z.number().int().nonnegative().default(0),
  updateAvailable: z.boolean().default(false),
  dirtyWorkingTree: z.boolean().default(false),
  checkedAt: z.string().nullable().default(null),
  startedAt: z.string().nullable().default(null),
  finishedAt: z.string().nullable().default(null),
  message: z.string().nullable().default(null),
  error: z.string().nullable().default(null),
  logs: z.array(z.string()).default([]),
});
export type RuntimeCoreUpdateStatus = z.infer<
  typeof RuntimeCoreUpdateStatusSchema
>;

export const RuntimeCoreUpdateApplyResultSchema = z.object({
  ok: z.boolean(),
  started: z.boolean(),
  status: RuntimeCoreUpdateStatusSchema,
});
export type RuntimeCoreUpdateApplyResult = z.infer<
  typeof RuntimeCoreUpdateApplyResultSchema
>;

export interface RuntimeExecInAppInput {
  slug: string;
  command: string;
  service?: string | undefined;
  timeoutSeconds?: number | undefined;
}

export interface RuntimeHostCommandInput {
  command: string;
  cwd?: string | undefined;
  timeoutSeconds?: number | undefined;
}

export interface RuntimeListFilesInput {
  path: string;
  showHidden?: boolean | undefined;
  maxEntries?: number | undefined;
}

export interface RuntimeReadFileInput {
  path: string;
  startLine?: number | undefined;
  endLine?: number | undefined;
  maxBytes?: number | undefined;
}

export interface RuntimeWriteFileInput {
  path: string;
  content: string;
  append?: boolean | undefined;
  createDirs?: boolean | undefined;
}

export interface RuntimeDeleteFileInput {
  path: string;
  recursive?: boolean | undefined;
}

export interface RuntimeListServicesInput {
  filter?: string | undefined;
  state?: "all" | "running" | "failed" | undefined;
  limit?: number | undefined;
}

export interface RuntimeManageServiceInput {
  service: string;
  action: RuntimeServiceAction;
}

export interface RuntimeDockerCleanupInput {
  pruneImages?: boolean | undefined;
  pruneBuildCache?: boolean | undefined;
  pruneVolumes?: boolean | undefined;
}

export interface RuntimeInspectOptions {
  probeHttp?: boolean | undefined;
  internalPort?: number | undefined;
  probePath?: string | undefined;
}

export interface RuntimeBuildGitInput {
  slug: string;
  gitRepoUrl: string;
  gitBranch?: string | null | undefined;
  dockerfilePath?: string | undefined;
  allowAutoDetect?: boolean | undefined;
  timeoutSeconds?: number | undefined;
}

export interface RuntimeInspectGitInput {
  gitRepoUrl: string;
  gitBranch?: string | null | undefined;
  dockerfilePath?: string | undefined;
  timeoutSeconds?: number | undefined;
}

export interface RuntimeReadinessOptions {
  internalPort: number;
  probeHttp?: boolean | undefined;
  probePath?: string | undefined;
  timeoutSeconds?: number | undefined;
  pollIntervalMs?: number | undefined;
}

/** Narrow, allowlisted runtime bridge interface between core services and host Docker/Caddy. */
export interface RuntimeBridge {
  health(): Promise<RuntimeHealthResult>;
  getHostStats(): Promise<RuntimeHostStatsResult>;
  lifecycle(
    slug: string,
    action: RuntimeLifecycleAction,
  ): Promise<RuntimeLifecycleResult>;
  buildGitImage(input: RuntimeBuildGitInput): Promise<RuntimeBuildGitResult>;
  inspectGitRepo?(input: RuntimeInspectGitInput): Promise<RuntimeInspectGitResult>;
  getLogs(slug: string, tail: number): Promise<string[]>;
  getLogsDetailed?(slug: string, tail: number): Promise<RuntimeLogsResult>;
  routeCaddy(input: {
    slug: string;
    domain: string | null;
    internalPort: number;
  }): Promise<RuntimeRouteCaddyResult>;
  routeCoreDomain(input: {
    domain: string | null;
    acmeEmail?: string | null | undefined;
  }): Promise<RuntimeCoreDomainResult>;
  checkCoreTls?(domain: string): Promise<RuntimeTlsCheckResult>;
  removeWorkload(
    slug: string,
    options?: { removeFiles?: boolean | undefined },
  ): Promise<RuntimeRemoveResult>;
  getStatuses(slugs: string[]): Promise<Record<string, AppStatus>>;
  inspectWorkload(
    slug: string,
    options?: RuntimeInspectOptions,
  ): Promise<RuntimeInspectResult>;
  waitForReadiness(
    slug: string,
    options: RuntimeReadinessOptions,
  ): Promise<RuntimeReadinessResult>;
  execInApp(input: RuntimeExecInAppInput): Promise<RuntimeCommandResult>;
  runHostCommand(input: RuntimeHostCommandInput): Promise<RuntimeCommandResult>;
  listHostFiles(input: RuntimeListFilesInput): Promise<RuntimeListFilesResult>;
  readHostFile(input: RuntimeReadFileInput): Promise<RuntimeReadFileResult>;
  writeHostFile(input: RuntimeWriteFileInput): Promise<RuntimeWriteFileResult>;
  deleteHostFile(
    input: RuntimeDeleteFileInput,
  ): Promise<RuntimeDeleteFileResult>;
  listHostServices(
    input?: RuntimeListServicesInput,
  ): Promise<RuntimeListServicesResult>;
  manageHostService(
    input: RuntimeManageServiceInput,
  ): Promise<RuntimeManageServiceResult>;
  dockerCleanup(
    input?: RuntimeDockerCleanupInput,
  ): Promise<RuntimeDockerCleanupResult>;
  getCoreUpdateStatus?(): Promise<RuntimeCoreUpdateStatus>;
  checkCoreUpdate?(): Promise<RuntimeCoreUpdateStatus>;
  applyCoreUpdate?(): Promise<RuntimeCoreUpdateApplyResult>;
}

export class RuntimeBridgeError extends Error {
  readonly statusCode: number;
  readonly buildLogTail: string[];

  constructor(
    statusCode: number,
    message: string,
    buildLogTail: string[] = [],
  ) {
    super(redactSecrets(message));
    this.name = "RuntimeBridgeError";
    this.statusCode = statusCode;
    this.buildLogTail = buildLogTail.map((line) => redactSecrets(line));
  }
}

export interface HttpRuntimeBridgeClientOptions {
  socketPath?: string | undefined;
  baseUrl?: string | undefined;
  runtimeToken?: string | undefined;
  defaultTimeoutMs?: number | undefined;
  maxResponseBytes?: number | undefined;
}

const DEFAULT_TIMEOUT_MS = 240_000;
const BUILD_TIMEOUT_MS = 630_000;
const SHORT_TIMEOUT_MS = 30_000;
const DEFAULT_MAX_RESPONSE_BYTES = 2 * 1024 * 1024;
const MAX_STATUS_BATCH = 100;

/**
 * Typed HTTP-over-Unix-Socket (or loopback HTTP for tests) client for the host
 * `vpsagent-runtime` daemon. Enforces input validation, wall-clock timeouts,
 * response caps, and secret redaction on every boundary.
 */
export class HttpRuntimeBridgeClient implements RuntimeBridge {
  private readonly socketPath: string | undefined;
  private readonly parsedBaseUrl: URL | undefined;
  private readonly runtimeToken: string | undefined;
  private readonly defaultTimeoutMs: number;
  private readonly maxResponseBytes: number;

  constructor(options: HttpRuntimeBridgeClientOptions) {
    const socket = options.socketPath?.trim() || undefined;
    const rawUrl = options.baseUrl?.trim() || undefined;
    if (!socket && !rawUrl) {
      throw new Error(
        "HttpRuntimeBridgeClient requires either socketPath or baseUrl.",
      );
    }

    this.socketPath = socket;
    this.parsedBaseUrl = rawUrl
      ? new URL(validateHttpBaseUrl(rawUrl))
      : undefined;
    this.runtimeToken = options.runtimeToken?.trim() || undefined;
    this.defaultTimeoutMs = Math.max(
      500,
      options.defaultTimeoutMs ?? DEFAULT_TIMEOUT_MS,
    );
    this.maxResponseBytes = Math.max(
      4096,
      options.maxResponseBytes ?? DEFAULT_MAX_RESPONSE_BYTES,
    );
  }

  async health(): Promise<RuntimeHealthResult> {
    const raw = await this.requestJson(
      "GET",
      "/health",
      undefined,
      SHORT_TIMEOUT_MS,
    );
    return RuntimeHealthResultSchema.parse(raw);
  }

  async getHostStats(): Promise<RuntimeHostStatsResult> {
    const raw = await this.requestJson(
      "GET",
      "/v1/host/stats",
      undefined,
      SHORT_TIMEOUT_MS,
    );
    return RuntimeHostStatsResultSchema.parse(raw);
  }

  async lifecycle(
    slug: string,
    action: RuntimeLifecycleAction,
  ): Promise<RuntimeLifecycleResult> {
    const safeSlug = validateAppSlug(slug);
    const safeAction = RuntimeLifecycleActionSchema.parse(action);
    const timeoutMs =
      safeAction === "status" ? SHORT_TIMEOUT_MS : this.defaultTimeoutMs;
    const raw = await this.requestJson(
      "POST",
      "/v1/apps/lifecycle",
      { slug: safeSlug, action: safeAction },
      timeoutMs,
    );
    const parsed = RuntimeLifecycleResultSchema.parse(raw);
    return {
      ...parsed,
      ...(parsed.detail !== undefined
        ? { detail: redactSecrets(parsed.detail) }
        : {}),
    };
  }

  async buildGitImage(
    input: RuntimeBuildGitInput,
  ): Promise<RuntimeBuildGitResult> {
    const safeSlug = validateAppSlug(input.slug);
    const safeRepoUrl = validateHttpBaseUrl(input.gitRepoUrl, {
      allowPrivateNetwork: false,
    });
    if (!safeRepoUrl.startsWith("https://")) {
      throw new Error("Git repository URL must use https://.");
    }
    const safeBranch = input.gitBranch
      ? validateGitBranch(input.gitBranch)
      : undefined;
    const safeDockerfile =
      input.dockerfilePath && input.dockerfilePath !== "auto"
        ? validateDockerfilePath(input.dockerfilePath)
        : input.dockerfilePath === "auto"
          ? "auto"
          : "Dockerfile";
    const safeTimeoutSeconds =
      input.timeoutSeconds !== undefined
        ? z.number().int().min(10).max(600).parse(input.timeoutSeconds)
        : undefined;

    const httpTimeoutMs = safeTimeoutSeconds
      ? Math.max(SHORT_TIMEOUT_MS, (safeTimeoutSeconds + 30) * 1000)
      : Math.max(this.defaultTimeoutMs, BUILD_TIMEOUT_MS);

    const raw = await this.requestJson(
      "POST",
      "/v1/apps/build-git",
      {
        slug: safeSlug,
        gitRepoUrl: safeRepoUrl,
        ...(safeBranch !== undefined ? { gitBranch: safeBranch } : {}),
        dockerfilePath: safeDockerfile,
        ...(input.allowAutoDetect !== undefined
          ? { allowAutoDetect: Boolean(input.allowAutoDetect) }
          : {}),
        ...(safeTimeoutSeconds !== undefined
          ? { timeoutSeconds: safeTimeoutSeconds }
          : {}),
      },
      httpTimeoutMs,
    );
    const parsed = RuntimeBuildGitResultSchema.parse(raw);
    return {
      ...parsed,
      buildLogTail: parsed.buildLogTail.map((line) => redactSecrets(line)),
    };
  }

  async inspectGitRepo(
    input: RuntimeInspectGitInput,
  ): Promise<RuntimeInspectGitResult> {
    const safeRepoUrl = validateHttpBaseUrl(input.gitRepoUrl, {
      allowPrivateNetwork: false,
    });
    if (!safeRepoUrl.startsWith("https://")) {
      throw new Error("Git repository URL must use https://.");
    }
    const safeBranch = input.gitBranch
      ? validateGitBranch(input.gitBranch)
      : undefined;
    const safeDockerfile =
      input.dockerfilePath && input.dockerfilePath !== "auto"
        ? validateDockerfilePath(input.dockerfilePath)
        : "Dockerfile";
    const safeTimeoutSeconds =
      input.timeoutSeconds !== undefined
        ? z.number().int().min(5).max(120).parse(input.timeoutSeconds)
        : undefined;

    const httpTimeoutMs = safeTimeoutSeconds
      ? Math.max(SHORT_TIMEOUT_MS, (safeTimeoutSeconds + 15) * 1000)
      : 90_000;

    const raw = await this.requestJson(
      "POST",
      "/v1/apps/inspect-git",
      {
        gitRepoUrl: safeRepoUrl,
        ...(safeBranch !== undefined ? { gitBranch: safeBranch } : {}),
        dockerfilePath: safeDockerfile,
        ...(safeTimeoutSeconds !== undefined
          ? { timeoutSeconds: safeTimeoutSeconds }
          : {}),
      },
      httpTimeoutMs,
    );
    return RuntimeInspectGitResultSchema.parse(raw);
  }

  async getLogsDetailed(slug: string, tail: number): Promise<RuntimeLogsResult> {
    const safeSlug = validateAppSlug(slug);
    const safeTail = z.number().int().min(1).max(500).parse(tail);
    const raw = await this.requestJson(
      "POST",
      "/v1/apps/logs",
      { slug: safeSlug, tail: safeTail },
      SHORT_TIMEOUT_MS,
    );
    const parsed = RuntimeLogsResultSchema.parse(raw);
    const joined = redactSecrets(parsed.lines.join("\n"));
    const lines = joined ? joined.split(/\r?\n/).slice(-safeTail) : [];
    return {
      slug: parsed.slug,
      lines,
      ...(parsed.truncated !== undefined
        ? { truncated: parsed.truncated }
        : {}),
    };
  }

  async getLogs(slug: string, tail: number): Promise<string[]> {
    const detailed = await this.getLogsDetailed(slug, tail);
    return detailed.lines;
  }

  async routeCaddy(input: {
    slug: string;
    domain: string | null;
    internalPort: number;
  }): Promise<RuntimeRouteCaddyResult> {
    const safeSlug = validateAppSlug(input.slug);
    const safeDomain = input.domain ? validateDomain(input.domain) : null;
    const safePort = z
      .number()
      .int()
      .min(1)
      .max(65535)
      .parse(input.internalPort);
    const raw = await this.requestJson(
      "POST",
      "/v1/apps/route-caddy",
      {
        slug: safeSlug,
        domain: safeDomain,
        internalPort: safePort,
      },
      this.defaultTimeoutMs,
    );
    return RuntimeRouteCaddyResultSchema.parse(raw);
  }

  async routeCoreDomain(input: {
    domain: string | null;
    acmeEmail?: string | null | undefined;
  }): Promise<RuntimeCoreDomainResult> {
    const safeDomain = input.domain ? validateDomain(input.domain) : null;
    const safeEmail = input.acmeEmail?.trim() || null;
    const raw = await this.requestJson(
      "POST",
      "/v1/core/route-domain",
      {
        domain: safeDomain,
        acmeEmail: safeEmail,
      },
      this.defaultTimeoutMs,
    );
    return RuntimeCoreDomainResultSchema.parse(raw);
  }

  async checkCoreTls(domain: string): Promise<RuntimeTlsCheckResult> {
    const safeDomain = validateDomain(domain);
    const raw = await this.requestJson(
      "POST",
      "/v1/core/tls-check",
      { domain: safeDomain },
      SHORT_TIMEOUT_MS,
    );
    return RuntimeTlsCheckResultSchema.parse(raw);
  }

  async removeWorkload(
    slug: string,
    options?: { removeFiles?: boolean | undefined },
  ): Promise<RuntimeRemoveResult> {
    const safeSlug = validateAppSlug(slug);
    const raw = await this.requestJson(
      "POST",
      "/v1/apps/remove",
      {
        slug: safeSlug,
        removeFiles: Boolean(options?.removeFiles),
      },
      this.defaultTimeoutMs,
    );
    return RuntimeRemoveResultSchema.parse(raw);
  }

  async getStatuses(slugs: string[]): Promise<Record<string, AppStatus>> {
    const uniqueSlugs = Array.from(
      new Set(slugs.map((slug) => validateAppSlug(slug))),
    );
    if (uniqueSlugs.length === 0) {
      return {};
    }

    const merged: Record<string, AppStatus> = {};
    for (let i = 0; i < uniqueSlugs.length; i += MAX_STATUS_BATCH) {
      const batch = uniqueSlugs.slice(i, i + MAX_STATUS_BATCH);
      const raw = await this.requestJson(
        "POST",
        "/v1/apps/statuses",
        { slugs: batch },
        SHORT_TIMEOUT_MS,
      );
      const parsed = RuntimeStatusesResultSchema.parse(raw);
      Object.assign(merged, parsed.statuses);
    }
    return merged;
  }

  async inspectWorkload(
    slug: string,
    options?: RuntimeInspectOptions,
  ): Promise<RuntimeInspectResult> {
    const safeSlug = validateAppSlug(slug);
    const safePort =
      options?.internalPort !== undefined
        ? z.number().int().min(1).max(65535).parse(options.internalPort)
        : undefined;
    const raw = await this.requestJson(
      "POST",
      "/v1/apps/inspect",
      {
        slug: safeSlug,
        probeHttp: Boolean(options?.probeHttp),
        ...(safePort !== undefined ? { internalPort: safePort } : {}),
        ...(options?.probePath !== undefined
          ? { probePath: options.probePath }
          : {}),
      },
      SHORT_TIMEOUT_MS,
    );
    return RuntimeInspectResultSchema.parse(raw);
  }

  async waitForReadiness(
    slug: string,
    options: RuntimeReadinessOptions,
  ): Promise<RuntimeReadinessResult> {
    const safeSlug = validateAppSlug(slug);
    const safePort = z
      .number()
      .int()
      .min(1)
      .max(65535)
      .parse(options.internalPort);
    const safeTimeoutS =
      options.timeoutSeconds !== undefined
        ? z.number().min(0.1).max(60).parse(options.timeoutSeconds)
        : undefined;
    const safePollMs =
      options.pollIntervalMs !== undefined
        ? z.number().int().min(10).max(5000).parse(options.pollIntervalMs)
        : undefined;

    const httpTimeoutMs = Math.max(
      SHORT_TIMEOUT_MS,
      Math.ceil(((safeTimeoutS ?? 15) + 10) * 1000),
    );

    const raw = await this.requestJson(
      "POST",
      "/v1/apps/readiness",
      {
        slug: safeSlug,
        internalPort: safePort,
        ...(options.probeHttp !== undefined
          ? { probeHttp: options.probeHttp }
          : {}),
        ...(options.probePath !== undefined
          ? { probePath: options.probePath }
          : {}),
        ...(safeTimeoutS !== undefined ? { timeoutSeconds: safeTimeoutS } : {}),
        ...(safePollMs !== undefined ? { pollIntervalMs: safePollMs } : {}),
      },
      httpTimeoutMs,
    );
    return RuntimeReadinessResultSchema.parse(raw);
  }

  async execInApp(
    input: RuntimeExecInAppInput,
  ): Promise<RuntimeCommandResult> {
    const safeSlug = validateAppSlug(input.slug);
    const command = z.string().trim().min(1).max(8000).parse(input.command);
    const service =
      input.service !== undefined
        ? z
            .string()
            .regex(/^[a-z0-9][a-z0-9_-]{0,47}$/)
            .parse(input.service)
        : undefined;
    const timeoutSeconds =
      input.timeoutSeconds !== undefined
        ? z.number().int().min(1).max(180).parse(input.timeoutSeconds)
        : undefined;
    const httpTimeoutMs = Math.max(
      SHORT_TIMEOUT_MS,
      ((timeoutSeconds ?? 30) + 15) * 1000,
    );
    const raw = await this.requestJson(
      "POST",
      "/v1/apps/exec",
      {
        slug: safeSlug,
        command,
        ...(service !== undefined ? { service } : {}),
        ...(timeoutSeconds !== undefined ? { timeoutSeconds } : {}),
      },
      httpTimeoutMs,
    );
    const parsed = RuntimeCommandResultSchema.parse(raw);
    return {
      ...parsed,
      stdout: redactSecrets(parsed.stdout),
      stderr: redactSecrets(parsed.stderr),
    };
  }

  async runHostCommand(
    input: RuntimeHostCommandInput,
  ): Promise<RuntimeCommandResult> {
    const command = z.string().trim().min(1).max(8000).parse(input.command);
    const cwd =
      input.cwd !== undefined
        ? z.string().trim().min(1).max(512).parse(input.cwd)
        : undefined;
    const timeoutSeconds =
      input.timeoutSeconds !== undefined
        ? z.number().int().min(1).max(180).parse(input.timeoutSeconds)
        : undefined;
    const httpTimeoutMs = Math.max(
      SHORT_TIMEOUT_MS,
      ((timeoutSeconds ?? 30) + 15) * 1000,
    );
    const raw = await this.requestJson(
      "POST",
      "/v1/host/exec",
      {
        command,
        ...(cwd !== undefined ? { cwd } : {}),
        ...(timeoutSeconds !== undefined ? { timeoutSeconds } : {}),
      },
      httpTimeoutMs,
    );
    const parsed = RuntimeCommandResultSchema.parse(raw);
    return {
      ...parsed,
      stdout: redactSecrets(parsed.stdout),
      stderr: redactSecrets(parsed.stderr),
    };
  }

  async listHostFiles(
    input: RuntimeListFilesInput,
  ): Promise<RuntimeListFilesResult> {
    const targetPath = z.string().trim().min(1).max(1024).parse(input.path);
    const maxEntries =
      input.maxEntries !== undefined
        ? z.number().int().min(1).max(500).parse(input.maxEntries)
        : undefined;
    const raw = await this.requestJson(
      "POST",
      "/v1/host/files/list",
      {
        path: targetPath,
        ...(input.showHidden !== undefined
          ? { showHidden: Boolean(input.showHidden) }
          : {}),
        ...(maxEntries !== undefined ? { maxEntries } : {}),
      },
      SHORT_TIMEOUT_MS,
    );
    return RuntimeListFilesResultSchema.parse(raw);
  }

  async readHostFile(
    input: RuntimeReadFileInput,
  ): Promise<RuntimeReadFileResult> {
    const targetPath = z.string().trim().min(1).max(1024).parse(input.path);
    const startLine =
      input.startLine !== undefined
        ? z.number().int().min(1).parse(input.startLine)
        : undefined;
    const endLine =
      input.endLine !== undefined
        ? z.number().int().min(1).parse(input.endLine)
        : undefined;
    const maxBytes =
      input.maxBytes !== undefined
        ? z.number().int().min(256).max(131072).parse(input.maxBytes)
        : undefined;
    const raw = await this.requestJson(
      "POST",
      "/v1/host/files/read",
      {
        path: targetPath,
        ...(startLine !== undefined ? { startLine } : {}),
        ...(endLine !== undefined ? { endLine } : {}),
        ...(maxBytes !== undefined ? { maxBytes } : {}),
      },
      SHORT_TIMEOUT_MS,
    );
    const parsed = RuntimeReadFileResultSchema.parse(raw);
    return {
      ...parsed,
      content: redactSecrets(parsed.content),
    };
  }

  async writeHostFile(
    input: RuntimeWriteFileInput,
  ): Promise<RuntimeWriteFileResult> {
    const targetPath = z.string().trim().min(1).max(1024).parse(input.path);
    const content = z.string().max(262144).parse(input.content);
    const raw = await this.requestJson(
      "POST",
      "/v1/host/files/write",
      {
        path: targetPath,
        content,
        append: Boolean(input.append),
        createDirs: Boolean(input.createDirs),
      },
      SHORT_TIMEOUT_MS,
    );
    return RuntimeWriteFileResultSchema.parse(raw);
  }

  async deleteHostFile(
    input: RuntimeDeleteFileInput,
  ): Promise<RuntimeDeleteFileResult> {
    const targetPath = z.string().trim().min(1).max(1024).parse(input.path);
    const raw = await this.requestJson(
      "POST",
      "/v1/host/files/delete",
      {
        path: targetPath,
        recursive: Boolean(input.recursive),
      },
      SHORT_TIMEOUT_MS,
    );
    return RuntimeDeleteFileResultSchema.parse(raw);
  }

  async listHostServices(
    input?: RuntimeListServicesInput,
  ): Promise<RuntimeListServicesResult> {
    const filter = input?.filter?.trim() || undefined;
    const state =
      input?.state !== undefined
        ? z.enum(["all", "running", "failed"]).parse(input.state)
        : undefined;
    const limit =
      input?.limit !== undefined
        ? z.number().int().min(1).max(300).parse(input.limit)
        : undefined;
    const raw = await this.requestJson(
      "POST",
      "/v1/host/services/list",
      {
        ...(filter !== undefined ? { filter } : {}),
        ...(state !== undefined ? { state } : {}),
        ...(limit !== undefined ? { limit } : {}),
      },
      SHORT_TIMEOUT_MS,
    );
    return RuntimeListServicesResultSchema.parse(raw);
  }

  async manageHostService(
    input: RuntimeManageServiceInput,
  ): Promise<RuntimeManageServiceResult> {
    const service = z
      .string()
      .trim()
      .regex(/^[A-Za-z0-9@._-]{1,128}$/)
      .parse(input.service);
    const action = RuntimeServiceActionSchema.parse(input.action);
    const raw = await this.requestJson(
      "POST",
      "/v1/host/services/manage",
      { service, action },
      this.defaultTimeoutMs,
    );
    const parsed = RuntimeManageServiceResultSchema.parse(raw);
    return {
      ...parsed,
      output: redactSecrets(parsed.output),
    };
  }

  async dockerCleanup(
    input?: RuntimeDockerCleanupInput,
  ): Promise<RuntimeDockerCleanupResult> {
    const raw = await this.requestJson(
      "POST",
      "/v1/host/docker/cleanup",
      {
        pruneImages: input?.pruneImages !== false,
        pruneBuildCache: input?.pruneBuildCache !== false,
        pruneVolumes: Boolean(input?.pruneVolumes),
      },
      this.defaultTimeoutMs,
    );
    const parsed = RuntimeDockerCleanupResultSchema.parse(raw);
    return {
      ...parsed,
      output: redactSecrets(parsed.output),
      reclaimedSummary: redactSecrets(parsed.reclaimedSummary),
    };
  }

  private sanitizeUpdateStatus(
    parsed: RuntimeCoreUpdateStatus,
  ): RuntimeCoreUpdateStatus {
    return {
      ...parsed,
      unavailableReason: parsed.unavailableReason
        ? redactSecrets(parsed.unavailableReason)
        : null,
      latestCommitSubject: parsed.latestCommitSubject
        ? redactSecrets(parsed.latestCommitSubject)
        : null,
      message: parsed.message ? redactSecrets(parsed.message) : null,
      error: parsed.error ? redactSecrets(parsed.error) : null,
      logs: parsed.logs.map((line) => redactSecrets(line)),
    };
  }

  async getCoreUpdateStatus(): Promise<RuntimeCoreUpdateStatus> {
    const raw = await this.requestJson(
      "GET",
      "/v1/core/update/status",
      undefined,
      SHORT_TIMEOUT_MS,
    );
    return this.sanitizeUpdateStatus(RuntimeCoreUpdateStatusSchema.parse(raw));
  }

  async checkCoreUpdate(): Promise<RuntimeCoreUpdateStatus> {
    const raw = await this.requestJson(
      "POST",
      "/v1/core/update/check",
      {},
      60_000,
    );
    return this.sanitizeUpdateStatus(RuntimeCoreUpdateStatusSchema.parse(raw));
  }

  async applyCoreUpdate(): Promise<RuntimeCoreUpdateApplyResult> {
    const raw = await this.requestJson(
      "POST",
      "/v1/core/update/apply",
      {},
      SHORT_TIMEOUT_MS,
    );
    const parsed = RuntimeCoreUpdateApplyResultSchema.parse(raw);
    return {
      ...parsed,
      status: this.sanitizeUpdateStatus(parsed.status),
    };
  }

  private async requestJson(
    method: "GET" | "POST",
    routePath: string,
    body: Record<string, unknown> | undefined,
    timeoutMs: number,
  ): Promise<unknown> {
    const payload = body !== undefined ? JSON.stringify(body) : undefined;
    const headers: Record<string, string> = {
      accept: "application/json",
    };
    if (this.runtimeToken) {
      headers["x-vpsagent-runtime-token"] = this.runtimeToken;
    }
    if (payload !== undefined) {
      headers["content-type"] = "application/json";
      headers["content-length"] = String(Buffer.byteLength(payload, "utf8"));
    }

    return new Promise((resolve, reject) => {
      let settled = false;
      let req: http.ClientRequest | undefined;
      const timer = setTimeout(() => {
        req?.destroy();
        fail(
          new RuntimeBridgeError(
            504,
            `Host runtime bridge timed out after ${timeoutMs}ms.`,
          ),
        );
      }, timeoutMs);
      timer.unref();

      const fail = (err: RuntimeBridgeError) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        reject(err);
      };

      const succeed = (value: unknown) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        resolve(value);
      };

      const onResponse = (res: http.IncomingMessage) => {
        const chunks: Buffer[] = [];
        let totalBytes = 0;

        res.on("data", (chunk: Buffer) => {
          totalBytes += chunk.length;
          if (totalBytes > this.maxResponseBytes) {
            res.destroy();
            fail(
              new RuntimeBridgeError(
                502,
                "Runtime bridge response exceeded maximum allowed size.",
              ),
            );
            return;
          }
          chunks.push(chunk);
        });

        res.on("error", (err) => {
          fail(
            new RuntimeBridgeError(
              502,
              `Runtime bridge stream error: ${err.message}`,
            ),
          );
        });

        res.on("end", () => {
          if (settled) return;
          const text = Buffer.concat(chunks).toString("utf8");
          const status = res.statusCode ?? 502;
          let parsed: unknown = null;
          if (text.trim()) {
            try {
              parsed = JSON.parse(text);
            } catch {
              fail(
                new RuntimeBridgeError(
                  status >= 400 ? status : 502,
                  `Runtime bridge returned invalid JSON (HTTP ${status}).`,
                ),
              );
              return;
            }
          }

          if (status >= 400) {
            const msg =
              typeof parsed === "object" &&
              parsed !== null &&
              "error" in parsed &&
              typeof (parsed as { error: unknown }).error === "string"
                ? (parsed as { error: string }).error
                : `Runtime bridge failed with HTTP ${status}.`;
            const buildLogTail =
              typeof parsed === "object" &&
              parsed !== null &&
              "buildLogTail" in parsed &&
              Array.isArray((parsed as { buildLogTail: unknown }).buildLogTail)
                ? (parsed as { buildLogTail: unknown[] }).buildLogTail.filter(
                    (line): line is string => typeof line === "string",
                  )
                : [];
            fail(new RuntimeBridgeError(status, msg, buildLogTail));
            return;
          }

          succeed(parsed);
        });
      };

      if (this.socketPath) {
        req = http.request(
          {
            socketPath: this.socketPath,
            path: routePath,
            method,
            headers,
          },
          onResponse,
        );
      } else if (this.parsedBaseUrl) {
        const basePath = this.parsedBaseUrl.pathname.replace(/\/+$/, "");
        const transport =
          this.parsedBaseUrl.protocol === "https:" ? https : http;
        req = transport.request(
          {
            protocol: this.parsedBaseUrl.protocol,
            hostname: this.parsedBaseUrl.hostname,
            port: this.parsedBaseUrl.port || undefined,
            path: `${basePath}${routePath}`,
            method,
            headers,
          },
          onResponse,
        );
      } else {
        fail(
          new RuntimeBridgeError(500, "Runtime bridge transport is unconfigured."),
        );
        return;
      }

      req.on("error", (err) => {
        fail(
          new RuntimeBridgeError(
            503,
            `Host runtime bridge is unavailable: ${err.message}`,
          ),
        );
      });

      if (payload !== undefined) {
        req.write(payload);
      }
      req.end();
    });
  }
}

/** Builds an `HttpRuntimeBridgeClient` from standard `VPSAGENT_RUNTIME_*` environment variables. */
export function createRuntimeBridgeFromEnv(
  env: NodeJS.ProcessEnv = process.env,
): HttpRuntimeBridgeClient | undefined {
  const socketPath = env.VPSAGENT_RUNTIME_SOCKET?.trim();
  const baseUrl = env.VPSAGENT_RUNTIME_URL?.trim();
  const runtimeToken = env.VPSAGENT_RUNTIME_TOKEN?.trim();
  if (!socketPath && !baseUrl) {
    return undefined;
  }
  return new HttpRuntimeBridgeClient({
    socketPath,
    baseUrl,
    runtimeToken,
  });
}

export type StatusSyncProvider =
  | Pick<RuntimeBridge, "getStatuses">
  | ((
      slugs: string[],
    ) => Promise<Record<string, AppStatus>> | Record<string, AppStatus>);

/**
 * Queries live container statuses from a runtime bridge and updates drifted registry
 * records while preserving workloads currently in `"provisioning"` or `"building"`.
 */
export async function syncAppStatuses(
  store: RegistryStore,
  provider: StatusSyncProvider | undefined,
  slugs?: string[],
): Promise<AppRecord[]> {
  const existingApps = store.listApps();
  if (!provider || existingApps.length === 0) {
    return existingApps;
  }

  const isSyncEligible = (app: AppRecord): boolean =>
    app.status !== "provisioning" && app.status !== "building";

  const targetSlugs = slugs
    ? slugs.filter((s) =>
        existingApps.some((app) => app.slug === s && isSyncEligible(app)),
      )
    : existingApps.filter(isSyncEligible).map((app) => app.slug);

  if (targetSlugs.length === 0) {
    return existingApps;
  }

  try {
    const fetchStatuses =
      typeof provider === "function"
        ? provider
        : (ids: string[]) => provider.getStatuses(ids);
    const liveStatuses = await fetchStatuses(targetSlugs);
    for (const app of existingApps) {
      if (!isSyncEligible(app)) continue;
      const live = liveStatuses[app.slug];
      if (live && live !== app.status) {
        store.updateAppStatus(app.slug, live);
      }
    }
    return store.listApps();
  } catch {
    return existingApps;
  }
}
