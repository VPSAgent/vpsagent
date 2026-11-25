export interface SetupState {
  claimed: boolean;
  domain: string | null;
  appsBaseDomain: string | null;
  acmeEmail: string | null;
  httpsActive: boolean;
  tlsStatus: "inactive" | "pending" | "active" | "failed";
  tlsError: string | null;
  claimedAt: string | null;
}

export interface SessionInfo {
  claimed: boolean;
  authenticated: boolean;
  setup: SetupState;
  publicIp: string | null;
}

export interface CompanionService {
  type: "postgres" | "redis";
  version?: string;
  envKey?: string;
}

export interface AppRecord {
  slug: string;
  name: string;
  sourceType: "image" | "git";
  image: string | null;
  gitRepoUrl: string | null;
  gitBranch: string | null;
  dockerfilePath: string;
  domain: string | null;
  folderPath: string;
  internalPort: number;
  status: "provisioning" | "building" | "running" | "stopped" | "error";
  cpuLimit: string;
  memoryLimitMb: number;
  companions: CompanionService[];
  lastCommitSha: string | null;
  detectedRuntime: string | null;
  envExampleKeys: string[];
  createdAt: string;
  updatedAt: string;
}

export interface DeploymentRecord {
  id: string;
  slug: string;
  action: "deploy_app" | "rebuild_app";
  status:
    | "queued"
    | "cloning"
    | "building"
    | "starting"
    | "verifying"
    | "succeeded"
    | "failed";
  actor: "user" | "agent" | "system";
  actorTokenId: string | null;
  sourceType: "image" | "git";
  gitRepoUrl: string | null;
  gitBranch: string | null;
  commitSha: string | null;
  detectedRuntime: string | null;
  usedAutoDockerfile: boolean;
  domain: string | null;
  phaseDetail: string | null;
  buildLogs: string[];
  error: string | null;
  createdAt: string;
  updatedAt: string;
  finishedAt: string | null;
}

export interface GitInspectResult {
  ok: boolean;
  gitRepoUrl: string;
  resolvedBranch: string | null;
  commitSha: string | null;
  hasDockerfile: boolean;
  dockerfilePath: string;
  detectedRuntime: string;
  suggestedPort: number;
  suggestedSlug: string;
  suggestedName: string;
  suggestedDomain: string | null;
  envExampleKeys: Array<{ key: string; isSecret: boolean }>;
  suggestedCompanions: Array<"postgres" | "redis">;
  buildPlanSummary: string;
  notes: string[];
}

export interface AppEnvEntry {
  key: string;
  isSecret: boolean;
  maskedValue: string;
  updatedAt: string;
}

export interface SystemMetrics {
  hostname: string;
  platform: string;
  uptimeSeconds: number;
  cpuCount: number;
  loadAverage1m: number;
  memoryTotalMb: number;
  memoryUsedMb: number;
  memoryUsagePercent: number;
  collectedAt: string;
}

export interface DiskMetrics {
  totalGb: number;
  usedGb: number;
  freeGb: number;
  usedPercent: number;
  mount: string;
}

export interface OverviewResponse {
  metrics: SystemMetrics;
  disk: DiskMetrics;
  apps: AppRecord[];
  pendingApprovals: number;
  activeMcpTokens: number;
  setup: SetupState;
}

export type McpTokenScope =
  | "read-only"
  | "approval-required"
  | "safe-auto-deploy"
  | "auto-approve"
  | "host-admin";

export interface ApprovalRequest {
  id: string;
  action: string;
  targetSlug: string | null;
  summary: string;
  payload: Record<string, unknown>;
  requestedBy: string;
  tokenScope: McpTokenScope;
  status: "pending" | "approved" | "rejected" | "executed" | "failed";
  riskLevel: "low" | "medium" | "high";
  decidedBy: string | null;
  decisionNote: string | null;
  resultSummary: string | null;
  createdAt: string;
  decidedAt: string | null;
  executedAt: string | null;
}

export interface AuditEvent {
  id: string;
  actor: "user" | "agent" | "system";
  action: string;
  targetSlug: string | null;
  summary: string;
  riskLevel: "low" | "medium" | "high";
  createdAt: string;
}

export interface McpTokenRecord {
  id: string;
  name: string;
  scope: McpTokenScope;
  allowedSlugs: string[];
  tokenPrefix: string;
  createdAt: string;
  lastUsedAt: string | null;
  revokedAt: string | null;
}

export interface McpSnippets {
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

export interface McpConnectionTestResult {
  ok: boolean;
  mcpUrl: string;
  httpsReady: boolean;
  bridgeOk: boolean;
  toolCount: number;
  activeTokens: number;
  protocolVersion: string;
  message: string;
}

export interface SystemUpdateStatus {
  state: "idle" | "updating" | "succeeded" | "failed";
  phase: string | null;
  canUpdate: boolean;
  unavailableReason: string | null;
  repoDir: string | null;
  branch: string | null;
  currentVersion: string | null;
  currentCommit: string | null;
  latestCommit: string | null;
  latestCommitSubject: string | null;
  latestCommitDate: string | null;
  commitsBehind: number;
  updateAvailable: boolean;
  dirtyWorkingTree: boolean;
  checkedAt: string | null;
  startedAt: string | null;
  finishedAt: string | null;
  message: string | null;
  error: string | null;
  logs: string[];
}

export interface InspectResult {
  slug: string;
  status: AppRecord["status"];
  lockedApartmentCompliant: boolean;
  caddyRouteConfigured: boolean;
  caddyDomains: string[];
  httpProbe?: {
    attempted: boolean;
    ok: boolean;
    statusCode: number | null;
    latencyMs: number | null;
    contentType: string | null;
    error: string | null;
  } | null;
  hostHttpHealth?: {
    status: string;
    consecutiveFailures: number;
    lastOutput: string | null;
  } | null;
  containers: Array<{
    id: string;
    name: string;
    image: string;
    state: string;
    running: boolean;
    healthStatus: string;
    lastHealthOutput?: string | null;
    security: {
      capDropAll: boolean;
      noNewPrivileges: boolean;
      privileged: boolean;
      hasDockerSocketMount: boolean;
      isolatedNetworkOnly: boolean;
      lockedApartmentCompliant: boolean;
    };
  }>;
}

async function apiFetch<T>(
  url: string,
  init?: RequestInit,
): Promise<T> {
  const res = await fetch(url, {
    credentials: "include",
    headers: {
      "content-type": "application/json",
      ...(init?.headers ?? {}),
    },
    ...init,
  });
  const text = await res.text();
  let data: unknown = null;
  if (text.trim()) {
    try {
      data = JSON.parse(text);
    } catch {
      throw new Error(`Server returned unexpected response (${res.status}).`);
    }
  }
  if (!res.ok) {
    const msg =
      typeof data === "object" &&
      data !== null &&
      "error" in data &&
      typeof (data as { error: unknown }).error === "string"
        ? (data as { error: string }).error
        : `Request failed (${res.status}).`;
    throw new Error(msg);
  }
  return data as T;
}

export const api = {
  getSession: () => apiFetch<SessionInfo>("/api/auth/session"),
  claimSetup: (claimToken: string, passphrase: string) =>
    apiFetch<{ ok: true; setup: SetupState }>("/api/setup/claim", {
      method: "POST",
      body: JSON.stringify({ claimToken, passphrase }),
    }),
  updateSetupDomain: (domain: string | null, acmeEmail: string | null) =>
    apiFetch<{ ok: true; setup: SetupState }>("/api/setup/domain", {
      method: "POST",
      body: JSON.stringify({ domain, acmeEmail }),
    }),
  updateAppsBaseDomain: (appsBaseDomain: string | null) =>
    apiFetch<{ ok: true; setup: SetupState }>("/api/setup/apps-base-domain", {
      method: "POST",
      body: JSON.stringify({ appsBaseDomain }),
    }),
  recheckTls: () =>
    apiFetch<{ ok: true; setup: SetupState }>("/api/setup/tls-recheck", {
      method: "POST",
    }),
  login: (passphrase: string) =>
    apiFetch<{ ok: true; setup: SetupState }>("/api/auth/login", {
      method: "POST",
      body: JSON.stringify({ passphrase }),
    }),
  logout: () => apiFetch<{ ok: true }>("/api/auth/logout", { method: "POST" }),

  getOverview: () => apiFetch<OverviewResponse>("/api/overview"),
  listApps: () => apiFetch<{ apps: AppRecord[] }>("/api/apps"),
  inspectGitRepo: (
    gitRepoUrl: string,
    gitBranch?: string | null,
    dockerfilePath?: string,
  ) =>
    apiFetch<{ inspect: GitInspectResult }>("/api/git/inspect", {
      method: "POST",
      body: JSON.stringify({
        gitRepoUrl,
        ...(gitBranch ? { gitBranch } : {}),
        ...(dockerfilePath ? { dockerfilePath } : {}),
      }),
    }),
  listDeployments: (slug?: string, limit = 15) =>
    apiFetch<{ deployments: DeploymentRecord[] }>(
      `/api/deployments?limit=${limit}${slug ? `&slug=${encodeURIComponent(slug)}` : ""}`,
    ),
  getDeployment: (id: string) =>
    apiFetch<{
      deployment: DeploymentRecord;
      app: AppRecord | null;
      missingEnvKeys: string[];
    }>(`/api/deployments/${encodeURIComponent(id)}`),
  deployApp: (
    body: {
      slug: string;
      name: string;
      sourceType: "image" | "git";
      image?: string | null;
      gitRepoUrl?: string | null;
      gitBranch?: string | null;
      dockerfilePath?: string;
      domain?: string | null;
      noDomain?: boolean;
      internalPort?: number;
      cpuLimit: string;
      memoryLimitMb: number;
      companions: CompanionService[];
      envVars: Record<string, string>;
    },
    asyncMode = true,
  ) =>
    apiFetch<{ app: AppRecord | null; deployment?: DeploymentRecord }>(
      `/api/apps${asyncMode ? "?async=true" : ""}`,
      {
        method: "POST",
        body: JSON.stringify(body),
      },
    ),
  appAction: (
    slug: string,
    action: "start" | "stop" | "restart" | "rebuild",
    asyncRebuild = false,
  ) =>
    apiFetch<{ app: AppRecord | null; deployment?: DeploymentRecord }>(
      `/api/apps/${encodeURIComponent(slug)}/${action}${action === "rebuild" && asyncRebuild ? "?async=true" : ""}`,
      {
        method: "POST",
      },
    ),
  deleteApp: (slug: string) =>
    apiFetch<{ ok: true }>(`/api/apps/${encodeURIComponent(slug)}?removeFiles=true`, {
      method: "DELETE",
    }),
  getAppLogs: (slug: string, tail = 100) =>
    apiFetch<{ slug: string; lines: string[] }>(
      `/api/apps/${encodeURIComponent(slug)}/logs?tail=${tail}`,
    ),
  inspectApp: (slug: string) =>
    apiFetch<{ inspect: InspectResult }>(
      `/api/apps/${encodeURIComponent(slug)}/inspect`,
    ),
  setAppDomain: (slug: string, domain: string | null) =>
    apiFetch<{ app: AppRecord }>(
      `/api/apps/${encodeURIComponent(slug)}/domain`,
      {
        method: "PUT",
        body: JSON.stringify({ domain }),
      },
    ),
  getAppEnv: (slug: string) =>
    apiFetch<{ envVars: AppEnvEntry[]; missingEnvKeys: string[] }>(
      `/api/apps/${encodeURIComponent(slug)}/env`,
    ),
  updateAppEnv: (
    slug: string,
    vars: Array<{ key: string; value: string; isSecret?: boolean }>,
  ) =>
    apiFetch<{
      app: AppRecord;
      envVars: AppEnvEntry[];
      missingEnvKeys: string[];
    }>(`/api/apps/${encodeURIComponent(slug)}/env`, {
      method: "PUT",
      body: JSON.stringify({ vars, deleteKeys: [] }),
    }),
  deleteAppEnv: (slug: string, key: string) =>
    apiFetch<{
      app: AppRecord;
      envVars: AppEnvEntry[];
      missingEnvKeys: string[];
    }>(`/api/apps/${encodeURIComponent(slug)}/env/${encodeURIComponent(key)}`, {
      method: "DELETE",
    }),

  listApprovals: () =>
    apiFetch<{ approvals: ApprovalRequest[] }>("/api/approvals"),
  approveRequest: (id: string, note?: string, asyncDeploy = true) =>
    apiFetch<{
      ok: boolean;
      approval: ApprovalRequest;
      summary: string;
      deployment?: DeploymentRecord;
    }>(
      `/api/approvals/${encodeURIComponent(id)}/approve${asyncDeploy ? "?async=true" : ""}`,
      {
        method: "POST",
        body: JSON.stringify({
          ...(note ? { note } : {}),
          ...(asyncDeploy ? { async: true } : {}),
        }),
      },
    ),
  rejectRequest: (id: string, note?: string) =>
    apiFetch<{ ok: boolean; approval: ApprovalRequest }>(
      `/api/approvals/${encodeURIComponent(id)}/reject`,
      {
        method: "POST",
        body: JSON.stringify(note ? { note } : {}),
      },
    ),
  listAudit: (query?: string) =>
    apiFetch<{ events: AuditEvent[] }>(
      `/api/audit${query ? `?query=${encodeURIComponent(query)}` : ""}`,
    ),

  listTokens: () => apiFetch<{ tokens: McpTokenRecord[] }>("/api/mcp/tokens"),
  createToken: (
    name: string,
    scope: McpTokenScope,
    allowedSlugs: string[] = [],
  ) =>
    apiFetch<{ token: McpTokenRecord; rawToken: string }>("/api/mcp/tokens", {
      method: "POST",
      body: JSON.stringify({ name, scope, allowedSlugs }),
    }),
  revokeToken: (id: string) =>
    apiFetch<{ ok: true }>(`/api/mcp/tokens/${encodeURIComponent(id)}`, {
      method: "DELETE",
    }),
  getSnippets: () => apiFetch<McpSnippets>("/api/mcp/snippets"),
  testMcpConnection: () =>
    apiFetch<McpConnectionTestResult>("/api/mcp/test", { method: "POST" }),
  getSystemUpdateStatus: () =>
    apiFetch<{ status: SystemUpdateStatus }>("/api/system/update/status"),
  checkSystemUpdate: () =>
    apiFetch<{ status: SystemUpdateStatus }>("/api/system/update/check", {
      method: "POST",
    }),
  applySystemUpdate: () =>
    apiFetch<{ ok: boolean; started: boolean; status: SystemUpdateStatus }>(
      "/api/system/update/apply",
      { method: "POST" },
    ),
};
