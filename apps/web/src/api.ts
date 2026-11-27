export interface SetupState {
  claimed: boolean;
  domain: string | null;
  appsBaseDomain: string | null;
  acmeEmail: string | null;
  httpsActive: boolean;
  tlsStatus: "inactive" | "pending" | "active" | "failed";
  tlsError: string | null;
  claimedAt: string | null;
  tailscaleDomain: string | null;
  tailscaleServeEnabled: boolean;
}

export type TailscaleBackendState =
  | "not_installed"
  | "stopped"
  | "needs_login"
  | "needs_machine_auth"
  | "starting"
  | "running"
  | "unknown";

export interface TailscaleServeConflictDetails {
  funnelActive: boolean;
  preservedFunnelSiblings: string[];
  replacedRootRoute: string | null;
  removedMcpRoute: string | null;
}

export interface TailscaleStatus {
  installed: boolean;
  serviceActive: boolean;
  connected: boolean;
  backendState: TailscaleBackendState;
  tailscaleIp: string | null;
  tailscaleIps: string[];
  hostname: string | null;
  dnsName: string | null;
  tailnetName: string | null;
  magicDnsEnabled: boolean;
  httpsCertsAvailable: boolean;
  loginUrl: string | null;
  serveEnabled: boolean;
  serveTarget: string | null;
  serveUrl: string | null;
  mcpUrl: string | null;
  serveConflict: string | null;
  serveConflictDetails: TailscaleServeConflictDetails | null;
  cliVersion: string | null;
  detail: string | null;
}

export interface TailscaleStatusResponse {
  status: TailscaleStatus;
  bridgeSupported: boolean;
  setup: SetupState;
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

export interface GitCredentialRecord {
  id: string;
  provider: "github";
  label: string;
  accountLogin: string | null;
  tokenHint: string;
  isDefault: boolean;
  createdAt: string;
  updatedAt: string;
  lastUsedAt: string | null;
}

export interface GithubRepoSummary {
  fullName: string;
  name: string;
  owner: string;
  private: boolean;
  defaultBranch: string | null;
  htmlUrl: string;
  description: string | null;
  updatedAt: string | null;
  credentialId: string;
  credentialLabel: string;
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
  probeHttp?: boolean;
  probePath?: string;
  status: "provisioning" | "building" | "running" | "stopped" | "error";
  cpuLimit: string;
  memoryLimitMb: number;
  companions: CompanionService[];
  lastCommitSha: string | null;
  detectedRuntime: string | null;
  envExampleKeys: string[];
  gitCredentialId: string | null;
  webhookEnabled?: boolean;
  webhookLastTriggeredAt?: string | null;
  previousCommitSha?: string | null;
  previousImage?: string | null;
  rollbackAvailable?: boolean;
  createdAt: string;
  updatedAt: string;
}

export interface DeploymentRecord {
  id: string;
  slug: string;
  action: "deploy_app" | "rebuild_app" | "rollback_app";
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
  usedAuth?: boolean;
  gitCredentialId?: string | null;
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
  githubConnected?: boolean;
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

export interface McpSnippetVariant {
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

export interface McpSnippetEndpoint {
  url: string;
  httpsReady: boolean;
  snippets: McpSnippetVariant;
}

export interface McpSnippets extends McpSnippetVariant {
  primarySource?: "domain" | "tailscale" | "local";
  customDomain?: McpSnippetEndpoint | null;
  tailscale?: McpSnippetEndpoint | null;
}

export interface McpConnectionTestResult {
  ok: boolean;
  mcpUrl: string;
  domainMcpUrl?: string | null;
  tailscaleMcpUrl?: string | null;
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
  updateSource: "release" | "git" | "none";
  releaseRepo: string | null;
  releaseStatus:
    | "unchecked"
    | "available"
    | "up_to_date"
    | "no_releases"
    | "unavailable";
  releaseNote: string | null;
  installedFrom: "release" | "git" | "unknown";
  currentVersion: string | null;
  currentReleaseTag: string | null;
  currentCommit: string | null;
  latestVersion: string | null;
  latestReleaseTag: string | null;
  latestReleaseName: string | null;
  latestReleaseUrl: string | null;
  latestReleaseNotes: string | null;
  latestReleasePublishedAt: string | null;
  latestReleasePrerelease: boolean;
  latestReleaseAssetName: string | null;
  checksumAvailable: boolean;
  checksumStatus: "none" | "available" | "verified" | "not_provided" | "failed";
  checksumSha256: string | null;
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

export type NotificationChannel =
  | "none"
  | "discord"
  | "slack"
  | "telegram"
  | "webhook";

export interface NotificationSettings {
  enabled: boolean;
  channel: NotificationChannel;
  hasTargetSecret: boolean;
  targetHint: string | null;
  telegramChatId: string | null;
  notifyOnApproval: boolean;
  notifyOnAppDown: boolean;
  notifyOnDeployFailure: boolean;
  lastSentAt: string | null;
  lastError: string | null;
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

async function downloadBackupArchive(
  url: string,
  body: Record<string, unknown>,
  fallbackFilename: string,
): Promise<{ filename: string; sizeBytes: number }> {
  const res = await fetch(url, {
    method: "POST",
    credentials: "include",
    headers: {
      "content-type": "application/json",
    },
    body: JSON.stringify(body),
  });
  if (!res.ok) {
    const text = await res.text();
    let msg = `Download failed (${res.status}).`;
    if (text.trim()) {
      try {
        const parsed = JSON.parse(text) as { error?: unknown };
        if (typeof parsed.error === "string" && parsed.error.trim()) {
          msg = parsed.error;
        }
      } catch {
        // Ignore non-JSON error text
      }
    }
    throw new Error(msg);
  }
  const headerName = res.headers.get("x-vpsagent-backup-filename");
  const disp = res.headers.get("content-disposition") ?? "";
  const dispMatch = disp.match(/filename="?([^";]+)"?/i);
  const filename =
    (headerName || dispMatch?.[1] || fallbackFilename)
      .replace(/[^A-Za-z0-9._-]/g, "_") || fallbackFilename;
  const blob = await res.blob();
  const objectUrl = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = objectUrl;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  link.remove();
  window.setTimeout(() => URL.revokeObjectURL(objectUrl), 1000);
  return { filename, sizeBytes: blob.size };
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
  getTailscaleStatus: () =>
    apiFetch<TailscaleStatusResponse>("/api/tailscale/status"),
  setTailscaleServe: (enabled: boolean, force = false) =>
    apiFetch<{
      ok: boolean;
      status: TailscaleStatus;
      actionUrl: string | null;
      setup: SetupState;
    }>("/api/tailscale/serve", {
      method: "POST",
      body: JSON.stringify({ enabled, force }),
    }),
  connectTailscale: (body?: { mode?: "login" | "authkey"; authKey?: string }) =>
    apiFetch<{
      ok: boolean;
      status: TailscaleStatus;
      loginUrl: string | null;
      setup: SetupState;
    }>("/api/tailscale/connect", {
      method: "POST",
      body: JSON.stringify(body ?? { mode: "login" }),
    }),
  login: (passphrase: string) =>
    apiFetch<{ ok: true; setup: SetupState }>("/api/auth/login", {
      method: "POST",
      body: JSON.stringify({ passphrase }),
    }),
  logout: () => apiFetch<{ ok: true }>("/api/auth/logout", { method: "POST" }),
  changePassword: (currentPassword: string, newPassword: string) =>
    apiFetch<{ ok: true }>("/api/auth/change-password", {
      method: "POST",
      body: JSON.stringify({ currentPassword, newPassword }),
    }),
  logoutAll: (keepCurrent = false) =>
    apiFetch<{ ok: true; signedOutCurrent: boolean }>("/api/auth/logout-all", {
      method: "POST",
      body: JSON.stringify({ keepCurrent }),
    }),

  getOverview: () => apiFetch<OverviewResponse>("/api/overview"),
  getMetrics: () =>
    apiFetch<Pick<OverviewResponse, "metrics" | "disk">>("/api/metrics"),
  listApps: () => apiFetch<{ apps: AppRecord[] }>("/api/apps"),
  inspectGitRepo: (
    gitRepoUrl: string,
    gitBranch?: string | null,
    dockerfilePath?: string,
    gitCredentialId?: string | null,
  ) =>
    apiFetch<{ inspect: GitInspectResult }>("/api/git/inspect", {
      method: "POST",
      body: JSON.stringify({
        gitRepoUrl,
        ...(gitBranch ? { gitBranch } : {}),
        ...(dockerfilePath ? { dockerfilePath } : {}),
        ...(gitCredentialId ? { gitCredentialId } : {}),
      }),
    }),
  listGitCredentials: () =>
    apiFetch<{ credentials: GitCredentialRecord[] }>("/api/git/credentials"),
  createGitCredential: (body: {
    label?: string;
    token: string;
    isDefault?: boolean;
  }) =>
    apiFetch<{
      credential: GitCredentialRecord;
      accountLogin: string | null;
      accessibleRepoCount: number;
      warning: string | null;
    }>("/api/git/credentials", {
      method: "POST",
      body: JSON.stringify(body),
    }),
  setDefaultGitCredential: (id: string) =>
    apiFetch<{ ok: true; credential: GitCredentialRecord }>(
      `/api/git/credentials/${encodeURIComponent(id)}/default`,
      {
        method: "POST",
        body: JSON.stringify({}),
      },
    ),
  testGitCredential: (id: string) =>
    apiFetch<{
      ok: true;
      credential: GitCredentialRecord;
      accountLogin: string | null;
      accessibleRepoCount: number;
      warning: string | null;
    }>(`/api/git/credentials/${encodeURIComponent(id)}/test`, {
      method: "POST",
      body: JSON.stringify({}),
    }),
  deleteGitCredential: (id: string) =>
    apiFetch<{ ok: true }>(`/api/git/credentials/${encodeURIComponent(id)}`, {
      method: "DELETE",
    }),
  listGithubRepos: (options?: {
    credentialId?: string;
    query?: string;
    limit?: number;
  }) => {
    const params = new URLSearchParams();
    if (options?.credentialId) params.set("credentialId", options.credentialId);
    if (options?.query) params.set("query", options.query);
    if (options?.limit) params.set("limit", String(options.limit));
    const qs = params.toString();
    return apiFetch<{
      connected: boolean;
      repos: GithubRepoSummary[];
      hasMore?: boolean;
      errors: Array<{ credentialId: string; label: string; error: string }>;
    }>(`/api/git/repos${qs ? `?${qs}` : ""}`);
  },
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
      gitCredentialId?: string | null;
      dockerfilePath?: string;
      domain?: string | null;
      noDomain?: boolean;
      internalPort?: number;
      cpuLimit: string;
      memoryLimitMb: number;
      companions: CompanionService[];
      envVars: Record<string, string>;
      createOnly?: boolean;
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
  updateAppSettings: (
    slug: string,
    patch: {
      name?: string;
      cpuLimit?: string;
      memoryLimitMb?: number;
      internalPort?: number;
      probeHttp?: boolean;
      probePath?: string;
      image?: string;
      gitBranch?: string | null;
      dockerfilePath?: string;
      gitCredentialId?: string | null;
      companions?: CompanionService[];
    },
  ) =>
    apiFetch<{ app: AppRecord; needsRebuild: boolean }>(
      `/api/apps/${encodeURIComponent(slug)}`,
      {
        method: "PATCH",
        body: JSON.stringify(patch),
      },
    ),
  rollbackApp: (slug: string) =>
    apiFetch<{ app: AppRecord; deployment: DeploymentRecord }>(
      `/api/apps/${encodeURIComponent(slug)}/rollback`,
      {
        method: "POST",
        body: JSON.stringify({}),
      },
    ),
  enableAppWebhook: (slug: string) =>
    apiFetch<{
      app: AppRecord;
      webhookUrl: string;
      rawSecret: string;
      branch: string;
      publicDomainReady: boolean;
    }>(`/api/apps/${encodeURIComponent(slug)}/webhook`, {
      method: "POST",
      body: JSON.stringify({}),
    }),
  disableAppWebhook: (slug: string) =>
    apiFetch<{ app: AppRecord }>(
      `/api/apps/${encodeURIComponent(slug)}/webhook`,
      {
        method: "DELETE",
      },
    ),
  downloadAppBackup: (slug: string) =>
    downloadBackupArchive(
      `/api/apps/${encodeURIComponent(slug)}/backup`,
      {},
      `vpsagent-app-${slug}.tar.gz`,
    ),
  downloadSystemBackup: (includeAppData = false) =>
    downloadBackupArchive(
      "/api/system/backup",
      { includeAppData },
      "vpsagent-server-backup.tar.gz",
    ),
  getNotifications: () =>
    apiFetch<{ settings: NotificationSettings }>("/api/notifications"),
  updateNotifications: (payload: {
    enabled?: boolean;
    channel?: NotificationChannel;
    webhookUrl?: string | null;
    telegramBotToken?: string | null;
    telegramChatId?: string | null;
    notifyOnApproval?: boolean;
    notifyOnAppDown?: boolean;
    notifyOnDeployFailure?: boolean;
  }) =>
    apiFetch<{ settings: NotificationSettings }>("/api/notifications", {
      method: "PUT",
      body: JSON.stringify(payload),
    }),
  testNotification: () =>
    apiFetch<{
      ok: boolean;
      error: string | null;
      settings: NotificationSettings;
    }>("/api/notifications/test", {
      method: "POST",
      body: JSON.stringify({}),
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
  applySystemUpdate: (source?: "auto" | "release" | "git") =>
    apiFetch<{ ok: boolean; started: boolean; status: SystemUpdateStatus }>(
      "/api/system/update/apply",
      {
        method: "POST",
        ...(source ? { body: JSON.stringify({ source }) } : {}),
      },
    ),
};
