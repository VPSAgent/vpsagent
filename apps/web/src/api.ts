export interface SetupState {
  claimed: boolean;
  domain: string | null;
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
  createdAt: string;
  updatedAt: string;
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

export interface ApprovalRequest {
  id: string;
  action: string;
  targetSlug: string | null;
  summary: string;
  payload: Record<string, unknown>;
  requestedBy: string;
  tokenScope: "read-only" | "approval-required" | "auto-approve";
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
  scope: "read-only" | "approval-required" | "auto-approve";
  tokenPrefix: string;
  createdAt: string;
  lastUsedAt: string | null;
  revokedAt: string | null;
}

export interface McpSnippets {
  mcpUrl: string;
  httpsReady: boolean;
  claudeCode: string;
  cursor: string;
  codex: string;
}

export interface InspectResult {
  slug: string;
  status: string;
  lockedApartmentCompliant: boolean;
  caddyRouteConfigured: boolean;
  caddyDomains: string[];
  containers: Array<{
    id: string;
    name: string;
    image: string;
    state: string;
    running: boolean;
    healthStatus: string;
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
  deployApp: (body: {
    slug: string;
    name: string;
    sourceType: "image" | "git";
    image?: string | null;
    gitRepoUrl?: string | null;
    gitBranch?: string | null;
    dockerfilePath?: string;
    domain?: string | null;
    internalPort: number;
    cpuLimit: string;
    memoryLimitMb: number;
    companions: CompanionService[];
    envVars: Record<string, string>;
  }) =>
    apiFetch<{ app: AppRecord }>("/api/apps", {
      method: "POST",
      body: JSON.stringify(body),
    }),
  appAction: (slug: string, action: "start" | "stop" | "restart" | "rebuild") =>
    apiFetch<{ app: AppRecord }>(`/api/apps/${encodeURIComponent(slug)}/${action}`, {
      method: "POST",
    }),
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
    apiFetch<{ envVars: AppEnvEntry[] }>(
      `/api/apps/${encodeURIComponent(slug)}/env`,
    ),
  updateAppEnv: (
    slug: string,
    vars: Array<{ key: string; value: string; isSecret?: boolean }>,
  ) =>
    apiFetch<{ app: AppRecord; envVars: AppEnvEntry[] }>(
      `/api/apps/${encodeURIComponent(slug)}/env`,
      {
        method: "PUT",
        body: JSON.stringify({ vars, deleteKeys: [] }),
      },
    ),
  deleteAppEnv: (slug: string, key: string) =>
    apiFetch<{ app: AppRecord; envVars: AppEnvEntry[] }>(
      `/api/apps/${encodeURIComponent(slug)}/env/${encodeURIComponent(key)}`,
      { method: "DELETE" },
    ),

  listApprovals: () =>
    apiFetch<{ approvals: ApprovalRequest[] }>("/api/approvals"),
  approveRequest: (id: string, note?: string) =>
    apiFetch<{ ok: boolean; approval: ApprovalRequest; summary: string }>(
      `/api/approvals/${encodeURIComponent(id)}/approve`,
      {
        method: "POST",
        body: JSON.stringify(note ? { note } : {}),
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
    scope: "read-only" | "approval-required" | "auto-approve",
  ) =>
    apiFetch<{ token: McpTokenRecord; rawToken: string }>("/api/mcp/tokens", {
      method: "POST",
      body: JSON.stringify({ name, scope }),
    }),
  revokeToken: (id: string) =>
    apiFetch<{ ok: true }>(`/api/mcp/tokens/${encodeURIComponent(id)}`, {
      method: "DELETE",
    }),
  getSnippets: () => apiFetch<McpSnippets>("/api/mcp/snippets"),
};
