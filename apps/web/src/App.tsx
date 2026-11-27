import { useCallback, useEffect, useState } from "react";
import {
  api,
  type ApprovalRequest,
  type AuditEvent,
  type GitCredentialRecord,
  type InspectResult,
  type McpSnippets,
  type McpTokenRecord,
  type OverviewResponse,
  type SessionInfo,
  type SystemUpdateStatus,
} from "./api";
import { applyInspectStatusToApps } from "./health-display";
import { ApprovalsTab } from "./components/ApprovalsTab";
import { AppsTab } from "./components/AppsTab";
import { KeysSettingsTab } from "./components/KeysSettingsTab";
import { OverviewTab } from "./components/OverviewTab";
import { SetupAndAuth } from "./components/SetupAndAuth";
import { Boxes, Inbox, LayoutGrid, LogOut, Settings2, type LucideIcon } from "lucide-react";
import { Logo } from "./brand/Logo";
import {
  appendResourceSample,
  loadResourceDisplayMode,
  saveResourceDisplayMode,
  type ResourceDisplayMode,
  type ResourceSample,
} from "./resource-display";

type TabId = "overview" | "apps" | "approvals" | "keys";
type AppDrawerSection =
  | "deployments"
  | "logs"
  | "domain"
  | "env"
  | "security"
  | "settings";
type KeysFocusSection =
  | "general"
  | "github"
  | "updates"
  | "alerts"
  | "backups"
  | "account";

interface AppDeepLink {
  slug: string;
  section: AppDrawerSection;
  deploymentId?: string;
}

function parseAppDeepLink(hash: string): AppDeepLink | null {
  const match = hash.match(
    /^#?\/?apps\/([a-z0-9][a-z0-9-]{0,46}[a-z0-9])\/(deployments|logs|domain|env|security|settings)$/i,
  );
  if (!match) return null;
  return {
    slug: match[1]!.toLowerCase(),
    section: match[2]!.toLowerCase() as AppDrawerSection,
  };
}

function parseKeysDeepLink(hash: string): KeysFocusSection | null {
  const match = hash
    .trim()
    .match(/^#?\/?keys\/(general|github|updates|alerts|backups|account)$/i);
  return match ? (match[1]!.toLowerCase() as KeysFocusSection) : null;
}

function isApprovalsDeepLink(hash: string): boolean {
  return /^#?\/?approvals$/i.test(hash.trim());
}

export function App() {
  const [session, setSession] = useState<SessionInfo | null>(null);
  const [connectError, setConnectError] = useState<string | null>(null);
  const [tab, setTab] = useState<TabId>(() => {
    if (typeof window !== "undefined") {
      if (isApprovalsDeepLink(window.location.hash)) {
        return "approvals";
      }
      if (parseKeysDeepLink(window.location.hash)) {
        return "keys";
      }
      if (parseAppDeepLink(window.location.hash)) return "apps";
    }
    return "overview";
  });
  const [deepLink, setDeepLink] = useState<AppDeepLink | null>(() =>
    typeof window !== "undefined" ? parseAppDeepLink(window.location.hash) : null,
  );
  const [keysFocusSection, setKeysFocusSection] =
    useState<KeysFocusSection | null>(() =>
      typeof window !== "undefined"
        ? parseKeysDeepLink(window.location.hash)
        : null,
    );
  const [overview, setOverview] = useState<OverviewResponse | null>(null);
  const [approvals, setApprovals] = useState<ApprovalRequest[]>([]);
  const [auditEvents, setAuditEvents] = useState<AuditEvent[]>([]);
  const [tokens, setTokens] = useState<McpTokenRecord[]>([]);
  const [gitCredentials, setGitCredentials] = useState<GitCredentialRecord[]>([]);
  const [snippets, setSnippets] = useState<McpSnippets | null>(null);
  const [systemUpdate, setSystemUpdate] = useState<SystemUpdateStatus | null>(
    null,
  );
  const [resourceDisplay, setResourceDisplay] = useState<ResourceDisplayMode>(
    () => loadResourceDisplayMode(),
  );
  const [resourceHistory, setResourceHistory] = useState<ResourceSample[]>([]);
  const [loading, setLoading] = useState(true);

  const handleResourceDisplayChange = useCallback(
    (mode: ResourceDisplayMode) => {
      setResourceDisplay(mode);
      saveResourceDisplayMode(mode);
    },
    [],
  );

  const recordOverviewSample = useCallback((ov: OverviewResponse) => {
    const cpuPercent = Math.min(
      100,
      Math.round(
        (ov.metrics.loadAverage1m / Math.max(1, ov.metrics.cpuCount)) * 100,
      ),
    );
    setResourceHistory((prev) =>
      appendResourceSample(prev, {
        timestamp: ov.metrics.collectedAt,
        cpu: cpuPercent,
        memory: ov.metrics.memoryUsagePercent,
        disk: ov.disk.usedPercent,
      }),
    );
  }, []);

  useEffect(() => {
    const syncFromHash = () => {
      if (isApprovalsDeepLink(window.location.hash)) {
        setTab("approvals");
        return;
      }
      const parsed = parseAppDeepLink(window.location.hash);
      if (parsed) {
        setTab("apps");
        setDeepLink(parsed);
        return;
      }
      const keySection = parseKeysDeepLink(window.location.hash);
      if (keySection) {
        setTab("keys");
        setKeysFocusSection(keySection);
      }
    };
    syncFromHash();
    window.addEventListener("hashchange", syncFromHash);
    return () => window.removeEventListener("hashchange", syncFromHash);
  }, []);

  const loadAll = useCallback(async (auditQuery?: string) => {
    setLoading(true);
    setConnectError(null);
    try {
      const sess = await api.getSession();
      setSession(sess);
      if (sess.claimed && sess.authenticated) {
        const [ov, appr, aud, toks, snips, gitCreds, upd] = await Promise.all([
          api.getOverview(),
          api.listApprovals(),
          api.listAudit(auditQuery),
          api.listTokens(),
          api.getSnippets(),
          api.listGitCredentials(),
          api
            .getSystemUpdateStatus()
            .then((res) => res.status)
            .catch(() => null),
        ]);
        setOverview(ov);
        recordOverviewSample(ov);
        setApprovals(appr.approvals);
        setAuditEvents(aud.events);
        setTokens(toks.tokens);
        setSnippets(snips);
        setGitCredentials(gitCreds.credentials);
        if (upd) {
          setSystemUpdate(upd);
        }
      }
    } catch (err) {
      setConnectError(
        err instanceof Error ? err.message : "Could not reach your server.",
      );
    } finally {
      setLoading(false);
    }
  }, [recordOverviewSample]);

  useEffect(() => {
    void loadAll();
  }, [loadAll]);

  useEffect(() => {
    if (
      !session?.claimed ||
      !session?.authenticated ||
      tab !== "overview" ||
      resourceDisplay !== "chart"
    ) {
      return;
    }
    const timer = window.setInterval(() => {
      void api
        .getOverview()
        .then((ov) => {
          setOverview(ov);
          recordOverviewSample(ov);
        })
        .catch(() => {
          // Ignore background poll errors; manual refresh surfaces connectivity issues.
        });
    }, 10000);
    return () => window.clearInterval(timer);
  }, [
    session?.claimed,
    session?.authenticated,
    tab,
    resourceDisplay,
    recordOverviewSample,
  ]);

  const handleInspectSync = useCallback((inspect: InspectResult) => {
    setOverview((prev) =>
      prev
        ? { ...prev, apps: applyInspectStatusToApps(prev.apps, inspect) }
        : prev,
    );
  }, []);

  const handleLogout = async () => {
    await api.logout();
    await loadAll();
  };

  if (!session) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-canvas px-4">
        <div className="surface-panel rounded-xl px-6 py-5 max-w-sm w-full text-center space-y-3">
          {connectError ? (
            <>
              <Logo className="mb-2" />
              <p className="text-sm font-medium text-fg">
                Can’t reach this server
              </p>
              <p className="text-xs text-muted">{connectError}</p>
              <button
                type="button"
                onClick={() => void loadAll()}
                className="btn-press inline-flex items-center gap-1.5 rounded-lg bg-primary px-3.5 py-2 text-xs font-semibold text-on-primary hover:bg-primary-hover cursor-pointer"
              >
                Try again
              </button>
            </>
          ) : (
            <p className="text-sm text-muted">Connecting…</p>
          )}
        </div>
      </div>
    );
  }

  if (!session.claimed || !session.authenticated) {
    return <SetupAndAuth session={session} onAuthenticated={() => loadAll()} />;
  }

  const pendingCount = approvals.filter((a) => a.status === "pending").length;
  const hasReadyUpdate = Boolean(
    systemUpdate?.updateAvailable && systemUpdate.canUpdate,
  );

  const tabs: Array<{
    id: TabId;
    label: string;
    icon: LucideIcon;
    count?: number;
    dot?: boolean;
  }> = [
    { id: "overview", label: "Overview", icon: LayoutGrid },
    { id: "apps", label: "Apps", icon: Boxes },
    {
      id: "approvals",
      label: "Approvals",
      icon: Inbox,
      count: pendingCount > 0 ? pendingCount : undefined,
    },
    { id: "keys", label: "Settings", icon: Settings2, dot: hasReadyUpdate },
  ];

  const openUpdatesSection = () => {
    setKeysFocusSection("updates");
    setTab("keys");
  };

  const hostname = overview?.metrics.hostname;

  return (
    <div className="min-h-screen bg-canvas text-fg md:flex">
      <aside className="hidden md:flex w-60 shrink-0 flex-col border-r border-line bg-canvas sticky top-0 h-screen">
        <div className="h-16 px-5 flex items-center">
          <Logo />
        </div>

        <nav aria-label="Primary" className="flex-1 px-3 py-2 space-y-0.5">
          {tabs.map((item) => {
            const active = tab === item.id;
            const Icon = item.icon;
            return (
              <button
                key={item.id}
                type="button"
                onClick={() => setTab(item.id)}
                aria-current={active ? "page" : undefined}
                className={`btn-press w-full flex items-center gap-3 rounded-md px-3 py-2 text-sm cursor-pointer ${
                  active
                    ? "bg-surface-2 text-fg font-medium"
                    : "text-muted hover:text-fg hover:bg-surface"
                }`}
              >
                <Icon className="h-4 w-4 shrink-0" strokeWidth={1.75} />
                <span className="flex-1 text-left">{item.label}</span>
                {item.count !== undefined && (
                  <span className="tabular-nums rounded bg-fg px-1.5 text-[11px] leading-[18px] font-semibold text-canvas">
                    {item.count}
                  </span>
                )}
                {item.dot && (
                  <span title="An update is available" className="h-1.5 w-1.5 rounded-full bg-fg" />
                )}
              </button>
            );
          })}
        </nav>

        <div className="border-t border-line p-4 space-y-3">
          {hasReadyUpdate && (
            <button
              type="button"
              onClick={openUpdatesSection}
              className="btn-press w-full rounded-md border border-line-strong px-3 py-2 text-left text-xs hover:bg-surface cursor-pointer"
            >
              <span className="block font-medium text-fg">Update available</span>
              <span className="block text-muted">
                {systemUpdate?.latestReleaseTag ?? "New version"} is ready to install
              </span>
            </button>
          )}
          <div className="flex items-center justify-between gap-3 px-1">
            <div className="min-w-0">
              <p className="text-[11px] text-subtle">Server</p>
              <p className="truncate font-mono text-xs text-fg-2" title={hostname}>
                {hostname ?? "—"}
              </p>
            </div>
            <button
              type="button"
              onClick={handleLogout}
              title="Sign out"
              aria-label="Sign out"
              className="btn-press rounded-md p-1.5 text-muted hover:text-fg hover:bg-surface cursor-pointer"
            >
              <LogOut className="h-4 w-4" strokeWidth={1.75} />
            </button>
          </div>
        </div>
      </aside>

      <div className="flex-1 min-w-0">
        <header className="md:hidden sticky top-0 z-20 border-b border-line bg-canvas">
          <div className="h-14 px-4 flex items-center justify-between">
            <Logo />
            <button
              type="button"
              onClick={handleLogout}
              className="btn-press text-xs text-muted hover:text-fg cursor-pointer"
            >
              Sign out
            </button>
          </div>
          <nav aria-label="Mobile" className="px-2 flex border-t border-line">
            {tabs.map((item) => {
              const active = tab === item.id;
              return (
                <button
                  key={item.id}
                  type="button"
                  onClick={() => setTab(item.id)}
                  aria-current={active ? "page" : undefined}
                  className={`btn-press flex-1 inline-flex items-center justify-center gap-1.5 border-b-2 py-2.5 text-[13px] cursor-pointer ${
                    active ? "border-fg text-fg font-medium" : "border-transparent text-muted"
                  }`}
                >
                  {item.label}
                  {item.count !== undefined && (
                    <span className="tabular-nums rounded bg-fg px-1 text-[11px] leading-4 font-semibold text-canvas">
                      {item.count}
                    </span>
                  )}
                </button>
              );
            })}
          </nav>
        </header>

      <main className="mx-auto max-w-6xl px-4 sm:px-8 py-8 md:py-10">
        {connectError && (
          <div
            role="alert"
            className="mb-6 rounded-xl border border-warn-line bg-warn-soft px-4 py-3 text-xs text-warn flex flex-wrap items-center justify-between gap-3"
          >
            <span>
              <strong className="font-semibold">
                Could not refresh server data:
              </strong>{" "}
              {connectError}
            </span>
            <button
              type="button"
              onClick={() => void loadAll()}
              className="btn-press inline-flex items-center gap-1.5 rounded-lg bg-warn px-3 py-1.5 text-xs font-semibold text-on-warn hover:opacity-90 cursor-pointer"
            >
              Retry
            </button>
          </div>
        )}
        {tab === "overview" && (
          <OverviewTab
            data={overview}
            loading={loading}
            resourceDisplay={resourceDisplay}
            resourceHistory={resourceHistory}
            onRefresh={() => void loadAll()}
            onNavigateTab={setTab}
            onOpenApp={(slug) => {
              setDeepLink({ slug, section: "deployments" });
              setTab("apps");
            }}
          />
        )}
        {tab === "apps" && (
          <AppsTab
            apps={overview?.apps ?? []}
            appsBaseDomain={session.setup.appsBaseDomain}
            gitCredentials={gitCredentials}
            deepLink={deepLink}
            onConsumeDeepLink={() => setDeepLink(null)}
            onOpenGithubSettings={() => {
              setKeysFocusSection("github");
              setTab("keys");
            }}
            onRefresh={() => loadAll()}
            onInspectSync={handleInspectSync}
          />
        )}
        {tab === "approvals" && (
          <ApprovalsTab
            approvals={approvals}
            events={auditEvents}
            onRefresh={(q) => loadAll(q)}
            onWatchDeployment={(slug, deploymentId) => {
              setDeepLink({ slug, section: "deployments", deploymentId });
              setTab("apps");
            }}
          />
        )}
        {tab === "keys" && (
          <KeysSettingsTab
            tokens={tokens}
            apps={overview?.apps ?? []}
            gitCredentials={gitCredentials}
            snippets={snippets}
            setup={session.setup}
            publicIp={session.publicIp}
            resourceDisplay={resourceDisplay}
            onResourceDisplayChange={handleResourceDisplayChange}
            focusSection={keysFocusSection}
            onConsumeFocusSection={() => setKeysFocusSection(null)}
            initialUpdateStatus={systemUpdate}
            onUpdateStatusChange={setSystemUpdate}
            onRefresh={() => loadAll()}
            onSignedOut={() => void loadAll()}
          />
        )}
      </main>
      </div>
    </div>
  );
}
