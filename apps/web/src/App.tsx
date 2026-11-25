import { useCallback, useEffect, useState } from "react";
import {
  Activity,
  Box,
  KeyRound,
  LogOut,
  RefreshCw,
  ShieldCheck,
  ShieldQuestion,
} from "lucide-react";
import {
  api,
  type ApprovalRequest,
  type AuditEvent,
  type InspectResult,
  type McpSnippets,
  type McpTokenRecord,
  type OverviewResponse,
  type SessionInfo,
} from "./api";
import { applyInspectStatusToApps } from "./health-display";
import { ApprovalsTab } from "./components/ApprovalsTab";
import { AppsTab } from "./components/AppsTab";
import { KeysSettingsTab } from "./components/KeysSettingsTab";
import { OverviewTab } from "./components/OverviewTab";
import { SetupAndAuth } from "./components/SetupAndAuth";

type TabId = "overview" | "apps" | "approvals" | "keys";
type AppDrawerSection = "deployments" | "logs" | "domain" | "env" | "security";

interface AppDeepLink {
  slug: string;
  section: AppDrawerSection;
  deploymentId?: string;
}

function parseAppDeepLink(hash: string): AppDeepLink | null {
  const match = hash.match(
    /^#?\/?apps\/([a-z0-9][a-z0-9-]{0,46}[a-z0-9])\/(deployments|logs|domain|env|security)$/i,
  );
  if (!match) return null;
  return {
    slug: match[1]!.toLowerCase(),
    section: match[2]!.toLowerCase() as AppDrawerSection,
  };
}

export function App() {
  const [session, setSession] = useState<SessionInfo | null>(null);
  const [connectError, setConnectError] = useState<string | null>(null);
  const [tab, setTab] = useState<TabId>("overview");
  const [deepLink, setDeepLink] = useState<AppDeepLink | null>(() =>
    typeof window !== "undefined" ? parseAppDeepLink(window.location.hash) : null,
  );
  const [overview, setOverview] = useState<OverviewResponse | null>(null);
  const [approvals, setApprovals] = useState<ApprovalRequest[]>([]);
  const [auditEvents, setAuditEvents] = useState<AuditEvent[]>([]);
  const [tokens, setTokens] = useState<McpTokenRecord[]>([]);
  const [snippets, setSnippets] = useState<McpSnippets | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const syncFromHash = () => {
      const parsed = parseAppDeepLink(window.location.hash);
      if (parsed) {
        setTab("apps");
        setDeepLink(parsed);
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
        const [ov, appr, aud, toks, snips] = await Promise.all([
          api.getOverview(),
          api.listApprovals(),
          api.listAudit(auditQuery),
          api.listTokens(),
          api.getSnippets(),
        ]);
        setOverview(ov);
        setApprovals(appr.approvals);
        setAuditEvents(aud.events);
        setTokens(toks.tokens);
        setSnippets(snips);
      }
    } catch (err) {
      setConnectError(
        err instanceof Error ? err.message : "Could not reach your server.",
      );
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void loadAll();
  }, [loadAll]);

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
      <div className="min-h-screen flex items-center justify-center bg-[#090A0C] px-4">
        <div className="surface-panel rounded-xl px-6 py-5 max-w-sm w-full text-center space-y-3">
          <div className="mx-auto h-9 w-9 rounded-lg bg-emerald-500/10 border border-emerald-500/25 flex items-center justify-center">
            <ShieldCheck className="h-4.5 w-4.5 text-emerald-400" />
          </div>
          {connectError ? (
            <>
              <p className="text-sm font-medium text-[#F4F5F7]">
                Unable to reach VPSAgent
              </p>
              <p className="text-xs text-[#9CA3AF]">{connectError}</p>
              <button
                type="button"
                onClick={() => void loadAll()}
                className="btn-press inline-flex items-center gap-1.5 rounded-lg bg-emerald-500 px-3.5 py-2 text-xs font-semibold text-[#042F1E] hover:bg-emerald-400 cursor-pointer"
              >
                <RefreshCw className="h-3.5 w-3.5" />
                Try again
              </button>
            </>
          ) : (
            <p className="text-sm text-[#9CA3AF]">Connecting to VPSAgent...</p>
          )}
        </div>
      </div>
    );
  }

  if (!session.claimed || !session.authenticated) {
    return <SetupAndAuth session={session} onAuthenticated={() => loadAll()} />;
  }

  const pendingCount = approvals.filter((a) => a.status === "pending").length;

  const tabs: Array<{
    id: TabId;
    label: string;
    icon: typeof Activity;
    badge?: number;
  }> = [
    { id: "overview", label: "Overview", icon: Activity },
    { id: "apps", label: "Apps", icon: Box },
    {
      id: "approvals",
      label: "Approvals & History",
      icon: ShieldQuestion,
      badge: pendingCount > 0 ? pendingCount : undefined,
    },
    { id: "keys", label: "AI Keys & Settings", icon: KeyRound },
  ];

  return (
    <div className="min-h-screen bg-[#090A0C] text-[#F4F5F7]">
      <header className="sticky top-0 z-20 border-b border-white/[0.08] bg-[#090A0C]/90 backdrop-blur-md">
        <div className="mx-auto max-w-6xl px-4 sm:px-6 h-15 flex items-center justify-between gap-4">
          {/* Brand Wordmark */}
          <div className="flex items-center gap-2.5 shrink-0">
            <div className="h-8 w-8 rounded-lg bg-emerald-500/12 border border-emerald-500/30 flex items-center justify-center">
              <ShieldCheck className="h-4.5 w-4.5 text-emerald-400" />
            </div>
            <span className="text-[15px] font-bold tracking-[-0.02em] text-white">
              VPSAgent
            </span>
          </div>

          {/* Desktop Single-Line Navigation */}
          <nav
            aria-label="Primary"
            className="hidden md:flex items-center gap-1"
          >
            {tabs.map((item) => {
              const Icon = item.icon;
              const active = tab === item.id;
              return (
                <button
                  key={item.id}
                  type="button"
                  onClick={() => setTab(item.id)}
                  className={`btn-press relative inline-flex items-center gap-2 rounded-lg px-3.5 py-2 text-[13px] font-medium whitespace-nowrap cursor-pointer ${
                    active
                      ? "bg-white/[0.08] text-white"
                      : "text-[#9CA3AF] hover:text-[#F4F5F7] hover:bg-white/[0.04]"
                  }`}
                >
                  <Icon
                    className={`h-3.5 w-3.5 ${active ? "text-emerald-400" : "text-[#6B7280]"}`}
                  />
                  <span>{item.label}</span>
                  {item.badge !== undefined && (
                    <span className="tabular-nums rounded-full bg-amber-400 px-1.5 py-0.5 text-[11px] leading-none font-bold text-[#1A1200]">
                      {item.badge}
                    </span>
                  )}
                </button>
              );
            })}
          </nav>

          {/* Right Utilities */}
          <div className="flex items-center gap-3 shrink-0">
            {overview?.metrics.hostname && (
              <span className="hidden lg:inline-flex items-center gap-1.5 text-xs font-mono text-[#9CA3AF]">
                <span className="h-1.5 w-1.5 rounded-full bg-emerald-400" />
                {overview.metrics.hostname}
              </span>
            )}
            <button
              type="button"
              onClick={handleLogout}
              className="btn-press inline-flex items-center gap-1.5 rounded-lg border border-white/[0.08] bg-[#111317] px-3 py-1.5 text-xs font-medium text-[#9CA3AF] hover:text-white hover:border-white/[0.16] cursor-pointer"
            >
              <LogOut className="h-3.5 w-3.5" />
              <span>Sign out</span>
            </button>
          </div>
        </div>

        {/* Mobile Tab Strip */}
        <nav
          aria-label="Mobile"
          className="md:hidden border-t border-white/[0.06] px-2 flex gap-1 overflow-x-auto"
        >
          {tabs.map((item) => {
            const Icon = item.icon;
            const active = tab === item.id;
            return (
              <button
                key={item.id}
                type="button"
                onClick={() => setTab(item.id)}
                className={`btn-press inline-flex items-center gap-1.5 border-b-2 px-3 py-2.5 text-[13px] font-medium whitespace-nowrap cursor-pointer ${
                  active
                    ? "border-emerald-400 text-white"
                    : "border-transparent text-[#9CA3AF] hover:text-[#F4F5F7]"
                }`}
              >
                <Icon className="h-3.5 w-3.5" />
                <span>{item.label}</span>
                {item.badge !== undefined && (
                  <span className="tabular-nums rounded-full bg-amber-400 px-1.5 py-0.5 text-[11px] leading-none font-bold text-[#1A1200]">
                    {item.badge}
                  </span>
                )}
              </button>
            );
          })}
        </nav>
      </header>

      <main className="mx-auto max-w-6xl px-4 sm:px-6 py-7">
        {tab === "overview" && (
          <OverviewTab
            data={overview}
            loading={loading}
            onRefresh={() => void loadAll()}
            onNavigateTab={setTab}
          />
        )}
        {tab === "apps" && (
          <AppsTab
            apps={overview?.apps ?? []}
            appsBaseDomain={session.setup.appsBaseDomain}
            deepLink={deepLink}
            onConsumeDeepLink={() => setDeepLink(null)}
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
            snippets={snippets}
            setup={session.setup}
            publicIp={session.publicIp}
            onRefresh={() => loadAll()}
          />
        )}
      </main>
    </div>
  );
}
