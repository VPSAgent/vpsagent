import { useCallback, useEffect, useState } from "react";
import {
  Activity,
  Box,
  KeyRound,
  LogOut,
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
      <div className="min-h-screen flex items-center justify-center bg-slate-950 text-slate-400 text-sm">
        Connecting to VPSAgent...
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
    <div className="min-h-screen bg-slate-950 text-slate-100">
      <header className="sticky top-0 z-20 border-b border-slate-800/80 bg-slate-950/90 backdrop-blur">
        <div className="mx-auto max-w-6xl px-4 sm:px-6 h-16 flex items-center justify-between gap-4">
          <div className="flex items-center gap-2.5">
            <div className="h-9 w-9 rounded-xl bg-emerald-500/15 border border-emerald-500/30 flex items-center justify-center">
              <ShieldCheck className="h-5 w-5 text-emerald-400" />
            </div>
            <div>
              <span className="font-semibold text-white tracking-tight">
                VPSAgent
              </span>
              <span className="hidden sm:inline text-xs text-slate-500 ml-2">
                Safe AI Server Panel
              </span>
            </div>
          </div>

          <button
            type="button"
            onClick={handleLogout}
            className="inline-flex items-center gap-1.5 rounded-lg border border-slate-800 px-3 py-1.5 text-xs font-medium text-slate-400 hover:text-white hover:bg-slate-900 transition cursor-pointer"
          >
            <LogOut className="h-3.5 w-3.5" />
            Sign Out
          </button>
        </div>

        {/* 4-Tab Navigation Bar */}
        <div className="mx-auto max-w-6xl px-4 sm:px-6 flex gap-1 overflow-x-auto">
          {tabs.map((item) => {
            const Icon = item.icon;
            const active = tab === item.id;
            return (
              <button
                key={item.id}
                type="button"
                onClick={() => setTab(item.id)}
                className={`inline-flex items-center gap-2 border-b-2 px-4 py-3 text-sm font-medium whitespace-nowrap transition cursor-pointer ${
                  active
                    ? "border-emerald-400 text-white"
                    : "border-transparent text-slate-400 hover:text-slate-200"
                }`}
              >
                <Icon className="h-4 w-4" />
                {item.label}
                {item.badge !== undefined && (
                  <span className="rounded-full bg-amber-400 px-1.5 py-0.2 text-[11px] font-bold text-slate-950">
                    {item.badge}
                  </span>
                )}
              </button>
            );
          })}
        </div>
      </header>

      <main className="mx-auto max-w-6xl px-4 sm:px-6 py-8">
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
