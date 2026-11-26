import { useCallback, useEffect, useRef, useState } from "react";
import {
  Activity,
  ArrowDownToLine,
  Check,
  ChevronDown,
  ChevronUp,
  Copy,
  ExternalLink,
  GitBranch,
  Globe,
  KeyRound,
  Loader2,
  Lock,
  Plus,
  RefreshCw,
  Star,
  Trash2,
} from "lucide-react";
import {
  api,
  type AppRecord,
  type GitCredentialRecord,
  type McpConnectionTestResult,
  type McpSnippets,
  type McpTokenRecord,
  type McpTokenScope,
  type SetupState,
  type SystemUpdateStatus,
} from "../api";

interface KeysSettingsTabProps {
  tokens: McpTokenRecord[];
  apps: AppRecord[];
  gitCredentials: GitCredentialRecord[];
  snippets: McpSnippets | null;
  setup: SetupState;
  publicIp: string | null;
  focusSection?: "github" | "updates" | null;
  onConsumeFocusSection?: () => void;
  initialUpdateStatus?: SystemUpdateStatus | null;
  onUpdateStatusChange?: (status: SystemUpdateStatus) => void;
  onRefresh: () => Promise<void>;
}

const RELEASE_UPDATE_STEPS = [
  { key: "downloading", label: "Download release" },
  { key: "verifying", label: "Verify SHA-256" },
  { key: "building", label: "Rebuild VPSAgent" },
  { key: "restarting", label: "Restart & reconnect" },
] as const;

const GIT_UPDATE_STEPS = [
  { key: "fetching", label: "Download code" },
  { key: "syncing", label: "Update config" },
  { key: "building", label: "Rebuild VPSAgent" },
  { key: "restarting", label: "Restart & reconnect" },
] as const;

function getUpdateStepIndex(
  phase: string | null,
  reconnecting: boolean,
  isRelease: boolean,
): number {
  if (reconnecting || phase === "restarting" || phase === "completed") {
    return 3;
  }
  if (isRelease) {
    if (phase === "building") return 2;
    if (phase === "verifying" || phase === "extracting" || phase === "syncing") {
      return 1;
    }
    return 0;
  }
  if (phase === "building") return 2;
  if (phase === "syncing") return 1;
  return 0;
}

function isSafeHttpsUrl(raw: string | null | undefined): raw is string {
  if (!raw) return false;
  try {
    const u = new URL(raw);
    return u.protocol === "https:";
  } catch {
    return false;
  }
}

const SCOPE_LABELS: Record<
  McpTokenScope,
  { title: string; desc: string; dot: string; text: string }
> = {
  "read-only": {
    title: "Look Only",
    desc: "Check server health, inspect GitHub repos, and read logs. Can never change or delete anything.",
    dot: "bg-[#9CA3AF]",
    text: "text-[#D1D5DB]",
  },
  "approval-required": {
    title: "Ask Me First",
    desc: "Check health and logs, and queue every deploy or change for your Approve click.",
    dot: "bg-amber-400",
    text: "text-amber-300",
  },
  "safe-auto-deploy": {
    title: "Safe Auto-Deploy",
    desc: "Launch, rebuild, restart, and update apps right away, while always asking your approval before deleting an app.",
    dot: "bg-sky-400",
    text: "text-sky-300",
  },
  "auto-approve": {
    title: "Trusted Auto-Pass",
    desc: "Launch, update, and delete isolated apps right away. Host-level commands, files, and services still ask for your Approve click.",
    dot: "bg-emerald-400",
    text: "text-emerald-300",
  },
  "host-admin": {
    title: "Full Server Admin (Root)",
    desc: "Full hands-free VPS administration: runs shell commands directly on the server as root, edits allowed files, and manages system services without waiting for approval.",
    dot: "bg-rose-400",
    text: "text-rose-300",
  },
};

export function KeysSettingsTab({
  tokens,
  apps,
  gitCredentials,
  snippets,
  setup,
  publicIp,
  focusSection,
  onConsumeFocusSection,
  initialUpdateStatus = null,
  onUpdateStatusChange,
  onRefresh,
}: KeysSettingsTabProps) {
  const [name, setName] = useState("");
  const [scope, setScope] = useState<McpTokenScope>("safe-auto-deploy");
  const [restrictApps, setRestrictApps] = useState(false);
  const [selectedSlugs, setSelectedSlugs] = useState<string[]>([]);
  const [customSlugsText, setCustomSlugsText] = useState("");
  const [newCreatedToken, setNewCreatedToken] = useState<{
    id: string;
    rawToken: string;
  } | null>(null);
  const [copiedId, setCopiedId] = useState<string | null>(null);
  const [activeClient, setActiveClient] = useState<
    "claudeCode" | "t3AndAgy" | "cursor" | "codex" | "genericHttp" | "curlTest"
  >("claudeCode");
  const [testResult, setTestResult] = useState<McpConnectionTestResult | null>(
    null,
  );
  const [testing, setTesting] = useState(false);
  const [domain, setDomain] = useState(setup.domain ?? "");
  const [acmeEmail, setAcmeEmail] = useState(setup.acmeEmail ?? "");
  const [appsBaseDomain, setAppsBaseDomain] = useState(
    setup.appsBaseDomain ?? "",
  );
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [updateStatus, setUpdateStatus] = useState<SystemUpdateStatus | null>(
    initialUpdateStatus,
  );
  const [updateLoading, setUpdateLoading] = useState(!initialUpdateStatus);
  const [checkingUpdate, setCheckingUpdate] = useState(false);
  const [startingUpdate, setStartingUpdate] = useState(false);
  const [reconnectingUpdate, setReconnectingUpdate] = useState(false);
  const [updateLoadError, setUpdateLoadError] = useState<string | null>(null);
  const [showUpdateLogs, setShowUpdateLogs] = useState(false);
  const baselineBuildRef = useRef<{
    version: string | null;
    commit: string | null;
  } | null>(null);

  const githubSectionRef = useRef<HTMLElement | null>(null);
  const updatesSectionRef = useRef<HTMLElement | null>(null);
  const [githubToken, setGithubToken] = useState("");
  const [githubLabel, setGithubLabel] = useState("");
  const [githubBusy, setGithubBusy] = useState(false);
  const [testingCredId, setTestingCredId] = useState<string | null>(null);

  const applyLocalUpdateStatus = useCallback(
    (next: SystemUpdateStatus) => {
      setUpdateStatus(next);
      onUpdateStatusChange?.(next);
    },
    [onUpdateStatusChange],
  );

  useEffect(() => {
    if (focusSection === "github") {
      githubSectionRef.current?.scrollIntoView({
        behavior: "smooth",
        block: "start",
      });
      onConsumeFocusSection?.();
    } else if (focusSection === "updates") {
      updatesSectionRef.current?.scrollIntoView({
        behavior: "smooth",
        block: "start",
      });
      onConsumeFocusSection?.();
    }
  }, [focusSection, onConsumeFocusSection]);

  const loadUpdateStatus = useCallback(async () => {
    try {
      const res = await api.getSystemUpdateStatus();
      applyLocalUpdateStatus(res.status);
      setReconnectingUpdate(false);
      setUpdateLoadError(null);
    } catch (err) {
      // Keep previous status if the server is restarting mid-update; otherwise surface why updates are unavailable
      setUpdateLoadError(
        err instanceof Error
          ? err.message
          : "Could not load VPSAgent update status from the server.",
      );
    } finally {
      setUpdateLoading(false);
    }
  }, [applyLocalUpdateStatus]);

  useEffect(() => {
    void loadUpdateStatus();
  }, [loadUpdateStatus]);

  useEffect(() => {
    if (updateStatus?.state !== "updating") {
      return;
    }
    let cancelled = false;
    let sawDrop = false;
    let inFlight = false;
    const baseline = baselineBuildRef.current ?? {
      version: updateStatus.currentVersion,
      commit: updateStatus.currentCommit,
    };
    baselineBuildRef.current = baseline;

    const timer = window.setInterval(async () => {
      if (inFlight || cancelled) return;
      inFlight = true;
      try {
        const res = await api.getSystemUpdateStatus();
        if (cancelled) return;
        setReconnectingUpdate(false);
        applyLocalUpdateStatus(res.status);
        const versionOrCommitChanged =
          (res.status.currentVersion &&
            res.status.currentVersion !== baseline.version) ||
          (res.status.currentCommit &&
            res.status.currentCommit !== baseline.commit);
        if (
          res.status.state === "succeeded" ||
          (sawDrop &&
            res.status.state === "idle" &&
            Boolean(versionOrCommitChanged))
        ) {
          setNotice(
            res.status.message ||
              "VPSAgent updated! Reloading the dashboard...",
          );
          window.setTimeout(() => {
            window.location.reload();
          }, 1800);
        } else if (res.status.state === "failed") {
          setError(res.status.error || "VPSAgent update failed.");
        }
      } catch {
        if (!cancelled) {
          sawDrop = true;
          setReconnectingUpdate(true);
        }
      } finally {
        inFlight = false;
      }
    }, 2500);
    return () => {
      cancelled = true;
      window.clearInterval(timer);
    };
  }, [
    updateStatus?.state,
    updateStatus?.currentVersion,
    updateStatus?.currentCommit,
    applyLocalUpdateStatus,
  ]);

  const handleCheckUpdates = async () => {
    setCheckingUpdate(true);
    setError(null);
    setNotice(null);
    try {
      const res = await api.checkSystemUpdate();
      applyLocalUpdateStatus(res.status);
      if (res.status.updateAvailable) {
        setNotice(
          res.status.message ||
            "A new version of VPSAgent is ready to install.",
        );
      } else if (res.status.canUpdate) {
        setNotice(res.status.message || "VPSAgent is already up to date.");
      }
    } catch (err) {
      setError(
        err instanceof Error ? err.message : "Could not check for updates.",
      );
    } finally {
      setCheckingUpdate(false);
    }
  };

  const handleApplyUpdate = async () => {
    setStartingUpdate(true);
    setError(null);
    setNotice(null);
    setShowUpdateLogs(true);
    baselineBuildRef.current = {
      version: updateStatus?.currentVersion ?? null,
      commit: updateStatus?.currentCommit ?? null,
    };
    try {
      const source =
        updateStatus?.updateAvailable &&
        (updateStatus?.updateSource === "release" ||
          updateStatus?.updateSource === "git")
          ? updateStatus.updateSource
          : "auto";
      const res = await api.applySystemUpdate(source);
      applyLocalUpdateStatus(res.status);
      setNotice(
        "Update started. VPSAgent will rebuild and restart automatically in 1–2 minutes.",
      );
    } catch (err) {
      setError(
        err instanceof Error ? err.message : "Could not start VPSAgent update.",
      );
    } finally {
      setStartingUpdate(false);
    }
  };

  const copyText = async (id: string, text: string) => {
    await navigator.clipboard.writeText(text);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  const toggleAllowedSlug = (slug: string) => {
    setSelectedSlugs((prev) =>
      prev.includes(slug) ? prev.filter((s) => s !== slug) : [...prev, slug],
    );
  };

  const handleCreateToken = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setNotice(null);
    setBusy(true);
    try {
      const extraSlugs = customSlugsText
        .split(",")
        .map((s) => s.trim().toLowerCase())
        .filter(Boolean);
      const allowedSlugs = restrictApps
        ? Array.from(new Set([...selectedSlugs, ...extraSlugs]))
        : [];
      if (restrictApps && allowedSlugs.length === 0) {
        setError(
          "Pick at least one app or enter an app short ID when app lock is turned on.",
        );
        return;
      }
      const res = await api.createToken(name.trim(), scope, allowedSlugs);
      setNewCreatedToken({ id: res.token.id, rawToken: res.rawToken });
      setName("");
      setRestrictApps(false);
      setSelectedSlugs([]);
      setCustomSlugsText("");
      await onRefresh();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not create key.");
    } finally {
      setBusy(false);
    }
  };

  const handleRevoke = async (id: string) => {
    setError(null);
    try {
      await api.revokeToken(id);
      if (newCreatedToken?.id === id) {
        setNewCreatedToken(null);
      }
      setNotice("AI visitor pass turned off.");
      await onRefresh();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not revoke pass.");
    }
  };

  const handleUpdateDomain = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setNotice(null);
    setBusy(true);
    try {
      await api.updateSetupDomain(
        domain.trim() || null,
        acmeEmail.trim() || null,
      );
      setNotice("Saved dashboard domain settings.");
      await onRefresh();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not update domain.");
    } finally {
      setBusy(false);
    }
  };

  const handleUpdateAppsBaseDomain = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setNotice(null);
    setBusy(true);
    try {
      await api.updateAppsBaseDomain(appsBaseDomain.trim() || null);
      setNotice(
        appsBaseDomain.trim()
          ? `Default app addresses enabled for *.${appsBaseDomain.trim()}.`
          : "Cleared default apps base domain.",
      );
      await onRefresh();
    } catch (err) {
      setError(
        err instanceof Error
          ? err.message
          : "Could not save default apps base domain.",
      );
    } finally {
      setBusy(false);
    }
  };

  const handleCheckGatewayStatus = async () => {
    setTesting(true);
    setError(null);
    try {
      const res = await api.testMcpConnection();
      setTestResult(res);
    } catch (err) {
      setError(
        err instanceof Error ? err.message : "Could not check AI doorway status.",
      );
    } finally {
      setTesting(false);
    }
  };

  const handleAddGithubToken = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!githubToken.trim()) return;
    setGithubBusy(true);
    setError(null);
    setNotice(null);
    try {
      const res = await api.createGitCredential({
        label: githubLabel.trim() || undefined,
        token: githubToken.trim(),
      });
      setGithubToken("");
      setGithubLabel("");
      const baseMsg = `Connected ${res.accountLogin ? `@${res.accountLogin}` : "GitHub"} (${res.accessibleRepoCount} ${res.accessibleRepoCount === 1 ? "repo" : "repos"} visible).`;
      setNotice(res.warning ? `${baseMsg} ${res.warning}` : baseMsg);
      await onRefresh();
    } catch (err) {
      setError(
        err instanceof Error
          ? err.message
          : "Could not verify or save GitHub token.",
      );
    } finally {
      setGithubBusy(false);
    }
  };

  const handleTestGithubCred = async (id: string) => {
    setTestingCredId(id);
    setError(null);
    setNotice(null);
    try {
      const res = await api.testGitCredential(id);
      const baseMsg = `GitHub token verified${res.accountLogin ? ` for @${res.accountLogin}` : ""}: ${res.accessibleRepoCount} ${res.accessibleRepoCount === 1 ? "repo" : "repos"} accessible.`;
      setNotice(res.warning ? `${baseMsg} ${res.warning}` : baseMsg);
      await onRefresh();
    } catch (err) {
      setError(
        err instanceof Error ? err.message : "GitHub token check failed.",
      );
    } finally {
      setTestingCredId(null);
    }
  };

  const handleSetDefaultGithubCred = async (id: string) => {
    setGithubBusy(true);
    setError(null);
    setNotice(null);
    try {
      const res = await api.setDefaultGitCredential(id);
      setNotice(`Set "${res.credential.label}" as the default GitHub token.`);
      await onRefresh();
    } catch (err) {
      setError(
        err instanceof Error
          ? err.message
          : "Could not update default GitHub token.",
      );
    } finally {
      setGithubBusy(false);
    }
  };

  const handleDeleteGithubCred = async (id: string, label: string) => {
    if (
      !window.confirm(
        `Remove GitHub token "${label}"? Apps already built stay running, but future rebuilds of private repos using this token will need another token.`,
      )
    ) {
      return;
    }
    setGithubBusy(true);
    setError(null);
    setNotice(null);
    try {
      await api.deleteGitCredential(id);
      setNotice(`Removed GitHub token "${label}".`);
      await onRefresh();
    } catch (err) {
      setError(
        err instanceof Error ? err.message : "Could not remove GitHub token.",
      );
    } finally {
      setGithubBusy(false);
    }
  };

  const newRawToken = newCreatedToken?.rawToken ?? null;
  const rawActiveSnippet = snippets ? snippets[activeClient] : "";
  const placeholder = snippets?.tokenPlaceholder || "vpsmcp_YOUR_TOKEN_HERE";
  const activeSnippet =
    newRawToken && rawActiveSnippet
      ? rawActiveSnippet.split(placeholder).join(newRawToken)
      : rawActiveSnippet;

  return (
    <div className="space-y-7 panel-enter">
      <div>
        <h1 className="text-2xl font-semibold tracking-[-0.025em] text-white">
          AI keys &amp; settings
        </h1>
        <p className="mt-1 text-sm text-[#9CA3AF]">
          Create scoped visitor passes for Claude Code, T3 Code, Antigravity
          (AGY), Cursor, or Codex, and configure automatic app web addresses.
        </p>
      </div>

      {error && (
        <div className="rounded-xl border border-rose-500/35 bg-rose-500/10 px-4 py-3 text-sm text-rose-200">
          {error}
        </div>
      )}
      {notice && (
        <div className="rounded-xl border border-emerald-500/35 bg-emerald-500/10 px-4 py-3 text-sm text-emerald-200">
          {notice}
        </div>
      )}

      {/* Create AI Visitor Pass */}
      <section className="surface-panel rounded-xl p-6 space-y-5">
        <div className="flex items-center gap-2">
          <KeyRound className="h-4 w-4 text-emerald-400" />
          <h2 className="text-sm font-semibold text-white">
            Create an AI visitor pass
          </h2>
        </div>

        <form onSubmit={handleCreateToken} className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <label className="block text-xs font-medium text-[#9CA3AF] mb-1.5">
                Pass label
              </label>
              <input
                type="text"
                value={name}
                onChange={(e) => setName(e.target.value)}
                placeholder="Claude Code on MacBook"
                required
                className="field-input w-full rounded-lg px-3.5 py-2 text-sm"
              />
            </div>
            <div>
              <label className="block text-xs font-medium text-[#9CA3AF] mb-1.5">
                Permission level
              </label>
              <select
                value={scope}
                onChange={(e) => setScope(e.target.value as McpTokenScope)}
                className="field-input w-full rounded-lg px-3.5 py-2 text-sm"
              >
                <option value="safe-auto-deploy">
                  Safe Auto-Deploy (Recommended, asks before delete)
                </option>
                <option value="approval-required">
                  Ask Me First (queues every change for approval)
                </option>
                <option value="read-only">Look Only (Read-Only)</option>
                <option value="auto-approve">
                  Trusted Auto-Pass (isolated apps auto, host commands ask)
                </option>
                <option value="host-admin">
                  Full Server Admin (Root, unrestricted host commands)
                </option>
              </select>
            </div>
          </div>

          <p className="text-xs text-[#9CA3AF]">{SCOPE_LABELS[scope].desc}</p>

          {/* Optional App Lock */}
          <div className="surface-well rounded-lg p-4 space-y-3">
            <label className="inline-flex items-center gap-2 text-xs font-medium text-[#F4F5F7] cursor-pointer">
              <input
                type="checkbox"
                checked={restrictApps}
                onChange={(e) => setRestrictApps(e.target.checked)}
                className="rounded border-white/20 bg-[#090A0C] accent-emerald-500"
              />
              <Lock className="h-3.5 w-3.5 text-sky-400" />
              Lock this pass to specific apps only (optional)
            </label>

            {restrictApps && (
              <div className="space-y-3 pt-1">
                {apps.length > 0 && (
                  <div className="flex flex-wrap gap-2">
                    {apps.map((app) => {
                      const checked = selectedSlugs.includes(app.slug);
                      return (
                        <button
                          key={app.slug}
                          type="button"
                          onClick={() => toggleAllowedSlug(app.slug)}
                          className={`btn-press rounded-lg border px-2.5 py-1 text-xs font-mono cursor-pointer ${
                            checked
                              ? "border-sky-400/60 bg-sky-500/15 text-sky-200"
                              : "border-white/[0.1] bg-[#111317] text-[#9CA3AF] hover:text-white"
                          }`}
                        >
                          {checked ? "✓ " : "+ "}
                          {app.slug}
                        </button>
                      );
                    })}
                  </div>
                )}
                <div>
                  <label className="block text-xs text-[#9CA3AF] mb-1.5">
                    Or type allowed app short IDs separated by commas
                  </label>
                  <input
                    type="text"
                    value={customSlugsText}
                    onChange={(e) => setCustomSlugsText(e.target.value)}
                    placeholder="my-blog, landing-page"
                    className="field-input w-full rounded-lg px-3 py-1.5 text-xs font-mono"
                  />
                </div>
              </div>
            )}
          </div>

          <button
            type="submit"
            disabled={busy}
            className="btn-press inline-flex items-center gap-2 rounded-lg bg-emerald-500 px-4 py-2 text-[13px] font-semibold text-[#042F1E] hover:bg-emerald-400 disabled:opacity-50 cursor-pointer"
          >
            <Plus className="h-4 w-4" />
            Create visitor pass
          </button>
        </form>

        {newRawToken && (
          <div className="rounded-xl border border-emerald-500/40 bg-emerald-500/[0.08] p-4 space-y-2">
            <p className="text-xs font-semibold text-emerald-300">
              Copy this key now. For your safety it will never be shown again:
            </p>
            <div className="flex items-center gap-2">
              <code className="surface-well flex-1 overflow-x-auto rounded-lg px-3 py-2 text-xs font-mono text-emerald-200">
                {newRawToken}
              </code>
              <button
                type="button"
                onClick={() => copyText("new-token", newRawToken)}
                className="btn-press inline-flex items-center gap-1.5 rounded-lg bg-emerald-500 px-3 py-2 text-xs font-semibold text-[#042F1E] hover:bg-emerald-400 cursor-pointer"
              >
                {copiedId === "new-token" ? (
                  <Check className="h-3.5 w-3.5" />
                ) : (
                  <Copy className="h-3.5 w-3.5" />
                )}
                {copiedId === "new-token" ? "Copied" : "Copy"}
              </button>
            </div>
          </div>
        )}
      </section>

      {/* Connect Your AI Tool */}
      {snippets && (
        <section className="surface-panel rounded-xl p-6 space-y-4">
          {!snippets.httpsReady && (
            <div className="rounded-lg border border-amber-500/35 bg-amber-500/10 px-4 py-3 text-xs text-amber-200 flex flex-wrap items-center justify-between gap-2">
              <span>
                {setup.domain
                  ? `HTTPS certificate for ${setup.domain} is currently ${setup.tlsStatus}${setup.tlsError ? `: ${setup.tlsError}` : ""}. Remote HTTPS MCP will be advertised once TLS succeeds.`
                  : "No verified HTTPS domain yet. Using local URL until you bind a domain below."}
              </span>
              {setup.domain && (
                <button
                  type="button"
                  onClick={async () => {
                    setBusy(true);
                    try {
                      await api.recheckTls();
                      await onRefresh();
                    } finally {
                      setBusy(false);
                    }
                  }}
                  className="btn-press rounded-lg bg-amber-400 px-3 py-1 text-xs font-semibold text-[#1A1200] hover:bg-amber-300 cursor-pointer"
                >
                  Re-check HTTPS
                </button>
              )}
            </div>
          )}

          <div className="flex flex-wrap items-start justify-between gap-4">
            <div className="space-y-1">
              <div className="flex flex-wrap items-center gap-2.5">
                <h2 className="text-sm font-semibold text-white">
                  Connect your AI tool
                </h2>
                {newRawToken && (
                  <span className="text-xs font-medium text-emerald-400">
                    New key auto-filled
                  </span>
                )}
              </div>
              <div className="flex flex-wrap items-center gap-2.5 text-xs text-[#9CA3AF]">
                <span>
                  Doorway URL:{" "}
                  <code className="text-emerald-300">{snippets.mcpUrl}</code>
                </span>
                <button
                  type="button"
                  disabled={testing}
                  onClick={handleCheckGatewayStatus}
                  className="btn-press inline-flex items-center gap-1 rounded-md border border-white/[0.1] bg-[#0C0E12] px-2 py-0.5 text-[11px] font-medium text-[#F4F5F7] hover:bg-[#161920] disabled:opacity-50 cursor-pointer"
                >
                  <Activity className="h-3 w-3 text-emerald-400" />
                  {testing ? "Checking..." : "Check gateway"}
                </button>
              </div>
            </div>

            {/* Connected Segmented Client Selector */}
            <div
              role="tablist"
              aria-label="AI client snippets"
              className="inline-flex flex-wrap rounded-lg border border-white/[0.08] bg-[#0C0E12] p-1 gap-0.5"
              onKeyDown={(e) => {
                if (
                  e.key !== "ArrowLeft" &&
                  e.key !== "ArrowRight" &&
                  e.key !== "Home" &&
                  e.key !== "End"
                ) {
                  return;
                }
                e.preventDefault();
                const order = [
                  "claudeCode",
                  "t3AndAgy",
                  "cursor",
                  "codex",
                  "genericHttp",
                  "curlTest",
                ] as const;
                const idx = order.indexOf(activeClient);
                const next =
                  e.key === "Home"
                    ? order[0]
                    : e.key === "End"
                      ? order[order.length - 1]!
                      : e.key === "ArrowRight"
                        ? order[(idx + 1) % order.length]!
                        : order[(idx - 1 + order.length) % order.length]!;
                setActiveClient(next);
                document.getElementById(`mcp-client-tab-${next}`)?.focus();
              }}
            >
              {(
                [
                  ["claudeCode", "Claude Code"],
                  ["t3AndAgy", "T3 / AGY"],
                  ["cursor", "Cursor"],
                  ["codex", "Codex"],
                  ["genericHttp", "HTTP"],
                  ["curlTest", "Curl"],
                ] as const
              ).map(([id, label]) => (
                <button
                  key={id}
                  id={`mcp-client-tab-${id}`}
                  role="tab"
                  aria-selected={activeClient === id}
                  aria-controls="mcp-client-snippet-panel"
                  tabIndex={activeClient === id ? 0 : -1}
                  type="button"
                  onClick={() => setActiveClient(id)}
                  className={`btn-press rounded-md px-2.5 py-1 text-xs font-medium cursor-pointer ${
                    activeClient === id
                      ? "bg-white/[0.1] text-white"
                      : "text-[#9CA3AF] hover:text-[#F4F5F7]"
                  }`}
                >
                  {label}
                </button>
              ))}
            </div>
          </div>

          {testResult && (
            <div
              className={`rounded-lg border px-4 py-3 text-xs ${
                testResult.ok
                  ? "border-emerald-500/35 bg-emerald-500/10 text-emerald-200"
                  : "border-amber-500/35 bg-amber-500/10 text-amber-200"
              }`}
            >
              <span className="font-semibold">
                {testResult.ok ? "Gateway healthy: " : "Attention: "}
              </span>
              {testResult.message}
            </div>
          )}

          <div
            id="mcp-client-snippet-panel"
            role="tabpanel"
            aria-labelledby={`mcp-client-tab-${activeClient}`}
            className="relative"
          >
            <pre className="surface-well rounded-lg p-4 pr-24 text-xs font-mono text-[#E5E7EB] overflow-x-auto leading-relaxed">
              {activeSnippet}
            </pre>
            <button
              type="button"
              onClick={() => copyText("snippet", activeSnippet)}
              className="btn-press absolute top-3 right-3 inline-flex items-center gap-1.5 rounded-md border border-white/[0.1] bg-[#161920] px-2.5 py-1 text-xs font-medium text-[#F4F5F7] hover:bg-[#1E222B] cursor-pointer"
            >
              {copiedId === "snippet" ? (
                <Check className="h-3.5 w-3.5 text-emerald-400" />
              ) : (
                <Copy className="h-3.5 w-3.5" />
              )}
              {copiedId === "snippet" ? "Copied" : "Copy"}
            </button>
          </div>
        </section>
      )}

      {/* Existing Visitor Passes */}
      <section className="surface-panel rounded-xl overflow-hidden">
        <div className="px-6 py-4 border-b border-white/[0.08] flex items-center justify-between">
          <h2 className="text-sm font-semibold text-white">
            Your AI visitor passes
            <span className="ml-2 text-xs font-normal text-[#9CA3AF] tabular-nums">
              ({tokens.length})
            </span>
          </h2>
        </div>

        {tokens.length === 0 ? (
          <p className="p-6 text-sm text-[#9CA3AF]">
            No visitor passes created yet. Create one above to connect your AI
            coding assistant.
          </p>
        ) : (
          <div className="divide-y divide-white/[0.06]">
            {tokens.map((tok) => {
              const info = SCOPE_LABELS[tok.scope];
              const isRevoked = Boolean(tok.revokedAt);
              return (
                <div
                  key={tok.id}
                  className="row-interactive flex flex-wrap items-center justify-between gap-4 px-6 py-4"
                >
                  <div className="space-y-1 min-w-0">
                    <div className="flex flex-wrap items-center gap-2.5">
                      <span
                        className={`text-sm font-medium ${
                          isRevoked
                            ? "line-through text-[#6B7280]"
                            : "text-white"
                        }`}
                      >
                        {tok.name}
                      </span>
                      <span
                        className={`inline-flex items-center gap-1.5 text-xs font-medium ${info.text}`}
                      >
                        <span className={`h-1.5 w-1.5 rounded-full ${info.dot}`} />
                        {info.title}
                      </span>
                      {tok.allowedSlugs.length > 0 && (
                        <span className="inline-flex items-center gap-1 text-xs font-mono text-sky-300">
                          <Lock className="h-3 w-3" />
                          {tok.allowedSlugs.join(", ")}
                        </span>
                      )}
                      {isRevoked && (
                        <span className="text-xs text-rose-400">Turned off</span>
                      )}
                    </div>
                    <p className="text-xs font-mono text-[#6B7280] tabular-nums">
                      {tok.tokenPrefix}•••••••• &middot;{" "}
                      {tok.lastUsedAt
                        ? `Last used ${new Date(tok.lastUsedAt).toLocaleString()}`
                        : "Never used yet"}
                    </p>
                  </div>
                  {!isRevoked && (
                    <button
                      type="button"
                      onClick={() => handleRevoke(tok.id)}
                      className="btn-press inline-flex items-center gap-1.5 rounded-lg border border-rose-500/30 bg-rose-500/[0.05] px-3 py-1.5 text-xs font-medium text-rose-300 hover:bg-rose-500/15 cursor-pointer"
                    >
                      <Trash2 className="h-3.5 w-3.5" />
                      Turn off
                    </button>
                  )}
                </div>
              );
            })}
          </div>
        )}
      </section>

      {/* Private GitHub Repositories */}
      <section
        id="github-access"
        ref={githubSectionRef}
        className="surface-panel rounded-xl p-6 space-y-5"
      >
        <div className="flex flex-wrap items-start justify-between gap-4">
          <div className="space-y-1">
            <div className="flex flex-wrap items-center gap-2.5">
              <GitBranch className="h-4 w-4 text-emerald-400" />
              <h2 className="text-sm font-semibold text-white">
                Private GitHub repositories
              </h2>
              {gitCredentials.length > 0 ? (
                <span className="inline-flex items-center gap-1.5 rounded-full border border-emerald-500/35 bg-emerald-500/10 px-2.5 py-0.5 text-[11px] font-medium text-emerald-300">
                  <span className="h-1.5 w-1.5 rounded-full bg-emerald-400" />
                  Connected ({gitCredentials.length})
                </span>
              ) : (
                <span className="inline-flex items-center gap-1.5 rounded-full border border-white/[0.1] bg-white/[0.04] px-2.5 py-0.5 text-[11px] font-medium text-[#9CA3AF]">
                  Not connected
                </span>
              )}
            </div>
            <p className="text-xs text-[#9CA3AF] leading-relaxed">
              Connect a read-only GitHub token so you and your AI can browse and
              deploy private GitHub repos. Your token is encrypted at rest and
              never shown again or sent to AI chats.
            </p>
          </div>
          <a
            href="https://github.com/settings/personal-access-tokens/new"
            target="_blank"
            rel="noreferrer"
            className="btn-press inline-flex items-center gap-1.5 rounded-lg border border-white/[0.12] bg-[#0C0E12] px-3 py-1.5 text-xs font-medium text-[#F4F5F7] hover:bg-[#161920] shrink-0"
          >
            <span>Create token on GitHub</span>
            <ExternalLink className="h-3.5 w-3.5 text-emerald-400" />
          </a>
        </div>

        <div className="surface-well rounded-lg px-4 py-3 text-xs text-[#D1D5DB] space-y-1">
          <p className="font-medium text-white">
            Quick 3-step setup on GitHub (recommended fine-grained token):
          </p>
          <ol className="list-decimal list-inside space-y-0.5 text-[#9CA3AF]">
            <li>
              Choose <strong className="text-[#E5E7EB]">Only select repositories</strong> (or All repositories).
            </li>
            <li>
              Under <strong className="text-[#E5E7EB]">Repository permissions</strong>, set{" "}
              <strong className="text-emerald-300">Contents</strong> to{" "}
              <strong className="text-emerald-300">Read-only</strong> (Metadata is included automatically).
            </li>
            <li>
              Click <strong className="text-[#E5E7EB]">Generate token</strong>, copy it, and paste it below.
            </li>
          </ol>
        </div>

        <form
          onSubmit={handleAddGithubToken}
          className="grid grid-cols-1 md:grid-cols-12 gap-3.5 items-end"
        >
          <div className="md:col-span-5">
            <label className="block text-xs font-medium text-[#9CA3AF] mb-1.5">
              GitHub personal access token
            </label>
            <input
              type="password"
              value={githubToken}
              onChange={(e) => setGithubToken(e.target.value)}
              placeholder="github_pat_... or ghp_..."
              required
              autoComplete="off"
              className="field-input w-full rounded-lg px-3.5 py-2 text-sm font-mono"
            />
          </div>
          <div className="md:col-span-4">
            <label className="block text-xs font-medium text-[#9CA3AF] mb-1.5">
              Label (optional)
            </label>
            <input
              type="text"
              value={githubLabel}
              onChange={(e) => setGithubLabel(e.target.value)}
              placeholder="Personal GitHub or Work Org"
              className="field-input w-full rounded-lg px-3.5 py-2 text-sm"
            />
          </div>
          <div className="md:col-span-3">
            <button
              type="submit"
              disabled={githubBusy || !githubToken.trim()}
              className="btn-press w-full inline-flex items-center justify-center gap-1.5 rounded-lg bg-emerald-500 px-4 py-2 text-[13px] font-semibold text-[#042F1E] hover:bg-emerald-400 disabled:opacity-50 cursor-pointer"
            >
              {githubBusy ? (
                <Loader2 className="h-3.5 w-3.5 animate-spin" />
              ) : (
                <Lock className="h-3.5 w-3.5" />
              )}
              {githubBusy ? "Verifying..." : "Verify & connect"}
            </button>
          </div>
        </form>

        {gitCredentials.length > 0 && (
          <div className="divide-y divide-white/[0.06] rounded-lg border border-white/[0.08] bg-[#090A0C]">
            {gitCredentials.map((cred) => (
              <div
                key={cred.id}
                className="flex flex-wrap items-center justify-between gap-3 px-4 py-3"
              >
                <div className="space-y-1 min-w-0">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="text-sm font-medium text-white">
                      {cred.label}
                    </span>
                    {cred.accountLogin && (
                      <span className="text-xs font-mono text-sky-300">
                        @{cred.accountLogin}
                      </span>
                    )}
                    {cred.isDefault && (
                      <span className="inline-flex items-center gap-1 rounded-full border border-emerald-500/35 bg-emerald-500/10 px-2 py-0.5 text-[11px] font-medium text-emerald-300">
                        <Star className="h-2.5 w-2.5" />
                        Default
                      </span>
                    )}
                  </div>
                  <p className="text-xs font-mono text-[#6B7280] tabular-nums">
                    {cred.tokenHint} &middot;{" "}
                    {cred.lastUsedAt
                      ? `Last used ${new Date(cred.lastUsedAt).toLocaleString()}`
                      : `Added ${new Date(cred.createdAt).toLocaleDateString()}`}
                  </p>
                </div>
                <div className="flex flex-wrap items-center gap-2">
                  <button
                    type="button"
                    disabled={githubBusy || testingCredId === cred.id}
                    onClick={() => void handleTestGithubCred(cred.id)}
                    className="btn-press inline-flex items-center gap-1 rounded-lg border border-white/[0.1] bg-[#111317] px-2.5 py-1.5 text-xs font-medium text-[#F4F5F7] hover:bg-[#161920] disabled:opacity-50 cursor-pointer"
                  >
                    {testingCredId === cred.id ? (
                      <Loader2 className="h-3 w-3 animate-spin" />
                    ) : (
                      <Check className="h-3 w-3 text-emerald-400" />
                    )}
                    Test
                  </button>
                  {!cred.isDefault && (
                    <button
                      type="button"
                      disabled={githubBusy}
                      onClick={() => void handleSetDefaultGithubCred(cred.id)}
                      className="btn-press rounded-lg border border-white/[0.1] bg-[#111317] px-2.5 py-1.5 text-xs font-medium text-[#D1D5DB] hover:text-white disabled:opacity-50 cursor-pointer"
                    >
                      Set default
                    </button>
                  )}
                  <button
                    type="button"
                    disabled={githubBusy}
                    onClick={() =>
                      void handleDeleteGithubCred(cred.id, cred.label)
                    }
                    className="btn-press inline-flex items-center gap-1 rounded-lg border border-rose-500/30 bg-rose-500/[0.05] px-2.5 py-1.5 text-xs font-medium text-rose-300 hover:bg-rose-500/15 disabled:opacity-50 cursor-pointer"
                  >
                    <Trash2 className="h-3 w-3" />
                    Remove
                  </button>
                </div>
              </div>
            ))}
          </div>
        )}
      </section>

      {/* Domains & Automatic HTTPS */}
      <section className="surface-panel rounded-xl p-6 space-y-6">
        <div className="flex items-center gap-2">
          <Globe className="h-4 w-4 text-sky-400" />
          <h2 className="text-sm font-semibold text-white">
            Domains &amp; automatic HTTPS
          </h2>
        </div>

        <form
          onSubmit={handleUpdateDomain}
          className="grid grid-cols-1 md:grid-cols-3 gap-3.5 items-end"
        >
          <div>
            <label className="block text-xs font-medium text-[#9CA3AF] mb-1.5">
              Dashboard domain name
            </label>
            <input
              type="text"
              value={domain}
              onChange={(e) => setDomain(e.target.value)}
              placeholder="vps.yourdomain.com"
              className="field-input w-full rounded-lg px-3.5 py-2 text-sm"
            />
          </div>
          <div>
            <label className="block text-xs font-medium text-[#9CA3AF] mb-1.5">
              Certificate notice email (optional)
            </label>
            <input
              type="email"
              value={acmeEmail}
              onChange={(e) => setAcmeEmail(e.target.value)}
              placeholder="you@yourdomain.com"
              className="field-input w-full rounded-lg px-3.5 py-2 text-sm"
            />
          </div>
          <button
            type="submit"
            disabled={busy}
            className="btn-press rounded-lg bg-[#F4F5F7] px-4 py-2 text-[13px] font-semibold text-[#090A0C] hover:bg-white disabled:opacity-50 cursor-pointer"
          >
            Save dashboard domain
          </button>
        </form>

        <div className="border-t border-white/[0.08] pt-5 space-y-3.5">
          <div>
            <h3 className="text-sm font-semibold text-white">
              Default web address for new apps (optional)
            </h3>
            <p className="text-xs text-[#9CA3AF] mt-1 leading-relaxed">
              Set a base domain once so every new app automatically gets{" "}
              <code className="text-emerald-300">
                https://app-name.{appsBaseDomain || "yourdomain.com"}
              </code>{" "}
              with automatic HTTPS. Add one wildcard DNS{" "}
              <code className="text-[#F4F5F7]">A</code> record:{" "}
              <code className="text-[#F4F5F7]">
                *.{appsBaseDomain || "yourdomain.com"}
              </code>{" "}
              &rarr;{" "}
              <code className="text-[#F4F5F7]">
                {publicIp || "YOUR_SERVER_IP"}
              </code>
              .
            </p>
          </div>
          <form
            onSubmit={handleUpdateAppsBaseDomain}
            className="grid grid-cols-1 md:grid-cols-3 gap-3.5 items-end"
          >
            <div className="md:col-span-2">
              <label className="block text-xs font-medium text-[#9CA3AF] mb-1.5">
                Default apps base domain
              </label>
              <input
                type="text"
                value={appsBaseDomain}
                onChange={(e) => setAppsBaseDomain(e.target.value)}
                placeholder="apps.yourdomain.com (leave empty to disable)"
                className="field-input w-full rounded-lg px-3.5 py-2 text-sm"
              />
            </div>
            <button
              type="submit"
              disabled={busy}
              className="btn-press rounded-lg bg-emerald-500 px-4 py-2 text-[13px] font-semibold text-[#042F1E] hover:bg-emerald-400 disabled:opacity-50 cursor-pointer"
            >
              Save default domain
            </button>
          </form>
        </div>
      </section>

      {/* VPSAgent Updates */}
      <section
        id="vpsagent-updates"
        ref={updatesSectionRef}
        className="surface-panel rounded-xl p-6 space-y-5"
      >
        {(() => {
          const isUpdating = updateStatus?.state === "updating";
          const isReleaseUpdate = updateStatus?.updateSource === "release";
          const updateSteps = isReleaseUpdate
            ? RELEASE_UPDATE_STEPS
            : GIT_UPDATE_STEPS;
          const activeStepIdx = getUpdateStepIndex(
            updateStatus?.phase ?? null,
            reconnectingUpdate,
            isReleaseUpdate,
          );
          const safeReleaseUrl = isSafeHttpsUrl(updateStatus?.latestReleaseUrl)
            ? updateStatus.latestReleaseUrl
            : null;
          const installedVersionLabel = updateStatus?.currentVersion
            ? `v${updateStatus.currentVersion.replace(/^v/i, "")}`
            : updateStatus?.currentReleaseTag || "Unknown";
          const latestReleaseLabel = updateStatus?.latestVersion
            ? `v${updateStatus.latestVersion.replace(/^v/i, "")}`
            : updateStatus?.latestReleaseTag || null;
          const updateButtonLabel = isUpdating
            ? "Updating..."
            : startingUpdate
              ? "Starting..."
              : updateStatus?.updateAvailable &&
                  isReleaseUpdate &&
                  updateStatus.latestReleaseTag
                ? `Update to ${updateStatus.latestReleaseTag}`
                : updateStatus?.updateAvailable
                  ? "Install update"
                  : updateStatus?.checkedAt && !updateStatus.updateAvailable
                    ? "Rebuild VPSAgent"
                    : "Update VPSAgent";
          const isSecondaryRebuild = Boolean(
            updateStatus?.canUpdate &&
              updateStatus.checkedAt &&
              !updateStatus.updateAvailable &&
              !isUpdating,
          );

          return (
            <>
              <div className="flex flex-wrap items-start justify-between gap-4">
                <div className="space-y-1">
                  <div className="flex flex-wrap items-center gap-2.5">
                    <ArrowDownToLine className="h-4 w-4 text-emerald-400" />
                    <h2 className="text-sm font-semibold text-white">
                      VPSAgent updates
                    </h2>
                    {isUpdating && (
                      <span className="inline-flex items-center gap-1.5 rounded-full border border-amber-500/35 bg-amber-500/10 px-2.5 py-0.5 text-[11px] font-medium text-amber-300">
                        <span className="h-1.5 w-1.5 rounded-full bg-amber-400 animate-pulse" />
                        {reconnectingUpdate ? "Restarting..." : "Updating..."}
                      </span>
                    )}
                    {!isUpdating && updateStatus?.updateAvailable && (
                      <span className="inline-flex items-center gap-1.5 rounded-full border border-emerald-500/35 bg-emerald-500/10 px-2.5 py-0.5 text-[11px] font-medium text-emerald-300">
                        <span className="h-1.5 w-1.5 rounded-full bg-emerald-400" />
                        {isReleaseUpdate && updateStatus.latestReleaseTag
                          ? `${updateStatus.latestReleaseTag} ready`
                          : `${updateStatus.commitsBehind} new ${
                              updateStatus.commitsBehind === 1
                                ? "update"
                                : "updates"
                            }`}
                      </span>
                    )}
                    {!isUpdating &&
                      updateStatus?.state !== "failed" &&
                      updateStatus?.checkedAt &&
                      !updateStatus.updateAvailable &&
                      updateStatus.canUpdate && (
                        <span className="inline-flex items-center gap-1.5 rounded-full border border-white/[0.1] bg-white/[0.04] px-2.5 py-0.5 text-[11px] font-medium text-[#D1D5DB]">
                          Up to date
                        </span>
                      )}
                    {updateStatus?.checksumStatus === "verified" && (
                      <span className="inline-flex items-center gap-1 rounded-full border border-emerald-500/30 bg-emerald-500/[0.08] px-2.5 py-0.5 text-[11px] font-medium text-emerald-300">
                        <Check className="h-3 w-3" />
                        SHA-256 verified
                      </span>
                    )}
                    {updateStatus?.checksumStatus !== "verified" &&
                      updateStatus?.checksumAvailable && (
                        <span className="inline-flex items-center gap-1 rounded-full border border-sky-500/30 bg-sky-500/[0.08] px-2.5 py-0.5 text-[11px] font-medium text-sky-300">
                          SHA-256 check included
                        </span>
                      )}
                    {updateStatus?.updateSource === "git" &&
                      (updateStatus.releaseStatus === "no_releases" ||
                        updateStatus.releaseStatus === "unavailable") && (
                        <span className="inline-flex items-center rounded-full border border-white/[0.1] bg-white/[0.04] px-2.5 py-0.5 text-[11px] font-medium text-[#9CA3AF]">
                          Branch fallback
                        </span>
                      )}
                  </div>
                  <p className="text-xs text-[#9CA3AF]">
                    Checks GitHub Releases (or your linked branch if no release
                    is published yet) and safely updates VPSAgent without
                    touching your apps, secrets, or database.
                  </p>
                </div>

                <div className="flex flex-wrap items-center gap-2">
                  <button
                    type="button"
                    disabled={
                      updateLoading ||
                      checkingUpdate ||
                      startingUpdate ||
                      isUpdating
                    }
                    onClick={handleCheckUpdates}
                    className="btn-press inline-flex items-center gap-1.5 rounded-lg border border-white/[0.1] bg-[#0C0E12] px-3 py-2 text-xs font-medium text-[#F4F5F7] hover:bg-[#161920] disabled:opacity-50 cursor-pointer"
                  >
                    <RefreshCw
                      className={`h-3.5 w-3.5 ${checkingUpdate ? "animate-spin" : ""}`}
                    />
                    {checkingUpdate ? "Checking..." : "Check for updates"}
                  </button>
                  <button
                    type="button"
                    disabled={
                      updateLoading ||
                      startingUpdate ||
                      checkingUpdate ||
                      !updateStatus?.canUpdate ||
                      isUpdating
                    }
                    onClick={handleApplyUpdate}
                    className={
                      isSecondaryRebuild
                        ? "btn-press inline-flex items-center gap-1.5 rounded-lg border border-white/[0.12] bg-[#111317] px-3.5 py-2 text-xs font-medium text-[#F4F5F7] hover:bg-[#181B22] disabled:opacity-50 cursor-pointer"
                        : "btn-press inline-flex items-center gap-1.5 rounded-lg bg-emerald-500 px-4 py-2 text-[13px] font-semibold text-[#042F1E] hover:bg-emerald-400 disabled:opacity-50 cursor-pointer"
                    }
                  >
                    <ArrowDownToLine className="h-4 w-4" />
                    {updateButtonLabel}
                  </button>
                </div>
              </div>

              <div className="surface-well rounded-lg px-4 py-3 flex flex-wrap items-center justify-between gap-3 text-xs">
                <div className="flex flex-wrap items-center gap-x-5 gap-y-1.5 text-[#9CA3AF]">
                  <span>
                    Installed:{" "}
                    <code className="font-mono text-[#F4F5F7]">
                      {installedVersionLabel}
                    </code>
                    {updateStatus?.currentCommit && (
                      <code className="ml-1.5 font-mono text-[#6B7280]">
                        ({updateStatus.currentCommit.slice(0, 7)})
                      </code>
                    )}
                    {updateStatus?.installedFrom === "release" && (
                      <span className="ml-1.5 text-[11px] text-emerald-400">
                        release
                      </span>
                    )}
                  </span>

                  <span>
                    Latest available:{" "}
                    {latestReleaseLabel ? (
                      <>
                        <code
                          className={`font-mono ${
                            updateStatus?.updateAvailable && isReleaseUpdate
                              ? "text-emerald-300 font-semibold"
                              : "text-[#F4F5F7]"
                          }`}
                        >
                          {latestReleaseLabel}
                        </code>
                        {updateStatus?.latestReleasePrerelease && (
                          <span className="ml-1.5 rounded border border-amber-500/30 bg-amber-500/10 px-1.5 py-0.5 text-[10px] font-medium text-amber-300">
                            Pre-release
                          </span>
                        )}
                        {safeReleaseUrl && (
                          <a
                            href={safeReleaseUrl}
                            target="_blank"
                            rel="noreferrer"
                            className="ml-2 inline-flex items-center gap-1 text-[11px] text-sky-300 hover:text-sky-200"
                          >
                            <span>View release</span>
                            <ExternalLink className="h-3 w-3" />
                          </a>
                        )}
                      </>
                    ) : updateStatus?.releaseStatus === "no_releases" ? (
                      <span className="text-[#D1D5DB]">
                        No GitHub release yet{" "}
                        {updateStatus.branch
                          ? `(tracking ${updateStatus.branch})`
                          : ""}
                      </span>
                    ) : updateStatus?.releaseStatus === "unavailable" ? (
                      <span className="text-amber-300">
                        Release check unavailable{" "}
                        {updateStatus.branch
                          ? `(tracking ${updateStatus.branch})`
                          : ""}
                      </span>
                    ) : updateStatus?.updateSource === "git" &&
                      updateStatus.updateAvailable &&
                      updateStatus.latestCommit ? (
                      <code className="font-mono text-emerald-300">
                        {updateStatus.commitsBehind} commit
                        {updateStatus.commitsBehind === 1 ? "" : "s"} ahead (
                        {updateStatus.latestCommit.slice(0, 7)})
                      </code>
                    ) : (
                      <span className="text-[#6B7280]">
                        Click &ldquo;Check for updates&rdquo;
                      </span>
                    )}
                  </span>

                  {updateStatus?.branch && (
                    <span>
                      Branch:{" "}
                      <code className="font-mono text-[#F4F5F7]">
                        {updateStatus.branch}
                      </code>
                    </span>
                  )}
                </div>
                {updateStatus?.checkedAt && (
                  <span className="text-[11px] text-[#6B7280] tabular-nums">
                    Last checked{" "}
                    {new Date(updateStatus.checkedAt).toLocaleString()}
                  </span>
                )}
              </div>

              {!isUpdating &&
                updateStatus?.updateAvailable &&
                isReleaseUpdate && (
                  <div className="rounded-lg border border-emerald-500/30 bg-emerald-500/[0.06] px-4 py-3 text-xs text-emerald-100 space-y-2">
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <div>
                        <span className="font-semibold text-emerald-300">
                          {updateStatus.latestReleaseName ||
                            updateStatus.latestReleaseTag ||
                            "New release available"}
                        </span>
                        {updateStatus.latestReleasePublishedAt && (
                          <span className="ml-2 text-[11px] text-emerald-200/75">
                            Published{" "}
                            {new Date(
                              updateStatus.latestReleasePublishedAt,
                            ).toLocaleDateString()}
                          </span>
                        )}
                      </div>
                      {safeReleaseUrl && (
                        <a
                          href={safeReleaseUrl}
                          target="_blank"
                          rel="noreferrer"
                          className="inline-flex items-center gap-1 text-[11px] font-medium text-emerald-300 hover:text-emerald-200"
                        >
                          <span>Release notes on GitHub</span>
                          <ExternalLink className="h-3 w-3" />
                        </a>
                      )}
                    </div>
                    {updateStatus.latestReleaseNotes && (
                      <p className="whitespace-pre-line text-[11px] text-[#D1D5DB] leading-relaxed max-h-28 overflow-y-auto">
                        {updateStatus.latestReleaseNotes}
                      </p>
                    )}
                    <p className="text-[11px] text-emerald-200/80">
                      {updateStatus.checksumAvailable
                        ? "Includes a SHA-256 checksum that VPSAgent verifies automatically before rebuilding."
                        : "Downloads directly from GitHub Releases without touching your apps, secrets, or database."}
                    </p>
                  </div>
                )}

              {!isUpdating &&
                updateStatus?.updateAvailable &&
                !isReleaseUpdate &&
                updateStatus.latestCommitSubject && (
                  <div className="rounded-lg border border-emerald-500/30 bg-emerald-500/[0.06] px-4 py-3 text-xs text-emerald-200">
                    <span className="font-semibold">Latest change: </span>
                    {updateStatus.latestCommitSubject}
                    {updateStatus.latestCommit && (
                      <code className="ml-2 font-mono text-emerald-300/80">
                        ({updateStatus.latestCommit.slice(0, 7)})
                      </code>
                    )}
                  </div>
                )}

              {!isUpdating && updateStatus?.releaseNote && (
                <p className="text-xs text-[#9CA3AF]">
                  {updateStatus.releaseNote}
                </p>
              )}

              {isUpdating && (
                <div className="rounded-lg border border-amber-500/35 bg-amber-500/10 px-4 py-3.5 text-xs text-amber-200 space-y-3">
                  <div>
                    <span className="font-semibold">
                      {reconnectingUpdate
                        ? "Restarting VPSAgent: "
                        : "Update in progress: "}
                    </span>
                    {reconnectingUpdate
                      ? "Reconnecting to your server automatically. This page will reload as soon as it is back."
                      : updateStatus?.message ||
                        "Downloading and rebuilding VPSAgent..."}
                  </div>
                  <div className="grid grid-cols-2 sm:grid-cols-4 gap-2">
                    {updateSteps.map((step, idx) => {
                      const done = idx < activeStepIdx;
                      const current = idx === activeStepIdx;
                      return (
                        <div
                          key={step.key}
                          className={`rounded-md border px-2.5 py-1.5 text-[11px] flex items-center gap-1.5 ${
                            done
                              ? "border-emerald-500/35 bg-emerald-500/15 text-emerald-200"
                              : current
                                ? "border-amber-400/45 bg-amber-400/15 text-amber-100 font-medium"
                                : "border-white/[0.08] bg-black/20 text-[#9CA3AF]"
                          }`}
                        >
                          {done ? (
                            <Check className="h-3 w-3 text-emerald-400 shrink-0" />
                          ) : current ? (
                            <Loader2 className="h-3 w-3 text-amber-300 animate-spin shrink-0" />
                          ) : (
                            <span className="h-1.5 w-1.5 rounded-full bg-white/25 shrink-0" />
                          )}
                          <span className="truncate">{step.label}</span>
                        </div>
                      );
                    })}
                  </div>
                  <p className="text-[11px] text-amber-100/80">
                    Your apps, secrets, database, and login stay untouched while
                    VPSAgent restarts.
                  </p>
                </div>
              )}

              {updateStatus?.state === "failed" && updateStatus.error && (
                <div className="rounded-lg border border-rose-500/35 bg-rose-500/10 px-4 py-3 text-xs text-rose-200">
                  <span className="font-semibold">Last update failed: </span>
                  {updateStatus.error}
                </div>
              )}

              {!updateLoading &&
                updateStatus &&
                !updateStatus.canUpdate &&
                updateStatus.unavailableReason && (
                  <p className="text-xs text-[#9CA3AF]">
                    {updateStatus.unavailableReason}
                  </p>
                )}

              {!updateLoading && !updateStatus && updateLoadError && (
                <p className="text-xs text-amber-300">
                  Could not check update availability: {updateLoadError}
                </p>
              )}

              {updateStatus && updateStatus.logs.length > 0 && (
                <div className="space-y-2">
                  <button
                    type="button"
                    onClick={() => setShowUpdateLogs((prev) => !prev)}
                    className="inline-flex items-center gap-1.5 text-xs font-medium text-[#9CA3AF] hover:text-white cursor-pointer"
                  >
                    {showUpdateLogs ? (
                      <ChevronUp className="h-3.5 w-3.5" />
                    ) : (
                      <ChevronDown className="h-3.5 w-3.5" />
                    )}
                    {showUpdateLogs ? "Hide update log" : "View update log"}
                  </button>
                  {showUpdateLogs && (
                    <pre className="surface-well max-h-56 overflow-auto rounded-lg p-3 text-[11px] font-mono text-[#D1D5DB] leading-relaxed">
                      {updateStatus.logs.join("\n")}
                    </pre>
                  )}
                </div>
              )}
            </>
          );
        })()}
      </section>
    </div>
  );
}
