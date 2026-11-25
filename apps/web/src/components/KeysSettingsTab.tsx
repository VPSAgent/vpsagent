import { useState } from "react";
import {
  Activity,
  Check,
  Copy,
  Globe,
  KeyRound,
  Lock,
  Plus,
  Trash2,
} from "lucide-react";
import {
  api,
  type AppRecord,
  type McpConnectionTestResult,
  type McpSnippets,
  type McpTokenRecord,
  type McpTokenScope,
  type SetupState,
} from "../api";

interface KeysSettingsTabProps {
  tokens: McpTokenRecord[];
  apps: AppRecord[];
  snippets: McpSnippets | null;
  setup: SetupState;
  publicIp: string | null;
  onRefresh: () => Promise<void>;
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
  snippets,
  setup,
  publicIp,
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
                  role="tab"
                  aria-selected={activeClient === id}
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

          <div className="relative">
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
    </div>
  );
}
