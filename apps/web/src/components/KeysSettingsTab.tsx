import { useState } from "react";
import { Check, Copy, Globe, KeyRound, Lock, Plus, Trash2 } from "lucide-react";
import {
  api,
  type AppRecord,
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
  { title: string; desc: string; badge: string }
> = {
  "read-only": {
    title: "Look Only",
    desc: "Check server health, inspect GitHub repos, and read logs. Can never change or delete anything.",
    badge: "bg-slate-700/80 text-slate-200",
  },
  "approval-required": {
    title: "Ask Me First",
    desc: "Can check health & logs, and queues every deploy or change for your Approve click.",
    badge: "bg-amber-500/15 text-amber-300",
  },
  "safe-auto-deploy": {
    title: "Safe Auto-Deploy (Recommended)",
    desc: "Can launch, rebuild, restart, and update apps right away — but ALWAYS asks your approval before deleting an app.",
    badge: "bg-sky-500/15 text-sky-300",
  },
  "auto-approve": {
    title: "Trusted Auto-Pass",
    desc: "Can launch, update, and delete isolated apps right away without waiting.",
    badge: "bg-emerald-500/15 text-emerald-300",
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
  const [newRawToken, setNewRawToken] = useState<string | null>(null);
  const [copiedId, setCopiedId] = useState<string | null>(null);
  const [activeClient, setActiveClient] = useState<
    "claudeCode" | "cursor" | "codex" | "genericHttp"
  >("claudeCode");
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
      setNewRawToken(res.rawToken);
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

  const activeSnippet = snippets ? snippets[activeClient] : "";

  return (
    <div className="space-y-8">
      <div>
        <h2 className="text-xl font-semibold text-white">
          AI Keys &amp; Settings
        </h2>
        <p className="text-sm text-slate-400">
          Create scoped visitor passes for Claude Code, Cursor, Codex, or T3
          Code, and configure automatic app web addresses.
        </p>
      </div>

      {error && (
        <div className="rounded-xl border border-rose-500/30 bg-rose-500/10 px-4 py-3 text-sm text-rose-300">
          {error}
        </div>
      )}
      {notice && (
        <div className="rounded-xl border border-emerald-500/30 bg-emerald-500/10 px-4 py-3 text-sm text-emerald-300">
          {notice}
        </div>
      )}

      {/* Create AI Visitor Pass */}
      <section className="rounded-2xl border border-slate-800 bg-slate-900/70 p-6 space-y-4">
        <div className="flex items-center gap-2">
          <KeyRound className="h-4 w-4 text-emerald-400" />
          <h3 className="text-base font-semibold text-white">
            Create an AI Visitor Pass
          </h3>
        </div>

        <form onSubmit={handleCreateToken} className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <label className="block text-xs font-medium text-slate-300 mb-1">
                Pass Label (e.g. Claude Code on Laptop)
              </label>
              <input
                type="text"
                value={name}
                onChange={(e) => setName(e.target.value)}
                placeholder="Claude Code"
                required
                className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-white"
              />
            </div>
            <div>
              <label className="block text-xs font-medium text-slate-300 mb-1">
                Permission Level
              </label>
              <select
                value={scope}
                onChange={(e) => setScope(e.target.value as McpTokenScope)}
                className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-white"
              >
                <option value="safe-auto-deploy">
                  Safe Auto-Deploy (Recommended — always asks before delete)
                </option>
                <option value="approval-required">
                  Ask Me First (queues every change for approval)
                </option>
                <option value="read-only">Look Only (Read-Only)</option>
                <option value="auto-approve">
                  Trusted Auto-Pass (full auto, including delete)
                </option>
              </select>
            </div>
          </div>

          <p className="text-xs text-slate-400">{SCOPE_LABELS[scope].desc}</p>

          {/* Optional App Lock */}
          <div className="rounded-xl border border-slate-800 bg-slate-950/60 p-4 space-y-3">
            <label className="inline-flex items-center gap-2 text-xs font-medium text-slate-200 cursor-pointer">
              <input
                type="checkbox"
                checked={restrictApps}
                onChange={(e) => setRestrictApps(e.target.checked)}
                className="rounded border-slate-600 bg-slate-950"
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
                          className={`rounded-lg border px-2.5 py-1 text-xs font-mono transition cursor-pointer ${
                            checked
                              ? "border-sky-400 bg-sky-500/20 text-sky-200"
                              : "border-slate-700 bg-slate-900 text-slate-400 hover:text-slate-200"
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
                  <label className="block text-xs text-slate-400 mb-1">
                    Or type allowed app short IDs separated by commas (even for
                    apps not launched yet)
                  </label>
                  <input
                    type="text"
                    value={customSlugsText}
                    onChange={(e) => setCustomSlugsText(e.target.value)}
                    placeholder="my-blog, landing-page"
                    className="w-full rounded-lg border border-slate-700 bg-slate-900 px-3 py-1.5 text-xs font-mono text-white"
                  />
                </div>
              </div>
            )}
          </div>

          <button
            type="submit"
            disabled={busy}
            className="inline-flex items-center gap-2 rounded-lg bg-emerald-500 px-4 py-2 text-sm font-semibold text-slate-950 hover:bg-emerald-400 disabled:opacity-50 cursor-pointer"
          >
            <Plus className="h-4 w-4" />
            Create Visitor Pass
          </button>
        </form>

        {newRawToken && (
          <div className="rounded-xl border border-emerald-500/40 bg-emerald-500/10 p-4 space-y-2">
            <p className="text-xs font-semibold text-emerald-300">
              Copy this key now — for your safety it will never be shown again:
            </p>
            <div className="flex items-center gap-2">
              <code className="flex-1 overflow-x-auto rounded-lg bg-slate-950 px-3 py-2 text-xs font-mono text-emerald-200">
                {newRawToken}
              </code>
              <button
                type="button"
                onClick={() => copyText("new-token", newRawToken)}
                className="inline-flex items-center gap-1 rounded-lg bg-emerald-500 px-3 py-2 text-xs font-semibold text-slate-950 hover:bg-emerald-400 cursor-pointer"
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

      {/* Setup Snippets */}
      {snippets && (
        <section className="rounded-2xl border border-slate-800 bg-slate-900/70 p-6 space-y-4">
          {!snippets.httpsReady && (
            <div className="rounded-xl border border-amber-500/30 bg-amber-500/10 px-4 py-3 text-xs text-amber-200 flex flex-wrap items-center justify-between gap-2">
              <span>
                {setup.domain
                  ? `HTTPS certificate for ${setup.domain} is currently ${setup.tlsStatus}${setup.tlsError ? `: ${setup.tlsError}` : ""}. Remote HTTPS MCP will be advertised once TLS succeeds.`
                  : "No verified HTTPS domain yet — using local URL. Bind a domain below for remote HTTPS MCP access."}
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
                  className="rounded-lg bg-amber-400 px-3 py-1 text-xs font-semibold text-slate-950 hover:bg-amber-300 cursor-pointer"
                >
                  Re-check HTTPS
                </button>
              )}
            </div>
          )}
          <div className="flex flex-wrap items-center justify-between gap-2">
            <div>
              <h3 className="text-base font-semibold text-white">
                Connect Your AI Tool
              </h3>
              <p className="text-xs text-slate-400">
                Doorway URL:{" "}
                <code className="text-emerald-300">{snippets.mcpUrl}</code>
              </p>
            </div>
            <div className="flex flex-wrap gap-1.5">
              {(
                [
                  ["claudeCode", "Claude Code"],
                  ["cursor", "Cursor"],
                  ["codex", "Codex"],
                  ["genericHttp", "T3 Code / Generic"],
                ] as const
              ).map(([id, label]) => (
                <button
                  key={id}
                  type="button"
                  onClick={() => setActiveClient(id)}
                  className={`rounded-lg px-3 py-1.5 text-xs font-medium transition cursor-pointer ${
                    activeClient === id
                      ? "bg-emerald-500/20 text-emerald-300 border border-emerald-500/40"
                      : "bg-slate-950 text-slate-400 border border-slate-800 hover:text-slate-200"
                  }`}
                >
                  {label}
                </button>
              ))}
            </div>
          </div>

          <div className="relative">
            <pre className="rounded-xl border border-slate-800 bg-slate-950 p-4 text-xs font-mono text-slate-200 overflow-x-auto">
              {activeSnippet}
            </pre>
            <button
              type="button"
              onClick={() => copyText("snippet", activeSnippet)}
              className="absolute top-3 right-3 inline-flex items-center gap-1 rounded-lg border border-slate-700 bg-slate-900 px-2.5 py-1 text-xs text-slate-200 hover:bg-slate-800 cursor-pointer"
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

      {/* Existing Tokens */}
      <section className="rounded-2xl border border-slate-800 bg-slate-900/70 overflow-hidden">
        <div className="px-6 py-4 border-b border-slate-800">
          <h3 className="text-base font-semibold text-white">
            Your AI Visitor Passes ({tokens.length})
          </h3>
        </div>
        {tokens.length === 0 ? (
          <p className="p-6 text-sm text-slate-400">
            No visitor passes created yet.
          </p>
        ) : (
          <div className="divide-y divide-slate-800/80">
            {tokens.map((tok) => {
              const info = SCOPE_LABELS[tok.scope];
              const isRevoked = Boolean(tok.revokedAt);
              return (
                <div
                  key={tok.id}
                  className="flex flex-wrap items-center justify-between gap-3 px-6 py-3.5"
                >
                  <div className="space-y-0.5">
                    <div className="flex flex-wrap items-center gap-2">
                      <span
                        className={`text-sm font-medium ${
                          isRevoked
                            ? "line-through text-slate-500"
                            : "text-white"
                        }`}
                      >
                        {tok.name}
                      </span>
                      <span
                        className={`rounded-full px-2 py-0.5 text-xs font-medium ${info.badge}`}
                      >
                        {info.title}
                      </span>
                      {tok.allowedSlugs.length > 0 && (
                        <span className="inline-flex items-center gap-1 rounded-full bg-slate-800 px-2 py-0.5 text-xs font-mono text-sky-300">
                          <Lock className="h-3 w-3" />
                          {tok.allowedSlugs.join(", ")}
                        </span>
                      )}
                      {isRevoked && (
                        <span className="rounded-full bg-rose-500/15 px-2 py-0.5 text-xs text-rose-300">
                          Turned Off
                        </span>
                      )}
                    </div>
                    <p className="text-xs font-mono text-slate-500">
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
                      className="inline-flex items-center gap-1 rounded-lg border border-rose-500/30 px-3 py-1.5 text-xs font-medium text-rose-300 hover:bg-rose-500/10 cursor-pointer"
                    >
                      <Trash2 className="h-3.5 w-3.5" /> Turn Off
                    </button>
                  )}
                </div>
              );
            })}
          </div>
        )}
      </section>

      {/* Dashboard Domain & Default Apps Base Domain */}
      <section className="rounded-2xl border border-slate-800 bg-slate-900/70 p-6 space-y-6">
        <div className="flex items-center gap-2">
          <Globe className="h-4 w-4 text-sky-400" />
          <h3 className="text-base font-semibold text-white">
            Domains &amp; Automatic HTTPS
          </h3>
        </div>

        <form
          onSubmit={handleUpdateDomain}
          className="grid grid-cols-1 md:grid-cols-3 gap-3 items-end"
        >
          <div>
            <label className="block text-xs font-medium text-slate-300 mb-1">
              Dashboard Domain Name
            </label>
            <input
              type="text"
              value={domain}
              onChange={(e) => setDomain(e.target.value)}
              placeholder="vps.yourdomain.com"
              className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-white"
            />
          </div>
          <div>
            <label className="block text-xs font-medium text-slate-300 mb-1">
              Certificate Notice Email (Optional)
            </label>
            <input
              type="email"
              value={acmeEmail}
              onChange={(e) => setAcmeEmail(e.target.value)}
              placeholder="you@yourdomain.com"
              className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-white"
            />
          </div>
          <button
            type="submit"
            disabled={busy}
            className="rounded-lg bg-slate-100 px-4 py-2 text-sm font-semibold text-slate-950 hover:bg-white disabled:opacity-50 cursor-pointer"
          >
            Save Dashboard Domain
          </button>
        </form>

        <div className="border-t border-slate-800 pt-5 space-y-3">
          <div>
            <h4 className="text-sm font-semibold text-white">
              Default Web Address for New Apps (Optional)
            </h4>
            <p className="text-xs text-slate-400 mt-0.5">
              Set a base domain once so every new app automatically gets{" "}
              <code className="text-emerald-300">
                https://app-name.{appsBaseDomain || "yourdomain.com"}
              </code>{" "}
              with automatic HTTPS. Add one wildcard DNS{" "}
              <code className="text-slate-200">A</code> record:{" "}
              <code className="text-slate-200">
                *.{appsBaseDomain || "yourdomain.com"}
              </code>{" "}
              &rarr;{" "}
              <code className="text-slate-200">
                {publicIp || "YOUR_SERVER_IP"}
              </code>
              .
            </p>
          </div>
          <form
            onSubmit={handleUpdateAppsBaseDomain}
            className="grid grid-cols-1 md:grid-cols-3 gap-3 items-end"
          >
            <div className="md:col-span-2">
              <label className="block text-xs font-medium text-slate-300 mb-1">
                Default Apps Base Domain
              </label>
              <input
                type="text"
                value={appsBaseDomain}
                onChange={(e) => setAppsBaseDomain(e.target.value)}
                placeholder="apps.yourdomain.com (leave empty to disable)"
                className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-white"
              />
            </div>
            <button
              type="submit"
              disabled={busy}
              className="rounded-lg bg-emerald-500 px-4 py-2 text-sm font-semibold text-slate-950 hover:bg-emerald-400 disabled:opacity-50 cursor-pointer"
            >
              Save Default Domain
            </button>
          </form>
        </div>
      </section>
    </div>
  );
}
