import { useState } from "react";
import { Check, Copy, Globe, KeyRound, Plus, Trash2 } from "lucide-react";
import {
  api,
  type McpSnippets,
  type McpTokenRecord,
  type SetupState,
} from "../api";

interface KeysSettingsTabProps {
  tokens: McpTokenRecord[];
  snippets: McpSnippets | null;
  setup: SetupState;
  onRefresh: () => Promise<void>;
}

const SCOPE_LABELS: Record<
  McpTokenRecord["scope"],
  { title: string; desc: string; badge: string }
> = {
  "read-only": {
    title: "Look Only",
    desc: "Check server health and read logs. Can never change or delete anything.",
    badge: "bg-slate-700/80 text-slate-200",
  },
  "approval-required": {
    title: "Ask Me First (Recommended)",
    desc: "Can check health & logs, and queues deploys/changes for your Approve click.",
    badge: "bg-amber-500/15 text-amber-300",
  },
  "auto-approve": {
    title: "Trusted Auto-Pass",
    desc: "Can launch and update isolated apps right away without waiting.",
    badge: "bg-emerald-500/15 text-emerald-300",
  },
};

export function KeysSettingsTab({
  tokens,
  snippets,
  setup,
  onRefresh,
}: KeysSettingsTabProps) {
  const [name, setName] = useState("");
  const [scope, setScope] =
    useState<McpTokenRecord["scope"]>("approval-required");
  const [newRawToken, setNewRawToken] = useState<string | null>(null);
  const [copiedId, setCopiedId] = useState<string | null>(null);
  const [activeClient, setActiveClient] = useState<
    "claudeCode" | "cursor" | "codex"
  >("claudeCode");
  const [domain, setDomain] = useState(setup.domain ?? "");
  const [acmeEmail, setAcmeEmail] = useState(setup.acmeEmail ?? "");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  const copyText = async (id: string, text: string) => {
    await navigator.clipboard.writeText(text);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  const handleCreateToken = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setBusy(true);
    try {
      const res = await api.createToken(name.trim(), scope);
      setNewRawToken(res.rawToken);
      setName("");
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

  const activeSnippet = snippets ? snippets[activeClient] : "";

  return (
    <div className="space-y-8">
      <div>
        <h2 className="text-xl font-semibold text-white">
          AI Keys &amp; Settings
        </h2>
        <p className="text-sm text-slate-400">
          Create visitor passes for Claude Code, Cursor, or Codex and copy their
          ready-to-paste setup snippets.
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
                onChange={(e) =>
                  setScope(e.target.value as McpTokenRecord["scope"])
                }
                className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-white"
              >
                <option value="approval-required">
                  Ask Me First (Recommended)
                </option>
                <option value="read-only">Look Only (Read-Only)</option>
                <option value="auto-approve">Trusted Auto-Pass</option>
              </select>
            </div>
          </div>

          <p className="text-xs text-slate-400">{SCOPE_LABELS[scope].desc}</p>

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
            <div className="flex gap-1.5">
              {(
                [
                  ["claudeCode", "Claude Code"],
                  ["cursor", "Cursor"],
                  ["codex", "Codex"],
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
                    <div className="flex items-center gap-2">
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

      {/* Dashboard Domain / Automatic HTTPS Settings */}
      <section className="rounded-2xl border border-slate-800 bg-slate-900/70 p-6 space-y-4">
        <div className="flex items-center gap-2">
          <Globe className="h-4 w-4 text-sky-400" />
          <h3 className="text-base font-semibold text-white">
            Dashboard Domain &amp; Automatic HTTPS
          </h3>
        </div>
        <form onSubmit={handleUpdateDomain} className="grid grid-cols-1 md:grid-cols-3 gap-3 items-end">
          <div>
            <label className="block text-xs font-medium text-slate-300 mb-1">
              Domain Name
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
            Save Domain
          </button>
        </form>
      </section>
    </div>
  );
}
