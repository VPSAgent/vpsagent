import { useState } from "react";
import { Check, Clock, Search, X } from "lucide-react";
import { api, type ApprovalRequest, type AuditEvent } from "../api";

interface ApprovalsTabProps {
  approvals: ApprovalRequest[];
  events: AuditEvent[];
  onRefresh: (query?: string) => Promise<void>;
  onWatchDeployment?: (slug: string, deploymentId: string) => void;
}

export function ApprovalsTab({
  approvals,
  events,
  onRefresh,
  onWatchDeployment,
}: ApprovalsTabProps) {
  const [busyId, setBusyId] = useState<string | null>(null);
  const [searchQuery, setSearchQuery] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  const pending = approvals.filter((a) => a.status === "pending");
  const resolved = approvals.filter((a) => a.status !== "pending");

  const handleDecision = async (id: string, approve: boolean) => {
    setBusyId(id);
    setError(null);
    setNotice(null);
    try {
      if (approve) {
        const res = await api.approveRequest(id, undefined, true);
        if (res.deployment && onWatchDeployment) {
          onWatchDeployment(res.deployment.slug, res.deployment.id);
          return;
        }
        setNotice(`Approved & executed: ${res.summary}`);
      } else {
        await api.rejectRequest(id);
        setNotice("Request rejected.");
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : "Action failed.");
    } finally {
      await onRefresh(searchQuery);
      setBusyId(null);
    }
  };

  const handleSearch = async (e: React.FormEvent) => {
    e.preventDefault();
    await onRefresh(searchQuery);
  };

  return (
    <div className="space-y-8">
      <div>
        <h2 className="text-xl font-semibold text-white">
          Approvals &amp; History
        </h2>
        <p className="text-sm text-slate-400">
          Review changes your AI asks to make before they run, and search every
          action taken on your server.
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

      {/* Pending Queue */}
      <section className="space-y-3">
        <h3 className="text-sm font-semibold uppercase tracking-wider text-amber-300">
          Waiting for Your Approval ({pending.length})
        </h3>
        {pending.length === 0 ? (
          <div className="rounded-2xl border border-slate-800 bg-slate-900/50 p-6 text-sm text-slate-400">
            No pending AI requests right now.
          </div>
        ) : (
          <div className="space-y-3">
            {pending.map((req) => (
              <div
                key={req.id}
                className="rounded-2xl border border-amber-500/30 bg-slate-900/90 p-5 space-y-3"
              >
                <div className="flex flex-wrap items-start justify-between gap-3">
                  <div>
                    <div className="flex items-center gap-2">
                      <span className="rounded-md bg-amber-500/15 px-2 py-0.5 text-xs font-semibold text-amber-300">
                        {req.action}
                      </span>
                      <span className="text-xs text-slate-400">
                        Requested by <strong className="text-slate-200">{req.requestedBy}</strong>
                      </span>
                    </div>
                    <p className="text-base font-medium text-white mt-1.5">
                      {req.summary}
                    </p>
                  </div>
                  <div className="flex items-center gap-2">
                    <button
                      type="button"
                      disabled={busyId === req.id}
                      onClick={() => handleDecision(req.id, true)}
                      className="inline-flex items-center gap-1.5 rounded-lg bg-emerald-500 px-3.5 py-2 text-xs font-semibold text-slate-950 hover:bg-emerald-400 disabled:opacity-50 cursor-pointer"
                    >
                      <Check className="h-4 w-4" />
                      {busyId === req.id ? "Running..." : "Approve & Run"}
                    </button>
                    <button
                      type="button"
                      disabled={busyId === req.id}
                      onClick={() => handleDecision(req.id, false)}
                      className="inline-flex items-center gap-1.5 rounded-lg border border-rose-500/40 px-3.5 py-2 text-xs font-semibold text-rose-300 hover:bg-rose-500/10 disabled:opacity-50 cursor-pointer"
                    >
                      <X className="h-4 w-4" />
                      Reject
                    </button>
                  </div>
                </div>
                <pre className="rounded-xl border border-slate-800 bg-slate-950 p-3 text-xs font-mono text-slate-400 overflow-x-auto">
                  {JSON.stringify(req.payload, null, 2)}
                </pre>
              </div>
            ))}
          </div>
        )}
      </section>

      {/* Past Decisions */}
      {resolved.length > 0 && (
        <section className="space-y-3">
          <h3 className="text-sm font-semibold uppercase tracking-wider text-slate-400">
            Recent Decisions
          </h3>
          <div className="divide-y divide-slate-800/80 rounded-2xl border border-slate-800 bg-slate-900/60">
            {resolved.slice(0, 10).map((req) => (
              <div
                key={req.id}
                className="flex flex-wrap items-center justify-between gap-2 px-4 py-3 text-sm"
              >
                <div>
                  <span className="font-medium text-slate-200">{req.summary}</span>
                  {req.resultSummary && (
                    <p className="text-xs text-slate-400 mt-0.5">
                      {req.resultSummary}
                    </p>
                  )}
                </div>
                <span
                  className={`rounded-full px-2.5 py-0.5 text-xs font-medium ${
                    req.status === "executed"
                      ? "bg-emerald-500/15 text-emerald-300"
                      : req.status === "rejected"
                        ? "bg-slate-700 text-slate-300"
                        : "bg-rose-500/15 text-rose-300"
                  }`}
                >
                  {req.status}
                </span>
              </div>
            ))}
          </div>
        </section>
      )}

      {/* Searchable Activity History */}
      <section className="space-y-3">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <h3 className="text-sm font-semibold uppercase tracking-wider text-slate-400">
            Full Activity History
          </h3>
          <form onSubmit={handleSearch} className="flex gap-2">
            <div className="relative">
              <Search className="h-3.5 w-3.5 text-slate-500 absolute left-3 top-1/2 -translate-y-1/2" />
              <input
                type="text"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder="Search history..."
                className="rounded-lg border border-slate-700 bg-slate-900 pl-8 pr-3 py-1.5 text-xs text-white"
              />
            </div>
            <button
              type="submit"
              className="rounded-lg border border-slate-700 px-3 py-1.5 text-xs font-medium text-slate-200 hover:bg-slate-800 cursor-pointer"
            >
              Search
            </button>
          </form>
        </div>

        <div className="divide-y divide-slate-800/80 rounded-2xl border border-slate-800 bg-slate-900/60">
          {events.length === 0 ? (
            <p className="p-5 text-sm text-slate-400">No history events yet.</p>
          ) : (
            events.map((ev) => (
              <div
                key={ev.id}
                className="flex flex-wrap items-center justify-between gap-3 px-4 py-3 text-xs"
              >
                <div className="space-y-0.5">
                  <div className="flex items-center gap-2">
                    <span className="rounded bg-slate-800 px-2 py-0.5 font-mono text-slate-300">
                      {ev.actor}
                    </span>
                    <span className="font-semibold text-slate-200">
                      {ev.action}
                    </span>
                    {ev.targetSlug && (
                      <span className="text-slate-400">({ev.targetSlug})</span>
                    )}
                  </div>
                  <p className="text-slate-300">{ev.summary}</p>
                </div>
                <span className="inline-flex items-center gap-1 text-slate-500">
                  <Clock className="h-3 w-3" />
                  {new Date(ev.createdAt).toLocaleString()}
                </span>
              </div>
            ))
          )}
        </div>
      </section>
    </div>
  );
}
