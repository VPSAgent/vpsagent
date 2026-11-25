import { useState } from "react";
import { Check, Clock, Search, ShieldCheck, X } from "lucide-react";
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
        setNotice(`Approved and executed: ${res.summary}`);
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
    <div className="space-y-8 panel-enter">
      <div>
        <h1 className="text-2xl font-semibold tracking-[-0.025em] text-white">
          Approvals &amp; history
        </h1>
        <p className="mt-1 text-sm text-[#9CA3AF]">
          Review changes your AI asks to make before they run, and search every
          action taken on your server.
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

      {/* Pending Queue */}
      <section className="space-y-3">
        <div className="flex items-center justify-between">
          <h2 className="text-sm font-semibold text-white">
            Waiting for your approval
            <span className="ml-2 text-xs font-normal text-[#9CA3AF] tabular-nums">
              ({pending.length})
            </span>
          </h2>
        </div>

        {pending.length === 0 ? (
          <div className="surface-panel rounded-xl px-5 py-6 flex items-center gap-3 text-sm text-[#9CA3AF]">
            <ShieldCheck className="h-4.5 w-4.5 text-emerald-400 shrink-0" />
            <span>
              All caught up. No pending AI requests waiting for review.
            </span>
          </div>
        ) : (
          <div className="space-y-3">
            {pending.map((req) => (
              <div
                key={req.id}
                className="surface-panel rounded-xl border-l-4 border-l-amber-400 p-5 space-y-3.5"
              >
                <div className="flex flex-wrap items-start justify-between gap-4">
                  <div className="min-w-0 space-y-1">
                    <div className="flex flex-wrap items-center gap-2 text-xs">
                      <span className="font-mono font-medium text-amber-300">
                        {req.action}
                      </span>
                      <span className="text-[#6B7280]">&middot;</span>
                      <span className="text-[#9CA3AF]">
                        Requested by{" "}
                        <strong className="font-medium text-[#F4F5F7]">
                          {req.requestedBy}
                        </strong>
                      </span>
                      <span className="text-[#6B7280]">&middot;</span>
                      <span className="text-[#6B7280] tabular-nums">
                        {new Date(req.createdAt).toLocaleString()}
                      </span>
                    </div>
                    <p className="text-[15px] font-medium text-white">
                      {req.summary}
                    </p>
                  </div>

                  <div className="flex items-center gap-2 shrink-0">
                    <button
                      type="button"
                      disabled={busyId === req.id}
                      onClick={() => handleDecision(req.id, true)}
                      className="btn-press inline-flex items-center gap-1.5 rounded-lg bg-emerald-500 px-3.5 py-2 text-xs font-semibold text-[#042F1E] hover:bg-emerald-400 disabled:opacity-50 cursor-pointer"
                    >
                      <Check className="h-3.5 w-3.5" />
                      {busyId === req.id ? "Running..." : "Approve & run"}
                    </button>
                    <button
                      type="button"
                      disabled={busyId === req.id}
                      onClick={() => handleDecision(req.id, false)}
                      className="btn-press inline-flex items-center gap-1.5 rounded-lg border border-rose-500/35 bg-rose-500/[0.06] px-3.5 py-2 text-xs font-semibold text-rose-300 hover:bg-rose-500/15 disabled:opacity-50 cursor-pointer"
                    >
                      <X className="h-3.5 w-3.5" />
                      Reject
                    </button>
                  </div>
                </div>

                <pre className="surface-well rounded-lg p-3 text-xs font-mono text-[#9CA3AF] overflow-x-auto">
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
          <h2 className="text-sm font-semibold text-white">Recent decisions</h2>
          <div className="surface-panel rounded-xl divide-y divide-white/[0.06] overflow-hidden">
            {resolved.slice(0, 10).map((req) => (
              <div
                key={req.id}
                className="row-interactive flex flex-wrap items-center justify-between gap-3 px-5 py-3.5 text-sm"
              >
                <div className="min-w-0">
                  <p className="font-medium text-[#F4F5F7] truncate">
                    {req.summary}
                  </p>
                  {req.resultSummary && (
                    <p className="text-xs text-[#9CA3AF] mt-0.5">
                      {req.resultSummary}
                    </p>
                  )}
                </div>
                <span
                  className={`inline-flex items-center gap-1.5 text-xs font-medium capitalize shrink-0 ${
                    req.status === "executed"
                      ? "text-emerald-300"
                      : req.status === "rejected"
                        ? "text-[#9CA3AF]"
                        : "text-rose-300"
                  }`}
                >
                  <span
                    className={`h-1.5 w-1.5 rounded-full ${
                      req.status === "executed"
                        ? "bg-emerald-400"
                        : req.status === "rejected"
                          ? "bg-[#6B7280]"
                          : "bg-rose-400"
                    }`}
                  />
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
          <h2 className="text-sm font-semibold text-white">
            Full activity history
          </h2>
          <form onSubmit={handleSearch} className="flex items-center gap-2">
            <div className="relative">
              <Search className="h-3.5 w-3.5 text-[#6B7280] absolute left-3 top-1/2 -translate-y-1/2 pointer-events-none" />
              <input
                type="text"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder="Search history..."
                className="field-input rounded-lg pl-8 pr-3 py-1.5 text-xs w-52 sm:w-64"
              />
            </div>
            <button
              type="submit"
              className="btn-press rounded-lg border border-white/[0.1] bg-[#111317] px-3 py-1.5 text-xs font-medium text-[#F4F5F7] hover:bg-[#161920] cursor-pointer"
            >
              Search
            </button>
          </form>
        </div>

        <div className="surface-panel rounded-xl divide-y divide-white/[0.06] overflow-hidden">
          {events.length === 0 ? (
            <p className="p-5 text-sm text-[#9CA3AF]">No history events yet.</p>
          ) : (
            events.map((ev) => (
              <div
                key={ev.id}
                className="row-interactive flex flex-wrap items-center justify-between gap-3 px-5 py-3.5 text-xs"
              >
                <div className="space-y-0.5 min-w-0">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="font-mono text-[#9CA3AF]">{ev.actor}</span>
                    <span className="text-[#6B7280]">/</span>
                    <span className="font-mono font-medium text-[#F4F5F7]">
                      {ev.action}
                    </span>
                    {ev.targetSlug && (
                      <span className="font-mono text-[#6B7280]">
                        ({ev.targetSlug})
                      </span>
                    )}
                  </div>
                  <p className="text-[#9CA3AF]">{ev.summary}</p>
                </div>
                <span className="inline-flex items-center gap-1.5 text-[#6B7280] tabular-nums shrink-0">
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
