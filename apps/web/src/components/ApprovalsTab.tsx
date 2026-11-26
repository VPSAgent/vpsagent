import { useState } from "react";
import { api, type ApprovalRequest, type AuditEvent } from "../api";
import { formatFullTime, formatRelativeTime } from "../format";
import { PageHeader } from "./PageHeader";

type Risk = ApprovalRequest["riskLevel"];

const RISK: Record<Risk, { text: string; dot: string; label: string }> = {
  high: { text: "text-bad", dot: "bg-bad", label: "High risk" },
  medium: { text: "text-warn", dot: "bg-warn", label: "Medium risk" },
  low: { text: "text-muted", dot: "bg-subtle", label: "Low risk" },
};
const RISK_ORDER: Record<Risk, number> = { high: 0, medium: 1, low: 2 };
const risk = (level: Risk) => RISK[level] ?? RISK.medium;

const STATUS_TEXT: Record<ApprovalRequest["status"], string> = {
  pending: "text-warn",
  approved: "text-muted",
  executed: "text-ok",
  rejected: "text-subtle",
  failed: "text-bad",
};

/** "deploy_app" -> "Deploy app" */
function humanize(action: string): string {
  const words = action.replace(/[_-]+/g, " ").trim();
  return words.charAt(0).toUpperCase() + words.slice(1);
}

function formatValue(value: unknown): string {
  if (value === null || value === undefined) return "—";
  if (typeof value === "string") return value;
  if (typeof value === "number" || typeof value === "boolean") return String(value);
  return JSON.stringify(value);
}

/** The exact request, as a readable list instead of raw JSON. */
function RequestDetails({ payload }: { payload: Record<string, unknown> }) {
  const entries = Object.entries(payload ?? {});
  if (entries.length === 0) return null;
  return (
    <dl className="grid grid-cols-[max-content_1fr] gap-x-6 gap-y-1.5 rounded-md bg-well border border-line px-4 py-3 text-xs">
      {entries.map(([key, value]) => (
        <div key={key} className="contents">
          <dt className="font-mono text-subtle">{key}</dt>
          <dd className="font-mono text-fg-2 break-all">{formatValue(value)}</dd>
        </div>
      ))}
    </dl>
  );
}

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

  const pending = approvals
    .filter((a) => a.status === "pending")
    .sort((a, b) => (RISK_ORDER[a.riskLevel] ?? 1) - (RISK_ORDER[b.riskLevel] ?? 1));
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
        setNotice(`Approved and done: ${res.summary}`);
      } else {
        await api.rejectRequest(id);
        setNotice("Request rejected.");
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : "That didn’t work.");
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
    <div className="space-y-10">
      <PageHeader
        title="Approvals"
        description="Changes your AI wants to make wait here until you decide."
      />

      {error && (
        <div className="rounded-md border border-bad-line bg-bad-soft px-4 py-3 text-sm text-bad">
          {error}
        </div>
      )}
      {notice && (
        <div className="rounded-md border border-line bg-surface px-4 py-3 text-sm text-fg-2">
          {notice}
        </div>
      )}

      <section className="space-y-3">
        <h2 className="text-[15px] font-semibold">
          Waiting for you{" "}
          <span className="text-muted font-normal tabular-nums">{pending.length}</span>
        </h2>

        {pending.length === 0 ? (
          <p className="surface-panel rounded-lg px-5 py-5 text-sm text-muted">
            Nothing waiting. New requests from your AI will show up here.
          </p>
        ) : (
          <div className="space-y-3">
            {pending.map((req) => {
              const r = risk(req.riskLevel);
              const busy = busyId === req.id;
              return (
                <article key={req.id} className="surface-panel rounded-lg p-5 space-y-4">
                  <div className="flex flex-wrap items-start justify-between gap-4">
                    <div className="min-w-0 space-y-1.5">
                      <p className="text-[15px] font-medium leading-snug">{req.summary}</p>
                      <p className="flex flex-wrap items-center gap-x-2 gap-y-1 text-xs text-muted">
                        <span className={`inline-flex items-center gap-1.5 font-medium ${r.text}`}>
                          <span className={`h-1.5 w-1.5 rounded-full ${r.dot}`} />
                          {r.label}
                        </span>
                        <span className="text-faint">·</span>
                        <span>{humanize(req.action)}</span>
                        <span className="text-faint">·</span>
                        <span>
                          from <span className="text-fg-2">{req.requestedBy}</span>
                        </span>
                        <span className="text-faint">·</span>
                        <span title={formatFullTime(req.createdAt)}>
                          {formatRelativeTime(req.createdAt)}
                        </span>
                      </p>
                    </div>

                    <div className="flex items-center gap-2 shrink-0">
                      <button
                        type="button"
                        disabled={busy}
                        onClick={() => handleDecision(req.id, false)}
                        className="btn-press rounded-md border border-line-strong px-3.5 py-1.5 text-xs text-fg-2 hover:bg-fill disabled:opacity-50 cursor-pointer"
                      >
                        Reject
                      </button>
                      <button
                        type="button"
                        disabled={busy}
                        onClick={() => handleDecision(req.id, true)}
                        className="btn-press rounded-md bg-primary px-3.5 py-1.5 text-xs font-medium text-on-primary hover:bg-primary-hover disabled:opacity-50 cursor-pointer"
                      >
                        {busy ? "Running…" : "Approve"}
                      </button>
                    </div>
                  </div>

                  <RequestDetails payload={req.payload} />
                </article>
              );
            })}
          </div>
        )}
      </section>

      {resolved.length > 0 && (
        <section className="space-y-3">
          <h2 className="text-[15px] font-semibold">Recently decided</h2>
          <ul className="surface-panel rounded-lg divide-y divide-line overflow-hidden">
            {resolved.slice(0, 10).map((req) => (
              <li
                key={req.id}
                className="flex flex-wrap items-baseline justify-between gap-x-4 gap-y-1 px-5 py-3 text-sm"
              >
                <div className="min-w-0">
                  <p className="truncate">{req.summary}</p>
                  {req.resultSummary && (
                    <p className="text-xs text-muted mt-0.5">{req.resultSummary}</p>
                  )}
                </div>
                <p className="text-xs shrink-0 tabular-nums">
                  <span className={`capitalize ${STATUS_TEXT[req.status] ?? "text-muted"}`}>
                    {req.status}
                  </span>
                  <span
                    className="text-subtle"
                    title={formatFullTime(req.decidedAt ?? req.createdAt)}
                  >
                    {" "}
                    · {formatRelativeTime(req.decidedAt ?? req.createdAt)}
                  </span>
                </p>
              </li>
            ))}
          </ul>
        </section>
      )}

      <section className="space-y-3">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <h2 className="text-[15px] font-semibold">Activity</h2>
          <form onSubmit={handleSearch} className="flex items-center gap-2">
            <input
              type="search"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Search activity"
              aria-label="Search activity"
              className="field-input rounded-md px-3 py-1.5 text-xs w-48 sm:w-64"
            />
            <button
              type="submit"
              className="btn-press rounded-md border border-line-strong px-3 py-1.5 text-xs text-fg-2 hover:bg-fill cursor-pointer"
            >
              Search
            </button>
          </form>
        </div>

        {events.length === 0 ? (
          <p className="surface-panel rounded-lg px-5 py-5 text-sm text-muted">
            No activity yet.
          </p>
        ) : (
          <ol className="surface-panel rounded-lg divide-y divide-line overflow-hidden">
            {events.map((ev) => {
              const r = risk(ev.riskLevel);
              return (
                <li
                  key={ev.id}
                  className="grid grid-cols-[auto_1fr_auto] items-baseline gap-x-4 px-5 py-3 text-xs"
                >
                  <span
                    title={formatFullTime(ev.createdAt)}
                    className="w-20 text-subtle tabular-nums"
                  >
                    {formatRelativeTime(ev.createdAt)}
                  </span>
                  <div className="min-w-0">
                    <p className="text-sm text-fg-2">{ev.summary}</p>
                    <p className="mt-0.5 text-subtle">
                      <span className="capitalize">{ev.actor === "agent" ? "AI agent" : ev.actor}</span>
                      {" · "}
                      {humanize(ev.action)}
                      {ev.targetSlug && (
                        <>
                          {" · "}
                          <span className="font-mono">{ev.targetSlug}</span>
                        </>
                      )}
                    </p>
                  </div>
                  {ev.riskLevel !== "low" ? (
                    <span className={`${r.text} whitespace-nowrap`}>{r.label}</span>
                  ) : (
                    <span />
                  )}
                </li>
              );
            })}
          </ol>
        )}
      </section>
    </div>
  );
}
