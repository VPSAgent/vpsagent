import {
  ArrowRight,
  Cpu,
  ExternalLink,
  HardDrive,
  KeyRound,
  MemoryStick,
  RefreshCw,
  ShieldAlert,
  ShieldCheck,
} from "lucide-react";
import type { OverviewResponse } from "../api";

interface OverviewTabProps {
  data: OverviewResponse | null;
  loading: boolean;
  onRefresh: () => void;
  onNavigateTab: (tab: "overview" | "apps" | "approvals" | "keys") => void;
}

function formatUptime(seconds: number): string {
  const days = Math.floor(seconds / 86400);
  const hours = Math.floor((seconds % 86400) / 3600);
  const mins = Math.floor((seconds % 3600) / 60);
  if (days > 0) return `${days}d ${hours}h`;
  if (hours > 0) return `${hours}h ${mins}m`;
  return `${mins}m`;
}

function MeterBar({ percent, tone }: { percent: number; tone: string }) {
  const clamped = Math.min(100, Math.max(0, percent));
  return (
    <div className="h-1.5 w-full rounded-full bg-white/[0.06] overflow-hidden mt-3.5">
      <div
        className={`h-full w-full rounded-full meter-fill ${tone}`}
        style={{ transform: `scaleX(${clamped / 100})` }}
      />
    </div>
  );
}

function OverviewSkeleton() {
  return (
    <div className="space-y-6" aria-busy="true" aria-label="Loading server overview">
      <div className="flex items-center justify-between gap-4">
        <div className="space-y-2">
          <div className="h-7 w-44 rounded-md skeleton-bar" />
          <div className="h-4 w-64 rounded-md skeleton-bar" />
        </div>
        <div className="h-9 w-24 rounded-lg skeleton-bar" />
      </div>
      <div className="surface-panel rounded-xl grid grid-cols-1 md:grid-cols-3 divide-y md:divide-y-0 md:divide-x divide-white/[0.08]">
        {[0, 1, 2].map((i) => (
          <div key={i} className="p-5 space-y-3">
            <div className="h-4 w-28 rounded skeleton-bar" />
            <div className="h-8 w-20 rounded skeleton-bar" />
            <div className="h-1.5 w-full rounded-full skeleton-bar" />
          </div>
        ))}
      </div>
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-5">
        <div className="lg:col-span-7 surface-panel rounded-xl p-5 space-y-3">
          <div className="h-5 w-32 rounded skeleton-bar" />
          <div className="h-14 w-full rounded-lg skeleton-bar" />
          <div className="h-14 w-full rounded-lg skeleton-bar" />
        </div>
        <div className="lg:col-span-5 surface-panel rounded-xl p-5 space-y-3">
          <div className="h-5 w-36 rounded skeleton-bar" />
          <div className="h-20 w-full rounded-lg skeleton-bar" />
        </div>
      </div>
    </div>
  );
}

function statusDotClass(status: string): string {
  if (status === "running") return "bg-emerald-400";
  if (status === "error") return "bg-rose-400";
  return "bg-amber-400";
}

function statusTextClass(status: string): string {
  if (status === "running") return "text-emerald-300";
  if (status === "error") return "text-rose-300";
  return "text-amber-300";
}

export function OverviewTab({
  data,
  loading,
  onRefresh,
  onNavigateTab,
}: OverviewTabProps) {
  if (!data) {
    if (loading) {
      return <OverviewSkeleton />;
    }
    return (
      <div className="surface-panel rounded-xl p-8 text-center space-y-3">
        <p className="text-sm font-medium text-[#F4F5F7]">
          Could not load server overview
        </p>
        <p className="text-xs text-[#9CA3AF]">
          Check that your VPSAgent service is reachable and try again.
        </p>
        <button
          type="button"
          onClick={onRefresh}
          className="btn-press inline-flex items-center gap-1.5 rounded-lg bg-emerald-500 px-3.5 py-2 text-xs font-semibold text-[#042F1E] hover:bg-emerald-400 cursor-pointer"
        >
          <RefreshCw className="h-3.5 w-3.5" />
          Retry
        </button>
      </div>
    );
  }

  const runningApps = data.apps.filter((a) => a.status === "running");
  const cpuLoadPercent = Math.min(
    100,
    Math.round(
      (data.metrics.loadAverage1m / Math.max(1, data.metrics.cpuCount)) * 100,
    ),
  );

  return (
    <div className="space-y-6 panel-enter">
      {/* Page Header & Command Strip */}
      <div className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <h1 className="text-2xl font-semibold tracking-[-0.025em] text-white">
            Server overview
          </h1>
          <p className="mt-1 text-sm text-[#9CA3AF] tabular-nums">
            <span className="font-mono text-[#F4F5F7]">
              {data.metrics.hostname}
            </span>
            <span className="mx-2 text-[#6B7280]">/</span>
            Up {formatUptime(data.metrics.uptimeSeconds)}
            <span className="mx-2 text-[#6B7280]">/</span>
            <span className="text-emerald-400">Zero-Root Wall active</span>
          </p>
        </div>

        <button
          type="button"
          onClick={onRefresh}
          disabled={loading}
          className="btn-press inline-flex items-center gap-2 rounded-lg border border-white/[0.1] bg-[#111317] px-3.5 py-2 text-[13px] font-medium text-[#F4F5F7] hover:bg-[#161920] hover:border-white/[0.16] disabled:opacity-50 cursor-pointer"
        >
          <RefreshCw
            className={`h-3.5 w-3.5 text-[#9CA3AF] ${loading ? "animate-spin" : ""}`}
          />
          Refresh
        </button>
      </div>

      {/* Priority 1: Pending AI Approvals Banner (wins visual hierarchy when present) */}
      {data.pendingApprovals > 0 && (
        <div className="flex flex-wrap items-center justify-between gap-4 rounded-xl border border-amber-500/35 bg-amber-500/[0.08] px-5 py-4 border-l-4 border-l-amber-400">
          <div className="flex items-start gap-3">
            <ShieldAlert className="h-5 w-5 text-amber-400 shrink-0 mt-0.5" />
            <div>
              <p className="text-sm font-semibold text-amber-100">
                {data.pendingApprovals} AI request
                {data.pendingApprovals === 1 ? "" : "s"} waiting for your
                approval
              </p>
              <p className="text-xs text-amber-200/75 mt-0.5">
                Nothing runs on your server until you review and click Approve.
              </p>
            </div>
          </div>
          <button
            type="button"
            onClick={() => onNavigateTab("approvals")}
            className="btn-press inline-flex items-center gap-1.5 rounded-lg bg-amber-400 px-3.5 py-2 text-xs font-semibold text-[#1A1200] hover:bg-amber-300 cursor-pointer"
          >
            Review queue
            <ArrowRight className="h-3.5 w-3.5" />
          </button>
        </div>
      )}

      {/* Unified Telemetry Strip */}
      <section
        aria-label="Server resources"
        className="surface-panel rounded-xl grid grid-cols-1 md:grid-cols-3 divide-y md:divide-y-0 md:divide-x divide-white/[0.08]"
      >
        <div className="p-5">
          <div className="flex items-center justify-between text-[13px] text-[#9CA3AF]">
            <span>Processor (CPU)</span>
            <Cpu className="h-4 w-4 text-emerald-400/80" />
          </div>
          <div className="mt-2.5 flex items-baseline justify-between gap-2 tabular-nums">
            <span className="text-[28px] leading-none font-semibold tracking-[-0.03em] text-white">
              {cpuLoadPercent}%
            </span>
            <span className="text-xs text-[#9CA3AF]">
              {data.metrics.cpuCount} core
              {data.metrics.cpuCount === 1 ? "" : "s"} &middot; load{" "}
              {data.metrics.loadAverage1m}
            </span>
          </div>
          <MeterBar
            percent={cpuLoadPercent}
            tone={cpuLoadPercent > 85 ? "bg-rose-400" : "bg-emerald-400"}
          />
        </div>

        <div className="p-5">
          <div className="flex items-center justify-between text-[13px] text-[#9CA3AF]">
            <span>Memory (RAM)</span>
            <MemoryStick className="h-4 w-4 text-sky-400/80" />
          </div>
          <div className="mt-2.5 flex items-baseline justify-between gap-2 tabular-nums">
            <span className="text-[28px] leading-none font-semibold tracking-[-0.03em] text-white">
              {data.metrics.memoryUsagePercent}%
            </span>
            <span className="text-xs text-[#9CA3AF]">
              {Math.round(data.metrics.memoryUsedMb)} /{" "}
              {Math.round(data.metrics.memoryTotalMb)} MB
            </span>
          </div>
          <MeterBar
            percent={data.metrics.memoryUsagePercent}
            tone={
              data.metrics.memoryUsagePercent > 85 ? "bg-amber-400" : "bg-sky-400"
            }
          />
        </div>

        <div className="p-5">
          <div className="flex items-center justify-between text-[13px] text-[#9CA3AF]">
            <span>Storage (Disk)</span>
            <HardDrive className="h-4 w-4 text-indigo-400/80" />
          </div>
          <div className="mt-2.5 flex items-baseline justify-between gap-2 tabular-nums">
            <span className="text-[28px] leading-none font-semibold tracking-[-0.03em] text-white">
              {data.disk.usedPercent}%
            </span>
            <span className="text-xs text-[#9CA3AF]">
              {data.disk.usedGb} / {data.disk.totalGb} GB
            </span>
          </div>
          <MeterBar
            percent={data.disk.usedPercent}
            tone={data.disk.usedPercent > 85 ? "bg-rose-400" : "bg-indigo-400"}
          />
        </div>
      </section>

      {/* Asymmetric 7/5 Operational Workspace */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-5 items-start">
        {/* Apps Ledger (Primary Focus) */}
        <section className="lg:col-span-7 surface-panel rounded-xl overflow-hidden">
          <div className="flex items-center justify-between px-5 py-4 border-b border-white/[0.08]">
            <div>
              <h2 className="text-sm font-semibold text-white">
                Isolated apps
              </h2>
              <p className="text-xs text-[#9CA3AF] tabular-nums mt-0.5">
                {runningApps.length} of {data.apps.length} running in locked
                apartments
              </p>
            </div>
            <button
              type="button"
              onClick={() => onNavigateTab("apps")}
              className="btn-press inline-flex items-center gap-1 text-xs font-medium text-emerald-400 hover:text-emerald-300 cursor-pointer"
            >
              Manage apps
              <ArrowRight className="h-3.5 w-3.5" />
            </button>
          </div>

          {data.apps.length === 0 ? (
            <div className="p-7 text-center space-y-3">
              <p className="text-sm font-medium text-[#F4F5F7]">
                No apps deployed yet
              </p>
              <p className="text-xs text-[#9CA3AF] max-w-sm mx-auto">
                Deploy a public or private GitHub repository or Docker image in
                an isolated container, or let your connected AI agent launch one
                for you.
              </p>
              <button
                type="button"
                onClick={() => onNavigateTab("apps")}
                className="btn-press inline-flex items-center gap-1.5 rounded-lg bg-emerald-500 px-3.5 py-2 text-xs font-semibold text-[#042F1E] hover:bg-emerald-400 cursor-pointer"
              >
                Launch your first app
              </button>
            </div>
          ) : (
            <ul className="divide-y divide-white/[0.06]">
              {data.apps.slice(0, 6).map((app) => (
                <li
                  key={app.slug}
                  className="row-interactive flex items-center justify-between gap-4 px-5 py-3.5"
                >
                  <div className="min-w-0">
                    <div className="flex items-center gap-2">
                      <span className="text-sm font-medium text-white truncate">
                        {app.name}
                      </span>
                      {app.detectedRuntime && (
                        <span className="text-xs font-mono text-[#6B7280] shrink-0">
                          {app.detectedRuntime}
                        </span>
                      )}
                    </div>
                    <div className="mt-0.5 flex items-center gap-2 text-xs text-[#9CA3AF] truncate">
                      {app.domain ? (
                        <a
                          href={`https://${app.domain}`}
                          target="_blank"
                          rel="noreferrer"
                          className="inline-flex items-center gap-1 text-[#9CA3AF] hover:text-emerald-300 truncate"
                        >
                          <span className="truncate">{app.domain}</span>
                          <ExternalLink className="h-3 w-3 shrink-0" />
                        </a>
                      ) : (
                        <span className="font-mono text-[#6B7280]">
                          Private ({app.slug})
                        </span>
                      )}
                    </div>
                  </div>

                  <span
                    className={`inline-flex items-center gap-1.5 text-xs font-medium shrink-0 capitalize ${statusTextClass(app.status)}`}
                  >
                    <span
                      className={`h-1.5 w-1.5 rounded-full ${statusDotClass(app.status)}`}
                    />
                    {app.status}
                  </span>
                </li>
              ))}
            </ul>
          )}
        </section>

        {/* AI Doorway & Security Posture */}
        <section className="lg:col-span-5 surface-panel rounded-xl overflow-hidden">
          <div className="flex items-center justify-between px-5 py-4 border-b border-white/[0.08]">
            <div className="flex items-center gap-2">
              <KeyRound className="h-4 w-4 text-sky-400" />
              <h2 className="text-sm font-semibold text-white">
                AI doorway status
              </h2>
            </div>
            <button
              type="button"
              onClick={() => onNavigateTab("keys")}
              className="btn-press inline-flex items-center gap-1 text-xs font-medium text-emerald-400 hover:text-emerald-300 cursor-pointer"
            >
              Keys &amp; setup
              <ArrowRight className="h-3.5 w-3.5" />
            </button>
          </div>

          <div className="p-5 space-y-4">
            <div className="flex items-baseline justify-between">
              <span className="text-xs text-[#9CA3AF]">
                Active visitor passes
              </span>
              <span className="text-xl font-semibold text-white tabular-nums">
                {data.activeMcpTokens}
              </span>
            </div>

            <div className="surface-well rounded-lg p-3.5 text-xs leading-relaxed text-[#9CA3AF]">
              {data.setup.domain &&
              data.setup.httpsActive &&
              data.setup.tlsStatus === "active" ? (
                <div className="space-y-1">
                  <span className="text-emerald-400 font-medium">
                    Verified automatic HTTPS
                  </span>
                  <p className="font-mono text-[#F4F5F7] break-all">
                    https://{data.setup.domain}/mcp
                  </p>
                </div>
              ) : data.setup.domain ? (
                <span className="text-amber-300">
                  HTTPS certificate for{" "}
                  <code className="text-amber-200">{data.setup.domain}</code> is{" "}
                  <strong className="font-semibold">
                    {data.setup.tlsStatus}
                  </strong>
                  {data.setup.tlsError ? ` (${data.setup.tlsError})` : ""}. Keep
                  using your local SSH tunnel until DNS and HTTPS verify.
                </span>
              ) : (
                "Connect a domain in AI Keys & Settings to enable remote HTTPS access for Claude Code, Cursor, T3 Code, or Codex."
              )}
            </div>

            <div className="flex items-start gap-2.5 pt-2 border-t border-white/[0.06] text-xs text-[#9CA3AF]">
              <ShieldCheck className="h-4 w-4 text-emerald-400 shrink-0 mt-0.5" />
              <span>
                Zero-Root Safety Wall active. Apps run isolated and never touch
                your server&apos;s Docker socket.
              </span>
            </div>
          </div>
        </section>
      </div>
    </div>
  );
}
