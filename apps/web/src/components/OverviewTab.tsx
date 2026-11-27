import { useId, useState } from "react";
import type { AppRecord, OverviewResponse } from "../api";
import {
  buildChartGeometry,
  clampPercent,
  type ResourceDisplayMode,
  type ResourceSample,
} from "../resource-display";
import { AppCard } from "./AppCard";
import { PageHeader, SectionHeading, buttonPrimary, buttonSecondary } from "./PageHeader";

interface OverviewTabProps {
  data: OverviewResponse | null;
  loading: boolean;
  resourceDisplay?: ResourceDisplayMode;
  resourceHistory?: ResourceSample[];
  onRefresh: () => void;
  onNavigateTab: (tab: "overview" | "apps" | "approvals" | "keys") => void;
  onOpenAccessSettings?: () => void;
  onOpenApp?: (slug: string) => void;
}

function formatUptime(seconds: number): string {
  const days = Math.floor(seconds / 86400);
  const hours = Math.floor((seconds % 86400) / 3600);
  const mins = Math.floor((seconds % 3600) / 60);
  if (days > 0) return `${days}d ${hours}h`;
  if (hours > 0) return `${hours}h ${mins}m`;
  return `${mins}m`;
}

function formatMb(mb: number): string {
  return mb >= 1024 ? `${(mb / 1024).toFixed(1)} GB` : `${Math.round(mb)} MB`;
}

function Stat({
  label,
  percent,
  detail,
  displayMode = "bar",
  series,
}: {
  label: string;
  percent: number;
  detail: string;
  displayMode?: ResourceDisplayMode;
  series?: number[];
}) {
  const gradientId = useId();
  const clamped = clampPercent(percent);
  const tight = clamped >= 75;
  const chartValues = series && series.length > 0 ? series : [clamped];
  const chart =
    displayMode === "chart"
      ? buildChartGeometry(chartValues, 280, 76, 6)
      : null;
  const lastPoint = chart?.points[chart.points.length - 1];

  return (
    <div className="rounded-lg border border-line bg-surface px-5 py-4">
      <div className="flex items-center justify-between gap-2">
        <p className="text-xs text-muted">{label}</p>
        {displayMode === "chart" && (
          <span className="text-[11px] text-subtle tabular-nums">
            {chartValues.length === 1
              ? "1 sample"
              : `${chartValues.length} samples`}
          </span>
        )}
      </div>
      <p className="mt-2 flex items-baseline gap-2">
        <span className="text-2xl font-semibold tabular-nums tracking-[-0.02em]">{clamped}%</span>
        <span className="text-xs text-subtle tabular-nums">{detail}</span>
      </p>
      {displayMode === "chart" && chart ? (
        <div className="mt-3">
          <svg
            viewBox="0 0 280 76"
            className="block h-20 w-full overflow-visible"
            role="img"
            aria-label={`${label} usage chart, currently ${clamped}%`}
          >
            <defs>
              <linearGradient id={gradientId} x1="0" y1="0" x2="0" y2="1">
                <stop
                  offset="0%"
                  stopColor="var(--color-fg)"
                  stopOpacity={tight ? 0.24 : 0.14}
                />
                <stop offset="100%" stopColor="var(--color-fg)" stopOpacity="0" />
              </linearGradient>
            </defs>
            <line
              x1="6"
              y1="6"
              x2="274"
              y2="6"
              stroke="var(--color-line)"
              strokeDasharray="2 3"
              strokeWidth="1"
            />
            <line
              x1="6"
              y1="38"
              x2="274"
              y2="38"
              stroke="var(--color-line)"
              strokeDasharray="2 3"
              strokeWidth="1"
            />
            <line
              x1="6"
              y1="70"
              x2="274"
              y2="70"
              stroke="var(--color-line)"
              strokeWidth="1"
            />
            <path d={chart.areaPath} fill={`url(#${gradientId})`} />
            <path
              d={chart.linePath}
              fill="none"
              stroke={tight ? "var(--color-fg)" : "var(--color-fg-2)"}
              strokeWidth="1.75"
              strokeLinecap="round"
              strokeLinejoin="round"
            />
            {lastPoint && (
              <circle
                cx={lastPoint.x}
                cy={lastPoint.y}
                r="3"
                fill={tight ? "var(--color-fg)" : "var(--color-fg-2)"}
              />
            )}
          </svg>
        </div>
      ) : (
        <div className="mt-3 h-1 w-full rounded-full bg-fill overflow-hidden">
          <div
            className={`h-full w-full rounded-full meter-fill ${tight ? "bg-fg" : "bg-muted"}`}
            style={{ transform: `scaleX(${clamped / 100})` }}
          />
        </div>
      )}
    </div>
  );
}

const ATTENTION_ORDER: Record<AppRecord["status"], number> = {
  error: 0,
  building: 1,
  provisioning: 1,
  stopped: 2,
  running: 3,
};

function CopyButton({ value }: { value: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <button
      type="button"
      onClick={() => {
        void navigator.clipboard?.writeText(value).then(() => {
          setCopied(true);
          window.setTimeout(() => setCopied(false), 1500);
        });
      }}
      className="btn-press shrink-0 rounded px-2 py-1 text-xs text-muted hover:text-fg hover:bg-surface-2 cursor-pointer"
    >
      {copied ? "Copied" : "Copy"}
    </button>
  );
}

function OverviewSkeleton() {
  return (
    <div aria-busy="true" aria-label="Loading server overview">
      <div className="mb-8 space-y-2">
        <div className="h-7 w-40 rounded skeleton-bar" />
        <div className="h-4 w-72 rounded skeleton-bar" />
      </div>
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
        {[0, 1, 2].map((i) => (
          <div key={i} className="h-[104px] rounded-lg skeleton-bar" />
        ))}
      </div>
    </div>
  );
}

export function OverviewTab({
  data,
  loading,
  resourceDisplay = "bar",
  resourceHistory = [],
  onRefresh,
  onNavigateTab,
  onOpenAccessSettings,
  onOpenApp,
}: OverviewTabProps) {
  if (!data) {
    if (loading) return <OverviewSkeleton />;
    return (
      <div className="rounded-lg border border-line bg-surface p-8 text-center space-y-3">
        <p className="text-sm font-medium">Couldn’t load the server overview.</p>
        <p className="text-xs text-muted">Check that VPSAgent is running, then try again.</p>
        <button type="button" onClick={onRefresh} className={buttonPrimary}>
          Try again
        </button>
      </div>
    );
  }

  const { metrics, disk, setup } = data;
  const running = data.apps.filter((a) => a.status === "running").length;
  const apps = [...data.apps].sort(
    (a, b) => (ATTENTION_ORDER[a.status] ?? 2) - (ATTENTION_ORDER[b.status] ?? 2),
  );
  const cpuPercent = Math.min(
    100,
    Math.round((metrics.loadAverage1m / Math.max(1, metrics.cpuCount)) * 100),
  );

  const domainLive = Boolean(setup.domain && setup.httpsActive && setup.tlsStatus === "active");
  const tailscaleLive = Boolean(setup.tailscaleDomain && setup.tailscaleServeEnabled);
  const endpoints = [
    domainLive && { label: "Public", url: `https://${setup.domain}/mcp` },
    tailscaleLive && { label: "Tailscale", url: `https://${setup.tailscaleDomain}/mcp` },
  ].filter(Boolean) as Array<{ label: string; url: string }>;

  return (
    <div>
      <PageHeader
        title="Overview"
        description={
          <>
            <span className="font-mono text-fg-2">{metrics.hostname}</span> · up{" "}
            {formatUptime(metrics.uptimeSeconds)} · {metrics.cpuCount} CPU
            {metrics.cpuCount === 1 ? "" : "s"} · {formatMb(metrics.memoryTotalMb)} memory
          </>
        }
        actions={
          <button type="button" onClick={onRefresh} disabled={loading} className={buttonSecondary}>
            {loading ? "Refreshing…" : "Refresh"}
          </button>
        }
      />

      <div className="space-y-10">
        {data.pendingApprovals > 0 && (
          <div className="flex flex-wrap items-center justify-between gap-4 rounded-lg border border-line-strong bg-surface px-5 py-4">
            <div>
              <p className="text-sm font-medium">
                {data.pendingApprovals}{" "}
                {data.pendingApprovals === 1 ? "request needs" : "requests need"} your approval
              </p>
              <p className="mt-0.5 text-xs text-muted">Nothing runs until you say yes.</p>
            </div>
            <button type="button" onClick={() => onNavigateTab("approvals")} className={buttonPrimary}>
              Review requests
            </button>
          </div>
        )}

        <section>
          <SectionHeading title="Resources" />
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
            <Stat
              label="CPU"
              percent={cpuPercent}
              detail={`load ${metrics.loadAverage1m.toFixed(2)}`}
              displayMode={resourceDisplay}
              series={
                resourceHistory.length > 0
                  ? resourceHistory.map((s) => s.cpu)
                  : [cpuPercent]
              }
            />
            <Stat
              label="Memory"
              percent={metrics.memoryUsagePercent}
              detail={`${formatMb(metrics.memoryUsedMb)} / ${formatMb(metrics.memoryTotalMb)}`}
              displayMode={resourceDisplay}
              series={
                resourceHistory.length > 0
                  ? resourceHistory.map((s) => s.memory)
                  : [metrics.memoryUsagePercent]
              }
            />
            <Stat
              label="Disk"
              percent={disk.usedPercent}
              detail={`${disk.usedGb} / ${disk.totalGb} GB`}
              displayMode={resourceDisplay}
              series={
                resourceHistory.length > 0
                  ? resourceHistory.map((s) => s.disk)
                  : [disk.usedPercent]
              }
            />
          </div>
        </section>

        <section>
          <SectionHeading
            title={`Apps · ${running}/${data.apps.length} running`}
            action={
              <button
                type="button"
                onClick={() => onNavigateTab("apps")}
                className="btn-press text-xs text-muted hover:text-fg cursor-pointer"
              >
                View all
              </button>
            }
          />
          {data.apps.length === 0 ? (
            <div className="rounded-lg border border-dashed border-line-strong px-6 py-10 text-center">
              <p className="text-sm font-medium">No apps yet</p>
              <p className="mt-1 text-xs text-muted">
                Deploy a GitHub repo or Docker image, or ask your AI agent to do it.
              </p>
              <button type="button" onClick={() => onNavigateTab("apps")} className={`${buttonPrimary} mt-4`}>
                Deploy an app
              </button>
            </div>
          ) : (
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
              {apps.slice(0, 6).map((app) => (
                <AppCard
                  key={app.slug}
                  app={app}
                  onOpen={() => (onOpenApp ? onOpenApp(app.slug) : onNavigateTab("apps"))}
                />
              ))}
            </div>
          )}
        </section>

        <section>
          <SectionHeading
            title="AI agent connection"
            action={
              <button
                type="button"
                onClick={() =>
                  onOpenAccessSettings
                    ? onOpenAccessSettings()
                    : onNavigateTab("keys")
                }
                className="btn-press text-xs text-muted hover:text-fg cursor-pointer"
              >
                Manage access
              </button>
            }
          />
          <div className="rounded-lg border border-line bg-surface divide-y divide-line">
            {endpoints.map((ep) => (
              <div key={ep.label} className="flex items-center justify-between gap-4 px-5 py-3.5">
                <div className="min-w-0">
                  <p className="text-xs text-muted">{ep.label} address</p>
                  <p className="mt-0.5 font-mono text-[13px] [overflow-wrap:anywhere]">{ep.url}</p>
                </div>
                <CopyButton value={ep.url} />
              </div>
            ))}
            {setup.domain && !domainLive && (
              <p className="px-5 py-3.5 text-xs text-fg-2">
                The HTTPS certificate for <span className="font-mono">{setup.domain}</span> is{" "}
                {setup.tlsStatus}
                {setup.tlsError ? ` (${setup.tlsError})` : ""}.
                {!tailscaleLive && " Until it’s ready, connect over SSH or turn on Tailscale."}
              </p>
            )}
            {endpoints.length === 0 && !setup.domain && (
              <p className="px-5 py-3.5 text-xs text-muted">
                No address yet. Add a domain or turn on Tailscale in Settings so Claude Code,
                Cursor or Codex can reach this server.
              </p>
            )}
            <div className="flex items-center justify-between px-5 py-3.5 text-xs">
              <span className="text-muted">Active access keys</span>
              <span className="text-sm tabular-nums">{data.activeMcpTokens}</span>
            </div>
          </div>
        </section>
      </div>
    </div>
  );
}
