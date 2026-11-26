import type { AppRecord } from "../api";

const STATUS: Record<AppRecord["status"], { label: string; className: string }> = {
  running: { label: "Running", className: "text-ok" },
  building: { label: "Building", className: "text-warn" },
  provisioning: { label: "Starting", className: "text-warn" },
  stopped: { label: "Stopped", className: "text-subtle" },
  // greyscale UI: failures are inverted so they can't be missed
  error: { label: "Error", className: "rounded-sm bg-fg px-1.5 font-medium text-canvas" },
};

const DOT: Record<AppRecord["status"], string> = {
  running: "bg-ok",
  building: "bg-warn",
  provisioning: "bg-warn",
  stopped: "bg-subtle",
  error: "bg-fg",
};

export function AppStatus({ status }: { status: AppRecord["status"] }) {
  const s = STATUS[status] ?? STATUS.stopped;
  return (
    <span className={`inline-flex items-center gap-1.5 text-xs ${s.className}`}>
      {status !== "error" && <span className={`h-1.5 w-1.5 rounded-full ${DOT[status] ?? "bg-subtle"}`} />}
      {s.label}
    </span>
  );
}

/** A clickable app tile: name, status, address. Opens the app's page. */
export function AppCard({ app, onOpen }: { app: AppRecord; onOpen: () => void }) {
  const failing = app.status === "error";
  return (
    <button
      type="button"
      onClick={onOpen}
      className={`group w-full text-left rounded-lg border bg-surface px-4 py-3.5 transition-colors hover:bg-surface-2 cursor-pointer ${
        failing ? "border-bad-line" : "border-line hover:border-line-strong"
      }`}
    >
      <div className="flex items-start justify-between gap-3">
        <span className="min-w-0 truncate text-sm font-medium">{app.name}</span>
        <AppStatus status={app.status} />
      </div>
      <p className="mt-1 truncate text-xs text-muted">
        {app.domain ?? <span className="text-subtle">No public address</span>}
      </p>
      <p className="mt-3 flex gap-3 text-[11px] text-subtle">
        {app.detectedRuntime && <span>{app.detectedRuntime}</span>}
        <span>{app.sourceType === "git" ? "GitHub" : "Docker image"}</span>
        {app.companions.length > 0 && (
          <span>+ {app.companions.map((c) => c.type).join(", ")}</span>
        )}
      </p>
    </button>
  );
}
