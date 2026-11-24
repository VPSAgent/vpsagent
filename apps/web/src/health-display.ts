import type { AppRecord, InspectResult } from "./api";

export interface HealthBadge {
  label: string;
  tone: "healthy" | "unhealthy" | "warning" | "neutral";
}

export interface FormattedSafetyCheckHealth {
  dockerLiveness: HealthBadge;
  monitoredHttp: HealthBadge;
  liveHttpProbe: HealthBadge;
}

/**
 * Updates the Apps list immediately from the same inspection response shown in
 * the Safety Check drawer, so the app card and drawer never disagree while the
 * dashboard is already open.
 */
export function applyInspectStatusToApps(
  apps: AppRecord[],
  inspect: InspectResult,
): AppRecord[] {
  let changed = false;
  const next = apps.map((app) => {
    if (app.slug !== inspect.slug || app.status === inspect.status) {
      return app;
    }
    changed = true;
    return { ...app, status: inspect.status };
  });
  return changed ? next : apps;
}

/**
 * Formats Docker liveness, recurring monitored HTTP health (3-failure threshold),
 * and the fresh live HTTP probe as three distinct fields so users can see exactly
 * which check passed or failed without conflating monitored state with a live probe.
 */
export function formatSafetyCheckHealth(
  inspect: InspectResult,
): FormattedSafetyCheckHealth {
  const rawDocker = inspect.containers[0]?.healthStatus ?? "none";
  const dockerLiveness: HealthBadge = {
    label: rawDocker,
    tone:
      rawDocker === "healthy"
        ? "healthy"
        : rawDocker === "unhealthy"
          ? "unhealthy"
          : rawDocker === "starting"
            ? "warning"
            : "neutral",
  };

  let monitoredHttp: HealthBadge;
  if (inspect.hostHttpHealth) {
    const { status, consecutiveFailures } = inspect.hostHttpHealth;
    if (status === "unhealthy") {
      monitoredHttp = {
        label: `unhealthy (${consecutiveFailures} consecutive failure${consecutiveFailures === 1 ? "" : "s"})`,
        tone: "unhealthy",
      };
    } else if (status === "healthy" && consecutiveFailures > 0) {
      monitoredHttp = {
        label: `healthy (${consecutiveFailures} recent failure${consecutiveFailures === 1 ? "" : "s"} — threshold 3)`,
        tone: "warning",
      };
    } else if (status === "healthy") {
      monitoredHttp = { label: "healthy", tone: "healthy" };
    } else if (status === "starting" && consecutiveFailures === 0) {
      monitoredHttp = { label: "waiting for first check", tone: "neutral" };
    } else {
      monitoredHttp = {
        label:
          consecutiveFailures > 0
            ? `${status} (${consecutiveFailures} failure${consecutiveFailures === 1 ? "" : "s"})`
            : status,
        tone: status === "starting" ? "warning" : "neutral",
      };
    }
  } else {
    monitoredHttp = { label: "not monitored", tone: "neutral" };
  }

  let liveHttpProbe: HealthBadge;
  if (inspect.httpProbe?.attempted) {
    if (inspect.httpProbe.ok) {
      liveHttpProbe = {
        label:
          inspect.httpProbe.statusCode !== null
            ? `HTTP ${inspect.httpProbe.statusCode} (ok)`
            : "ok",
        tone: "healthy",
      };
    } else if (inspect.httpProbe.statusCode !== null) {
      liveHttpProbe = {
        label: `HTTP ${inspect.httpProbe.statusCode} (failed)`,
        tone: "unhealthy",
      };
    } else {
      liveHttpProbe = {
        label: inspect.httpProbe.error ?? "failed",
        tone: "unhealthy",
      };
    }
  } else {
    liveHttpProbe = { label: "not run", tone: "neutral" };
  }

  return { dockerLiveness, monitoredHttp, liveHttpProbe };
}
