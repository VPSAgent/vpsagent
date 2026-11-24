import assert from "node:assert/strict";
import { describe, it } from "node:test";
import type { AppRecord, InspectResult } from "../src/api.ts";
import {
  applyInspectStatusToApps,
  formatSafetyCheckHealth,
} from "../src/health-display.ts";

function makeApp(overrides: Partial<AppRecord> = {}): AppRecord {
  return {
    slug: "dual-check",
    name: "Dual Check",
    sourceType: "image",
    image: "nginx:alpine",
    gitRepoUrl: null,
    gitBranch: null,
    dockerfilePath: null,
    domain: null,
    internalPort: 8080,
    status: "running",
    cpuLimit: "0.5",
    memoryLimitMb: 256,
    companions: [],
    createdAt: "2026-01-01T00:00:00Z",
    updatedAt: "2026-01-01T00:00:00Z",
    ...overrides,
  };
}

function makeInspect(overrides: Partial<InspectResult> = {}): InspectResult {
  return {
    slug: "dual-check",
    status: "running",
    lockedApartmentCompliant: true,
    caddyRouteConfigured: false,
    caddyDomains: [],
    httpProbe: {
      attempted: true,
      ok: true,
      statusCode: 200,
      latencyMs: 3.2,
      contentType: "text/plain",
      error: null,
    },
    hostHttpHealth: {
      status: "healthy",
      consecutiveFailures: 0,
      lastOutput: "Host HTTP probe GET /health(v2) -> 200",
    },
    containers: [
      {
        id: "abc123",
        name: "vpsagent-app-dual-check",
        image: "nginx:alpine",
        state: "running",
        running: true,
        healthStatus: "healthy",
        security: {
          capDropAll: true,
          noNewPrivileges: true,
          privileged: false,
          hasDockerSocketMount: false,
          isolatedNetworkOnly: true,
          lockedApartmentCompliant: true,
        },
      },
    ],
    ...overrides,
  };
}

describe("Dashboard Safety Check & Apps card sync", () => {
  it("syncs the Apps card status directly from Safety Check without a manual refresh", () => {
    const openApps = [
      makeApp({ slug: "dual-check", status: "running" }),
      makeApp({ slug: "other-app", status: "running" }),
    ];

    const failingInspect = makeInspect({
      slug: "dual-check",
      status: "error",
      hostHttpHealth: {
        status: "unhealthy",
        consecutiveFailures: 3,
        lastOutput: "Host HTTP probe GET /health(v2) failed (3/3): HTTP 500",
      },
      httpProbe: {
        attempted: true,
        ok: false,
        statusCode: 500,
        latencyMs: 2.1,
        contentType: "text/plain",
        error: null,
      },
    });

    const syncedAfterFailure = applyInspectStatusToApps(
      openApps,
      failingInspect,
    );
    assert.equal(syncedAfterFailure[0]?.status, "error");
    assert.equal(syncedAfterFailure[1]?.status, "running");

    // And recovers back to running on the next Safety Check without manual refresh
    const recoveredInspect = makeInspect({
      slug: "dual-check",
      status: "running",
    });
    const syncedAfterRecovery = applyInspectStatusToApps(
      syncedAfterFailure,
      recoveredInspect,
    );
    assert.equal(syncedAfterRecovery[0]?.status, "running");
  });

  it("labels Docker liveness, monitored HTTP health, and live HTTP probe separately before and after the 3-failure threshold", () => {
    // Before 3rd failure: monitored state is still 'healthy' (1 recent failure) while live probe is HTTP 500
    const beforeThreshold = formatSafetyCheckHealth(
      makeInspect({
        status: "running",
        hostHttpHealth: {
          status: "healthy",
          consecutiveFailures: 1,
          lastOutput: "Host HTTP probe GET /health(v2) failed (1/3): HTTP 500",
        },
        httpProbe: {
          attempted: true,
          ok: false,
          statusCode: 500,
          latencyMs: 1.8,
          contentType: "text/plain",
          error: null,
        },
      }),
    );

    assert.equal(beforeThreshold.dockerLiveness.label, "healthy");
    assert.equal(
      beforeThreshold.monitoredHttp.label,
      "healthy (1 recent failure — threshold 3)",
    );
    assert.equal(beforeThreshold.monitoredHttp.tone, "warning");
    assert.equal(beforeThreshold.liveHttpProbe.label, "HTTP 500 (failed)");
    assert.equal(beforeThreshold.liveHttpProbe.tone, "unhealthy");

    // After 3rd failure: monitored state is unhealthy while Docker liveness stays healthy
    const afterThreshold = formatSafetyCheckHealth(
      makeInspect({
        status: "error",
        hostHttpHealth: {
          status: "unhealthy",
          consecutiveFailures: 3,
          lastOutput: "Host HTTP probe GET /health(v2) failed (3/3): HTTP 500",
        },
        httpProbe: {
          attempted: true,
          ok: false,
          statusCode: 500,
          latencyMs: 1.9,
          contentType: "text/plain",
          error: null,
        },
      }),
    );

    assert.equal(afterThreshold.dockerLiveness.label, "healthy");
    assert.equal(
      afterThreshold.monitoredHttp.label,
      "unhealthy (3 consecutive failures)",
    );
    assert.equal(afterThreshold.monitoredHttp.tone, "unhealthy");
    assert.equal(afterThreshold.liveHttpProbe.label, "HTTP 500 (failed)");
  });
});
