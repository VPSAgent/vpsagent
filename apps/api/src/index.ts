import crypto from "node:crypto";
import { pathToFileURL } from "node:url";
import { serve } from "@hono/node-server";
import {
  RegistryStore,
  createRuntimeBridgeFromEnv,
} from "@vpsagent/shared";
import { createVpsAgentApp } from "./app.js";

export * from "./app.js";
export * from "./auth.js";
export * from "./executor.js";
export * from "./github.js";
export * from "./mcp-gateway.js";
export * from "./notifications.js";

function startServerFromEnv(): void {
  const port = Number.parseInt(process.env.PORT ?? "3001", 10);
  const localSetupPort = Number.parseInt(
    process.env.VPSAGENT_LOCAL_SETUP_PORT ?? "3002",
    10,
  );
  const dbPath =
    process.env.VPSAGENT_DB_PATH?.trim() || "/var/lib/vpsagent/data/registry.db";
  const appsRoot =
    process.env.VPSAGENT_APPS_ROOT?.trim() || "/var/lib/vpsagent/apps";
  const encryptionSecret =
    process.env.VPSAGENT_ENCRYPTION_SECRET?.trim() ||
    process.env.VPSAGENT_SESSION_SECRET?.trim() ||
    crypto.randomBytes(32).toString("hex");
  const sessionSecret =
    process.env.VPSAGENT_SESSION_SECRET?.trim() || encryptionSecret;

  const bridge = createRuntimeBridgeFromEnv(process.env);
  if (!bridge) {
    throw new Error(
      "VPSAGENT_RUNTIME_SOCKET or VPSAGENT_RUNTIME_URL must be configured.",
    );
  }

  const store = new RegistryStore(dbPath, { encryptionSecret });

  // Record pre-configured installer domain as pending until a live TLS check confirms it
  const initialDomain = process.env.VPSAGENT_DOMAIN?.trim();
  const initialEmail = process.env.VPSAGENT_ACME_EMAIL?.trim() || null;
  if (
    initialDomain &&
    initialDomain !== "localhost" &&
    !store.getSetupState().domain
  ) {
    store.updateSetupState({
      domain: initialDomain,
      acmeEmail: initialEmail,
      httpsActive: false,
      tlsStatus: "pending",
      tlsError: null,
    });
  }

  // Sync initial Tailscale Serve state on startup so /mcp accepts Tailscale HTTPS immediately
  if (bridge.getTailscaleStatus) {
    void bridge
      .getTailscaleStatus()
      .then((ts) => {
        const nextDomain = ts.dnsName || null;
        const nextEnabled = Boolean(ts.serveEnabled && ts.dnsName);
        const cur = store.getSetupState();
        if (
          cur.tailscaleDomain !== nextDomain ||
          cur.tailscaleServeEnabled !== nextEnabled
        ) {
          store.updateSetupState({
            tailscaleDomain: nextDomain,
            tailscaleServeEnabled: nextEnabled,
          });
        }
      })
      .catch(() => {
        // Non-fatal: Tailscale may not be installed or bridge may still be starting
      });
  }

  // 1. Primary Caddy-fronted server (strictly requires HTTPS via X-Forwarded-Proto)
  const { app, generatedClaimToken, executor, notifier, healthAlerter } = createVpsAgentApp({
    store,
    bridge,
    appsRoot,
    sessionSecret,
    claimToken: process.env.VPSAGENT_CLAIM_TOKEN,
    webDistDir: process.env.VPSAGENT_WEB_DIST,
    publicIp: process.env.VPSAGENT_PUBLIC_IP,
    trustProxy: process.env.VPSAGENT_TRUST_PROXY === "true",
    isLocalListener: false,
  });

  if (process.env.VPSAGENT_ALERT_POLL_MS !== "0") {
    healthAlerter.start();
  }

  if (generatedClaimToken) {
    console.log(
      `[vpsagent-api] First-boot setup link ready (open via HTTPS or SSH tunnel): /#claim=${generatedClaimToken}`,
    );
  }

  serve({ fetch: app.fetch, port }, (info) => {
    console.log(`[vpsagent-api] Primary server listening on :${info.port}`);
  });

  // 2. Dedicated loopback-only local setup listener (published ONLY on host 127.0.0.1:3002)
  if (Number.isFinite(localSetupPort) && localSetupPort > 0 && localSetupPort !== port) {
    const { app: localApp } = createVpsAgentApp({
      store,
      bridge,
      appsRoot,
      sessionSecret,
      claimToken: process.env.VPSAGENT_CLAIM_TOKEN,
      webDistDir: process.env.VPSAGENT_WEB_DIST,
      publicIp: process.env.VPSAGENT_PUBLIC_IP,
      trustProxy: false,
      isLocalListener: true,
      executor,
      notifier,
      healthAlerter,
    });
    serve({ fetch: localApp.fetch, port: localSetupPort }, (info) => {
      console.log(
        `[vpsagent-api] Local-only SSH-tunnel setup listener on :${info.port}`,
      );
    });
  }
}

const isEntrypoint =
  typeof process.argv[1] === "string" &&
  import.meta.url === pathToFileURL(process.argv[1]).href;

if (isEntrypoint) {
  startServerFromEnv();
}
