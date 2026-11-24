import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { pathToFileURL } from "node:url";
import { serve } from "@hono/node-server";
import {
  RegistryStore,
  createRuntimeBridgeFromEnv,
  formatEnvFile,
} from "@vpsagent/shared";
import { createVpsAgentApp } from "./app.js";

export * from "./app.js";
export * from "./auth.js";
export * from "./executor.js";
export * from "./mcp-gateway.js";

function startServerFromEnv(): void {
  const port = Number.parseInt(process.env.PORT ?? "3001", 10);
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
  const domainConfigFile = process.env.VPSAGENT_DOMAIN_CONFIG_FILE?.trim();

  const bridge = createRuntimeBridgeFromEnv(process.env);
  if (!bridge) {
    throw new Error(
      "VPSAGENT_RUNTIME_SOCKET or VPSAGENT_RUNTIME_URL must be configured.",
    );
  }

  const store = new RegistryStore(dbPath, { encryptionSecret });
  const { app, generatedClaimToken } = createVpsAgentApp({
    store,
    bridge,
    appsRoot,
    sessionSecret,
    claimToken: process.env.VPSAGENT_CLAIM_TOKEN,
    webDistDir: process.env.VPSAGENT_WEB_DIST,
    publicIp: process.env.VPSAGENT_PUBLIC_IP,
    trustProxy: process.env.VPSAGENT_TRUST_PROXY === "true",
    onDomainUpdated: domainConfigFile
      ? (domain, acmeEmail) => {
          fs.mkdirSync(path.dirname(domainConfigFile), { recursive: true });
          const vars: Record<string, string> = {
            VPSAGENT_DOMAIN: domain ?? "localhost",
            VPSAGENT_SITE_ADDRESS: domain ?? ":80",
            ...(acmeEmail ? { VPSAGENT_ACME_EMAIL: acmeEmail } : {}),
          };
          fs.writeFileSync(domainConfigFile, formatEnvFile(vars), {
            encoding: "utf8",
            mode: 0o600,
          });
        }
      : undefined,
  });

  if (generatedClaimToken) {
    console.log(
      `[vpsagent-api] First-boot setup link ready (open in browser): /#claim=${generatedClaimToken}`,
    );
  }

  serve({ fetch: app.fetch, port }, (info) => {
    console.log(`[vpsagent-api] Listening on http://0.0.0.0:${info.port}`);
  });
}

const isEntrypoint =
  typeof process.argv[1] === "string" &&
  import.meta.url === pathToFileURL(process.argv[1]).href;

if (isEntrypoint) {
  startServerFromEnv();
}
