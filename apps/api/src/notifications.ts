import https from "node:https";
import net from "node:net";
import {
  type AppStatus,
  type ApprovalRequest,
  type DeploymentRecord,
  type HostLookupFn,
  type NotificationChannel,
  type RegistryStore,
  type RuntimeBridge,
  redactSecrets,
  resolveAndValidateHttpTarget,
  syncAppStatuses,
} from "@vpsagent/shared";

const DEFAULT_TELEGRAM_API_BASE = "https://api.telegram.org";
const TELEGRAM_BOT_TOKEN_RE = /^\d{5,15}:[A-Za-z0-9_-]{20,}$/;
const TELEGRAM_CHAT_ID_RE = /^(?:-?\d{1,24}|@[A-Za-z0-9_]{3,64})$/;
const DISCORD_WEBHOOK_HOSTS = new Set([
  "discord.com",
  "discordapp.com",
  "ptb.discord.com",
  "canary.discord.com",
]);
const MAX_NOTIFICATION_RESPONSE_BYTES = 4096;

export interface NotificationServiceOptions {
  store: RegistryStore;
  lookupFn?: HostLookupFn | undefined;
  fetchFn?: typeof fetch | undefined;
  telegramApiBaseUrl?: string | undefined;
}

export interface NotificationMessageEvent {
  kind: "test" | "approval" | "app_down" | "app_recovered" | "deploy_failed";
  title: string;
  body: string;
  slug?: string | null | undefined;
  linkPath?: string | null | undefined;
}

function buildActiveDashboardBaseUrl(store: RegistryStore): string | null {
  const setup = store.getSetupState();
  if (setup.domain && setup.httpsActive && setup.tlsStatus === "active") {
    return `https://${setup.domain}`;
  }
  if (setup.tailscaleDomain && setup.tailscaleServeEnabled) {
    return `https://${setup.tailscaleDomain}`;
  }
  return null;
}

function assertWebhookUrlMatchesChannel(
  channel: NotificationChannel,
  parsed: URL,
): void {
  if (parsed.protocol !== "https:") {
    throw new Error("Alert webhook URL must use https://.");
  }
  const host = parsed.hostname.toLowerCase();
  if (
    channel === "discord" &&
    (!DISCORD_WEBHOOK_HOSTS.has(host) ||
      !parsed.pathname.startsWith("/api/webhooks/"))
  ) {
    throw new Error(
      "Discord webhook URL must start with https://discord.com/api/webhooks/.",
    );
  }
  if (channel === "slack" && host !== "hooks.slack.com") {
    throw new Error("Slack webhook URL must use https://hooks.slack.com/...");
  }
}

async function postJsonPinnedHttps(
  targetUrl: string,
  payload: Record<string, unknown>,
  addresses: Array<{ address: string; family: number }>,
  timeoutMs: number,
): Promise<{ ok: boolean; status: number; bodyText: string }> {
  const parsed = new URL(targetUrl);
  const bodyBuf = Buffer.from(JSON.stringify(payload), "utf8");
  const rawHost = parsed.hostname.replace(/^\[|\]$/g, "");
  const isIpLiteral = net.isIP(rawHost) !== 0;

  return new Promise((resolve, reject) => {
    const pinnedLookup = (
      _hostname: string,
      opts: unknown,
      cb: (...args: unknown[]) => void,
    ) => {
      const wantAll =
        typeof opts === "object" &&
        opts !== null &&
        (opts as { all?: boolean }).all === true;
      if (wantAll) {
        cb(null, addresses);
      } else {
        const first = addresses[0]!;
        cb(null, first.address, first.family);
      }
    };

    const req = https.request(
      {
        protocol: parsed.protocol,
        hostname: rawHost,
        port: parsed.port ? Number.parseInt(parsed.port, 10) : 443,
        path: `${parsed.pathname}${parsed.search}`,
        method: "POST",
        headers: {
          "content-type": "application/json",
          "content-length": String(bodyBuf.byteLength),
        },
        lookup: pinnedLookup as unknown as NonNullable<
          https.RequestOptions["lookup"]
        >,
        ...(isIpLiteral ? {} : { servername: rawHost }),
        signal: AbortSignal.timeout(timeoutMs),
      },
      (res) => {
        const chunks: Buffer[] = [];
        let total = 0;
        res.on("data", (chunk: Buffer) => {
          if (total < MAX_NOTIFICATION_RESPONSE_BYTES) {
            const slice = chunk.subarray(
              0,
              MAX_NOTIFICATION_RESPONSE_BYTES - total,
            );
            chunks.push(slice);
            total += slice.length;
          }
        });
        res.on("end", () => {
          const status = res.statusCode ?? 0;
          resolve({
            ok: status >= 200 && status < 300,
            status,
            bodyText: Buffer.concat(chunks).toString("utf8"),
          });
        });
        res.on("error", reject);
      },
    );

    req.on("error", reject);
    req.write(bodyBuf);
    req.end();
  });
}

/**
 * Sends instant plain-English alerts to Discord, Slack, Telegram, or a custom HTTPS webhook.
 * Every outbound target is validated against SSRF rules (HTTPS + public DNS/IP check + pinned
 * address connection + no redirects) and all payloads pass through `redactSecrets`.
 */
export class NotificationService {
  private readonly store: RegistryStore;
  private readonly lookupFn: HostLookupFn | undefined;
  private readonly customFetchFn: typeof fetch | undefined;
  private readonly telegramApiBaseUrl: string;

  constructor(options: NotificationServiceOptions) {
    this.store = options.store;
    this.lookupFn = options.lookupFn;
    this.customFetchFn = options.fetchFn;
    this.telegramApiBaseUrl = (
      options.telegramApiBaseUrl ?? DEFAULT_TELEGRAM_API_BASE
    ).replace(/\/+$/, "");
  }

  async validateAndNormalizeTarget(params: {
    channel: NotificationChannel;
    webhookUrl?: string | null | undefined;
    telegramBotToken?: string | null | undefined;
    telegramChatId?: string | null | undefined;
  }): Promise<{
    webhookUrl?: string | null | undefined;
    telegramBotToken?: string | null | undefined;
    telegramChatId?: string | null | undefined;
  }> {
    const { channel } = params;
    if (channel === "none") {
      return {};
    }

    if (channel === "telegram") {
      let cleanToken: string | null | undefined = params.telegramBotToken;
      if (typeof cleanToken === "string" && cleanToken.trim()) {
        cleanToken = cleanToken.trim();
        if (!TELEGRAM_BOT_TOKEN_RE.test(cleanToken)) {
          throw new Error(
            "Invalid Telegram bot token format (expected digits:token from @BotFather).",
          );
        }
      }
      let cleanChatId: string | null | undefined = params.telegramChatId;
      if (typeof cleanChatId === "string" && cleanChatId.trim()) {
        cleanChatId = cleanChatId.trim();
        if (!TELEGRAM_CHAT_ID_RE.test(cleanChatId)) {
          throw new Error(
            "Invalid Telegram chat ID (use a numeric ID like 123456789 or @channelname).",
          );
        }
      }
      return {
        ...(cleanToken !== undefined ? { telegramBotToken: cleanToken } : {}),
        ...(cleanChatId !== undefined ? { telegramChatId: cleanChatId } : {}),
      };
    }

    let cleanUrl: string | null | undefined = params.webhookUrl;
    if (typeof cleanUrl === "string" && cleanUrl.trim()) {
      const resolved = await resolveAndValidateHttpTarget(cleanUrl.trim(), {
        allowPrivateNetwork: false,
        preserveTrailingSlash: true,
        ...(this.lookupFn ? { lookupFn: this.lookupFn } : {}),
      });
      assertWebhookUrlMatchesChannel(channel, new URL(resolved.url));
      cleanUrl = resolved.url;
    }

    return {
      ...(cleanUrl !== undefined ? { webhookUrl: cleanUrl } : {}),
    };
  }

  async sendMessage(
    event: NotificationMessageEvent,
  ): Promise<{ ok: boolean; error?: string }> {
    const cfg = this.store.getNotificationConfigForRuntime();
    if (cfg.channel === "none") {
      return { ok: false, error: "No alert channel is configured." };
    }
    if (event.kind !== "test") {
      if (!cfg.enabled) {
        return { ok: false, error: "Alerts are paused." };
      }
      if (event.kind === "approval" && !cfg.notifyOnApproval) {
        return { ok: false, error: "Approval alerts are disabled." };
      }
      if (
        (event.kind === "app_down" || event.kind === "app_recovered") &&
        !cfg.notifyOnAppDown
      ) {
        return { ok: false, error: "App health alerts are disabled." };
      }
      if (event.kind === "deploy_failed" && !cfg.notifyOnDeployFailure) {
        return { ok: false, error: "Deploy failure alerts are disabled." };
      }
    }

    const safeTitle = redactSecrets(event.title).slice(0, 180);
    const safeBody = redactSecrets(event.body).slice(0, 1200);
    const baseUrl = buildActiveDashboardBaseUrl(this.store);
    const fullLink =
      baseUrl && event.linkPath ? `${baseUrl}${event.linkPath}` : baseUrl;
    const textMessage = fullLink
      ? `${safeTitle}\n${safeBody}\nOpen dashboard: ${fullLink}`
      : `${safeTitle}\n${safeBody}`;

    try {
      let targetUrl: string;
      let pinnedAddresses: Array<{ address: string; family: number }> | null =
        null;
      let payload: Record<string, unknown>;

      if (cfg.channel === "telegram") {
        if (!cfg.telegramBotToken || !cfg.telegramChatId) {
          throw new Error(
            "Telegram bot token and chat ID must both be configured.",
          );
        }
        if (this.telegramApiBaseUrl === DEFAULT_TELEGRAM_API_BASE) {
          const resolved = await resolveAndValidateHttpTarget(
            this.telegramApiBaseUrl,
            {
              allowPrivateNetwork: false,
              ...(this.lookupFn ? { lookupFn: this.lookupFn } : {}),
            },
          );
          pinnedAddresses = resolved.addresses;
        }
        targetUrl = `${this.telegramApiBaseUrl}/bot${cfg.telegramBotToken}/sendMessage`;
        payload = {
          chat_id: cfg.telegramChatId,
          text: textMessage,
          disable_web_page_preview: true,
        };
      } else {
        if (!cfg.webhookUrl) {
          throw new Error("Alert webhook URL is not configured.");
        }
        const resolved = await resolveAndValidateHttpTarget(cfg.webhookUrl, {
          allowPrivateNetwork: false,
          preserveTrailingSlash: true,
          ...(this.lookupFn ? { lookupFn: this.lookupFn } : {}),
        });
        assertWebhookUrlMatchesChannel(cfg.channel, new URL(resolved.url));
        targetUrl = resolved.url;
        pinnedAddresses = resolved.addresses;

        if (cfg.channel === "discord") {
          payload = { content: textMessage };
        } else if (cfg.channel === "slack") {
          payload = { text: textMessage };
        } else {
          payload = {
            source: "vpsagent",
            event: event.kind,
            title: safeTitle,
            message: safeBody,
            slug: event.slug ?? null,
            dashboardUrl: fullLink,
            timestamp: new Date().toISOString(),
          };
        }
      }

      let ok: boolean;
      let status: number;
      let bodyText: string;

      if (this.customFetchFn) {
        const res = await this.customFetchFn(targetUrl, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify(payload),
          redirect: "error",
          signal: AbortSignal.timeout(10_000),
        });
        ok = res.ok;
        status = res.status;
        bodyText = await res.text();
      } else if (pinnedAddresses && targetUrl.startsWith("https://")) {
        const res = await postJsonPinnedHttps(
          targetUrl,
          payload,
          pinnedAddresses,
          10_000,
        );
        ok = res.ok;
        status = res.status;
        bodyText = res.bodyText;
      } else {
        const res = await fetch(targetUrl, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify(payload),
          redirect: "error",
          signal: AbortSignal.timeout(10_000),
        });
        ok = res.ok;
        status = res.status;
        bodyText = await res.text();
      }

      if (!ok) {
        const errText = redactSecrets(bodyText.trim()).slice(0, 200);
        const msg = `Alert target returned HTTP ${status}${errText ? `: ${errText}` : ""}`;
        this.store.recordNotificationDelivery(false, msg);
        return { ok: false, error: msg };
      }

      this.store.recordNotificationDelivery(true);
      return { ok: true };
    } catch (err) {
      const msg = redactSecrets(
        err instanceof Error ? err.message : String(err),
      );
      this.store.recordNotificationDelivery(false, msg);
      return { ok: false, error: msg };
    }
  }

  notifyApprovalPending(approval: ApprovalRequest): void {
    const cfg = this.store.getNotificationConfigForRuntime();
    if (!cfg.enabled || !cfg.notifyOnApproval || cfg.channel === "none") {
      return;
    }
    const target = approval.targetSlug ? ` on "${approval.targetSlug}"` : "";
    void this.sendMessage({
      kind: "approval",
      title: `VPSAgent: AI Approval Needed (${approval.riskLevel} risk)`,
      body: `${approval.requestedBy} requested "${approval.action}"${target}: ${approval.summary}`,
      slug: approval.targetSlug,
      linkPath: "/#approvals",
    }).catch(() => {});
  }

  notifyDeployFailed(
    slug: string,
    deployment: DeploymentRecord,
    errorMessage: string,
    options?: { appExists?: boolean },
  ): void {
    const cfg = this.store.getNotificationConfigForRuntime();
    if (!cfg.enabled || !cfg.notifyOnDeployFailure || cfg.channel === "none") {
      return;
    }
    void this.sendMessage({
      kind: "deploy_failed",
      title: `VPSAgent: ${deployment.action === "rollback_app" ? "Rollback" : "Build"} Failed for "${slug}"`,
      body: redactSecrets(errorMessage).slice(0, 400),
      slug,
      linkPath:
        options?.appExists === false
          ? "/#approvals"
          : `/#/apps/${slug}/deployments`,
    }).catch(() => {});
  }

  notifyAppHealthTransition(
    slug: string,
    appName: string,
    state: "down" | "recovered",
  ): void {
    const cfg = this.store.getNotificationConfigForRuntime();
    if (!cfg.enabled || !cfg.notifyOnAppDown || cfg.channel === "none") {
      return;
    }
    void this.sendMessage({
      kind: state === "down" ? "app_down" : "app_recovered",
      title:
        state === "down"
          ? `VPSAgent: "${appName}" (${slug}) looks offline`
          : `VPSAgent: "${appName}" (${slug}) is back online`,
      body:
        state === "down"
          ? `App "${slug}" stopped responding or exited unexpectedly. Check logs and health in your dashboard.`
          : `App "${slug}" recovered and is running normally again.`,
      slug,
      linkPath: `/#/apps/${slug}/security`,
    }).catch(() => {});
  }
}

export interface AppHealthAlerterOptions {
  store: RegistryStore;
  bridge: RuntimeBridge;
  notifier: NotificationService;
  pollIntervalMs?: number | undefined;
  cooldownMs?: number | undefined;
}

/**
 * Periodically syncs live app statuses and emits instant down/recovery alerts
 * when an app unexpectedly drops from `running` to `error` or `stopped`.
 */
export class AppHealthAlerter {
  private readonly store: RegistryStore;
  private readonly bridge: RuntimeBridge;
  private readonly notifier: NotificationService;
  private readonly pollIntervalMs: number;
  private readonly cooldownMs: number;
  private readonly lastStatusBySlug = new Map<string, AppStatus>();
  private readonly downAlertedSlugs = new Set<string>();
  private readonly intentionallyStopped = new Set<string>();
  private readonly lastAlertAtBySlug = new Map<string, number>();
  private seeded = false;
  private timer: NodeJS.Timeout | null = null;
  private running = false;

  constructor(options: AppHealthAlerterOptions) {
    this.store = options.store;
    this.bridge = options.bridge;
    this.notifier = options.notifier;
    this.pollIntervalMs = options.pollIntervalMs ?? 30_000;
    this.cooldownMs = options.cooldownMs ?? 5 * 60_000;
  }

  markIntentionalStop(slug: string): void {
    this.intentionallyStopped.add(slug);
    this.downAlertedSlugs.delete(slug);
  }

  clearIntentionalStop(slug: string): void {
    this.intentionallyStopped.delete(slug);
  }

  async checkOnce(): Promise<void> {
    const apps = await syncAppStatuses(this.store, this.bridge);
    const activeSlugs = new Set(apps.map((a) => a.slug));
    for (const known of Array.from(this.lastStatusBySlug.keys())) {
      if (!activeSlugs.has(known)) {
        this.lastStatusBySlug.delete(known);
        this.downAlertedSlugs.delete(known);
        this.intentionallyStopped.delete(known);
      }
    }

    if (!this.seeded) {
      for (const app of apps) {
        this.lastStatusBySlug.set(app.slug, app.status);
      }
      this.seeded = true;
      return;
    }

    const now = Date.now();
    for (const app of apps) {
      const prev = this.lastStatusBySlug.get(app.slug);
      this.lastStatusBySlug.set(app.slug, app.status);

      if (app.status === "running") {
        this.intentionallyStopped.delete(app.slug);
        if (this.downAlertedSlugs.has(app.slug)) {
          this.downAlertedSlugs.delete(app.slug);
          this.notifier.notifyAppHealthTransition(app.slug, app.name, "recovered");
        }
        continue;
      }

      if (prev === "running") {
        const unexpectedDown =
          app.status === "error" ||
          (app.status === "stopped" && !this.intentionallyStopped.has(app.slug));
        if (unexpectedDown && !this.downAlertedSlugs.has(app.slug)) {
          const lastAt = this.lastAlertAtBySlug.get(app.slug) ?? 0;
          if (now - lastAt >= this.cooldownMs) {
            this.downAlertedSlugs.add(app.slug);
            this.lastAlertAtBySlug.set(app.slug, now);
            this.notifier.notifyAppHealthTransition(app.slug, app.name, "down");
          }
        }
      }
    }
  }

  start(): void {
    if (this.timer || this.pollIntervalMs <= 0) {
      return;
    }
    this.timer = setInterval(() => {
      if (this.running) return;
      this.running = true;
      void this.checkOnce()
        .catch(() => {})
        .finally(() => {
          this.running = false;
        });
    }, this.pollIntervalMs);
    this.timer.unref();
  }

  stop(): void {
    if (this.timer) {
      clearInterval(this.timer);
      this.timer = null;
    }
  }
}
