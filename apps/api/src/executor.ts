import { z } from "zod";
import {
  type Actor,
  type AppRecord,
  AppSourceTypeSchema,
  CompanionServiceSchema,
  type HostLookupFn,
  type RegistryStore,
  type RuntimeBridge,
  RuntimeBridgeError,
  generateApartmentBlueprint,
  redactSecrets,
  resolveScopedAppDir,
  validateAppSlug,
  validateDockerfilePath,
  validateDomain,
  validateEnvKey,
  validateGitBranch,
  validateGitRepoUrl,
  writeApartmentBlueprint,
} from "@vpsagent/shared";

export const DeployAppInputSchema = z.object({
  slug: z.string().min(2).max(48),
  name: z.string().trim().min(1).max(100),
  sourceType: AppSourceTypeSchema,
  image: z.string().min(1).max(255).nullable().optional(),
  gitRepoUrl: z.string().min(1).max(500).nullable().optional(),
  gitBranch: z.string().min(1).max(120).nullable().optional(),
  dockerfilePath: z.string().min(1).max(200).optional(),
  domain: z.string().min(1).max(253).nullable().optional(),
  internalPort: z.number().int().min(1).max(65535).default(8080),
  cpuLimit: z.string().min(1).max(16).default("0.5"),
  memoryLimitMb: z.number().int().min(64).max(131072).default(512),
  companions: z.array(CompanionServiceSchema).default([]),
  envVars: z.record(z.string(), z.string()).default({}),
  probePath: z.string().min(1).max(128).optional(),
});
export type DeployAppInput = z.input<typeof DeployAppInputSchema>;

export const UpdateAppEnvInputSchema = z.object({
  vars: z
    .array(
      z.object({
        key: z.string().min(1).max(128),
        value: z.string(),
        isSecret: z.boolean().optional(),
      }),
    )
    .default([]),
  deleteKeys: z.array(z.string().min(1).max(128)).default([]),
});
export type UpdateAppEnvInput = z.input<typeof UpdateAppEnvInputSchema>;

export interface AppExecutorOptions {
  store: RegistryStore;
  bridge: RuntimeBridge;
  appsRoot: string;
  lookupFn?: HostLookupFn | undefined;
  readinessTimeoutSeconds?: number | undefined;
  readinessPollIntervalMs?: number | undefined;
  buildTimeoutSeconds?: number | undefined;
}

export class AppExecutor {
  private readonly store: RegistryStore;
  private readonly bridge: RuntimeBridge;
  private readonly appsRoot: string;
  private readonly lookupFn: HostLookupFn | undefined;
  private readonly readinessTimeoutSeconds: number;
  private readonly readinessPollIntervalMs: number;
  private readonly buildTimeoutSeconds: number;
  private readonly activeSlugs = new Set<string>();

  constructor(options: AppExecutorOptions) {
    this.store = options.store;
    this.bridge = options.bridge;
    this.appsRoot = options.appsRoot;
    this.lookupFn = options.lookupFn;
    this.readinessTimeoutSeconds = options.readinessTimeoutSeconds ?? 15;
    this.readinessPollIntervalMs = options.readinessPollIntervalMs ?? 500;
    this.buildTimeoutSeconds = options.buildTimeoutSeconds ?? 300;
  }

  private async withSlugLock<T>(slug: string, fn: () => Promise<T>): Promise<T> {
    if (this.activeSlugs.has(slug)) {
      throw new RuntimeBridgeError(
        409,
        `Another operation is already running for app "${slug}". Please wait a moment and try again.`,
      );
    }
    this.activeSlugs.add(slug);
    try {
      return await fn();
    } finally {
      this.activeSlugs.delete(slug);
    }
  }

  async deployApp(
    rawInput: DeployAppInput,
    actor: Actor,
  ): Promise<{ app: AppRecord; readinessAttempts: number }> {
    const input = DeployAppInputSchema.parse(rawInput);
    const slug = validateAppSlug(input.slug);
    const safeDomain = input.domain ? validateDomain(input.domain) : null;
    const safeDockerfile = input.dockerfilePath
      ? validateDockerfilePath(input.dockerfilePath)
      : "Dockerfile";
    const safeBranch = input.gitBranch ? validateGitBranch(input.gitBranch) : null;

    return this.withSlugLock(slug, async () => {
      const existing = this.store.getApp(slug);
      let validatedGitUrl: string | null = null;

      if (input.sourceType === "git") {
        if (!input.gitRepoUrl) {
          throw new Error("Git apps require a gitRepoUrl.");
        }
        validatedGitUrl = await validateGitRepoUrl(
          input.gitRepoUrl,
          this.lookupFn ? { lookupFn: this.lookupFn } : undefined,
        );
      }

      // Preserve existing companion passwords on re-deploy so DB access never breaks.
      const existingEnv = existing
        ? this.store.getAppEnvMapForRuntime(slug)
        : {};
      const mergedUserEnv: Record<string, string> = {
        ...existingEnv,
        ...input.envVars,
      };
      // Remove auto-managed slug/port before regenerating blueprint
      delete mergedUserEnv.APP_SLUG;
      delete mergedUserEnv.APP_PORT;

      const blueprint = generateApartmentBlueprint({
        slug,
        sourceType: input.sourceType,
        image: input.sourceType === "image" ? (input.image ?? null) : null,
        gitRepoUrl: validatedGitUrl,
        gitBranch: safeBranch,
        dockerfilePath: safeDockerfile,
        internalPort: input.internalPort,
        cpuLimit: input.cpuLimit,
        memoryLimitMb: input.memoryLimitMb,
        companions: input.companions,
        envVars: mergedUserEnv,
        companionSecrets: {
          ...(existingEnv.POSTGRES_PASSWORD
            ? { postgresPassword: existingEnv.POSTGRES_PASSWORD }
            : {}),
          ...(existingEnv.REDIS_PASSWORD
            ? { redisPassword: existingEnv.REDIS_PASSWORD }
            : {}),
        },
      });

      const appDir = resolveScopedAppDir(this.appsRoot, slug);
      writeApartmentBlueprint(this.appsRoot, blueprint);

      this.store.upsertApp({
        slug,
        name: input.name,
        sourceType: input.sourceType,
        image: blueprint.imageRef,
        gitRepoUrl: validatedGitUrl,
        gitBranch: safeBranch,
        dockerfilePath: safeDockerfile,
        domain: existing?.domain ?? null,
        folderPath: appDir,
        internalPort: input.internalPort,
        status: input.sourceType === "git" ? "building" : "provisioning",
        cpuLimit: input.cpuLimit,
        memoryLimitMb: input.memoryLimitMb,
        companions: blueprint.companions,
      });

      const envToStore = Object.entries(blueprint.envVars).map(
        ([key, value]) => ({
          key,
          value,
        }),
      );
      if (envToStore.length > 0) {
        this.store.setAppEnvVars(slug, envToStore);
      }

      try {
        if (input.sourceType === "git" && validatedGitUrl) {
          await this.bridge.buildGitImage({
            slug,
            gitRepoUrl: validatedGitUrl,
            gitBranch: safeBranch,
            dockerfilePath: safeDockerfile,
            timeoutSeconds: this.buildTimeoutSeconds,
          });
        }

        await this.bridge.lifecycle(slug, "start");

        const readiness = await this.bridge.waitForReadiness(slug, {
          internalPort: input.internalPort,
          probePath: input.probePath ?? "/",
          timeoutSeconds: this.readinessTimeoutSeconds,
          pollIntervalMs: this.readinessPollIntervalMs,
        });

        if (!readiness.ready) {
          throw new RuntimeBridgeError(
            502,
            readiness.reason ?? `App "${slug}" failed startup readiness checks.`,
          );
        }

        if (safeDomain) {
          await this.bridge.routeCaddy({
            slug,
            domain: safeDomain,
            internalPort: input.internalPort,
          });
          this.store.updateAppDomain(slug, safeDomain);
        }

        const running = this.store.updateAppStatus(slug, "running")!;
        this.store.recordAudit({
          actor,
          action: "deploy_app",
          targetSlug: slug,
          summary: `Deployed ${input.sourceType} app "${input.name}" (${slug})${safeDomain ? ` on ${safeDomain}` : ""}`,
          riskLevel: "medium",
        });

        return { app: running, readinessAttempts: readiness.attempts };
      } catch (err) {
        if (!existing) {
          try {
            await this.bridge.removeWorkload(slug, { removeFiles: true });
          } catch {
            // Best-effort cleanup on failed initial deploy
          }
          this.store.deleteApp(slug);
        } else {
          this.store.updateAppStatus(slug, "error");
        }
        this.store.recordAudit({
          actor,
          action: "deploy_app_failed",
          targetSlug: slug,
          summary: redactSecrets(
            `Deploy failed for "${slug}": ${err instanceof Error ? err.message : String(err)}`,
          ),
          riskLevel: "high",
        });
        throw err;
      }
    });
  }

  async rebuildApp(slugRaw: string, actor: Actor): Promise<AppRecord> {
    const slug = validateAppSlug(slugRaw);
    const existing = this.store.getApp(slug);
    if (!existing) {
      throw new RuntimeBridgeError(404, `App "${slug}" not found.`);
    }

    return this.withSlugLock(slug, async () => {
      const currentEnv = this.store.getAppEnvMapForRuntime(slug);
      const userEnv = { ...currentEnv };
      delete userEnv.APP_SLUG;
      delete userEnv.APP_PORT;

      if (existing.sourceType === "git") {
        if (!existing.gitRepoUrl) {
          throw new RuntimeBridgeError(
            400,
            `Git app "${slug}" is missing gitRepoUrl.`,
          );
        }
        const safeRepo = await validateGitRepoUrl(
          existing.gitRepoUrl,
          this.lookupFn ? { lookupFn: this.lookupFn } : undefined,
        );
        this.store.updateAppStatus(slug, "building");
        await this.bridge.buildGitImage({
          slug,
          gitRepoUrl: safeRepo,
          gitBranch: existing.gitBranch,
          dockerfilePath: existing.dockerfilePath,
          timeoutSeconds: this.buildTimeoutSeconds,
        });
      }

      const blueprint = generateApartmentBlueprint({
        slug,
        sourceType: existing.sourceType,
        image: existing.sourceType === "image" ? existing.image : null,
        gitRepoUrl: existing.gitRepoUrl,
        gitBranch: existing.gitBranch,
        dockerfilePath: existing.dockerfilePath,
        internalPort: existing.internalPort,
        cpuLimit: existing.cpuLimit,
        memoryLimitMb: existing.memoryLimitMb,
        companions: existing.companions,
        envVars: userEnv,
        companionSecrets: {
          ...(currentEnv.POSTGRES_PASSWORD
            ? { postgresPassword: currentEnv.POSTGRES_PASSWORD }
            : {}),
          ...(currentEnv.REDIS_PASSWORD
            ? { redisPassword: currentEnv.REDIS_PASSWORD }
            : {}),
        },
      });
      writeApartmentBlueprint(this.appsRoot, blueprint);

      await this.bridge.lifecycle(slug, "start");
      const readiness = await this.bridge.waitForReadiness(slug, {
        internalPort: existing.internalPort,
        probePath: "/",
        timeoutSeconds: this.readinessTimeoutSeconds,
        pollIntervalMs: this.readinessPollIntervalMs,
      });
      if (!readiness.ready) {
        this.store.updateAppStatus(slug, "error");
        throw new RuntimeBridgeError(
          502,
          readiness.reason ?? `App "${slug}" failed readiness after rebuild.`,
        );
      }

      const updated = this.store.updateAppStatus(slug, "running")!;
      this.store.recordAudit({
        actor,
        action: "rebuild_app",
        targetSlug: slug,
        summary: `Rebuilt and restarted app "${slug}"`,
        riskLevel: "medium",
      });
      return updated;
    });
  }

  async updateAppEnv(
    slugRaw: string,
    rawInput: UpdateAppEnvInput,
    actor: Actor,
  ): Promise<AppRecord> {
    const slug = validateAppSlug(slugRaw);
    const input = UpdateAppEnvInputSchema.parse(rawInput);
    const existing = this.store.getApp(slug);
    if (!existing) {
      throw new RuntimeBridgeError(404, `App "${slug}" not found.`);
    }

    return this.withSlugLock(slug, async () => {
      for (const delKey of input.deleteKeys) {
        this.store.deleteAppEnvVar(slug, validateEnvKey(delKey));
      }
      if (input.vars.length > 0) {
        this.store.setAppEnvVars(
          slug,
          input.vars.map((v) => ({
            key: validateEnvKey(v.key),
            value: v.value,
            ...(v.isSecret !== undefined ? { isSecret: v.isSecret } : {}),
          })),
        );
      }

      const runtimeEnv = this.store.getAppEnvMapForRuntime(slug);
      const userEnv = { ...runtimeEnv };
      delete userEnv.APP_SLUG;
      delete userEnv.APP_PORT;

      const blueprint = generateApartmentBlueprint({
        slug,
        sourceType: existing.sourceType,
        image: existing.sourceType === "image" ? existing.image : null,
        gitRepoUrl: existing.gitRepoUrl,
        gitBranch: existing.gitBranch,
        dockerfilePath: existing.dockerfilePath,
        internalPort: existing.internalPort,
        cpuLimit: existing.cpuLimit,
        memoryLimitMb: existing.memoryLimitMb,
        companions: existing.companions,
        envVars: userEnv,
        companionSecrets: {
          ...(runtimeEnv.POSTGRES_PASSWORD
            ? { postgresPassword: runtimeEnv.POSTGRES_PASSWORD }
            : {}),
          ...(runtimeEnv.REDIS_PASSWORD
            ? { redisPassword: runtimeEnv.REDIS_PASSWORD }
            : {}),
        },
      });
      writeApartmentBlueprint(this.appsRoot, blueprint);

      if (existing.status === "running") {
        await this.bridge.lifecycle(slug, "start");
      }

      const changedKeys = [
        ...input.vars.map((v) => v.key),
        ...input.deleteKeys.map((k) => `-${k}`),
      ];
      this.store.recordAudit({
        actor,
        action: "update_env",
        targetSlug: slug,
        summary: `Updated environment settings for "${slug}" (${changedKeys.join(", ") || "no changes"})`,
        riskLevel: "medium",
      });

      return this.store.getApp(slug)!;
    });
  }

  async setAppDomain(
    slugRaw: string,
    domain: string | null,
    actor: Actor,
  ): Promise<AppRecord> {
    const slug = validateAppSlug(slugRaw);
    const safeDomain = domain ? validateDomain(domain) : null;
    const existing = this.store.getApp(slug);
    if (!existing) {
      throw new RuntimeBridgeError(404, `App "${slug}" not found.`);
    }

    return this.withSlugLock(slug, async () => {
      await this.bridge.routeCaddy({
        slug,
        domain: safeDomain,
        internalPort: existing.internalPort,
      });
      const updated = this.store.updateAppDomain(slug, safeDomain)!;
      this.store.recordAudit({
        actor,
        action: "set_domain",
        targetSlug: slug,
        summary: safeDomain
          ? `Connected domain ${safeDomain} to "${slug}"`
          : `Removed public domain from "${slug}"`,
        riskLevel: "medium",
      });
      return updated;
    });
  }

  async lifecycleApp(
    slugRaw: string,
    action: "start" | "stop" | "restart",
    actor: Actor,
  ): Promise<AppRecord> {
    const slug = validateAppSlug(slugRaw);
    const existing = this.store.getApp(slug);
    if (!existing) {
      throw new RuntimeBridgeError(404, `App "${slug}" not found.`);
    }

    return this.withSlugLock(slug, async () => {
      const res = await this.bridge.lifecycle(slug, action);
      const updated = this.store.updateAppStatus(slug, res.status)!;
      this.store.recordAudit({
        actor,
        action: `${action}_app`,
        targetSlug: slug,
        summary: `Performed ${action} on "${slug}" (now ${res.status})`,
        riskLevel: action === "stop" ? "medium" : "low",
      });
      return updated;
    });
  }

  async deleteApp(
    slugRaw: string,
    removeFiles: boolean,
    actor: Actor,
  ): Promise<{ ok: true; slug: string }> {
    const slug = validateAppSlug(slugRaw);
    const existing = this.store.getApp(slug);
    if (!existing) {
      throw new RuntimeBridgeError(404, `App "${slug}" not found.`);
    }

    return this.withSlugLock(slug, async () => {
      await this.bridge.removeWorkload(slug, { removeFiles });
      this.store.deleteApp(slug);
      this.store.recordAudit({
        actor,
        action: "delete_app",
        targetSlug: slug,
        summary: `Deleted app "${slug}" (removeFiles=${String(removeFiles)})`,
        riskLevel: "high",
      });
      return { ok: true, slug };
    });
  }

  /**
   * Atomically claims an approved request and runs its underlying action exactly once.
   */
  async executeApprovedRequest(approvalId: string): Promise<{
    ok: boolean;
    summary: string;
    data?: unknown;
  }> {
    const claimed = this.store.claimApprovalForExecution(
      approvalId,
      `executor-${Date.now()}`,
    );
    if (!claimed) {
      throw new RuntimeBridgeError(
        409,
        `Approval "${approvalId}" could not be claimed for execution.`,
      );
    }

    const execPayload =
      this.store.consumeApprovalExecutionPayload(approvalId) ?? claimed.payload;

    try {
      let data: unknown;
      let summary: string;

      switch (claimed.action) {
        case "deploy_app": {
          const res = await this.deployApp(
            execPayload as DeployAppInput,
            "agent",
          );
          data = res.app;
          summary = `Deployed "${res.app.slug}" (${res.app.status})`;
          break;
        }
        case "rebuild_app": {
          const slug = String(execPayload.slug ?? claimed.targetSlug ?? "");
          const app = await this.rebuildApp(slug, "agent");
          data = app;
          summary = `Rebuilt "${app.slug}" (${app.status})`;
          break;
        }
        case "update_env": {
          const slug = String(execPayload.slug ?? claimed.targetSlug ?? "");
          const app = await this.updateAppEnv(
            slug,
            {
              vars: (execPayload.vars as UpdateAppEnvInput["vars"]) ?? [],
              deleteKeys: (execPayload.deleteKeys as string[]) ?? [],
            },
            "agent",
          );
          data = app;
          summary = `Updated environment settings for "${app.slug}"`;
          break;
        }
        case "set_domain": {
          const slug = String(execPayload.slug ?? claimed.targetSlug ?? "");
          const domain =
            execPayload.domain === null || execPayload.domain === undefined
              ? null
              : String(execPayload.domain);
          const app = await this.setAppDomain(slug, domain, "agent");
          data = app;
          summary = domain
            ? `Bound domain ${domain} to "${app.slug}"`
            : `Removed domain from "${app.slug}"`;
          break;
        }
        case "restart_app": {
          const slug = String(execPayload.slug ?? claimed.targetSlug ?? "");
          const app = await this.lifecycleApp(slug, "restart", "agent");
          data = app;
          summary = `Restarted "${app.slug}" (${app.status})`;
          break;
        }
        case "stop_app": {
          const slug = String(execPayload.slug ?? claimed.targetSlug ?? "");
          const app = await this.lifecycleApp(slug, "stop", "agent");
          data = app;
          summary = `Stopped "${app.slug}" (${app.status})`;
          break;
        }
        case "delete_app": {
          const slug = String(execPayload.slug ?? claimed.targetSlug ?? "");
          const removeFiles = execPayload.removeFiles !== false;
          const res = await this.deleteApp(slug, removeFiles, "agent");
          data = res;
          summary = `Deleted "${slug}"`;
          break;
        }
        default: {
          throw new Error(`Unsupported approval action "${String(claimed.action)}".`);
        }
      }

      this.store.completeApprovalExecution(approvalId, "executed", summary);
      return { ok: true, summary, data };
    } catch (err) {
      const msg = redactSecrets(
        err instanceof Error ? err.message : String(err),
      );
      this.store.completeApprovalExecution(approvalId, "failed", msg);
      return { ok: false, summary: msg };
    }
  }
}
