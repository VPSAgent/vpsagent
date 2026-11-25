import fs from "node:fs";
import path from "node:path";
import { z } from "zod";
import {
  type Actor,
  type AppRecord,
  AppSourceTypeSchema,
  CompanionServiceSchema,
  type DeploymentRecord,
  type HostLookupFn,
  type RegistryStore,
  type RuntimeBridge,
  RuntimeBridgeError,
  type RuntimeInspectGitResult,
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
  noDomain: z.boolean().optional(),
  internalPort: z.number().int().min(1).max(65535).optional(),
  probeHttp: z.boolean().default(true),
  probePath: z.string().min(1).max(128).default("/"),
  cpuLimit: z.string().min(1).max(16).default("0.5"),
  memoryLimitMb: z.number().int().min(64).max(131072).default(512),
  companions: z.array(CompanionServiceSchema).default([]),
  envVars: z.record(z.string(), z.string()).default({}),
});
export type DeployAppInput = z.input<typeof DeployAppInputSchema>;

export const InspectGitInputSchema = z.object({
  gitRepoUrl: z.string().min(1).max(500),
  gitBranch: z.string().min(1).max(120).nullable().optional(),
  dockerfilePath: z.string().min(1).max(200).optional(),
});
export type InspectGitInput = z.input<typeof InspectGitInputSchema>;

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

export interface StartDeploymentResult {
  done: boolean;
  deployment: DeploymentRecord;
  app: AppRecord | null;
  readinessAttempts?: number | undefined;
  missingEnvKeys: string[];
}

export interface AppExecutorOptions {
  store: RegistryStore;
  bridge: RuntimeBridge;
  appsRoot: string;
  lookupFn?: HostLookupFn | undefined;
  readinessTimeoutSeconds?: number | undefined;
  readinessPollIntervalMs?: number | undefined;
  buildTimeoutSeconds?: number | undefined;
}

const AUTO_MANAGED_ENV_KEYS = new Set(["PORT", "APP_PORT", "APP_SLUG"]);

function raceWithGrace<T>(
  promise: Promise<T>,
  waitMs: number,
): Promise<{ settled: true; value: T } | { settled: false }> {
  if (waitMs <= 0) {
    return Promise.resolve({ settled: false });
  }
  return new Promise((resolve, reject) => {
    let finished = false;
    const timer = setTimeout(() => {
      if (!finished) {
        finished = true;
        resolve({ settled: false });
      }
    }, waitMs);
    timer.unref();
    promise.then(
      (value) => {
        if (!finished) {
          finished = true;
          clearTimeout(timer);
          resolve({ settled: true, value });
        }
      },
      (err) => {
        if (!finished) {
          finished = true;
          clearTimeout(timer);
          reject(err);
        }
      },
    );
  });
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

  private acquireSlugLock(slug: string): () => void {
    if (this.activeSlugs.has(slug)) {
      throw new RuntimeBridgeError(
        409,
        `Another operation is already running for app "${slug}". Please wait a moment and try again.`,
      );
    }
    this.activeSlugs.add(slug);
    let released = false;
    return () => {
      if (!released) {
        released = true;
        this.activeSlugs.delete(slug);
      }
    };
  }

  private async withSlugLock<T>(slug: string, fn: () => Promise<T>): Promise<T> {
    const release = this.acquireSlugLock(slug);
    try {
      return await fn();
    } finally {
      release();
    }
  }

  /**
   * Computes which `.env.example` keys detected for an app are not yet configured
   * (excluding keys auto-wired by VPSAgent or attached Postgres/Redis companions).
   */
  getMissingEnvKeys(slug: string): string[] {
    const app = this.store.getApp(slug);
    if (!app || app.envExampleKeys.length === 0) {
      return [];
    }
    const configured = new Set(
      this.store.listAppEnvVars(slug).map((entry) => entry.key),
    );
    const hasPostgres = app.companions.some((c) => c.type === "postgres");
    const hasRedis = app.companions.some((c) => c.type === "redis");
    return app.envExampleKeys.filter((key) => {
      if (configured.has(key) || AUTO_MANAGED_ENV_KEYS.has(key)) {
        return false;
      }
      if (hasPostgres && (key === "DATABASE_URL" || key.startsWith("POSTGRES_"))) {
        return false;
      }
      if (hasRedis && (key === "REDIS_URL" || key.startsWith("REDIS_"))) {
        return false;
      }
      return true;
    });
  }

  /** Resolves the public domain for a deploy, optionally applying the server's default base domain. */
  resolveDefaultDomain(
    slug: string,
    explicitDomain: string | null | undefined,
    noDomain?: boolean,
  ): string | null {
    if (noDomain || explicitDomain === null) {
      return null;
    }
    if (typeof explicitDomain === "string" && explicitDomain.trim()) {
      return validateDomain(explicitDomain);
    }
    const baseDomain = this.store.getSetupState().appsBaseDomain;
    if (baseDomain) {
      return validateDomain(`${slug}.${baseDomain}`);
    }
    return null;
  }

  async inspectGitRepo(rawInput: InspectGitInput): Promise<
    RuntimeInspectGitResult & { suggestedDomain: string | null }
  > {
    if (!this.bridge.inspectGitRepo) {
      throw new RuntimeBridgeError(
        501,
        "Host runtime bridge does not support Git repository inspection.",
      );
    }
    const input = InspectGitInputSchema.parse(rawInput);
    const safeRepoUrl = await validateGitRepoUrl(
      input.gitRepoUrl,
      this.lookupFn ? { lookupFn: this.lookupFn } : undefined,
    );
    const safeBranch = input.gitBranch ? validateGitBranch(input.gitBranch) : null;
    const safeDockerfile =
      input.dockerfilePath && input.dockerfilePath !== "auto"
        ? validateDockerfilePath(input.dockerfilePath)
        : "Dockerfile";

    const result = await this.bridge.inspectGitRepo({
      gitRepoUrl: safeRepoUrl,
      gitBranch: safeBranch,
      dockerfilePath: safeDockerfile,
    });
    const baseDomain = this.store.getSetupState().appsBaseDomain;
    const suggestedDomain = baseDomain
      ? validateDomain(`${result.suggestedSlug}.${baseDomain}`)
      : null;
    return {
      ...result,
      suggestedDomain,
    };
  }

  /**
   * Starts a tracked deployment job (with optional grace wait so fast deploys finish inline
   * while slow Git builds continue safely in the background without timing out callers).
   */
  async startDeployApp(
    rawInput: DeployAppInput,
    actor: Actor,
    options?: {
      actorTokenId?: string | null;
      waitMs?: number;
      throwOnImmediateFailure?: boolean;
    },
  ): Promise<StartDeploymentResult> {
    const input = DeployAppInputSchema.parse(rawInput);
    const slug = validateAppSlug(input.slug);
    const safeDomain = this.resolveDefaultDomain(
      slug,
      input.domain,
      input.noDomain,
    );
    const safeDockerfile =
      input.dockerfilePath === "auto"
        ? "auto"
        : input.dockerfilePath
          ? validateDockerfilePath(input.dockerfilePath)
          : input.sourceType === "git"
            ? "auto"
            : "Dockerfile";
    const safeBranch = input.gitBranch ? validateGitBranch(input.gitBranch) : null;
    const initialPort = input.internalPort ?? 8080;
    const actorTokenId = options?.actorTokenId ?? null;

    const releaseLock = this.acquireSlugLock(slug);
    let backgroundStarted = false;
    try {
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
      delete mergedUserEnv.APP_SLUG;
      delete mergedUserEnv.APP_PORT;

      // Validate the full blueprint AND the 64 KiB .env size cap BEFORE mutating SQLite or disk!
      const blueprint = generateApartmentBlueprint({
        slug,
        sourceType: input.sourceType,
        image: input.sourceType === "image" ? (input.image ?? null) : null,
        gitRepoUrl: validatedGitUrl,
        gitBranch: safeBranch,
        dockerfilePath: safeDockerfile,
        internalPort: initialPort,
        probeHttp: input.probeHttp,
        probePath: input.probePath,
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
        internalPort: initialPort,
        probeHttp: input.probeHttp,
        probePath: input.probePath,
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

      const deployment = this.store.createDeployment({
        slug,
        action: "deploy_app",
        actor,
        actorTokenId,
        sourceType: input.sourceType,
        gitRepoUrl: validatedGitUrl,
        gitBranch: safeBranch,
        domain: safeDomain,
        phaseDetail:
          input.sourceType === "git"
            ? "Queued GitHub clone and container build..."
            : "Queued Locked Apartment container launch...",
      });

      const runPipeline = async (): Promise<{
        app: AppRecord;
        deployment: DeploymentRecord;
        readinessAttempts: number;
      }> => {
        let resolvedPort = initialPort;
        let buildLogs: string[] = [];
        try {
          if (input.sourceType === "git" && validatedGitUrl) {
            this.store.updateDeployment(deployment.id, {
              status: "building",
              phaseDetail: "Cloning public GitHub repository and building image...",
            });
            const buildRes = await this.bridge.buildGitImage({
              slug,
              gitRepoUrl: validatedGitUrl,
              gitBranch: safeBranch,
              dockerfilePath: safeDockerfile,
              allowAutoDetect:
                safeDockerfile === "Dockerfile" || safeDockerfile === "auto",
              timeoutSeconds: this.buildTimeoutSeconds,
            });
            buildLogs = buildRes.buildLogTail;
            if (
              input.internalPort === undefined &&
              typeof buildRes.suggestedPort === "number"
            ) {
              resolvedPort = buildRes.suggestedPort;
            }

            // If auto-detection chose a different port than provisional 8080, rewrite blueprint before launch!
            if (resolvedPort !== initialPort) {
              const updatedBlueprint = generateApartmentBlueprint({
                slug,
                sourceType: input.sourceType,
                image: null,
                gitRepoUrl: validatedGitUrl,
                gitBranch: safeBranch,
                dockerfilePath: safeDockerfile,
                internalPort: resolvedPort,
                probeHttp: input.probeHttp,
                probePath: input.probePath,
                cpuLimit: input.cpuLimit,
                memoryLimitMb: input.memoryLimitMb,
                companions: input.companions,
                envVars: mergedUserEnv,
                companionSecrets: {
                  ...(blueprint.envVars.POSTGRES_PASSWORD
                    ? { postgresPassword: blueprint.envVars.POSTGRES_PASSWORD }
                    : {}),
                  ...(blueprint.envVars.REDIS_PASSWORD
                    ? { redisPassword: blueprint.envVars.REDIS_PASSWORD }
                    : {}),
                },
              });
              writeApartmentBlueprint(this.appsRoot, updatedBlueprint);
              this.store.setAppEnvVars(
                slug,
                Object.entries(updatedBlueprint.envVars).map(([key, value]) => ({
                  key,
                  value,
                })),
              );
            }

            this.store.updateAppBuildMetadata(slug, {
              lastCommitSha: buildRes.commitSha ?? null,
              detectedRuntime: buildRes.detectedRuntime ?? null,
              envExampleKeys: buildRes.envExampleKeys ?? [],
              internalPort: resolvedPort,
            });
            this.store.updateDeployment(deployment.id, {
              status: "starting",
              commitSha: buildRes.commitSha ?? null,
              detectedRuntime: buildRes.detectedRuntime ?? null,
              usedAutoDockerfile: Boolean(buildRes.usedAutoDockerfile),
              buildLogs,
              phaseDetail: buildRes.usedAutoDockerfile
                ? `Built with auto-detected ${buildRes.detectedRuntime ?? "runtime"} (port ${resolvedPort}). Starting container...`
                : `Built image (port ${resolvedPort}). Starting container...`,
            });
          } else {
            this.store.updateDeployment(deployment.id, {
              status: "starting",
              phaseDetail: "Starting Locked Apartment container...",
            });
          }

          await this.bridge.lifecycle(slug, "start");

          this.store.updateDeployment(deployment.id, {
            status: "verifying",
            phaseDetail: `Checking app health on internal port ${resolvedPort}...`,
          });

          const readiness = await this.bridge.waitForReadiness(slug, {
            internalPort: resolvedPort,
            probeHttp: input.probeHttp,
            probePath: input.probePath,
            timeoutSeconds: this.readinessTimeoutSeconds,
            pollIntervalMs: this.readinessPollIntervalMs,
          });

          if (!readiness.ready) {
            throw new RuntimeBridgeError(
              502,
              readiness.reason ??
                `App "${slug}" failed startup readiness checks.`,
            );
          }

          if (safeDomain) {
            await this.bridge.routeCaddy({
              slug,
              domain: safeDomain,
              internalPort: resolvedPort,
            });
            this.store.updateAppDomain(slug, safeDomain);
          }

          const running = this.store.updateAppStatus(slug, "running")!;
          const succeededDeployment = this.store.updateDeployment(deployment.id, {
            status: "succeeded",
            domain: running.domain,
            phaseDetail: running.domain
              ? `App is live at https://${running.domain}`
              : "App is running safely inside its Locked Apartment.",
            buildLogs,
            error: null,
          })!;

          this.store.recordAudit({
            actor,
            actorTokenId,
            action: "deploy_app",
            targetSlug: slug,
            summary: `Deployed ${input.sourceType} app "${input.name}" (${slug})${safeDomain ? ` on ${safeDomain}` : ""}`,
            riskLevel: "medium",
          });

          return {
            app: running,
            deployment: succeededDeployment,
            readinessAttempts: readiness.attempts,
          };
        } catch (err) {
          const errLogs =
            err instanceof RuntimeBridgeError && err.buildLogTail.length > 0
              ? err.buildLogTail
              : buildLogs;
          const errMessage = redactSecrets(
            err instanceof Error ? err.message : String(err),
          );
          this.store.updateDeployment(deployment.id, {
            status: "failed",
            phaseDetail: "Deployment failed.",
            buildLogs: errLogs,
            error: errMessage,
          });

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
            actorTokenId,
            action: "deploy_app_failed",
            targetSlug: slug,
            summary: `Deploy failed for "${slug}": ${errMessage}`,
            riskLevel: "high",
          });
          throw err;
        } finally {
          releaseLock();
        }
      };

      backgroundStarted = true;
      const pipelinePromise = runPipeline();
      // Attach a catch handler so background failures never trigger unhandledRejection
      pipelinePromise.catch(() => {});

      const waitMs = options?.waitMs ?? 0;
      const raced = await raceWithGrace(pipelinePromise, waitMs).catch((err) => {
        if (options?.throwOnImmediateFailure) {
          throw err;
        }
        return {
          settled: true as const,
          failedDeployment: this.store.getDeployment(deployment.id)!,
        };
      });

      if (raced.settled) {
        if ("failedDeployment" in raced) {
          return {
            done: true,
            deployment: raced.failedDeployment,
            app: this.store.getApp(slug),
            missingEnvKeys: this.getMissingEnvKeys(slug),
          };
        }
        return {
          done: true,
          deployment: raced.value.deployment,
          app: raced.value.app,
          readinessAttempts: raced.value.readinessAttempts,
          missingEnvKeys: this.getMissingEnvKeys(slug),
        };
      }

      return {
        done: false,
        deployment: this.store.getDeployment(deployment.id) ?? deployment,
        app: this.store.getApp(slug),
        missingEnvKeys: [],
      };
    } finally {
      if (!backgroundStarted) {
        releaseLock();
      }
    }
  }

  async deployApp(
    rawInput: DeployAppInput,
    actor: Actor,
    actorTokenId?: string | null,
  ): Promise<{
    app: AppRecord;
    deployment: DeploymentRecord;
    readinessAttempts: number;
    missingEnvKeys: string[];
  }> {
    const res = await this.startDeployApp(rawInput, actor, {
      actorTokenId: actorTokenId ?? null,
      waitMs: (this.buildTimeoutSeconds + this.readinessTimeoutSeconds + 60) * 1000,
      throwOnImmediateFailure: true,
    });
    if (!res.app) {
      throw new RuntimeBridgeError(
        500,
        res.deployment.error ?? "Deployment did not produce an app record.",
      );
    }
    return {
      app: res.app,
      deployment: res.deployment,
      readinessAttempts: res.readinessAttempts ?? 1,
      missingEnvKeys: res.missingEnvKeys,
    };
  }

  async startRebuildApp(
    slugRaw: string,
    actor: Actor,
    options?: {
      actorTokenId?: string | null;
      waitMs?: number;
      throwOnImmediateFailure?: boolean;
    },
  ): Promise<StartDeploymentResult> {
    const slug = validateAppSlug(slugRaw);
    const existing = this.store.getApp(slug);
    if (!existing) {
      throw new RuntimeBridgeError(404, `App "${slug}" not found.`);
    }
    const actorTokenId = options?.actorTokenId ?? null;

    const releaseLock = this.acquireSlugLock(slug);
    let backgroundStarted = false;
    try {
      let safeRepo: string | null = null;
      if (existing.sourceType === "git") {
        if (!existing.gitRepoUrl) {
          throw new RuntimeBridgeError(
            400,
            `Git app "${slug}" is missing gitRepoUrl.`,
          );
        }
        safeRepo = await validateGitRepoUrl(
          existing.gitRepoUrl,
          this.lookupFn ? { lookupFn: this.lookupFn } : undefined,
        );
      }

      const deployment = this.store.createDeployment({
        slug,
        action: "rebuild_app",
        actor,
        actorTokenId,
        sourceType: existing.sourceType,
        gitRepoUrl: safeRepo ?? existing.gitRepoUrl,
        gitBranch: existing.gitBranch,
        domain: existing.domain,
        phaseDetail:
          existing.sourceType === "git"
            ? "Queued GitHub rebuild..."
            : "Queued container rebuild...",
      });

      const runPipeline = async (): Promise<{
        app: AppRecord;
        deployment: DeploymentRecord;
      }> => {
        let buildLogs: string[] = [];
        try {
          const currentEnv = this.store.getAppEnvMapForRuntime(slug);
          const userEnv = { ...currentEnv };
          delete userEnv.APP_SLUG;
          delete userEnv.APP_PORT;

          if (existing.sourceType === "git" && safeRepo) {
            this.store.updateAppStatus(slug, "building");
            this.store.updateDeployment(deployment.id, {
              status: "building",
              phaseDetail: "Re-cloning public GitHub repository and rebuilding image...",
            });
            const buildRes = await this.bridge.buildGitImage({
              slug,
              gitRepoUrl: safeRepo,
              gitBranch: existing.gitBranch,
              dockerfilePath: existing.dockerfilePath,
              allowAutoDetect:
                existing.dockerfilePath === "Dockerfile" ||
                existing.dockerfilePath === "auto",
              timeoutSeconds: this.buildTimeoutSeconds,
            });
            buildLogs = buildRes.buildLogTail;
            this.store.updateAppBuildMetadata(slug, {
              lastCommitSha: buildRes.commitSha ?? null,
              detectedRuntime:
                buildRes.detectedRuntime ?? existing.detectedRuntime,
              ...(buildRes.envExampleKeys
                ? { envExampleKeys: buildRes.envExampleKeys }
                : {}),
            });
            this.store.updateDeployment(deployment.id, {
              status: "starting",
              commitSha: buildRes.commitSha ?? null,
              detectedRuntime: buildRes.detectedRuntime ?? existing.detectedRuntime,
              usedAutoDockerfile: Boolean(buildRes.usedAutoDockerfile),
              buildLogs,
              phaseDetail: "Rebuild succeeded. Restarting Locked Apartment container...",
            });
          } else {
            this.store.updateDeployment(deployment.id, {
              status: "starting",
              phaseDetail: "Restarting Locked Apartment container...",
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
            probeHttp: existing.probeHttp,
            probePath: existing.probePath,
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

          this.store.updateDeployment(deployment.id, {
            status: "verifying",
            phaseDetail: `Checking app health on internal port ${existing.internalPort}...`,
          });

          const readiness = await this.bridge.waitForReadiness(slug, {
            internalPort: existing.internalPort,
            probeHttp: existing.probeHttp,
            probePath: existing.probePath,
            timeoutSeconds: this.readinessTimeoutSeconds,
            pollIntervalMs: this.readinessPollIntervalMs,
          });
          if (!readiness.ready) {
            throw new RuntimeBridgeError(
              502,
              readiness.reason ??
                `App "${slug}" failed readiness after rebuild.`,
            );
          }

          const updated = this.store.updateAppStatus(slug, "running")!;
          const succeededDeployment = this.store.updateDeployment(deployment.id, {
            status: "succeeded",
            phaseDetail: updated.domain
              ? `Rebuild live at https://${updated.domain}`
              : "Rebuild finished and app is healthy.",
            buildLogs,
            error: null,
          })!;
          this.store.recordAudit({
            actor,
            actorTokenId,
            action: "rebuild_app",
            targetSlug: slug,
            summary: `Rebuilt and restarted app "${slug}"`,
            riskLevel: "medium",
          });
          return { app: updated, deployment: succeededDeployment };
        } catch (err) {
          const errLogs =
            err instanceof RuntimeBridgeError && err.buildLogTail.length > 0
              ? err.buildLogTail
              : buildLogs;
          const errMessage = redactSecrets(
            err instanceof Error ? err.message : String(err),
          );
          this.store.updateAppStatus(slug, "error");
          this.store.updateDeployment(deployment.id, {
            status: "failed",
            phaseDetail: "Rebuild failed.",
            buildLogs: errLogs,
            error: errMessage,
          });
          this.store.recordAudit({
            actor,
            actorTokenId,
            action: "rebuild_app_failed",
            targetSlug: slug,
            summary: `Rebuild failed for "${slug}": ${errMessage}`,
            riskLevel: "high",
          });
          throw err;
        } finally {
          releaseLock();
        }
      };

      backgroundStarted = true;
      const pipelinePromise = runPipeline();
      pipelinePromise.catch(() => {});

      const waitMs = options?.waitMs ?? 0;
      const raced = await raceWithGrace(pipelinePromise, waitMs).catch((err) => {
        if (options?.throwOnImmediateFailure) {
          throw err;
        }
        return {
          settled: true as const,
          failedDeployment: this.store.getDeployment(deployment.id)!,
        };
      });

      if (raced.settled) {
        if ("failedDeployment" in raced) {
          return {
            done: true,
            deployment: raced.failedDeployment,
            app: this.store.getApp(slug),
            missingEnvKeys: this.getMissingEnvKeys(slug),
          };
        }
        return {
          done: true,
          deployment: raced.value.deployment,
          app: raced.value.app,
          missingEnvKeys: this.getMissingEnvKeys(slug),
        };
      }

      return {
        done: false,
        deployment: this.store.getDeployment(deployment.id) ?? deployment,
        app: this.store.getApp(slug),
        missingEnvKeys: [],
      };
    } finally {
      if (!backgroundStarted) {
        releaseLock();
      }
    }
  }

  async rebuildApp(
    slugRaw: string,
    actor: Actor,
    actorTokenId?: string | null,
  ): Promise<AppRecord> {
    const res = await this.startRebuildApp(slugRaw, actor, {
      actorTokenId: actorTokenId ?? null,
      waitMs: (this.buildTimeoutSeconds + this.readinessTimeoutSeconds + 60) * 1000,
      throwOnImmediateFailure: true,
    });
    if (!res.app) {
      throw new RuntimeBridgeError(
        500,
        res.deployment.error ?? `Rebuild failed for "${slugRaw}".`,
      );
    }
    return res.app;
  }

  async updateAppEnv(
    slugRaw: string,
    rawInput: UpdateAppEnvInput,
    actor: Actor,
    actorTokenId?: string | null,
  ): Promise<AppRecord> {
    const slug = validateAppSlug(slugRaw);
    const input = UpdateAppEnvInputSchema.parse(rawInput);
    const existing = this.store.getApp(slug);
    if (!existing) {
      throw new RuntimeBridgeError(404, `App "${slug}" not found.`);
    }

    return this.withSlugLock(slug, async () => {
      // Compute the candidate merged env map and validate the full 64 KiB .env
      // size & key rules BEFORE mutating SQLite or writing any file on disk!
      const currentEnv = this.store.getAppEnvMapForRuntime(slug);
      const candidateEnv: Record<string, string> = { ...currentEnv };
      const validatedDeleteKeys = input.deleteKeys.map((k) => validateEnvKey(k));
      for (const delKey of validatedDeleteKeys) {
        delete candidateEnv[delKey];
      }
      const validatedVars = input.vars.map((v) => ({
        key: validateEnvKey(v.key),
        value: v.value,
        ...(v.isSecret !== undefined ? { isSecret: v.isSecret } : {}),
      }));
      for (const item of validatedVars) {
        candidateEnv[item.key] = item.value;
      }

      const userEnv = { ...candidateEnv };
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
        probeHttp: existing.probeHttp,
        probePath: existing.probePath,
        cpuLimit: existing.cpuLimit,
        memoryLimitMb: existing.memoryLimitMb,
        companions: existing.companions,
        envVars: userEnv,
        companionSecrets: {
          ...(candidateEnv.POSTGRES_PASSWORD
            ? { postgresPassword: candidateEnv.POSTGRES_PASSWORD }
            : {}),
          ...(candidateEnv.REDIS_PASSWORD
            ? { redisPassword: candidateEnv.REDIS_PASSWORD }
            : {}),
        },
      });

      // Snapshot existing blueprint files so a failed write/apply rolls back cleanly
      // and NEVER commits broken changes to SQLite.
      const appDir = resolveScopedAppDir(this.appsRoot, slug);
      const composePath = path.join(appDir, "docker-compose.yml");
      const envPath = path.join(appDir, ".env");
      const prevCompose = fs.existsSync(composePath)
        ? fs.readFileSync(composePath, "utf8")
        : null;
      const prevEnv = fs.existsSync(envPath)
        ? fs.readFileSync(envPath, "utf8")
        : null;

      try {
        writeApartmentBlueprint(this.appsRoot, blueprint);
        if (existing.status === "running") {
          await this.bridge.lifecycle(slug, "start");
        }
      } catch (err) {
        try {
          if (prevCompose !== null) {
            fs.writeFileSync(composePath, prevCompose, {
              encoding: "utf8",
              mode: 0o644,
            });
          }
          if (prevEnv !== null) {
            fs.writeFileSync(envPath, prevEnv, {
              encoding: "utf8",
              mode: 0o600,
            });
          }
        } catch {
          // Best-effort restore on failure
        }
        throw err;
      }

      // Apply succeeded — now commit env updates to SQLite.
      for (const delKey of validatedDeleteKeys) {
        this.store.deleteAppEnvVar(slug, delKey);
      }
      if (validatedVars.length > 0) {
        this.store.setAppEnvVars(slug, validatedVars);
      }

      const changedKeys = [
        ...validatedVars.map((v) => v.key),
        ...validatedDeleteKeys.map((k) => `-${k}`),
      ];
      this.store.recordAudit({
        actor,
        actorTokenId: actorTokenId ?? null,
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
    actorTokenId?: string | null,
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
        actorTokenId: actorTokenId ?? null,
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
    actorTokenId?: string | null,
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
        actorTokenId: actorTokenId ?? null,
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
    actorTokenId?: string | null,
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
        actorTokenId: actorTokenId ?? null,
        action: "delete_app",
        targetSlug: slug,
        summary: `Deleted app "${slug}" (removeFiles=${String(removeFiles)})`,
        riskLevel: "high",
      });
      return { ok: true, slug };
    });
  }

  /**
   * Atomically claims an approved request and runs its underlying action strictly
   * from its sealed encrypted execution payload (never falling back to the redacted preview).
   */
  async executeApprovedRequest(
    approvalId: string,
    options?: { asyncDeploy?: boolean },
  ): Promise<{
    ok: boolean;
    summary: string;
    data?: unknown;
    deployment?: DeploymentRecord;
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

    let execPayload: Record<string, unknown> | null = null;
    try {
      execPayload = this.store.consumeApprovalExecutionPayload(approvalId);
    } catch (err) {
      const msg = redactSecrets(
        `Sealed execution payload could not be decrypted; refusing to execute from redacted preview (${err instanceof Error ? err.message : String(err)}).`,
      );
      this.store.completeApprovalExecution(approvalId, "failed", msg);
      return { ok: false, summary: msg };
    }

    if (!execPayload) {
      const msg =
        "Sealed execution payload is missing; refusing to execute from redacted preview.";
      this.store.completeApprovalExecution(approvalId, "failed", msg);
      return { ok: false, summary: msg };
    }

    const tokenId = claimed.tokenId;

    try {
      let data: unknown;
      let summary: string;
      let deployment: DeploymentRecord | undefined;

      switch (claimed.action) {
        case "deploy_app": {
          if (options?.asyncDeploy) {
            const started = await this.startDeployApp(
              execPayload as DeployAppInput,
              "agent",
              { actorTokenId: tokenId, waitMs: 0 },
            );
            deployment = started.deployment;
            data = started;
            summary = `Started deployment ${started.deployment.id} for "${started.deployment.slug}"`;
          } else {
            const res = await this.deployApp(
              execPayload as DeployAppInput,
              "agent",
              tokenId,
            );
            deployment = res.deployment;
            data = res.app;
            summary = `Deployed "${res.app.slug}" (${res.app.status})`;
          }
          break;
        }
        case "rebuild_app": {
          const slug = String(execPayload.slug ?? claimed.targetSlug ?? "");
          if (options?.asyncDeploy) {
            const started = await this.startRebuildApp(slug, "agent", {
              actorTokenId: tokenId,
              waitMs: 0,
            });
            deployment = started.deployment;
            data = started;
            summary = `Started rebuild ${started.deployment.id} for "${slug}"`;
          } else {
            const app = await this.rebuildApp(slug, "agent", tokenId);
            data = app;
            summary = `Rebuilt "${app.slug}" (${app.status})`;
          }
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
            tokenId,
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
          const app = await this.setAppDomain(slug, domain, "agent", tokenId);
          data = app;
          summary = domain
            ? `Bound domain ${domain} to "${app.slug}"`
            : `Removed domain from "${app.slug}"`;
          break;
        }
        case "restart_app": {
          const slug = String(execPayload.slug ?? claimed.targetSlug ?? "");
          const app = await this.lifecycleApp(slug, "restart", "agent", tokenId);
          data = app;
          summary = `Restarted "${app.slug}" (${app.status})`;
          break;
        }
        case "stop_app": {
          const slug = String(execPayload.slug ?? claimed.targetSlug ?? "");
          const app = await this.lifecycleApp(slug, "stop", "agent", tokenId);
          data = app;
          summary = `Stopped "${app.slug}" (${app.status})`;
          break;
        }
        case "delete_app": {
          const slug = String(execPayload.slug ?? claimed.targetSlug ?? "");
          const removeFiles = execPayload.removeFiles !== false;
          const res = await this.deleteApp(slug, removeFiles, "agent", tokenId);
          data = res;
          summary = `Deleted "${slug}"`;
          break;
        }
        default: {
          throw new Error(
            `Unsupported approval action "${String(claimed.action)}".`,
          );
        }
      }

      this.store.completeApprovalExecution(approvalId, "executed", summary);
      return {
        ok: true,
        summary,
        data,
        ...(deployment ? { deployment } : {}),
      };
    } catch (err) {
      const msg = redactSecrets(
        err instanceof Error ? err.message : String(err),
      );
      this.store.completeApprovalExecution(approvalId, "failed", msg);
      return { ok: false, summary: msg };
    }
  }
}
