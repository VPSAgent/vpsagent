import fs from "node:fs";
import path from "node:path";
import { z } from "zod";
import {
  type Actor,
  type AppRecord,
  AppSourceTypeSchema,
  CompanionServiceSchema,
  type DeploymentRecord,
  type GithubRepoSummary,
  type HostLookupFn,
  type RegistryStore,
  type RuntimeBridge,
  RuntimeBridgeError,
  type RuntimeInspectGitResult,
  type RuntimeCommandResult,
  type RuntimeDeleteFileResult,
  type RuntimeDockerCleanupResult,
  type RuntimeManageServiceResult,
  RuntimeServiceActionSchema,
  type RuntimeWriteFileResult,
  generateApartmentBlueprint,
  isGithubHttpsRepoUrl,
  parseGithubRepoOwnerAndName,
  redactSecrets,
  resolveScopedAppDir,
  scrubTokenFromText,
  validateAppSlug,
  validateDockerfilePath,
  validateDomain,
  validateEnvKey,
  validateGitBranch,
  validateGitRepoUrl,
  writeApartmentBlueprint,
} from "@vpsagent/shared";
import { listGithubReposForToken } from "./github.js";
import type { NotificationService } from "./notifications.js";

export const DeployAppInputSchema = z.object({
  slug: z.string().min(2).max(48),
  name: z.string().trim().min(1).max(100),
  sourceType: AppSourceTypeSchema,
  image: z.string().min(1).max(255).nullable().optional(),
  gitRepoUrl: z.string().min(1).max(500).nullable().optional(),
  gitBranch: z.string().min(1).max(120).nullable().optional(),
  gitCredentialId: z.string().trim().min(1).max(64).nullable().optional(),
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
  createOnly: z.boolean().optional(),
});
export type DeployAppInput = z.input<typeof DeployAppInputSchema>;

export const InspectGitInputSchema = z.object({
  gitRepoUrl: z.string().min(1).max(500),
  gitBranch: z.string().min(1).max(120).nullable().optional(),
  gitCredentialId: z.string().trim().min(1).max(64).nullable().optional(),
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

export const UpdateAppSettingsInputSchema = z.object({
  name: z.string().trim().min(1).max(100).optional(),
  cpuLimit: z.string().min(1).max(16).optional(),
  memoryLimitMb: z.number().int().min(64).max(131072).optional(),
  internalPort: z.number().int().min(1).max(65535).optional(),
  probeHttp: z.boolean().optional(),
  probePath: z.string().min(1).max(128).optional(),
  image: z.string().min(1).max(255).optional(),
  gitBranch: z.string().min(1).max(120).nullable().optional(),
  dockerfilePath: z.string().min(1).max(200).optional(),
  gitCredentialId: z.string().trim().min(1).max(64).nullable().optional(),
  companions: z.array(CompanionServiceSchema).optional(),
});
export type UpdateAppSettingsInput = z.input<typeof UpdateAppSettingsInputSchema>;

export interface StartDeploymentResult {
  done: boolean;
  deployment: DeploymentRecord;
  app: AppRecord | null;
  readinessAttempts?: number | undefined;
  missingEnvKeys: string[];
}

export const ExecInAppInputSchema = z.object({
  slug: z.string().min(2).max(48),
  command: z.string().trim().min(1).max(8000),
  service: z
    .string()
    .regex(/^[a-z0-9][a-z0-9_-]{0,47}$/)
    .optional(),
  timeoutSeconds: z.number().int().min(1).max(180).optional(),
});
export type ExecInAppInput = z.input<typeof ExecInAppInputSchema>;

export const RunHostCommandInputSchema = z.object({
  command: z.string().trim().min(1).max(8000),
  cwd: z.string().trim().min(1).max(512).optional(),
  timeoutSeconds: z.number().int().min(1).max(180).optional(),
});
export type RunHostCommandInput = z.input<typeof RunHostCommandInputSchema>;

export const WriteHostFileInputSchema = z.object({
  path: z.string().trim().min(1).max(1024),
  content: z.string().max(262144),
  append: z.boolean().default(false),
  createDirs: z.boolean().default(false),
});
export type WriteHostFileInput = z.input<typeof WriteHostFileInputSchema>;

export const DeleteHostFileInputSchema = z.object({
  path: z.string().trim().min(1).max(1024),
  recursive: z.boolean().default(false),
});
export type DeleteHostFileInput = z.input<typeof DeleteHostFileInputSchema>;

export const ManageHostServiceInputSchema = z.object({
  service: z
    .string()
    .trim()
    .regex(/^[A-Za-z0-9@._-]{1,128}$/),
  action: RuntimeServiceActionSchema,
});
export type ManageHostServiceInput = z.input<
  typeof ManageHostServiceInputSchema
>;

export const DockerCleanupInputSchema = z.object({
  pruneImages: z.boolean().default(true),
  pruneBuildCache: z.boolean().default(true),
  pruneVolumes: z.boolean().default(false),
});
export type DockerCleanupInput = z.input<typeof DockerCleanupInputSchema>;

export interface AppExecutorOptions {
  store: RegistryStore;
  bridge: RuntimeBridge;
  appsRoot: string;
  lookupFn?: HostLookupFn | undefined;
  readinessTimeoutSeconds?: number | undefined;
  readinessPollIntervalMs?: number | undefined;
  buildTimeoutSeconds?: number | undefined;
  githubApiBaseUrl?: string | undefined;
  githubFetchFn?: typeof fetch | undefined;
  notifier?: NotificationService | undefined;
  onIntentionalStop?: ((slug: string) => void) | undefined;
  onAppStarted?: ((slug: string) => void) | undefined;
}

interface GitAuthCandidate {
  id: string | null;
  token: string | null;
}

const MAX_SAVED_GIT_AUTH_ATTEMPTS = 5;

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
  private readonly githubApiBaseUrl: string | undefined;
  private readonly githubFetchFn: typeof fetch | undefined;
  private readonly notifier: NotificationService | undefined;
  private readonly onIntentionalStop: ((slug: string) => void) | undefined;
  private readonly onAppStarted: ((slug: string) => void) | undefined;
  private readonly activeSlugs = new Set<string>();
  private readonly pendingWebhookRebuilds = new Set<string>();

  constructor(options: AppExecutorOptions) {
    this.store = options.store;
    this.bridge = options.bridge;
    this.appsRoot = options.appsRoot;
    this.lookupFn = options.lookupFn;
    this.readinessTimeoutSeconds = options.readinessTimeoutSeconds ?? 15;
    this.readinessPollIntervalMs = options.readinessPollIntervalMs ?? 500;
    this.buildTimeoutSeconds = options.buildTimeoutSeconds ?? 300;
    this.githubApiBaseUrl = options.githubApiBaseUrl;
    this.githubFetchFn = options.githubFetchFn;
    this.notifier = options.notifier;
    this.onIntentionalStop = options.onIntentionalStop;
    this.onAppStarted = options.onAppStarted;
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
        if (this.pendingWebhookRebuilds.delete(slug)) {
          queueMicrotask(() => {
            const latest = this.store.getApp(slug);
            if (!latest || latest.sourceType !== "git") {
              return;
            }
            void this.startRebuildApp(slug, "system", { waitMs: 0 }).catch(
              (err) => {
                if (err instanceof RuntimeBridgeError && err.statusCode === 409) {
                  this.pendingWebhookRebuilds.add(slug);
                }
              },
            );
          });
        }
      }
    };
  }

  async queueOrStartWebhookRebuild(slugRaw: string): Promise<{
    triggered: boolean;
    queued: boolean;
    deploymentId?: string;
    reason?: string;
  }> {
    const slug = validateAppSlug(slugRaw);
    try {
      const started = await this.startRebuildApp(slug, "system", {
        waitMs: 0,
      });
      return {
        triggered: true,
        queued: false,
        deploymentId: started.deployment.id,
      };
    } catch (err) {
      if (err instanceof RuntimeBridgeError && err.statusCode === 409) {
        this.pendingWebhookRebuilds.add(slug);
        return {
          triggered: false,
          queued: true,
          reason:
            "Rebuild already in progress; queued a follow-up rebuild for the latest push.",
        };
      }
      throw err;
    }
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

  private getRankedGithubCandidates(
    repoUrl: string,
    excludeIds = new Set<string>(),
  ): GitAuthCandidate[] {
    const owner = parseGithubRepoOwnerAndName(repoUrl)?.owner.toLowerCase() ?? null;
    const allCreds = this.store
      .listGitCredentials()
      .filter((c) => !excludeIds.has(c.id));

    const tier1 = allCreds.filter(
      (c) => owner && c.accountLogin?.toLowerCase() === owner && c.isDefault,
    );
    const tier2 = allCreds.filter(
      (c) => owner && c.accountLogin?.toLowerCase() === owner && !c.isDefault,
    );
    const tier3 = allCreds.filter(
      (c) =>
        c.isDefault && !(owner && c.accountLogin?.toLowerCase() === owner),
    );
    const tier4 = allCreds.filter(
      (c) =>
        !c.isDefault && !(owner && c.accountLogin?.toLowerCase() === owner),
    );

    const ordered = [...tier1, ...tier2, ...tier3, ...tier4];
    const resolved: GitAuthCandidate[] = [];
    for (const cred of ordered) {
      if (resolved.length >= MAX_SAVED_GIT_AUTH_ATTEMPTS) {
        break;
      }
      const secret = this.store.getGitCredentialSecretForRuntime(cred.id);
      if (secret) {
        resolved.push({ id: secret.record.id, token: secret.token });
      }
    }
    return resolved;
  }

  private buildGitAuthCandidates(
    repoUrl: string,
    opts?: {
      explicitCredentialId?: string | null;
      storedCredentialId?: string | null;
      allowSavedGitCredentials?: boolean;
    },
  ): GitAuthCandidate[] {
    const allowSaved = opts?.allowSavedGitCredentials !== false;
    const explicitId = opts?.explicitCredentialId?.trim() || null;
    if (explicitId) {
      if (!allowSaved) {
        throw new RuntimeBridgeError(
          403,
          "This app-locked visitor pass cannot use the owner's saved GitHub credentials for an unrelated repository.",
        );
      }
      if (!isGithubHttpsRepoUrl(repoUrl)) {
        throw new RuntimeBridgeError(
          400,
          "GitHub access tokens can only be used with https://github.com repositories.",
        );
      }
      const secret = this.store.getGitCredentialSecretForRuntime(explicitId);
      if (!secret) {
        throw new RuntimeBridgeError(
          404,
          `GitHub access token "${explicitId}" was not found.`,
        );
      }
      return [{ id: secret.record.id, token: secret.token }];
    }

    if (!allowSaved || !isGithubHttpsRepoUrl(repoUrl)) {
      return [{ id: null, token: null }];
    }

    const storedId = opts?.storedCredentialId?.trim() || null;
    if (storedId) {
      const candidates: GitAuthCandidate[] = [];
      const seen = new Set<string>();
      const storedSecret = this.store.getGitCredentialSecretForRuntime(storedId);
      if (storedSecret) {
        candidates.push({ id: storedSecret.record.id, token: storedSecret.token });
        seen.add(storedSecret.record.id);
      }
      const remaining = this.getRankedGithubCandidates(repoUrl, seen).slice(
        0,
        Math.max(0, MAX_SAVED_GIT_AUTH_ATTEMPTS - candidates.length),
      );
      candidates.push(...remaining);
      candidates.push({ id: null, token: null });
      return candidates;
    }

    return [
      { id: null, token: null },
      ...this.getRankedGithubCandidates(repoUrl),
    ];
  }

  private async runGitWithCandidates<T>(
    repoUrl: string,
    candidates: GitAuthCandidate[],
    fn: (candidate: GitAuthCandidate) => Promise<T>,
  ): Promise<{ value: T; usedCredentialId: string | null }> {
    let lastAuthError: RuntimeBridgeError | null = null;
    for (const candidate of candidates) {
      try {
        const value = await fn(candidate);
        if (candidate.id) {
          this.store.touchGitCredentialLastUsed(candidate.id);
        }
        return { value, usedCredentialId: candidate.id };
      } catch (err) {
        if (err instanceof RuntimeBridgeError) {
          const scrubbed = new RuntimeBridgeError(
            err.statusCode,
            scrubTokenFromText(err.message, candidate.token),
            err.buildLogTail.map((line) =>
              scrubTokenFromText(line, candidate.token),
            ),
          );
          if (err.statusCode === 401) {
            lastAuthError = scrubbed;
            continue;
          }
          throw scrubbed;
        }
        const msg = err instanceof Error ? err.message : String(err);
        throw new Error(scrubTokenFromText(msg, candidate.token));
      }
    }

    if (!isGithubHttpsRepoUrl(repoUrl)) {
      throw (
        lastAuthError ??
        new RuntimeBridgeError(
          401,
          "Authentication required: this repository appears to be private or does not exist.",
        )
      );
    }

    const savedCount = this.store.listGitCredentials().length;
    if (savedCount === 0) {
      throw new RuntimeBridgeError(
        401,
        "This GitHub repository appears to be private (or was not found). Connect a GitHub access token in AI Keys & Settings → Private GitHub Repos, then try again.",
      );
    }
    throw new RuntimeBridgeError(
      401,
      "GitHub rejected access to this repository using your saved GitHub token(s). Verify the repository URL is correct and that your token has not expired and has Read-only Contents permission for this repo.",
    );
  }

  async listGithubRepos(options?: {
    credentialId?: string | undefined;
    query?: string | undefined;
    limit?: number | undefined;
  }): Promise<{
    connected: boolean;
    repos: GithubRepoSummary[];
    hasMore: boolean;
    errors: Array<{ credentialId: string; label: string; error: string }>;
  }> {
    const allCredentials = this.store.listGitCredentials();
    const targetId = options?.credentialId?.trim() || undefined;
    const targets = targetId
      ? allCredentials.filter((c) => c.id === targetId)
      : allCredentials;
    if (targetId && targets.length === 0) {
      throw new RuntimeBridgeError(
        404,
        `GitHub access token "${targetId}" was not found.`,
      );
    }
    if (targets.length === 0) {
      return { connected: false, repos: [], hasMore: false, errors: [] };
    }

    const seenFullNames = new Set<string>();
    const repos: GithubRepoSummary[] = [];
    const errors: Array<{ credentialId: string; label: string; error: string }> =
      [];
    let anyHasMore = false;

    for (const cred of targets) {
      const secret = this.store.getGitCredentialSecretForRuntime(cred.id);
      if (!secret) {
        continue;
      }
      try {
        const fetched = await listGithubReposForToken(
          secret.token,
          { credentialId: cred.id, credentialLabel: cred.label },
          {
            apiBaseUrl: this.githubApiBaseUrl,
            fetchFn: this.githubFetchFn,
            ...(options?.query ? { query: options.query } : {}),
            limit: 100,
          },
        );
        if (fetched.hasMore) {
          anyHasMore = true;
        }
        for (const repo of fetched.repos) {
          const key = repo.fullName.toLowerCase();
          if (!seenFullNames.has(key)) {
            seenFullNames.add(key);
            repos.push(repo);
          }
        }
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        errors.push({
          credentialId: cred.id,
          label: cred.label,
          error: scrubTokenFromText(msg, secret.token),
        });
      }
    }

    repos.sort((a, b) => (b.updatedAt ?? "").localeCompare(a.updatedAt ?? ""));
    const limit = Math.min(Math.max(options?.limit ?? 50, 1), 100);
    return {
      connected: true,
      repos: repos.slice(0, limit),
      hasMore: anyHasMore || repos.length > limit,
      errors,
    };
  }

  async inspectGitRepo(
    rawInput: InspectGitInput,
    options?: { allowSavedGitCredentials?: boolean | undefined },
  ): Promise<
    RuntimeInspectGitResult & {
      suggestedDomain: string | null;
      usedAuth: boolean;
      gitCredentialId: string | null;
    }
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
    const explicitCredentialId = input.gitCredentialId?.trim() || null;
    const candidates = this.buildGitAuthCandidates(safeRepoUrl, {
      explicitCredentialId,
      allowSavedGitCredentials: options?.allowSavedGitCredentials !== false,
    });

    const { value: result, usedCredentialId } = await this.runGitWithCandidates(
      safeRepoUrl,
      candidates,
      (candidate) =>
        this.bridge.inspectGitRepo!({
          gitRepoUrl: safeRepoUrl,
          gitBranch: safeBranch,
          dockerfilePath: safeDockerfile,
          ...(candidate.token ? { gitToken: candidate.token } : {}),
        }),
    );
    const baseDomain = this.store.getSetupState().appsBaseDomain;
    const suggestedDomain = baseDomain
      ? validateDomain(`${result.suggestedSlug}.${baseDomain}`)
      : null;
    return {
      ...result,
      usedAuth: Boolean(result.usedAuth ?? usedCredentialId),
      gitCredentialId: usedCredentialId,
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
      allowSavedGitCredentials?: boolean;
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
      const priorCommitSha = existing?.lastCommitSha ?? null;
      const priorImage = existing?.image ?? null;
      if (input.createOnly && existing) {
        throw new RuntimeBridgeError(
          409,
          `An app with short ID "${slug}" already exists. Choose a different short ID or use Rebuild on the existing app.`,
        );
      }
      let validatedGitUrl: string | null = null;
      const explicitCredentialId = input.gitCredentialId?.trim() || null;
      let gitCandidates: GitAuthCandidate[] = [{ id: null, token: null }];

      if (input.sourceType === "git") {
        if (!input.gitRepoUrl) {
          throw new Error("Git apps require a gitRepoUrl.");
        }
        validatedGitUrl = await validateGitRepoUrl(
          input.gitRepoUrl,
          this.lookupFn ? { lookupFn: this.lookupFn } : undefined,
        );
        gitCandidates = this.buildGitAuthCandidates(validatedGitUrl, {
          explicitCredentialId,
          allowSavedGitCredentials: options?.allowSavedGitCredentials !== false,
        });
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
        gitCredentialId:
          input.sourceType === "git"
            ? (explicitCredentialId ?? existing?.gitCredentialId ?? null)
            : null,
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

      const previousMode: "clear" | "preserve" | "save" = !existing
        ? "clear"
        : existing.status === "error" && existing.rollbackAvailable
          ? "preserve"
          : "save";

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
              phaseDetail: explicitCredentialId
                ? "Cloning private GitHub repository and building image..."
                : "Cloning GitHub repository and building image...",
            });
            const { value: buildRes, usedCredentialId } =
              await this.runGitWithCandidates(
                validatedGitUrl,
                gitCandidates,
                (candidate) =>
                  this.bridge.buildGitImage({
                    slug,
                    gitRepoUrl: validatedGitUrl,
                    gitBranch: safeBranch,
                    dockerfilePath: safeDockerfile,
                    ...(candidate.token ? { gitToken: candidate.token } : {}),
                    allowAutoDetect:
                      safeDockerfile === "Dockerfile" ||
                      safeDockerfile === "auto",
                    timeoutSeconds: this.buildTimeoutSeconds,
                    previousMode,
                  }),
              );
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
              gitCredentialId: usedCredentialId,
            });
            if (
              existing &&
              previousMode === "save" &&
              buildRes.previousImageSaved
            ) {
              this.store.updateAppRollbackState(slug, {
                previousCommitSha: priorCommitSha,
                previousImage: priorImage,
                rollbackAvailable: true,
              });
            }
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
            if (
              existing &&
              priorImage &&
              priorImage !== blueprint.imageRef &&
              previousMode === "save"
            ) {
              this.store.updateAppRollbackState(slug, {
                previousCommitSha: null,
                previousImage: priorImage,
                rollbackAvailable: true,
              });
            }
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

          this.onAppStarted?.(slug);
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
          const failedDeployment = this.store.updateDeployment(deployment.id, {
            status: "failed",
            phaseDetail: "Deployment failed.",
            buildLogs: errLogs,
            error: errMessage,
          });
          this.notifier?.notifyDeployFailed(
            slug,
            failedDeployment ?? deployment,
            errMessage,
            { appExists: Boolean(existing) },
          );

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
      let gitCandidates: GitAuthCandidate[] = [{ id: null, token: null }];
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
        gitCandidates = this.buildGitAuthCandidates(safeRepo, {
          storedCredentialId: existing.gitCredentialId,
        });
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

      const priorCommitSha = existing.lastCommitSha ?? null;
      const priorImage = existing.image ?? null;
      const previousMode: "preserve" | "save" =
        existing.status === "error" && existing.rollbackAvailable
          ? "preserve"
          : "save";
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
              phaseDetail: existing.gitCredentialId
                ? "Re-cloning private GitHub repository and rebuilding image..."
                : "Re-cloning GitHub repository and rebuilding image...",
            });
            const { value: buildRes, usedCredentialId } =
              await this.runGitWithCandidates(
                safeRepo,
                gitCandidates,
                (candidate) =>
                  this.bridge.buildGitImage({
                    slug,
                    gitRepoUrl: safeRepo,
                    gitBranch: existing.gitBranch,
                    dockerfilePath: existing.dockerfilePath,
                    ...(candidate.token ? { gitToken: candidate.token } : {}),
                    allowAutoDetect:
                      existing.dockerfilePath === "Dockerfile" ||
                      existing.dockerfilePath === "auto",
                    timeoutSeconds: this.buildTimeoutSeconds,
                    previousMode,
                  }),
              );
            buildLogs = buildRes.buildLogTail;
            this.store.updateAppBuildMetadata(slug, {
              lastCommitSha: buildRes.commitSha ?? null,
              detectedRuntime:
                buildRes.detectedRuntime ?? existing.detectedRuntime,
              ...(buildRes.envExampleKeys
                ? { envExampleKeys: buildRes.envExampleKeys }
                : {}),
              gitCredentialId: usedCredentialId,
            });
            if (previousMode === "save" && buildRes.previousImageSaved) {
              this.store.updateAppRollbackState(slug, {
                previousCommitSha: priorCommitSha,
                previousImage: priorImage,
                rollbackAvailable: true,
              });
            }
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

          this.onAppStarted?.(slug);
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
          const failedDeployment = this.store.updateDeployment(deployment.id, {
            status: "failed",
            phaseDetail: "Rebuild failed.",
            buildLogs: errLogs,
            error: errMessage,
          });
          this.notifier?.notifyDeployFailed(
            slug,
            failedDeployment ?? deployment,
            errMessage,
          );
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

  async updateAppSettings(
    slugRaw: string,
    rawInput: UpdateAppSettingsInput,
    actor: Actor,
    actorTokenId?: string | null,
  ): Promise<{ app: AppRecord; needsRebuild: boolean; needsStart: boolean }> {
    const slug = validateAppSlug(slugRaw);
    const input = UpdateAppSettingsInputSchema.parse(rawInput);
    const existing = this.store.getApp(slug);
    if (!existing) {
      throw new RuntimeBridgeError(404, `App "${slug}" not found.`);
    }

    return this.withSlugLock(slug, async () => {
      const current = this.store.getApp(slug);
      if (!current) {
        throw new RuntimeBridgeError(404, `App "${slug}" not found.`);
      }

      if (current.sourceType === "git" && input.image !== undefined) {
        throw new RuntimeBridgeError(
          400,
          "Cannot set a Docker image on a GitHub-built app.",
        );
      }
      if (
        current.sourceType === "image" &&
        (input.gitBranch !== undefined ||
          input.dockerfilePath !== undefined ||
          input.gitCredentialId !== undefined)
      ) {
        throw new RuntimeBridgeError(
          400,
          "Git branch, Dockerfile path, and GitHub credentials only apply to GitHub apps.",
        );
      }

      const nextName = input.name ?? current.name;
      const nextCpuLimit = input.cpuLimit ?? current.cpuLimit;
      const nextMemoryLimitMb = input.memoryLimitMb ?? current.memoryLimitMb;
      const nextInternalPort = input.internalPort ?? current.internalPort;
      const nextProbeHttp = input.probeHttp ?? current.probeHttp;
      const nextProbePath = input.probePath ?? current.probePath;
      const nextImage =
        current.sourceType === "image"
          ? (input.image?.trim() || current.image)
          : current.image;
      const nextGitBranch =
        current.sourceType === "git"
          ? input.gitBranch === undefined
            ? current.gitBranch
            : input.gitBranch
              ? validateGitBranch(input.gitBranch)
              : null
          : null;
      const nextDockerfilePath =
        current.sourceType === "git"
          ? input.dockerfilePath === undefined
            ? current.dockerfilePath
            : input.dockerfilePath === "auto"
              ? "auto"
              : validateDockerfilePath(input.dockerfilePath)
          : current.dockerfilePath;

      let nextGitCredentialId = current.gitCredentialId;
      if (current.sourceType === "git" && input.gitCredentialId !== undefined) {
        const cleaned = input.gitCredentialId?.trim() || null;
        if (cleaned && !this.store.getGitCredential(cleaned)) {
          throw new RuntimeBridgeError(
            404,
            `GitHub access token "${cleaned}" was not found.`,
          );
        }
        nextGitCredentialId = cleaned;
      }

      const nextCompanions = input.companions ?? current.companions;
      const currentEnv = this.store.getAppEnvMapForRuntime(slug);
      const userEnv = { ...currentEnv };
      delete userEnv.APP_SLUG;
      delete userEnv.APP_PORT;
      if (
        nextInternalPort !== current.internalPort &&
        userEnv.PORT === String(current.internalPort)
      ) {
        userEnv.PORT = String(nextInternalPort);
      }

      const blueprint = generateApartmentBlueprint({
        slug,
        sourceType: current.sourceType,
        image: current.sourceType === "image" ? nextImage : null,
        gitRepoUrl: current.gitRepoUrl,
        gitBranch: nextGitBranch,
        dockerfilePath: nextDockerfilePath,
        internalPort: nextInternalPort,
        probeHttp: nextProbeHttp,
        probePath: nextProbePath,
        cpuLimit: nextCpuLimit,
        memoryLimitMb: nextMemoryLimitMb,
        companions: nextCompanions,
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

      const appDir = resolveScopedAppDir(this.appsRoot, slug);
      const composePath = path.join(appDir, "docker-compose.yml");
      const envPath = path.join(appDir, ".env");
      const probeConfigPath = path.join(appDir, "probe.json");
      const prevCompose = fs.existsSync(composePath)
        ? fs.readFileSync(composePath, "utf8")
        : null;
      const prevEnv = fs.existsSync(envPath)
        ? fs.readFileSync(envPath, "utf8")
        : null;
      const prevProbe = fs.existsSync(probeConfigPath)
        ? fs.readFileSync(probeConfigPath, "utf8")
        : null;

      let hasRunningContainer = false;
      if (current.status === "running" || current.status === "error") {
        try {
          const live = await this.bridge.inspectWorkload(slug, {
            probeHttp: false,
          });
          const expectedAppContainerName = `vpsagent-app-${slug}`;
          const appContainer = live.containers.find(
            (ct) => ct.name === expectedAppContainerName,
          );
          hasRunningContainer = appContainer
            ? appContainer.running ||
              appContainer.state.trim().toLowerCase() === "running"
            : live.containers.some(
                (ct) =>
                  ct.running || ct.state.trim().toLowerCase() === "running",
              );
        } catch {
          hasRunningContainer = current.status === "running";
        }
      }

      const runtimeSpecChanged =
        nextImage !== current.image ||
        nextInternalPort !== current.internalPort ||
        nextCpuLimit !== current.cpuLimit ||
        nextMemoryLimitMb !== current.memoryLimitMb ||
        JSON.stringify(nextCompanions) !== JSON.stringify(current.companions);
      const probeChanged =
        nextProbeHttp !== current.probeHttp ||
        nextProbePath !== current.probePath;

      let lifecycleApplied = false;
      let nextStatus = current.status;
      try {
        writeApartmentBlueprint(this.appsRoot, blueprint);
        if (hasRunningContainer) {
          if (runtimeSpecChanged || (nextProbeHttp && probeChanged)) {
            const lifeRes = await this.bridge.lifecycle(slug, "start");
            lifecycleApplied = true;
            nextStatus = lifeRes.status;
          } else {
            const statusRes = await this.bridge.lifecycle(slug, "status");
            nextStatus = statusRes.status;
          }
        }
        if (current.domain && nextInternalPort !== current.internalPort) {
          await this.bridge.routeCaddy({
            slug,
            domain: current.domain,
            internalPort: nextInternalPort,
          });
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
          if (prevProbe !== null) {
            fs.writeFileSync(probeConfigPath, prevProbe, {
              encoding: "utf8",
              mode: 0o644,
            });
          }
          if (lifecycleApplied) {
            await this.bridge.lifecycle(slug, "start");
          }
        } catch {
          // Best-effort restore on failure
        }
        throw err;
      }

      const envToStore: Array<{ key: string; value: string }> = [];
      for (const [k, v] of Object.entries(blueprint.envVars)) {
        if (currentEnv[k] !== v) {
          envToStore.push({ key: k, value: v });
        }
      }
      if (envToStore.length > 0) {
        this.store.setAppEnvVars(slug, envToStore);
      }

      this.store.upsertApp({
        slug,
        name: nextName,
        sourceType: current.sourceType,
        image: blueprint.imageRef,
        gitRepoUrl: current.gitRepoUrl,
        gitBranch: nextGitBranch,
        dockerfilePath: nextDockerfilePath,
        domain: current.domain,
        folderPath: current.folderPath,
        internalPort: nextInternalPort,
        probeHttp: nextProbeHttp,
        probePath: nextProbePath,
        status: nextStatus,
        cpuLimit: nextCpuLimit,
        memoryLimitMb: nextMemoryLimitMb,
        companions: blueprint.companions,
        gitCredentialId: nextGitCredentialId,
      });
      if (nextStatus === "running") {
        this.onAppStarted?.(slug);
      }

      if (
        current.sourceType === "image" &&
        current.image &&
        current.image !== blueprint.imageRef
      ) {
        this.store.updateAppRollbackState(slug, {
          previousImage: current.image,
          rollbackAvailable: true,
        });
      }

      const needsRebuild =
        current.sourceType === "git" &&
        (nextGitBranch !== current.gitBranch ||
          nextDockerfilePath !== current.dockerfilePath ||
          nextGitCredentialId !== current.gitCredentialId);
      const needsStart =
        !hasRunningContainer && (runtimeSpecChanged || probeChanged);

      this.store.recordAudit({
        actor,
        actorTokenId: actorTokenId ?? null,
        action: "update_app_settings",
        targetSlug: slug,
        summary: `Updated app settings for "${slug}" (${nextCpuLimit} CPU, ${nextMemoryLimitMb} MB, port ${nextInternalPort})`,
        riskLevel: "medium",
      });

      return { app: this.store.getApp(slug)!, needsRebuild, needsStart };
    });
  }

  async rollbackApp(
    slugRaw: string,
    actor: Actor,
    actorTokenId?: string | null,
  ): Promise<{ app: AppRecord; deployment: DeploymentRecord }> {
    const slug = validateAppSlug(slugRaw);
    const existing = this.store.getApp(slug);
    if (!existing) {
      throw new RuntimeBridgeError(404, `App "${slug}" not found.`);
    }

    return this.withSlugLock(slug, async () => {
      const current = this.store.getApp(slug);
      if (!current) {
        throw new RuntimeBridgeError(404, `App "${slug}" not found.`);
      }
      if (!current.rollbackAvailable) {
        throw new RuntimeBridgeError(
          400,
          `No previous working version is available to roll back "${slug}".`,
        );
      }

      const deployment = this.store.createDeployment({
        slug,
        action: "rollback_app",
        actor,
        actorTokenId: actorTokenId ?? null,
        sourceType: current.sourceType,
        gitRepoUrl: current.gitRepoUrl,
        gitBranch: current.gitBranch,
        domain: current.domain,
        phaseDetail: "Rolling back to previous working version...",
      });

      const preRollbackStatus = current.status;
      let restoredPreRollback = false;

      try {
        if (current.sourceType === "git") {
          if (!this.bridge.rollbackApp) {
            throw new RuntimeBridgeError(
              501,
              "The host Runtime Bridge needs a one-time update before rollback can run.",
            );
          }
          this.store.updateDeployment(deployment.id, {
            status: "starting",
            phaseDetail: "Restoring previous built container image...",
          });
          const rbRes = await this.bridge.rollbackApp(slug);
          this.store.updateDeployment(deployment.id, {
            status: "verifying",
            phaseDetail: `Checking app health on internal port ${current.internalPort}...`,
          });
          try {
            const readiness = await this.bridge.waitForReadiness(slug, {
              internalPort: current.internalPort,
              probeHttp: current.probeHttp,
              probePath: current.probePath,
              timeoutSeconds: this.readinessTimeoutSeconds,
              pollIntervalMs: this.readinessPollIntervalMs,
            });
            if (!readiness.ready) {
              throw new RuntimeBridgeError(
                502,
                readiness.reason ??
                  `App "${slug}" failed readiness after rollback.`,
              );
            }
          } catch (readinessErr) {
            if (rbRes.swapped) {
              try {
                const restoreRes = await this.bridge.rollbackApp(slug);
                if (preRollbackStatus === "stopped") {
                  await this.bridge.lifecycle(slug, "stop");
                  restoredPreRollback = true;
                } else {
                  restoredPreRollback = restoreRes.status === "running";
                }
              } catch {
                // Best-effort restore of pre-rollback image/tags
              }
            }
            throw readinessErr;
          }
          const nextSha = current.previousCommitSha;
          const nextPrevSha = current.lastCommitSha;
          this.store.updateAppBuildMetadata(slug, { lastCommitSha: nextSha });
          this.store.updateAppRollbackState(slug, {
            previousCommitSha: nextPrevSha,
            rollbackAvailable: rbRes.swapped || Boolean(nextPrevSha),
          });
        } else {
          if (!current.previousImage) {
            throw new RuntimeBridgeError(
              400,
              `No previous Docker image is recorded for "${slug}".`,
            );
          }
          const targetImage = current.previousImage;
          const currentEnv = this.store.getAppEnvMapForRuntime(slug);
          const userEnv = { ...currentEnv };
          delete userEnv.APP_SLUG;
          delete userEnv.APP_PORT;

          const blueprint = generateApartmentBlueprint({
            slug,
            sourceType: "image",
            image: targetImage,
            gitRepoUrl: null,
            gitBranch: null,
            dockerfilePath: current.dockerfilePath,
            internalPort: current.internalPort,
            probeHttp: current.probeHttp,
            probePath: current.probePath,
            cpuLimit: current.cpuLimit,
            memoryLimitMb: current.memoryLimitMb,
            companions: current.companions,
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

          const appDir = resolveScopedAppDir(this.appsRoot, slug);
          const composePath = path.join(appDir, "docker-compose.yml");
          const envPath = path.join(appDir, ".env");
          const probeConfigPath = path.join(appDir, "probe.json");
          const prevCompose = fs.existsSync(composePath)
            ? fs.readFileSync(composePath, "utf8")
            : null;
          const prevEnv = fs.existsSync(envPath)
            ? fs.readFileSync(envPath, "utf8")
            : null;
          const prevProbe = fs.existsSync(probeConfigPath)
            ? fs.readFileSync(probeConfigPath, "utf8")
            : null;

          this.store.updateDeployment(deployment.id, {
            status: "starting",
            phaseDetail: `Restoring previous Docker image (${targetImage})...`,
          });

          let lifecycleStarted = false;
          try {
            writeApartmentBlueprint(this.appsRoot, blueprint);
            await this.bridge.lifecycle(slug, "start");
            lifecycleStarted = true;

            this.store.updateDeployment(deployment.id, {
              status: "verifying",
              phaseDetail: `Checking app health on internal port ${current.internalPort}...`,
            });
            const readiness = await this.bridge.waitForReadiness(slug, {
              internalPort: current.internalPort,
              probeHttp: current.probeHttp,
              probePath: current.probePath,
              timeoutSeconds: this.readinessTimeoutSeconds,
              pollIntervalMs: this.readinessPollIntervalMs,
            });
            if (!readiness.ready) {
              throw new RuntimeBridgeError(
                502,
                readiness.reason ??
                  `App "${slug}" failed readiness after rollback.`,
              );
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
              if (prevProbe !== null) {
                fs.writeFileSync(probeConfigPath, prevProbe, {
                  encoding: "utf8",
                  mode: 0o644,
                });
              }
              if (lifecycleStarted) {
                const restoreRes = await this.bridge.lifecycle(
                  slug,
                  preRollbackStatus === "stopped" ? "stop" : "start",
                );
                restoredPreRollback =
                  preRollbackStatus === "running"
                    ? restoreRes.status === "running"
                    : true;
              }
            } catch {
              // Best-effort restore on failure
            }
            throw err;
          }

          this.store.upsertApp({
            slug,
            name: current.name,
            sourceType: "image",
            image: targetImage,
            gitRepoUrl: null,
            gitBranch: null,
            dockerfilePath: current.dockerfilePath,
            domain: current.domain,
            folderPath: current.folderPath,
            internalPort: current.internalPort,
            probeHttp: current.probeHttp,
            probePath: current.probePath,
            status: "running",
            cpuLimit: current.cpuLimit,
            memoryLimitMb: current.memoryLimitMb,
            companions: current.companions,
            previousImage: current.image,
            rollbackAvailable: Boolean(current.image),
          });
        }

        this.onAppStarted?.(slug);
        const running = this.store.updateAppStatus(slug, "running")!;
        const finishedDep = this.store.updateDeployment(deployment.id, {
          status: "succeeded",
          commitSha: running.lastCommitSha,
          phaseDetail: running.domain
            ? `Rollback live at https://${running.domain}`
            : "Rolled back and running safely.",
          error: null,
        })!;
        this.store.recordAudit({
          actor,
          actorTokenId: actorTokenId ?? null,
          action: "rollback_app",
          targetSlug: slug,
          summary: `Rolled back app "${slug}" to previous version`,
          riskLevel: "medium",
        });
        return { app: running, deployment: finishedDep };
      } catch (err) {
        const errMessage = redactSecrets(
          err instanceof Error ? err.message : String(err),
        );
        this.store.updateAppStatus(
          slug,
          restoredPreRollback ? preRollbackStatus : "error",
        );
        const failedDeployment = this.store.updateDeployment(deployment.id, {
          status: "failed",
          phaseDetail: "Rollback failed.",
          error: errMessage,
        });
        this.store.recordAudit({
          actor,
          actorTokenId: actorTokenId ?? null,
          action: "rollback_app_failed",
          targetSlug: slug,
          summary: `Rollback failed for "${slug}": ${errMessage}`,
          riskLevel: "high",
        });
        this.notifier?.notifyDeployFailed(
          slug,
          failedDeployment ?? deployment,
          errMessage,
        );
        throw err;
      }
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
      if (action === "stop") {
        this.onIntentionalStop?.(slug);
      } else {
        this.onAppStarted?.(slug);
      }
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
      this.onIntentionalStop?.(slug);
      await this.bridge.removeWorkload(slug, { removeFiles });
      this.store.deleteApp(slug);
      this.pendingWebhookRebuilds.delete(slug);
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

  async execInApp(
    rawInput: ExecInAppInput,
    actor: Actor,
    actorTokenId?: string | null,
  ): Promise<RuntimeCommandResult> {
    const input = ExecInAppInputSchema.parse(rawInput);
    const slug = validateAppSlug(input.slug);
    const existing = this.store.getApp(slug);
    if (!existing) {
      throw new RuntimeBridgeError(404, `App "${slug}" not found.`);
    }

    const result = await this.bridge.execInApp({
      slug,
      command: input.command,
      service: input.service,
      timeoutSeconds: input.timeoutSeconds,
    });
    const cmdPreview = redactSecrets(input.command).slice(0, 120);
    this.store.recordAudit({
      actor,
      actorTokenId: actorTokenId ?? null,
      action: "exec_in_app",
      targetSlug: slug,
      summary: `Ran command in "${slug}" (${input.service ?? "app"}, exit ${result.exitCode}): ${cmdPreview}`,
      riskLevel: "medium",
    });
    return result;
  }

  async runHostCommand(
    rawInput: RunHostCommandInput,
    actor: Actor,
    actorTokenId?: string | null,
  ): Promise<RuntimeCommandResult> {
    const input = RunHostCommandInputSchema.parse(rawInput);
    const result = await this.bridge.runHostCommand({
      command: input.command,
      cwd: input.cwd,
      timeoutSeconds: input.timeoutSeconds,
    });
    const cmdPreview = redactSecrets(input.command).slice(0, 140);
    this.store.recordAudit({
      actor,
      actorTokenId: actorTokenId ?? null,
      action: "run_host_command",
      targetSlug: null,
      summary: `Ran host command (exit ${result.exitCode}): ${cmdPreview}`,
      riskLevel: "high",
    });
    return result;
  }

  async writeHostFile(
    rawInput: WriteHostFileInput,
    actor: Actor,
    actorTokenId?: string | null,
  ): Promise<RuntimeWriteFileResult> {
    const input = WriteHostFileInputSchema.parse(rawInput);
    const result = await this.bridge.writeHostFile(input);
    this.store.recordAudit({
      actor,
      actorTokenId: actorTokenId ?? null,
      action: "write_file",
      targetSlug: null,
      summary: `${result.appended ? "Appended to" : "Wrote"} ${result.path} (${result.bytesWritten} bytes)`,
      riskLevel: "high",
    });
    return result;
  }

  async deleteHostFile(
    rawInput: DeleteHostFileInput,
    actor: Actor,
    actorTokenId?: string | null,
  ): Promise<RuntimeDeleteFileResult> {
    const input = DeleteHostFileInputSchema.parse(rawInput);
    const result = await this.bridge.deleteHostFile(input);
    this.store.recordAudit({
      actor,
      actorTokenId: actorTokenId ?? null,
      action: "delete_file",
      targetSlug: null,
      summary: `Deleted ${result.deletedType} ${result.path}`,
      riskLevel: "high",
    });
    return result;
  }

  async manageHostService(
    rawInput: ManageHostServiceInput,
    actor: Actor,
    actorTokenId?: string | null,
  ): Promise<RuntimeManageServiceResult> {
    const input = ManageHostServiceInputSchema.parse(rawInput);
    const result = await this.bridge.manageHostService(input);
    this.store.recordAudit({
      actor,
      actorTokenId: actorTokenId ?? null,
      action: "manage_service",
      targetSlug: null,
      summary: `Ran systemctl ${input.action} on ${input.service} (state: ${result.activeState})`,
      riskLevel: input.action === "status" ? "low" : "high",
    });
    return result;
  }

  async dockerCleanup(
    rawInput: DockerCleanupInput,
    actor: Actor,
    actorTokenId?: string | null,
  ): Promise<RuntimeDockerCleanupResult> {
    const input = DockerCleanupInputSchema.parse(rawInput);
    const result = await this.bridge.dockerCleanup(input);
    this.store.recordAudit({
      actor,
      actorTokenId: actorTokenId ?? null,
      action: "docker_cleanup",
      targetSlug: null,
      summary: `Docker cleanup: ${result.reclaimedSummary.slice(0, 200)}`,
      riskLevel: "medium",
    });
    return result;
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
        case "update_app_settings": {
          const slug = String(execPayload.slug ?? claimed.targetSlug ?? "");
          const { slug: _ignored, ...settingsPatch } = execPayload;
          const res = await this.updateAppSettings(
            slug,
            settingsPatch as UpdateAppSettingsInput,
            "agent",
            tokenId,
          );
          data = res;
          summary = `Updated app settings for "${res.app.slug}"${res.needsRebuild ? " (rebuild needed)" : ""}`;
          break;
        }
        case "rollback_app": {
          const slug = String(execPayload.slug ?? claimed.targetSlug ?? "");
          const res = await this.rollbackApp(slug, "agent", tokenId);
          deployment = res.deployment;
          data = res;
          summary = `Rolled back "${res.app.slug}" (${res.app.status})`;
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
        case "start_app": {
          const slug = String(execPayload.slug ?? claimed.targetSlug ?? "");
          const app = await this.lifecycleApp(slug, "start", "agent", tokenId);
          data = app;
          summary = `Started "${app.slug}" (${app.status})`;
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
        case "exec_in_app": {
          const res = await this.execInApp(
            execPayload as ExecInAppInput,
            "agent",
            tokenId,
          );
          data = res;
          const slug = String(execPayload.slug ?? claimed.targetSlug ?? "");
          if (res.exitCode !== 0) {
            const detail = redactSecrets(
              (res.stderr || res.stdout || "").trim(),
            ).slice(0, 300);
            throw new Error(
              `Command in "${slug}" failed (exit ${res.exitCode})${detail ? `: ${detail}` : ""}`,
            );
          }
          const outSnippet = redactSecrets(res.stdout.trim()).slice(0, 200);
          summary = `Ran command in "${slug}" (exit 0)${outSnippet ? `: ${outSnippet}` : ""}`;
          break;
        }
        case "run_host_command": {
          const res = await this.runHostCommand(
            execPayload as RunHostCommandInput,
            "agent",
            tokenId,
          );
          data = res;
          if (res.exitCode !== 0) {
            const detail = redactSecrets(
              (res.stderr || res.stdout || "").trim(),
            ).slice(0, 300);
            throw new Error(
              `Host command failed (exit ${res.exitCode})${detail ? `: ${detail}` : ""}`,
            );
          }
          const outSnippet = redactSecrets(res.stdout.trim()).slice(0, 200);
          summary = `Ran host command (exit 0)${outSnippet ? `: ${outSnippet}` : ""}`;
          break;
        }
        case "write_file": {
          const res = await this.writeHostFile(
            execPayload as WriteHostFileInput,
            "agent",
            tokenId,
          );
          data = res;
          summary = `${res.appended ? "Appended to" : "Wrote"} ${res.path} (${res.bytesWritten} bytes)`;
          break;
        }
        case "delete_file": {
          const res = await this.deleteHostFile(
            execPayload as DeleteHostFileInput,
            "agent",
            tokenId,
          );
          data = res;
          summary = `Deleted ${res.deletedType} ${res.path}`;
          break;
        }
        case "manage_service": {
          const res = await this.manageHostService(
            execPayload as ManageHostServiceInput,
            "agent",
            tokenId,
          );
          data = res;
          if (!res.ok) {
            const detail = redactSecrets(res.output.trim()).slice(0, 300);
            throw new Error(
              `Service action ${res.action} on ${res.service} failed (state: ${res.activeState})${detail ? `: ${detail}` : ""}`,
            );
          }
          summary = `Ran ${res.action} on ${res.service} (state: ${res.activeState})`;
          break;
        }
        case "docker_cleanup": {
          const res = await this.dockerCleanup(
            execPayload as DockerCleanupInput,
            "agent",
            tokenId,
          );
          data = res;
          if (!res.ok) {
            throw new Error(res.reclaimedSummary || "Docker cleanup failed.");
          }
          summary = res.reclaimedSummary;
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
