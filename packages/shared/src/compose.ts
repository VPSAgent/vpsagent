import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { z } from "zod";
import {
  formatEnvFile,
  isForbiddenAppEnvKey,
  resolveScopedAppDir,
  validateAppSlug,
  validateDockerImageRef,
  validateDockerfilePath,
  validateEnvKey,
  validateGitBranch,
} from "./safety.js";
import {
  AppSourceTypeSchema,
  type CompanionService,
  CompanionServiceSchema,
} from "./types.js";

const DEFAULT_POSTGRES_VERSION = "16-alpine";
const DEFAULT_REDIS_VERSION = "7-alpine";
const SAFE_TAG_VERSION_PATTERN = /^[a-zA-Z0-9._-]{1,32}$/;
const SAFE_CONTAINER_PATH_PATTERN = /^\/[A-Za-z0-9._/-]+$/;

export const ApartmentCompanionSecretsSchema = z.object({
  postgresPassword: z.string().min(8).max(128).optional(),
  redisPassword: z.string().min(8).max(128).optional(),
});
export type ApartmentCompanionSecrets = z.infer<
  typeof ApartmentCompanionSecretsSchema
>;

export const ApartmentBlueprintInputSchema = z.object({
  slug: z.string().min(2).max(48),
  sourceType: AppSourceTypeSchema,
  image: z.string().min(1).max(255).nullable().optional(),
  gitRepoUrl: z.string().min(1).max(500).nullable().optional(),
  gitBranch: z.string().min(1).max(120).nullable().optional(),
  dockerfilePath: z.string().min(1).max(200).optional(),
  internalPort: z.number().int().min(1).max(65535).default(8080),
  cpuLimit: z.string().min(1).max(16).default("0.5"),
  memoryLimitMb: z.number().int().min(64).max(131072).default(512),
  envVars: z.record(z.string(), z.string()).default({}),
  companions: z.array(CompanionServiceSchema).default([]),
  companionSecrets: ApartmentCompanionSecretsSchema.optional(),
  workingDir: z.string().min(1).max(200).optional(),
  command: z.array(z.string().min(1).max(500)).min(1).max(64).optional(),
  mountDataDir: z.boolean().default(true),
  dataMountTarget: z.string().min(1).max(200).default("/app/data"),
});

export type ApartmentBlueprintInput = z.input<
  typeof ApartmentBlueprintInputSchema
>;

export interface ApartmentBlueprint {
  slug: string;
  projectName: string;
  containerName: string;
  networkName: string;
  imageRef: string;
  internalPort: number;
  composeYaml: string;
  envFile: string;
  envVars: Record<string, string>;
  companions: CompanionService[];
  requiredDataDirs: string[];
}

export function getAppProjectName(slug: string): string {
  return `vpsagent-${validateAppSlug(slug)}`;
}

export function getAppContainerName(slug: string): string {
  return `vpsagent-app-${validateAppSlug(slug)}`;
}

export function getAppNetworkName(slug: string): string {
  return `${getAppProjectName(slug)}_app_net`;
}

export function getBuiltGitImageTag(slug: string): string {
  return `vpsagent-app-${validateAppSlug(slug)}:latest`;
}

function validateCpuLimit(raw: string): string {
  const trimmed = raw.trim();
  if (!/^\d+(?:\.\d{1,2})?$/.test(trimmed)) {
    throw new Error(
      `Invalid CPU limit "${raw}": expected a positive number such as "0.5" or "1.0".`,
    );
  }
  const value = Number.parseFloat(trimmed);
  if (!Number.isFinite(value) || value < 0.1 || value > 64) {
    throw new Error(`CPU limit "${raw}" must be between 0.1 and 64 cores.`);
  }
  return trimmed;
}

function validateContainerPath(raw: string, label: string): string {
  const trimmed = raw.trim();
  if (
    !SAFE_CONTAINER_PATH_PATTERN.test(trimmed) ||
    trimmed.includes("..") ||
    trimmed.includes("docker.sock")
  ) {
    throw new Error(`Unsafe ${label} path "${raw}".`);
  }
  return trimmed;
}

function validateCompanionVersion(version: string): string {
  const trimmed = version.trim();
  if (!SAFE_TAG_VERSION_PATTERN.test(trimmed) || trimmed.includes("..")) {
    throw new Error(`Invalid companion image version "${version}".`);
  }
  return trimmed;
}

function yamlQuote(value: string): string {
  return JSON.stringify(value);
}

function generateCompanionPassword(): string {
  return crypto.randomBytes(24).toString("hex");
}

function toDbIdentifier(slug: string): string {
  return slug.replace(/-/g, "_").slice(0, 40);
}

/**
 * Generates a strict Locked Apartment Docker Compose blueprint and literally-quoted `.env` file.
 *
 * Security guarantees enforced on every generated service (main app + companions):
 * - `cap_drop: [ALL]` (no root Linux capabilities)
 * - `security_opt: [no-new-privileges:true]`
 * - Strict CPU & memory caps (`cpus`, `mem_limit`)
 * - Isolated per-app bridge network (`app_net`), zero host port bindings
 * - Zero Docker socket mounts (`/var/run/docker.sock` is never mounted)
 * - All user and companion environment variables serialized with literal quoting
 */
export function generateApartmentBlueprint(
  rawInput: ApartmentBlueprintInput,
): ApartmentBlueprint {
  const input = ApartmentBlueprintInputSchema.parse(rawInput);
  const slug = validateAppSlug(input.slug);
  const cpuLimit = validateCpuLimit(input.cpuLimit);
  const dataMountTarget = validateContainerPath(
    input.dataMountTarget,
    "dataMountTarget",
  );
  const workingDir = input.workingDir
    ? validateContainerPath(input.workingDir, "workingDir")
    : undefined;

  if (input.command) {
    for (const arg of input.command) {
      if (arg.includes("\0") || arg.includes("\n") || arg.includes("\r")) {
        throw new Error("Command arguments cannot contain control characters.");
      }
    }
  }

  let imageRef: string;
  if (input.sourceType === "image") {
    if (!input.image) {
      throw new Error(
        'Prebuilt image apps require a Docker image reference (e.g. "nginxinc/nginx-unprivileged:alpine").',
      );
    }
    imageRef = validateDockerImageRef(input.image);
  } else {
    if (!input.gitRepoUrl) {
      throw new Error("Git apps require a gitRepoUrl.");
    }
    if (input.gitBranch) {
      validateGitBranch(input.gitBranch);
    }
    if (input.dockerfilePath) {
      validateDockerfilePath(input.dockerfilePath);
    }
    imageRef = getBuiltGitImageTag(slug);
  }

  // Validate and copy user-supplied environment variables.
  const envVars: Record<string, string> = {};
  for (const [key, value] of Object.entries(input.envVars)) {
    const safeKey = validateEnvKey(key);
    if (isForbiddenAppEnvKey(safeKey)) {
      throw new Error(
        `Environment variable "${safeKey}" is reserved and cannot be set by apps.`,
      );
    }
    if (value.includes("\0")) {
      throw new Error(
        `Environment variable "${safeKey}" cannot contain null bytes.`,
      );
    }
    envVars[safeKey] = value;
  }

  envVars.APP_SLUG = slug;
  envVars.APP_PORT = String(input.internalPort);
  if (envVars.PORT === undefined) {
    envVars.PORT = String(input.internalPort);
  }

  // Deduplicate companions by service type (max 1 postgres, max 1 redis).
  const companionByType = new Map<CompanionService["type"], CompanionService>();
  for (const comp of input.companions) {
    if (companionByType.has(comp.type)) {
      throw new Error(
        `Duplicate companion service "${comp.type}" is not allowed in the same app.`,
      );
    }
    if (comp.envKey) {
      const safeEnvKey = validateEnvKey(comp.envKey);
      if (isForbiddenAppEnvKey(safeEnvKey)) {
        throw new Error(
          `Companion envKey "${safeEnvKey}" is reserved and cannot be used.`,
        );
      }
    }
    companionByType.set(comp.type, {
      type: comp.type,
      ...(comp.version
        ? { version: validateCompanionVersion(comp.version) }
        : {}),
      ...(comp.envKey ? { envKey: comp.envKey } : {}),
    });
  }

  const companions = Array.from(companionByType.values());
  const projectName = getAppProjectName(slug);
  const containerName = getAppContainerName(slug);
  const networkName = getAppNetworkName(slug);
  const requiredDataDirs: string[] = [];
  if (input.mountDataDir) {
    requiredDataDirs.push("data");
  }

  const lines: string[] = [
    `# Managed by VPSAgent v2 — Locked Apartment Blueprint (${slug})`,
    "services:",
    "  app:",
    `    image: ${yamlQuote(imageRef)}`,
    `    container_name: ${yamlQuote(containerName)}`,
    "    restart: unless-stopped",
    "    init: true",
  ];

  if (workingDir) {
    lines.push(`    working_dir: ${yamlQuote(workingDir)}`);
  }

  if (input.command) {
    lines.push(`    command: ${JSON.stringify(input.command)}`);
  }

  lines.push("    env_file:", "      - .env");

  if (input.mountDataDir) {
    lines.push("    volumes:", `      - ./data:${dataMountTarget}:rw`);
  }

  lines.push(
    `    cpus: ${yamlQuote(cpuLimit)}`,
    `    mem_limit: ${yamlQuote(`${input.memoryLimitMb}m`)}`,
    "    cap_drop:",
    "      - ALL",
    "    security_opt:",
    "      - no-new-privileges:true",
  );

  if (companions.length > 0) {
    lines.push("    depends_on:");
    for (const comp of companions) {
      lines.push(`      ${comp.type}:`, "        condition: service_healthy");
    }
  }

  lines.push("    networks:", "      - app_net");

  const pgCompanion = companionByType.get("postgres");
  if (pgCompanion) {
    const pgVersion = pgCompanion.version ?? DEFAULT_POSTGRES_VERSION;
    const pgImage = validateDockerImageRef(`postgres:${pgVersion}`);
    const dbName = `app_${toDbIdentifier(slug)}`;
    const dbUser = `vps_${toDbIdentifier(slug)}`;
    const dbPassword =
      input.companionSecrets?.postgresPassword ??
      envVars.POSTGRES_PASSWORD ??
      generateCompanionPassword();
    const targetEnvKey = pgCompanion.envKey ?? "DATABASE_URL";

    envVars.POSTGRES_DB = dbName;
    envVars.POSTGRES_USER = dbUser;
    envVars.POSTGRES_PASSWORD = dbPassword;
    if (envVars[targetEnvKey] === undefined) {
      envVars[targetEnvKey] =
        `postgresql://${dbUser}:${encodeURIComponent(dbPassword)}@postgres:5432/${dbName}`;
    }
    requiredDataDirs.push("data/postgres");

    lines.push(
      "  postgres:",
      `    image: ${yamlQuote(pgImage)}`,
      `    container_name: ${yamlQuote(`${containerName}-postgres`)}`,
      "    restart: unless-stopped",
      '    user: "70:70"',
      "    environment:",
      '      POSTGRES_DB: "${POSTGRES_DB}"',
      '      POSTGRES_USER: "${POSTGRES_USER}"',
      '      POSTGRES_PASSWORD: "${POSTGRES_PASSWORD}"',
      '      PGDATA: "/var/lib/postgresql/data/pgdata"',
      "    volumes:",
      "      - ./data/postgres:/var/lib/postgresql/data:rw",
      '    cpus: "0.5"',
      '    mem_limit: "256m"',
      "    cap_drop:",
      "      - ALL",
      "    security_opt:",
      "      - no-new-privileges:true",
      "    healthcheck:",
      '      test: ["CMD-SHELL", "pg_isready -U ${POSTGRES_USER} -d ${POSTGRES_DB}"]',
      '      interval: "5s"',
      '      timeout: "5s"',
      "      retries: 10",
      '      start_period: "5s"',
      "    networks:",
      "      - app_net",
    );
  }

  const redisCompanion = companionByType.get("redis");
  if (redisCompanion) {
    const redisVersion = redisCompanion.version ?? DEFAULT_REDIS_VERSION;
    const redisImage = validateDockerImageRef(`redis:${redisVersion}`);
    const redisPassword =
      input.companionSecrets?.redisPassword ??
      envVars.REDIS_PASSWORD ??
      generateCompanionPassword();
    const targetEnvKey = redisCompanion.envKey ?? "REDIS_URL";

    envVars.REDIS_PASSWORD = redisPassword;
    if (envVars[targetEnvKey] === undefined) {
      envVars[targetEnvKey] =
        `redis://:${encodeURIComponent(redisPassword)}@redis:6379/0`;
    }
    requiredDataDirs.push("data/redis");

    lines.push(
      "  redis:",
      `    image: ${yamlQuote(redisImage)}`,
      `    container_name: ${yamlQuote(`${containerName}-redis`)}`,
      "    restart: unless-stopped",
      '    user: "999:999"',
      '    command: ["redis-server", "--appendonly", "yes", "--requirepass", "${REDIS_PASSWORD}"]',
      "    environment:",
      '      REDISCLI_AUTH: "${REDIS_PASSWORD}"',
      "    volumes:",
      "      - ./data/redis:/data:rw",
      '    cpus: "0.25"',
      '    mem_limit: "128m"',
      "    cap_drop:",
      "      - ALL",
      "    security_opt:",
      "      - no-new-privileges:true",
      "    healthcheck:",
      '      test: ["CMD", "redis-cli", "ping"]',
      '      interval: "5s"',
      '      timeout: "3s"',
      "      retries: 10",
      '      start_period: "3s"',
      "    networks:",
      "      - app_net",
    );
  }

  lines.push("networks:", "  app_net:", "    driver: bridge", "");

  return {
    slug,
    projectName,
    containerName,
    networkName,
    imageRef,
    internalPort: input.internalPort,
    composeYaml: lines.join("\n"),
    envFile: formatEnvFile(envVars),
    envVars,
    companions,
    requiredDataDirs,
  };
}

function assertNotSymlink(targetPath: string): void {
  try {
    const stat = fs.lstatSync(targetPath);
    if (stat.isSymbolicLink()) {
      throw new Error(
        `Security boundary violation: "${targetPath}" cannot be a symbolic link.`,
      );
    }
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code !== "ENOENT") {
      throw err;
    }
  }
}

/**
 * Safely writes a generated Locked Apartment blueprint (`docker-compose.yml` + `0600` `.env`
 * + required `./data` directories) into the app's scoped workspace directory.
 */
export function writeApartmentBlueprint(
  appsRoot: string,
  blueprint: ApartmentBlueprint,
): { appDir: string; composePath: string; envPath: string } {
  const appDir = resolveScopedAppDir(appsRoot, blueprint.slug);
  fs.mkdirSync(appDir, { recursive: true, mode: 0o750 });
  assertNotSymlink(appDir);

  for (const relDir of blueprint.requiredDataDirs) {
    const fullDir = path.join(appDir, relDir);
    assertNotSymlink(fullDir);
    const isCompanionSubdir =
      relDir === "data/postgres" || relDir === "data/redis";
    const mode = relDir === "data" ? 0o755 : isCompanionSubdir ? 0o700 : 0o750;
    fs.mkdirSync(fullDir, { recursive: true, mode });
    fs.chmodSync(fullDir, mode);
  }

  const composePath = path.join(appDir, "docker-compose.yml");
  const envPath = path.join(appDir, ".env");
  assertNotSymlink(composePath);
  assertNotSymlink(envPath);

  fs.writeFileSync(composePath, blueprint.composeYaml, {
    encoding: "utf8",
    mode: 0o644,
  });
  fs.chmodSync(composePath, 0o644);

  fs.writeFileSync(envPath, blueprint.envFile, {
    encoding: "utf8",
    mode: 0o600,
  });
  fs.chmodSync(envPath, 0o600);

  return { appDir, composePath, envPath };
}
