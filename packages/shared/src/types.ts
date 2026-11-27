import { z } from "zod";
import { McpTokenScopeSchema } from "./mcp.js";

export const AppSourceTypeSchema = z.enum(["image", "git"]);
export type AppSourceType = z.infer<typeof AppSourceTypeSchema>;

export const GitProviderSchema = z.enum(["github"]);
export type GitProvider = z.infer<typeof GitProviderSchema>;

export const GitCredentialRecordSchema = z.object({
  id: z.string().min(1),
  provider: GitProviderSchema.default("github"),
  label: z.string().min(1).max(80),
  accountLogin: z.string().max(100).nullable().default(null),
  tokenHint: z.string().min(4).max(32),
  isDefault: z.boolean().default(false),
  createdAt: z.string(),
  updatedAt: z.string(),
  lastUsedAt: z.string().nullable().default(null),
});
export type GitCredentialRecord = z.infer<typeof GitCredentialRecordSchema>;

export const GithubRepoSummarySchema = z.object({
  fullName: z.string(),
  name: z.string(),
  owner: z.string(),
  private: z.boolean(),
  defaultBranch: z.string().nullable(),
  htmlUrl: z.string(),
  description: z.string().nullable(),
  updatedAt: z.string().nullable(),
  credentialId: z.string(),
  credentialLabel: z.string(),
});
export type GithubRepoSummary = z.infer<typeof GithubRepoSummarySchema>;

export const CompanionServiceTypeSchema = z.enum(["postgres", "redis"]);
export type CompanionServiceType = z.infer<typeof CompanionServiceTypeSchema>;

export const CompanionServiceSchema = z.object({
  type: CompanionServiceTypeSchema,
  version: z.string().min(1).max(32).optional(),
  envKey: z.string().min(1).max(64).optional(),
});
export type CompanionService = z.infer<typeof CompanionServiceSchema>;

export const AppStatusSchema = z.enum([
  "provisioning",
  "building",
  "running",
  "stopped",
  "error",
]);
export type AppStatus = z.infer<typeof AppStatusSchema>;

export const AppRecordSchema = z.object({
  slug: z.string().min(2).max(48),
  name: z.string().min(1).max(100),
  sourceType: AppSourceTypeSchema,
  image: z.string().min(1).max(255).nullable(),
  gitRepoUrl: z.string().min(1).max(500).nullable(),
  gitBranch: z.string().min(1).max(120).nullable(),
  dockerfilePath: z.string().min(1).max(200).default("Dockerfile"),
  domain: z.string().min(1).max(253).nullable(),
  folderPath: z.string().min(1),
  internalPort: z.number().int().min(1).max(65535),
  probeHttp: z.boolean().default(true),
  probePath: z.string().min(1).max(128).default("/"),
  status: AppStatusSchema,
  cpuLimit: z.string().min(1).max(16),
  memoryLimitMb: z.number().int().min(64).max(131072),
  companions: z.array(CompanionServiceSchema).default([]),
  lastCommitSha: z.string().max(64).nullable().default(null),
  detectedRuntime: z.string().max(48).nullable().default(null),
  envExampleKeys: z.array(z.string().min(1).max(128)).default([]),
  gitCredentialId: z.string().max(64).nullable().default(null),
  webhookEnabled: z.boolean().default(false),
  webhookLastTriggeredAt: z.string().nullable().default(null),
  previousCommitSha: z.string().max(64).nullable().default(null),
  previousImage: z.string().max(255).nullable().default(null),
  rollbackAvailable: z.boolean().default(false),
  createdAt: z.string(),
  updatedAt: z.string(),
});
export type AppRecord = z.infer<typeof AppRecordSchema>;

export const DetectedRuntimeSchema = z.enum([
  "dockerfile",
  "nextjs",
  "vite-static",
  "node",
  "python",
  "static",
  "unknown",
]);
export type DetectedRuntime = z.infer<typeof DetectedRuntimeSchema>;

export const DeploymentStatusSchema = z.enum([
  "queued",
  "cloning",
  "building",
  "starting",
  "verifying",
  "succeeded",
  "failed",
]);
export type DeploymentStatus = z.infer<typeof DeploymentStatusSchema>;

export const DeploymentActionSchema = z.enum([
  "deploy_app",
  "rebuild_app",
  "rollback_app",
]);
export type DeploymentAction = z.infer<typeof DeploymentActionSchema>;

export const DeploymentRecordSchema = z.object({
  id: z.string().min(1),
  slug: z.string().min(2).max(48),
  action: DeploymentActionSchema,
  status: DeploymentStatusSchema,
  actor: z.enum(["user", "agent", "system"]),
  actorTokenId: z.string().nullable().default(null),
  sourceType: AppSourceTypeSchema,
  gitRepoUrl: z.string().nullable().default(null),
  gitBranch: z.string().nullable().default(null),
  commitSha: z.string().nullable().default(null),
  detectedRuntime: z.string().nullable().default(null),
  usedAutoDockerfile: z.boolean().default(false),
  domain: z.string().nullable().default(null),
  phaseDetail: z.string().nullable().default(null),
  buildLogs: z.array(z.string()).default([]),
  error: z.string().nullable().default(null),
  createdAt: z.string(),
  updatedAt: z.string(),
  finishedAt: z.string().nullable().default(null),
});
export type DeploymentRecord = z.infer<typeof DeploymentRecordSchema>;

export const AppEnvEntrySchema = z.object({
  key: z.string().min(1).max(128),
  isSecret: z.boolean(),
  maskedValue: z.string(),
  updatedAt: z.string(),
});
export type AppEnvEntry = z.infer<typeof AppEnvEntrySchema>;

export const RequestedEnvKeySchema = z.object({
  key: z.string().min(1).max(128),
  description: z.string().max(240).optional(),
  isSecret: z.boolean().default(true),
  required: z.boolean().default(true),
});
export type RequestedEnvKey = z.infer<typeof RequestedEnvKeySchema>;

export const AppEnvRequestSchema = z.object({
  slug: z.string().min(2).max(48),
  note: z.string().max(400).nullable().default(null),
  keys: z.array(RequestedEnvKeySchema).max(60),
  rebuildAfterSave: z.boolean().default(false),
  requestedBy: z.string().min(1).max(80),
  updatedAt: z.string(),
});
export type AppEnvRequest = z.infer<typeof AppEnvRequestSchema>;

export const ActorSchema = z.enum(["user", "agent", "system"]);
export type Actor = z.infer<typeof ActorSchema>;

export const RiskLevelSchema = z.enum(["low", "medium", "high"]);
export type RiskLevel = z.infer<typeof RiskLevelSchema>;

export const AuditEventSchema = z.object({
  id: z.string().min(1),
  actor: ActorSchema,
  actorTokenId: z.string().nullable().default(null),
  action: z.string().min(1).max(100),
  targetSlug: z.string().nullable(),
  summary: z.string().min(1).max(500),
  riskLevel: RiskLevelSchema,
  createdAt: z.string(),
});
export type AuditEvent = z.infer<typeof AuditEventSchema>;

export const ApprovalStatusSchema = z.enum([
  "pending",
  "approved",
  "rejected",
  "executed",
  "failed",
]);
export type ApprovalStatus = z.infer<typeof ApprovalStatusSchema>;

export const ApprovalActionTypeSchema = z.enum([
  "deploy_app",
  "rebuild_app",
  "rollback_app",
  "update_app_settings",
  "update_env",
  "set_domain",
  "start_app",
  "restart_app",
  "stop_app",
  "delete_app",
  "exec_in_app",
  "run_host_command",
  "write_file",
  "delete_file",
  "manage_service",
  "docker_cleanup",
]);
export type ApprovalActionType = z.infer<typeof ApprovalActionTypeSchema>;

export const ApprovalRequestSchema = z.object({
  id: z.string().min(1),
  action: ApprovalActionTypeSchema,
  targetSlug: z.string().nullable(),
  summary: z.string().min(1).max(500),
  payload: z.record(z.string(), z.unknown()),
  requestedBy: z.string().min(1).max(120),
  tokenId: z.string().nullable().default(null),
  tokenScope: McpTokenScopeSchema,
  status: ApprovalStatusSchema,
  riskLevel: RiskLevelSchema,
  decidedBy: z.string().nullable(),
  decisionNote: z.string().nullable(),
  resultSummary: z.string().nullable(),
  createdAt: z.string(),
  decidedAt: z.string().nullable(),
  executedAt: z.string().nullable(),
});
export type ApprovalRequest = z.infer<typeof ApprovalRequestSchema>;

export const TlsStatusSchema = z.enum(["inactive", "pending", "active", "failed"]);
export type TlsStatus = z.infer<typeof TlsStatusSchema>;

export const SetupStateSchema = z.object({
  claimed: z.boolean(),
  domain: z.string().nullable(),
  appsBaseDomain: z.string().nullable().default(null),
  acmeEmail: z.string().nullable(),
  httpsActive: z.boolean().default(false),
  tlsStatus: TlsStatusSchema.default("inactive"),
  tlsError: z.string().nullable().default(null),
  claimedAt: z.string().nullable(),
  tailscaleDomain: z.string().nullable().default(null),
  tailscaleServeEnabled: z.boolean().default(false),
});
export type SetupState = z.infer<typeof SetupStateSchema>;

export const SystemMetricsSchema = z.object({
  hostname: z.string(),
  platform: z.string(),
  uptimeSeconds: z.number().nonnegative(),
  cpuCount: z.number().int().positive(),
  loadAverage1m: z.number().nonnegative(),
  memoryTotalMb: z.number().nonnegative(),
  memoryUsedMb: z.number().nonnegative(),
  memoryUsagePercent: z.number().min(0).max(100),
  collectedAt: z.string(),
});
export type SystemMetrics = z.infer<typeof SystemMetricsSchema>;

export const DiskMetricsSchema = z.object({
  totalGb: z.number().nonnegative(),
  usedGb: z.number().nonnegative(),
  freeGb: z.number().nonnegative(),
  usedPercent: z.number().min(0).max(100),
  mount: z.string(),
});
export type DiskMetrics = z.infer<typeof DiskMetricsSchema>;

export const NotificationChannelSchema = z.enum([
  "none",
  "discord",
  "slack",
  "telegram",
  "webhook",
]);
export type NotificationChannel = z.infer<typeof NotificationChannelSchema>;

export const NotificationSettingsSchema = z.object({
  enabled: z.boolean().default(false),
  channel: NotificationChannelSchema.default("none"),
  hasTargetSecret: z.boolean().default(false),
  targetHint: z.string().nullable().default(null),
  telegramChatId: z.string().max(64).nullable().default(null),
  notifyOnApproval: z.boolean().default(true),
  notifyOnAppDown: z.boolean().default(true),
  notifyOnDeployFailure: z.boolean().default(true),
  lastSentAt: z.string().nullable().default(null),
  lastError: z.string().nullable().default(null),
});
export type NotificationSettings = z.infer<typeof NotificationSettingsSchema>;

export interface NotificationRuntimeConfig {
  enabled: boolean;
  channel: NotificationChannel;
  webhookUrl: string | null;
  telegramBotToken: string | null;
  telegramChatId: string | null;
  notifyOnApproval: boolean;
  notifyOnAppDown: boolean;
  notifyOnDeployFailure: boolean;
}
