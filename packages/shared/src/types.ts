import { z } from "zod";
import { McpTokenScopeSchema } from "./mcp.js";

export const AppSourceTypeSchema = z.enum(["image", "git"]);
export type AppSourceType = z.infer<typeof AppSourceTypeSchema>;

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
  createdAt: z.string(),
  updatedAt: z.string(),
});
export type AppRecord = z.infer<typeof AppRecordSchema>;

export const AppEnvEntrySchema = z.object({
  key: z.string().min(1).max(128),
  isSecret: z.boolean(),
  maskedValue: z.string(),
  updatedAt: z.string(),
});
export type AppEnvEntry = z.infer<typeof AppEnvEntrySchema>;

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
  "update_env",
  "set_domain",
  "restart_app",
  "stop_app",
  "delete_app",
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
  acmeEmail: z.string().nullable(),
  httpsActive: z.boolean().default(false),
  tlsStatus: TlsStatusSchema.default("inactive"),
  tlsError: z.string().nullable().default(null),
  claimedAt: z.string().nullable(),
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
