import crypto from "node:crypto";
import { z } from "zod";
import { validateAppSlug } from "./safety.js";

export const MCP_TOKEN_PREFIX = "vpsmcp_";

export const McpTokenScopeSchema = z.enum([
  "read-only",
  "approval-required",
  "safe-auto-deploy",
  "auto-approve",
  "host-admin",
]);
export type McpTokenScope = z.infer<typeof McpTokenScopeSchema>;

export const HOST_ADMIN_ACTIONS = new Set([
  "run_host_command",
  "write_file",
  "delete_file",
  "manage_service",
]);

/** Returns true when an action operates directly on the VPS host rather than an isolated app. */
export function isHostAdminAction(action?: string): boolean {
  return Boolean(action && HOST_ADMIN_ACTIONS.has(action));
}

export const McpTokenRecordSchema = z.object({
  id: z.string().min(1),
  name: z.string().min(1).max(80),
  scope: McpTokenScopeSchema,
  allowedSlugs: z.array(z.string().min(2).max(48)).default([]),
  tokenPrefix: z.string().min(6).max(24),
  createdAt: z.string(),
  lastUsedAt: z.string().nullable(),
  revokedAt: z.string().nullable(),
});
export type McpTokenRecord = z.infer<typeof McpTokenRecordSchema>;

export const CreateMcpTokenInputSchema = z.object({
  name: z.string().trim().min(1).max(80),
  scope: McpTokenScopeSchema,
  allowedSlugs: z
    .array(z.string().trim().min(2).max(48))
    .max(50)
    .optional()
    .default([])
    .transform((slugs) => Array.from(new Set(slugs.map((s) => validateAppSlug(s))))),
});
export type CreateMcpTokenInput = z.input<typeof CreateMcpTokenInputSchema>;

/** Hashes a raw MCP bearer token with SHA-256 hex for at-rest storage and lookup. */
export function hashMcpToken(rawToken: string): string {
  return crypto.createHash("sha256").update(rawToken, "utf8").digest("hex");
}

/** Generates a high-entropy MCP bearer token, its SHA-256 hash, and safe display prefix. */
export function generateMcpToken(): {
  rawToken: string;
  tokenHash: string;
  tokenPrefix: string;
} {
  const secretPart = crypto.randomBytes(32).toString("base64url");
  const rawToken = `${MCP_TOKEN_PREFIX}${secretPart}`;
  const tokenHash = hashMcpToken(rawToken);
  const tokenPrefix = rawToken.slice(0, 14);
  return { rawToken, tokenHash, tokenPrefix };
}

/** Returns true only when the token scope is allowed to request or perform mutations. */
export function canScopeMutate(scope: McpTokenScope): boolean {
  return (
    scope === "approval-required" ||
    scope === "safe-auto-deploy" ||
    scope === "auto-approve" ||
    scope === "host-admin"
  );
}

/**
 * Returns true when a mutating action must wait for human approval in the dashboard.
 * - `approval-required`: every mutation waits for approval.
 * - `safe-auto-deploy`: app deploy/rebuild/restart/env/domain run right away; `delete_app` and host-admin actions require approval.
 * - `auto-approve`: all isolated app actions run right away; host-admin actions STILL require approval unless the pass has explicit `host-admin` scope.
 * - `host-admin`: explicit full server admin; runs both app and host actions without waiting.
 */
export function requiresApprovalForScope(
  scope: McpTokenScope,
  action?: string,
): boolean {
  if (!canScopeMutate(scope)) {
    throw new Error("Read-only tokens cannot perform or queue mutating actions.");
  }
  if (scope === "approval-required") {
    return true;
  }
  if (scope === "safe-auto-deploy") {
    return action === "delete_app" || isHostAdminAction(action);
  }
  if (scope === "auto-approve") {
    return isHostAdminAction(action);
  }
  return false;
}

/** Returns true when a token is permitted to view or act on the given app slug. */
export function isSlugAllowedForToken(
  token: Pick<McpTokenRecord, "allowedSlugs">,
  slug: string,
): boolean {
  if (!token.allowedSlugs || token.allowedSlugs.length === 0) {
    return true;
  }
  return token.allowedSlugs.includes(slug);
}
