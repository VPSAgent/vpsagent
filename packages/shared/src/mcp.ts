import crypto from "node:crypto";
import { z } from "zod";

export const MCP_TOKEN_PREFIX = "vpsmcp_";

export const McpTokenScopeSchema = z.enum([
  "read-only",
  "approval-required",
  "auto-approve",
]);
export type McpTokenScope = z.infer<typeof McpTokenScopeSchema>;

export const McpTokenRecordSchema = z.object({
  id: z.string().min(1),
  name: z.string().min(1).max(80),
  scope: McpTokenScopeSchema,
  tokenPrefix: z.string().min(6).max(24),
  createdAt: z.string(),
  lastUsedAt: z.string().nullable(),
  revokedAt: z.string().nullable(),
});
export type McpTokenRecord = z.infer<typeof McpTokenRecordSchema>;

export const CreateMcpTokenInputSchema = z.object({
  name: z.string().trim().min(1).max(80),
  scope: McpTokenScopeSchema,
});
export type CreateMcpTokenInput = z.infer<typeof CreateMcpTokenInputSchema>;

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
  return scope === "approval-required" || scope === "auto-approve";
}

/** Returns true when a mutating action must wait for human approval in the dashboard. */
export function requiresApprovalForScope(scope: McpTokenScope): boolean {
  if (!canScopeMutate(scope)) {
    throw new Error("Read-only tokens cannot perform or queue mutating actions.");
  }
  return scope === "approval-required";
}
