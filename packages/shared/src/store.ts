import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import {
  type McpTokenRecord,
  type McpTokenScope,
  McpTokenRecordSchema,
  canScopeMutate,
  generateMcpToken,
  hashMcpToken,
} from "./mcp.js";
import {
  redactSecrets,
  redactStructuredValue,
  validateAppSlug,
  validateDomain,
  validateEnvKey,
} from "./safety.js";
import {
  type Actor,
  type AppEnvEntry,
  type AppRecord,
  AppRecordSchema,
  type AppStatus,
  type ApprovalActionType,
  type ApprovalRequest,
  ApprovalRequestSchema,
  type ApprovalStatus,
  type AuditEvent,
  AuditEventSchema,
  type CompanionService,
  type RiskLevel,
  type SetupState,
  SetupStateSchema,
} from "./types.js";

interface AppRow {
  slug: string;
  name: string;
  source_type: AppRecord["sourceType"];
  image: string | null;
  git_repo_url: string | null;
  git_branch: string | null;
  dockerfile_path: string;
  domain: string | null;
  folder_path: string;
  internal_port: number;
  probe_http: number;
  probe_path: string;
  status: AppStatus;
  cpu_limit: string;
  memory_limit_mb: number;
  companions_json: string;
  created_at: string;
  updated_at: string;
}

interface AppEnvRow {
  app_slug: string;
  key: string;
  value_enc: string;
  is_secret: number;
  updated_at: string;
}

interface ApprovalRow {
  id: string;
  action: ApprovalActionType;
  target_slug: string | null;
  summary: string;
  payload_json: string;
  requested_by: string;
  token_id: string | null;
  token_scope: McpTokenScope;
  status: ApprovalStatus;
  risk_level: RiskLevel;
  decided_by: string | null;
  decision_note: string | null;
  result_summary: string | null;
  created_at: string;
  decided_at: string | null;
  executed_at: string | null;
}

interface AuditRow {
  id: string;
  actor: Actor;
  actor_token_id: string | null;
  action: string;
  target_slug: string | null;
  summary: string;
  risk_level: RiskLevel;
  created_at: string;
}

interface McpTokenRow {
  id: string;
  name: string;
  scope: McpTokenScope;
  token_hash: string;
  token_prefix: string;
  created_at: string;
  last_used_at: string | null;
  revoked_at: string | null;
}

export interface RegistryStoreOptions {
  /** Optional secret used to derive an AES-256-GCM key for encrypting app `.env` values at rest. */
  encryptionSecret?: string;
}

const DEFAULT_SETUP_STATE: SetupState = {
  claimed: false,
  domain: null,
  acmeEmail: null,
  httpsActive: false,
  claimedAt: null,
};

const ENV_SECRET_KEY_HINT =
  /(?:key|token|secret|password|passwd|pass|passphrase|credential|auth|private|database_url|redis_url)/i;

function deriveEncryptionKey(secret: string): Buffer {
  return crypto.createHash("sha256").update(secret, "utf8").digest();
}

function encryptValue(plaintext: string, key: Buffer | null): string {
  if (!key) {
    return `plain:${Buffer.from(plaintext, "utf8").toString("base64")}`;
  }
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  const encrypted = Buffer.concat([
    cipher.update(plaintext, "utf8"),
    cipher.final(),
  ]);
  const tag = cipher.getAuthTag();
  return `gcm:${iv.toString("base64")}:${tag.toString("base64")}:${encrypted.toString("base64")}`;
}

function decryptValue(stored: string, key: Buffer | null): string {
  if (stored.startsWith("plain:")) {
    return Buffer.from(stored.slice("plain:".length), "base64").toString("utf8");
  }
  if (stored.startsWith("gcm:")) {
    if (!key) {
      throw new Error(
        "Cannot decrypt encrypted environment variable without encryptionSecret.",
      );
    }
    const parts = stored.split(":");
    if (parts.length !== 4) {
      throw new Error("Corrupted encrypted environment variable payload.");
    }
    const iv = Buffer.from(parts[1]!, "base64");
    const tag = Buffer.from(parts[2]!, "base64");
    const ciphertext = Buffer.from(parts[3]!, "base64");
    const decipher = crypto.createDecipheriv("aes-256-gcm", key, iv);
    decipher.setAuthTag(tag);
    return Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString(
      "utf8",
    );
  }
  throw new Error("Unknown environment variable storage format.");
}

function maskEnvValue(plaintext: string, isSecret: boolean): string {
  if (isSecret) {
    return "••••••••";
  }
  if (plaintext.length <= 4) {
    return "••••";
  }
  return `${plaintext.slice(0, 2)}••••${plaintext.slice(-2)}`;
}

/**
 * SQLite WAL-backed Registry Store for VPSAgent v2.
 * Uses Node.js built-in `node:sqlite` with WAL mode and foreign keys enabled.
 */
export class RegistryStore {
  private readonly db: DatabaseSync;
  private readonly encryptionKey: Buffer | null;

  constructor(dbPath: string, options?: RegistryStoreOptions) {
    if (dbPath !== ":memory:") {
      fs.mkdirSync(path.dirname(path.resolve(dbPath)), { recursive: true });
    }
    this.encryptionKey = options?.encryptionSecret
      ? deriveEncryptionKey(options.encryptionSecret)
      : null;
    this.db = new DatabaseSync(dbPath);
    this.db.exec("PRAGMA journal_mode = WAL;");
    this.db.exec("PRAGMA busy_timeout = 5000;");
    this.db.exec("PRAGMA foreign_keys = ON;");
    this.migrate();
  }

  private migrate(): void {
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS apps (
        slug TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        source_type TEXT NOT NULL CHECK (source_type IN ('image', 'git')),
        image TEXT,
        git_repo_url TEXT,
        git_branch TEXT,
        dockerfile_path TEXT NOT NULL DEFAULT 'Dockerfile',
        domain TEXT,
        folder_path TEXT NOT NULL,
        internal_port INTEGER NOT NULL,
        probe_http INTEGER NOT NULL DEFAULT 1,
        probe_path TEXT NOT NULL DEFAULT '/',
        status TEXT NOT NULL CHECK (status IN ('provisioning', 'building', 'running', 'stopped', 'error')),
        cpu_limit TEXT NOT NULL,
        memory_limit_mb INTEGER NOT NULL,
        companions_json TEXT NOT NULL DEFAULT '[]',
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
      );

      CREATE TABLE IF NOT EXISTS app_env_vars (
        app_slug TEXT NOT NULL REFERENCES apps(slug) ON DELETE CASCADE,
        key TEXT NOT NULL,
        value_enc TEXT NOT NULL,
        is_secret INTEGER NOT NULL DEFAULT 1,
        updated_at TEXT NOT NULL,
        PRIMARY KEY (app_slug, key)
      );

      CREATE TABLE IF NOT EXISTS approval_requests (
        id TEXT PRIMARY KEY,
        action TEXT NOT NULL,
        target_slug TEXT,
        summary TEXT NOT NULL,
        payload_json TEXT NOT NULL,
        requested_by TEXT NOT NULL,
        token_id TEXT,
        token_scope TEXT NOT NULL CHECK (token_scope IN ('read-only', 'approval-required', 'auto-approve')),
        status TEXT NOT NULL CHECK (status IN ('pending', 'approved', 'rejected', 'executed', 'failed')),
        risk_level TEXT NOT NULL CHECK (risk_level IN ('low', 'medium', 'high')),
        decided_by TEXT,
        decision_note TEXT,
        result_summary TEXT,
        created_at TEXT NOT NULL,
        decided_at TEXT,
        executed_at TEXT,
        execution_owner TEXT
      );

      CREATE TABLE IF NOT EXISTS approval_execution_payloads (
        approval_id TEXT PRIMARY KEY REFERENCES approval_requests(id) ON DELETE CASCADE,
        payload_enc TEXT NOT NULL,
        created_at TEXT NOT NULL
      );

      CREATE INDEX IF NOT EXISTS idx_approvals_status_created
        ON approval_requests (status, created_at DESC);

      CREATE TABLE IF NOT EXISTS audit_events (
        id TEXT PRIMARY KEY,
        actor TEXT NOT NULL CHECK (actor IN ('user', 'agent', 'system')),
        actor_token_id TEXT,
        action TEXT NOT NULL,
        target_slug TEXT,
        summary TEXT NOT NULL,
        risk_level TEXT NOT NULL CHECK (risk_level IN ('low', 'medium', 'high')),
        created_at TEXT NOT NULL
      );

      CREATE INDEX IF NOT EXISTS idx_audit_created_at
        ON audit_events (created_at DESC);

      CREATE TABLE IF NOT EXISTS mcp_tokens (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        scope TEXT NOT NULL CHECK (scope IN ('read-only', 'approval-required', 'auto-approve')),
        token_hash TEXT NOT NULL UNIQUE,
        token_prefix TEXT NOT NULL,
        created_at TEXT NOT NULL,
        last_used_at TEXT,
        revoked_at TEXT
      );

      CREATE TABLE IF NOT EXISTS system_settings (
        key TEXT PRIMARY KEY,
        value_json TEXT NOT NULL,
        updated_at TEXT NOT NULL
      );
    `);
    this.ensureColumn("apps", "probe_http", "INTEGER NOT NULL DEFAULT 1");
    this.ensureColumn("apps", "probe_path", "TEXT NOT NULL DEFAULT '/'");
    this.ensureColumn("approval_requests", "token_id", "TEXT");
    this.ensureColumn("audit_events", "actor_token_id", "TEXT");
  }

  private ensureColumn(table: string, column: string, definition: string): void {
    const cols = this.db
      .prepare(`PRAGMA table_info(${table})`)
      .all() as unknown as Array<{ name: string }>;
    if (!cols.some((c) => c.name === column)) {
      this.db.exec(`ALTER TABLE ${table} ADD COLUMN ${column} ${definition};`);
    }
  }

  close(): void {
    this.db.close();
  }

  // ---------------------------------------------------------------------------
  // Apps
  // ---------------------------------------------------------------------------

  upsertApp(
    input: Omit<AppRecord, "createdAt" | "updatedAt" | "probeHttp" | "probePath"> & {
      probeHttp?: boolean;
      probePath?: string;
      createdAt?: string;
      updatedAt?: string;
    },
  ): AppRecord {
    const safeSlug = validateAppSlug(input.slug);
    const safeDomain = input.domain ? validateDomain(input.domain) : null;
    const now = new Date().toISOString();
    const existing = this.getApp(safeSlug);

    const record = AppRecordSchema.parse({
      ...input,
      slug: safeSlug,
      domain: safeDomain,
      probeHttp: input.probeHttp ?? existing?.probeHttp ?? true,
      probePath: input.probePath ?? existing?.probePath ?? "/",
      createdAt: existing?.createdAt ?? input.createdAt ?? now,
      updatedAt: input.updatedAt ?? now,
    });

    this.db
      .prepare(
        `INSERT INTO apps (
          slug, name, source_type, image, git_repo_url, git_branch, dockerfile_path,
          domain, folder_path, internal_port, probe_http, probe_path, status, cpu_limit,
          memory_limit_mb, companions_json, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(slug) DO UPDATE SET
          name = excluded.name,
          source_type = excluded.source_type,
          image = excluded.image,
          git_repo_url = excluded.git_repo_url,
          git_branch = excluded.git_branch,
          dockerfile_path = excluded.dockerfile_path,
          domain = excluded.domain,
          folder_path = excluded.folder_path,
          internal_port = excluded.internal_port,
          probe_http = excluded.probe_http,
          probe_path = excluded.probe_path,
          status = excluded.status,
          cpu_limit = excluded.cpu_limit,
          memory_limit_mb = excluded.memory_limit_mb,
          companions_json = excluded.companions_json,
          updated_at = excluded.updated_at`,
      )
      .run(
        record.slug,
        record.name,
        record.sourceType,
        record.image,
        record.gitRepoUrl,
        record.gitBranch,
        record.dockerfilePath,
        record.domain,
        record.folderPath,
        record.internalPort,
        record.probeHttp ? 1 : 0,
        record.probePath,
        record.status,
        record.cpuLimit,
        record.memoryLimitMb,
        JSON.stringify(record.companions),
        record.createdAt,
        record.updatedAt,
      );

    return record;
  }

  getApp(slug: string): AppRecord | null {
    const row = this.db
      .prepare("SELECT * FROM apps WHERE slug = ?")
      .get(slug) as AppRow | undefined;
    return row ? this.mapAppRow(row) : null;
  }

  listApps(): AppRecord[] {
    const rows = this.db
      .prepare("SELECT * FROM apps ORDER BY created_at DESC")
      .all() as unknown as AppRow[];
    return rows.map((row) => this.mapAppRow(row));
  }

  updateAppStatus(slug: string, status: AppStatus): AppRecord | null {
    const now = new Date().toISOString();
    const res = this.db
      .prepare("UPDATE apps SET status = ?, updated_at = ? WHERE slug = ?")
      .run(status, now, slug);
    if (res.changes === 0) {
      return null;
    }
    return this.getApp(slug);
  }

  updateAppDomain(slug: string, domain: string | null): AppRecord | null {
    const safeDomain = domain ? validateDomain(domain) : null;
    const now = new Date().toISOString();
    const res = this.db
      .prepare("UPDATE apps SET domain = ?, updated_at = ? WHERE slug = ?")
      .run(safeDomain, now, slug);
    if (res.changes === 0) {
      return null;
    }
    return this.getApp(slug);
  }

  deleteApp(slug: string): boolean {
    const res = this.db.prepare("DELETE FROM apps WHERE slug = ?").run(slug);
    return Number(res.changes) > 0;
  }

  private mapAppRow(row: AppRow): AppRecord {
    const companions = JSON.parse(row.companions_json) as CompanionService[];
    return AppRecordSchema.parse({
      slug: row.slug,
      name: row.name,
      sourceType: row.source_type,
      image: row.image,
      gitRepoUrl: row.git_repo_url,
      gitBranch: row.git_branch,
      dockerfilePath: row.dockerfile_path,
      domain: row.domain,
      folderPath: row.folder_path,
      internalPort: row.internal_port,
      probeHttp: row.probe_http !== 0,
      probePath: row.probe_path || "/",
      status: row.status,
      cpuLimit: row.cpu_limit,
      memoryLimitMb: row.memory_limit_mb,
      companions,
      createdAt: row.created_at,
      updatedAt: row.updated_at,
    });
  }

  // ---------------------------------------------------------------------------
  // App Environment Variables (encrypted at rest, masked in list views)
  // ---------------------------------------------------------------------------

  setAppEnvVars(
    slug: string,
    vars: Array<{ key: string; value: string; isSecret?: boolean }>,
  ): AppEnvEntry[] {
    const app = this.getApp(slug);
    if (!app) {
      throw new Error(`App "${slug}" not found.`);
    }
    const now = new Date().toISOString();
    const stmt = this.db.prepare(
      `INSERT INTO app_env_vars (app_slug, key, value_enc, is_secret, updated_at)
       VALUES (?, ?, ?, ?, ?)
       ON CONFLICT(app_slug, key) DO UPDATE SET
         value_enc = excluded.value_enc,
         is_secret = excluded.is_secret,
         updated_at = excluded.updated_at`,
    );

    for (const item of vars) {
      const safeKey = validateEnvKey(item.key);
      const isSecret = item.isSecret ?? ENV_SECRET_KEY_HINT.test(safeKey);
      const encrypted = encryptValue(item.value, this.encryptionKey);
      stmt.run(slug, safeKey, encrypted, isSecret ? 1 : 0, now);
    }

    return this.listAppEnvVars(slug);
  }

  deleteAppEnvVar(slug: string, key: string): boolean {
    const safeKey = validateEnvKey(key);
    const res = this.db
      .prepare("DELETE FROM app_env_vars WHERE app_slug = ? AND key = ?")
      .run(slug, safeKey);
    return Number(res.changes) > 0;
  }

  /** Returns masked env metadata safe for Dashboard and MCP responses (never plaintext). */
  listAppEnvVars(slug: string): AppEnvEntry[] {
    const rows = this.db
      .prepare(
        "SELECT * FROM app_env_vars WHERE app_slug = ? ORDER BY key ASC",
      )
      .all(slug) as unknown as AppEnvRow[];
    return rows.map((row) => {
      const plaintext = decryptValue(row.value_enc, this.encryptionKey);
      const isSecret = row.is_secret === 1;
      return {
        key: row.key,
        isSecret,
        maskedValue: maskEnvValue(plaintext, isSecret),
        updatedAt: row.updated_at,
      };
    });
  }

  /** Internal runtime helper: decrypts app env vars strictly for writing the container `.env` file. */
  getAppEnvMapForRuntime(slug: string): Record<string, string> {
    const rows = this.db
      .prepare(
        "SELECT * FROM app_env_vars WHERE app_slug = ? ORDER BY key ASC",
      )
      .all(slug) as unknown as AppEnvRow[];
    const out: Record<string, string> = {};
    for (const row of rows) {
      out[row.key] = decryptValue(row.value_enc, this.encryptionKey);
    }
    return out;
  }

  // ---------------------------------------------------------------------------
  // Approval Queue (blocks read-only tokens from creating/authorizing mutations)
  // ---------------------------------------------------------------------------

  createApproval(input: {
    action: ApprovalActionType;
    targetSlug?: string | null;
    summary: string;
    payload: Record<string, unknown>;
    /** Optional unredacted payload encrypted at rest strictly for post-approval execution (never returned in list/read views). */
    executionPayload?: Record<string, unknown>;
    requestedBy: string;
    tokenId?: string | null;
    tokenScope: McpTokenScope;
    riskLevel?: RiskLevel;
  }): ApprovalRequest {
    if (!canScopeMutate(input.tokenScope)) {
      throw new Error(
        "Read-only tokens are blocked from creating or authorizing mutation approvals.",
      );
    }

    const id = `apr_${crypto.randomUUID().replace(/-/g, "").slice(0, 16)}`;
    const now = new Date().toISOString();
    const safeSummary = redactSecrets(input.summary).slice(0, 500);
    const safePayload = redactStructuredValue(input.payload) as Record<
      string,
      unknown
    >;
    const riskLevel = input.riskLevel ?? "medium";

    this.db
      .prepare(
        `INSERT INTO approval_requests (
          id, action, target_slug, summary, payload_json, requested_by, token_id, token_scope,
          status, risk_level, decided_by, decision_note, result_summary,
          created_at, decided_at, executed_at, execution_owner
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?, NULL, NULL, NULL, ?, NULL, NULL, NULL)`,
      )
      .run(
        id,
        input.action,
        input.targetSlug ?? null,
        safeSummary,
        JSON.stringify(safePayload),
        input.requestedBy,
        input.tokenId ?? null,
        input.tokenScope,
        riskLevel,
        now,
      );

    if (input.executionPayload) {
      const encrypted = encryptValue(
        JSON.stringify(input.executionPayload),
        this.encryptionKey,
      );
      this.db
        .prepare(
          `INSERT INTO approval_execution_payloads (approval_id, payload_enc, created_at)
           VALUES (?, ?, ?)`,
        )
        .run(id, encrypted, now);
    }

    return this.getApproval(id)!;
  }

  /** Internal executor helper: retrieves and consumes the encrypted execution payload for an approved request. */
  consumeApprovalExecutionPayload(id: string): Record<string, unknown> | null {
    const row = this.db
      .prepare(
        "SELECT payload_enc FROM approval_execution_payloads WHERE approval_id = ?",
      )
      .get(id) as { payload_enc: string } | undefined;
    if (!row) {
      return null;
    }
    this.db
      .prepare("DELETE FROM approval_execution_payloads WHERE approval_id = ?")
      .run(id);
    return JSON.parse(
      decryptValue(row.payload_enc, this.encryptionKey),
    ) as Record<string, unknown>;
  }

  getApproval(id: string): ApprovalRequest | null {
    const row = this.db
      .prepare("SELECT * FROM approval_requests WHERE id = ?")
      .get(id) as ApprovalRow | undefined;
    return row ? this.mapApprovalRow(row) : null;
  }

  listApprovals(options?: {
    status?: ApprovalStatus;
    limit?: number;
  }): ApprovalRequest[] {
    const limit = Math.min(Math.max(options?.limit ?? 50, 1), 200);
    const rows = options?.status
      ? (this.db
          .prepare(
            "SELECT * FROM approval_requests WHERE status = ? ORDER BY created_at DESC LIMIT ?",
          )
          .all(options.status, limit) as unknown as ApprovalRow[])
      : (this.db
          .prepare(
            "SELECT * FROM approval_requests ORDER BY created_at DESC LIMIT ?",
          )
          .all(limit) as unknown as ApprovalRow[]);
    return rows.map((row) => this.mapApprovalRow(row));
  }

  decideApproval(
    id: string,
    decision: "approved" | "rejected",
    decidedBy: string,
    note?: string,
  ): ApprovalRequest | null {
    const existing = this.getApproval(id);
    if (!existing) {
      return null;
    }
    if (!canScopeMutate(existing.tokenScope)) {
      throw new Error(
        "Read-only approval records cannot be approved or executed.",
      );
    }
    if (existing.status !== "pending") {
      throw new Error(
        `Approval "${id}" is already "${existing.status}" and cannot be decided again.`,
      );
    }
    const now = new Date().toISOString();
    const safeNote = note ? redactSecrets(note).slice(0, 500) : null;
    this.db
      .prepare(
        `UPDATE approval_requests
         SET status = ?, decided_by = ?, decision_note = ?, decided_at = ?
         WHERE id = ? AND status = 'pending'`,
      )
      .run(decision, decidedBy, safeNote, now, id);
    if (decision === "rejected") {
      this.db
        .prepare("DELETE FROM approval_execution_payloads WHERE approval_id = ?")
        .run(id);
    }
    return this.getApproval(id);
  }

  /** Atomically claims an approved request for execution so it can never run twice. */
  claimApprovalForExecution(id: string, owner: string): ApprovalRequest | null {
    const existing = this.getApproval(id);
    if (!existing || existing.status !== "approved") {
      return null;
    }
    if (!canScopeMutate(existing.tokenScope)) {
      throw new Error("Read-only approval records cannot be executed.");
    }
    const res = this.db
      .prepare(
        `UPDATE approval_requests
         SET execution_owner = ?
         WHERE id = ? AND status = 'approved' AND execution_owner IS NULL`,
      )
      .run(owner, id);
    if (Number(res.changes) === 0) {
      return null;
    }
    return this.getApproval(id);
  }

  completeApprovalExecution(
    id: string,
    outcome: "executed" | "failed",
    resultSummary: string,
  ): ApprovalRequest | null {
    const now = new Date().toISOString();
    const safeSummary = redactSecrets(resultSummary).slice(0, 500);
    const res = this.db
      .prepare(
        `UPDATE approval_requests
         SET status = ?, result_summary = ?, executed_at = ?
         WHERE id = ?`,
      )
      .run(outcome, safeSummary, now, id);
    if (Number(res.changes) === 0) {
      return null;
    }
    return this.getApproval(id);
  }

  private mapApprovalRow(row: ApprovalRow): ApprovalRequest {
    return ApprovalRequestSchema.parse({
      id: row.id,
      action: row.action,
      targetSlug: row.target_slug,
      summary: row.summary,
      payload: JSON.parse(row.payload_json) as Record<string, unknown>,
      requestedBy: row.requested_by,
      tokenId: row.token_id ?? null,
      tokenScope: row.token_scope,
      status: row.status,
      riskLevel: row.risk_level,
      decidedBy: row.decided_by,
      decisionNote: row.decision_note,
      resultSummary: row.result_summary,
      createdAt: row.created_at,
      decidedAt: row.decided_at,
      executedAt: row.executed_at,
    });
  }

  // ---------------------------------------------------------------------------
  // Audit Log (always redacts secrets before writing)
  // ---------------------------------------------------------------------------

  recordAudit(input: {
    actor: Actor;
    actorTokenId?: string | null;
    action: string;
    targetSlug?: string | null;
    summary: string;
    riskLevel?: RiskLevel;
  }): AuditEvent {
    const id = `aud_${crypto.randomUUID().replace(/-/g, "").slice(0, 16)}`;
    const createdAt = new Date().toISOString();
    const safeSummary = redactSecrets(input.summary).slice(0, 500);
    const event = AuditEventSchema.parse({
      id,
      actor: input.actor,
      actorTokenId: input.actorTokenId ?? null,
      action: input.action,
      targetSlug: input.targetSlug ?? null,
      summary: safeSummary,
      riskLevel: input.riskLevel ?? "low",
      createdAt,
    });

    this.db
      .prepare(
        `INSERT INTO audit_events (id, actor, actor_token_id, action, target_slug, summary, risk_level, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .run(
        event.id,
        event.actor,
        event.actorTokenId,
        event.action,
        event.targetSlug,
        event.summary,
        event.riskLevel,
        event.createdAt,
      );

    return event;
  }

  listAuditEvents(options?: {
    limit?: number;
    targetSlug?: string;
    query?: string;
  }): AuditEvent[] {
    const limit = Math.min(Math.max(options?.limit ?? 100, 1), 500);
    const rows = options?.targetSlug
      ? (this.db
          .prepare(
            "SELECT * FROM audit_events WHERE target_slug = ? ORDER BY created_at DESC LIMIT ?",
          )
          .all(options.targetSlug, limit) as unknown as AuditRow[])
      : (this.db
          .prepare(
            "SELECT * FROM audit_events ORDER BY created_at DESC LIMIT ?",
          )
          .all(limit) as unknown as AuditRow[]);

    const events = rows.map((row) =>
      AuditEventSchema.parse({
        id: row.id,
        actor: row.actor,
        actorTokenId: row.actor_token_id ?? null,
        action: row.action,
        targetSlug: row.target_slug,
        summary: row.summary,
        riskLevel: row.risk_level,
        createdAt: row.created_at,
      }),
    );

    if (options?.query && options.query.trim()) {
      const needle = options.query.trim().toLowerCase();
      return events.filter(
        (e) =>
          e.summary.toLowerCase().includes(needle) ||
          e.action.toLowerCase().includes(needle) ||
          (e.targetSlug?.toLowerCase().includes(needle) ?? false),
      );
    }

    return events;
  }

  // ---------------------------------------------------------------------------
  // Scoped MCP Tokens
  // ---------------------------------------------------------------------------

  createMcpToken(input: {
    name: string;
    scope: McpTokenScope;
  }): { record: McpTokenRecord; rawToken: string } {
    const id = `mcp_${crypto.randomUUID().replace(/-/g, "").slice(0, 16)}`;
    const { rawToken, tokenHash, tokenPrefix } = generateMcpToken();
    const now = new Date().toISOString();

    this.db
      .prepare(
        `INSERT INTO mcp_tokens (id, name, scope, token_hash, token_prefix, created_at, last_used_at, revoked_at)
         VALUES (?, ?, ?, ?, ?, ?, NULL, NULL)`,
      )
      .run(id, input.name.trim(), input.scope, tokenHash, tokenPrefix, now);

    const record = McpTokenRecordSchema.parse({
      id,
      name: input.name.trim(),
      scope: input.scope,
      tokenPrefix,
      createdAt: now,
      lastUsedAt: null,
      revokedAt: null,
    });

    return { record, rawToken };
  }

  listMcpTokens(): McpTokenRecord[] {
    const rows = this.db
      .prepare("SELECT * FROM mcp_tokens ORDER BY created_at DESC")
      .all() as unknown as McpTokenRow[];
    return rows.map((row) =>
      McpTokenRecordSchema.parse({
        id: row.id,
        name: row.name,
        scope: row.scope,
        tokenPrefix: row.token_prefix,
        createdAt: row.created_at,
        lastUsedAt: row.last_used_at,
        revokedAt: row.revoked_at,
      }),
    );
  }

  verifyMcpToken(rawToken: string): McpTokenRecord | null {
    const hash = hashMcpToken(rawToken);
    const row = this.db
      .prepare(
        "SELECT * FROM mcp_tokens WHERE token_hash = ? AND revoked_at IS NULL",
      )
      .get(hash) as McpTokenRow | undefined;
    if (!row) {
      return null;
    }
    const now = new Date().toISOString();
    this.db
      .prepare("UPDATE mcp_tokens SET last_used_at = ? WHERE id = ?")
      .run(now, row.id);

    return McpTokenRecordSchema.parse({
      id: row.id,
      name: row.name,
      scope: row.scope,
      tokenPrefix: row.token_prefix,
      createdAt: row.created_at,
      lastUsedAt: now,
      revokedAt: row.revoked_at,
    });
  }

  revokeMcpToken(id: string): boolean {
    const now = new Date().toISOString();
    const res = this.db
      .prepare(
        "UPDATE mcp_tokens SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL",
      )
      .run(now, id);
    return Number(res.changes) > 0;
  }

  // ---------------------------------------------------------------------------
  // 2-Step First-Boot Setup & Admin Passphrase
  // ---------------------------------------------------------------------------

  getSetting<T>(key: string): T | null {
    const row = this.db
      .prepare("SELECT value_json FROM system_settings WHERE key = ?")
      .get(key) as { value_json: string } | undefined;
    if (!row) {
      return null;
    }
    return JSON.parse(row.value_json) as T;
  }

  setSetting(key: string, value: unknown): void {
    const now = new Date().toISOString();
    this.db
      .prepare(
        `INSERT INTO system_settings (key, value_json, updated_at)
         VALUES (?, ?, ?)
         ON CONFLICT(key) DO UPDATE SET value_json = excluded.value_json, updated_at = excluded.updated_at`,
      )
      .run(key, JSON.stringify(value), now);
  }

  getSetupState(): SetupState {
    const row = this.db
      .prepare("SELECT value_json FROM system_settings WHERE key = 'setup_state'")
      .get() as { value_json: string } | undefined;
    if (!row) {
      return { ...DEFAULT_SETUP_STATE };
    }
    return SetupStateSchema.parse(JSON.parse(row.value_json));
  }

  updateSetupState(patch: Partial<SetupState>): SetupState {
    const current = this.getSetupState();
    const nextDomain =
      patch.domain === undefined
        ? current.domain
        : patch.domain === null
          ? null
          : validateDomain(patch.domain);
    const next = SetupStateSchema.parse({
      ...current,
      ...patch,
      domain: nextDomain,
    });
    const now = new Date().toISOString();
    this.db
      .prepare(
        `INSERT INTO system_settings (key, value_json, updated_at)
         VALUES ('setup_state', ?, ?)
         ON CONFLICT(key) DO UPDATE SET value_json = excluded.value_json, updated_at = excluded.updated_at`,
      )
      .run(JSON.stringify(next), now);
    return next;
  }

  setAdminPassphrase(passphrase: string): void {
    if (passphrase.length < 8) {
      throw new Error("Admin passphrase must be at least 8 characters.");
    }
    const salt = crypto.randomBytes(16).toString("hex");
    const derived = crypto.scryptSync(passphrase, salt, 64).toString("hex");
    const now = new Date().toISOString();
    this.db
      .prepare(
        `INSERT INTO system_settings (key, value_json, updated_at)
         VALUES ('admin_passphrase', ?, ?)
         ON CONFLICT(key) DO UPDATE SET value_json = excluded.value_json, updated_at = excluded.updated_at`,
      )
      .run(JSON.stringify({ salt, hash: derived }), now);
  }

  verifyAdminPassphrase(passphrase: string): boolean {
    const row = this.db
      .prepare(
        "SELECT value_json FROM system_settings WHERE key = 'admin_passphrase'",
      )
      .get() as { value_json: string } | undefined;
    if (!row) {
      return false;
    }
    const parsed = JSON.parse(row.value_json) as { salt: string; hash: string };
    const candidate = crypto.scryptSync(passphrase, parsed.salt, 64);
    const stored = Buffer.from(parsed.hash, "hex");
    if (candidate.length !== stored.length) {
      return false;
    }
    return crypto.timingSafeEqual(candidate, stored);
  }
}
