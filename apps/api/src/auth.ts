import crypto from "node:crypto";
import type { Context } from "hono";
import { type RegistryStore, isLoopbackHost } from "@vpsagent/shared";

export const SESSION_COOKIE_NAME = "vpsagent_session";
const SESSION_TTL_SECONDS = 7 * 24 * 60 * 60;
const CLAIM_TOKEN_SETTING_KEY = "setup_claim_token_hash";
const LOGIN_WINDOW_MS = 5 * 60 * 1000;
const MAX_FAILED_LOGINS = 10;

interface SessionPayload {
  sub: "owner";
  iat: number;
  exp: number;
}

export interface TransportContextOptions {
  trustProxy: boolean;
  /** True ONLY on a dedicated loopback-only local listener (e.g. 127.0.0.1:3002 SSH tunnel). */
  isLocalListener?: boolean | undefined;
  /** Optional fallback peer IP for unit tests where no Node TCP socket is attached. */
  defaultPeerIp?: string | undefined;
}

function sha256Hex(value: string): string {
  return crypto.createHash("sha256").update(value, "utf8").digest("hex");
}

function timingSafeHexEqual(aHex: string, bHex: string): boolean {
  const a = Buffer.from(aHex, "utf8");
  const b = Buffer.from(bHex, "utf8");
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(a, b);
}

export function isLoopbackIp(ip: string | null | undefined): boolean {
  if (!ip) return false;
  const clean = ip.trim().toLowerCase().replace(/^\[|\]$/g, "");
  if (clean === "::1" || clean === "127.0.0.1" || clean === "::ffff:127.0.0.1") {
    return true;
  }
  if (clean.startsWith("127.")) return true;
  if (clean.startsWith("::ffff:127.")) return true;
  return false;
}

export function getSocketPeerIp(
  c: Context,
  defaultPeerIp?: string,
): string | null {
  const env = c.env as
    | { incoming?: { socket?: { remoteAddress?: string } } }
    | undefined;
  const socketIp = env?.incoming?.socket?.remoteAddress;
  if (typeof socketIp === "string" && socketIp.trim()) {
    return socketIp.trim();
  }
  return defaultPeerIp?.trim() || null;
}

export function getRequestHost(c: Context, trustProxy: boolean): string {
  if (trustProxy) {
    const fwdHost = c.req.header("x-forwarded-host")?.split(",")[0]?.trim();
    if (fwdHost) return fwdHost;
  }
  const hostHeader = c.req.header("host")?.trim();
  if (hostHeader) return hostHeader;
  try {
    return new URL(c.req.url).host;
  } catch {
    return "";
  }
}

export function getRequestProtocol(c: Context, trustProxy: boolean): string {
  if (trustProxy) {
    const fwdProto = c.req.header("x-forwarded-proto")?.split(",")[0]?.trim();
    if (fwdProto) return fwdProto.toLowerCase();
    // Behind a trusted proxy with missing X-Forwarded-Proto, never assume https
    return "http";
  }
  try {
    return new URL(c.req.url).protocol.replace(/:$/, "").toLowerCase();
  } catch {
    return "http";
  }
}

/**
 * Determines whether a request arrived over genuine local loopback (NEVER using the
 * spoofable `Host` header alone as proof of loopback).
 */
export function isGenuineLocalLoopback(
  c: Context,
  opts: TransportContextOptions,
): boolean {
  if (opts.isLocalListener) {
    return true;
  }
  const xff = c.req.header("x-forwarded-for");
  if (opts.trustProxy && xff) {
    const firstClient = xff.split(",")[0]?.trim();
    return isLoopbackIp(firstClient);
  }
  if (opts.trustProxy) {
    // Missing proxy metadata on a proxied listener: only allow if actual socket peer is loopback
    const peerIp = getSocketPeerIp(c, opts.defaultPeerIp);
    return isLoopbackIp(peerIp);
  }
  const peerIp = getSocketPeerIp(c, opts.defaultPeerIp);
  return isLoopbackIp(peerIp);
}

/**
 * Requires HTTPS (from trusted proxy or TLS) or a genuinely local loopback connection
 * before accepting owner credentials, creating keys, or serving Remote MCP.
 */
export function assertSecureTransport(
  c: Context,
  opts: TransportContextOptions,
): { isHttps: boolean; isLocalLoopback: boolean } {
  const proto = getRequestProtocol(c, opts.trustProxy);
  if (proto === "https") {
    return { isHttps: true, isLocalLoopback: false };
  }
  const localLoopback = isGenuineLocalLoopback(c, opts);
  const host = getRequestHost(c, opts.trustProxy);
  if (localLoopback && isLoopbackHost(host)) {
    return { isHttps: false, isLocalLoopback: true };
  }
  throw new Error(
    "HTTPS is required for remote access. Connect your domain for automatic HTTPS, or use a local SSH tunnel (ssh -L 3002:127.0.0.1:3002) for first-time setup.",
  );
}

function normalizeHostWithoutDefaultPort(
  hostHeader: string,
  isHttps: boolean,
): string {
  const trimmed = hostHeader.trim().toLowerCase();
  if (trimmed.startsWith("[")) {
    return trimmed;
  }
  const colonIdx = trimmed.lastIndexOf(":");
  if (colonIdx !== -1) {
    const hostname = trimmed.slice(0, colonIdx);
    const port = trimmed.slice(colonIdx + 1);
    if ((isHttps && port === "443") || (!isHttps && port === "80")) {
      return hostname;
    }
  }
  return trimmed;
}

/**
 * Validates `Host` and optional `Origin` headers on `/mcp` to prevent DNS rebinding
 * and cross-origin browser attacks while still allowing CLI/server MCP clients that
 * omit `Origin`.
 */
export function validateMcpHostAndOrigin(
  c: Context,
  params: {
    setupDomain: string | null;
    httpsActive: boolean;
    transport: { isHttps: boolean; isLocalLoopback: boolean };
    trustProxy: boolean;
  },
): void {
  const rawHost = getRequestHost(c, params.trustProxy);
  if (!rawHost) {
    throw new Error("Missing Host header.");
  }

  const normalizedHost = normalizeHostWithoutDefaultPort(
    rawHost,
    params.transport.isHttps,
  );
  const expectedDomain =
    params.setupDomain && params.httpsActive
      ? params.setupDomain.trim().toLowerCase()
      : null;

  const hostIsLoopback =
    params.transport.isLocalLoopback && isLoopbackHost(rawHost);
  const hostMatchesDomain =
    expectedDomain !== null &&
    params.transport.isHttps &&
    normalizedHost === expectedDomain;

  if (!hostIsLoopback && !hostMatchesDomain) {
    throw new Error(`Unexpected Host header "${rawHost}" for /mcp.`);
  }

  const originHeader = c.req.header("origin")?.trim();
  if (!originHeader) {
    // CLI / desktop MCP clients normally omit Origin — allow.
    return;
  }

  let parsedOrigin: URL;
  try {
    parsedOrigin = new URL(originHeader);
  } catch {
    throw new Error(`Invalid Origin header "${originHeader}".`);
  }

  if (
    expectedDomain !== null &&
    parsedOrigin.protocol === "https:" &&
    parsedOrigin.hostname.toLowerCase() === expectedDomain &&
    (parsedOrigin.port === "" || parsedOrigin.port === "443")
  ) {
    return;
  }

  if (
    params.transport.isLocalLoopback &&
    (parsedOrigin.protocol === "http:" || parsedOrigin.protocol === "https:") &&
    isLoopbackHost(parsedOrigin.host)
  ) {
    return;
  }

  throw new Error(`Disallowed Origin header "${originHeader}" for /mcp.`);
}

function parseCookies(cookieHeader: string | undefined): Record<string, string> {
  const out: Record<string, string> = {};
  if (!cookieHeader) return out;
  for (const part of cookieHeader.split(";")) {
    const idx = part.indexOf("=");
    if (idx === -1) continue;
    const key = part.slice(0, idx).trim();
    const val = part.slice(idx + 1).trim();
    if (key) {
      out[key] = decodeURIComponent(val);
    }
  }
  return out;
}

export class SessionManager {
  private readonly sessionSecret: Buffer;
  private readonly store: RegistryStore;
  private readonly envClaimTokenHash: string | null;
  private readonly loginFailures = new Map<string, number[]>();

  constructor(options: {
    store: RegistryStore;
    sessionSecret: string;
    claimToken?: string | undefined;
  }) {
    this.store = options.store;
    this.sessionSecret = crypto
      .createHash("sha256")
      .update(options.sessionSecret, "utf8")
      .digest();
    const cleanedClaim = options.claimToken?.trim();
    this.envClaimTokenHash = cleanedClaim ? sha256Hex(cleanedClaim) : null;
  }

  /** Ensures a claim token exists when unclaimed; returns raw token only if newly generated here. */
  ensureClaimToken(): string | null {
    if (this.store.getSetupState().claimed) {
      return null;
    }
    if (this.envClaimTokenHash) {
      return null;
    }
    const existing = this.store.getSetting<{ hash: string }>(
      CLAIM_TOKEN_SETTING_KEY,
    );
    if (existing?.hash) {
      return null;
    }
    const raw = crypto.randomBytes(24).toString("base64url");
    this.store.setSetting(CLAIM_TOKEN_SETTING_KEY, { hash: sha256Hex(raw) });
    return raw;
  }

  verifyClaimToken(rawToken: string): boolean {
    const candidate = rawToken.trim();
    if (!candidate) return false;
    const candidateHash = sha256Hex(candidate);

    if (
      this.envClaimTokenHash &&
      timingSafeHexEqual(candidateHash, this.envClaimTokenHash)
    ) {
      return true;
    }
    const stored = this.store.getSetting<{ hash: string }>(
      CLAIM_TOKEN_SETTING_KEY,
    );
    if (stored?.hash && timingSafeHexEqual(candidateHash, stored.hash)) {
      return true;
    }
    return false;
  }

  clearStoredClaimToken(): void {
    this.store.setSetting(CLAIM_TOKEN_SETTING_KEY, { hash: "" });
  }

  createSessionToken(): string {
    const nowSec = Math.floor(Date.now() / 1000);
    const payload: SessionPayload = {
      sub: "owner",
      iat: nowSec,
      exp: nowSec + SESSION_TTL_SECONDS,
    };
    const encoded = Buffer.from(JSON.stringify(payload), "utf8").toString(
      "base64url",
    );
    const sig = crypto
      .createHmac("sha256", this.sessionSecret)
      .update(encoded, "utf8")
      .digest("base64url");
    return `${encoded}.${sig}`;
  }

  verifySessionToken(token: string | undefined): boolean {
    if (!token) return false;
    const parts = token.split(".");
    if (parts.length !== 2) return false;
    const [encoded, sig] = parts;
    if (!encoded || !sig) return false;
    const expectedSig = crypto
      .createHmac("sha256", this.sessionSecret)
      .update(encoded, "utf8")
      .digest("base64url");
    if (!timingSafeHexEqual(sig, expectedSig)) {
      return false;
    }
    try {
      const parsed = JSON.parse(
        Buffer.from(encoded, "base64url").toString("utf8"),
      ) as SessionPayload;
      if (parsed.sub !== "owner") return false;
      const nowSec = Math.floor(Date.now() / 1000);
      return typeof parsed.exp === "number" && parsed.exp > nowSec;
    } catch {
      return false;
    }
  }

  isAuthenticatedRequest(c: Context): boolean {
    if (!this.store.getSetupState().claimed) {
      return false;
    }
    const cookies = parseCookies(c.req.header("cookie"));
    return this.verifySessionToken(cookies[SESSION_COOKIE_NAME]);
  }

  buildSetSessionCookie(token: string, isSecure: boolean): string {
    const parts = [
      `${SESSION_COOKIE_NAME}=${encodeURIComponent(token)}`,
      "Path=/",
      "HttpOnly",
      "SameSite=Lax",
      `Max-Age=${SESSION_TTL_SECONDS}`,
    ];
    if (isSecure) {
      parts.push("Secure");
    }
    return parts.join("; ");
  }

  buildClearSessionCookie(isSecure: boolean): string {
    const parts = [
      `${SESSION_COOKIE_NAME}=`,
      "Path=/",
      "HttpOnly",
      "SameSite=Lax",
      "Max-Age=0",
    ];
    if (isSecure) {
      parts.push("Secure");
    }
    return parts.join("; ");
  }

  checkLoginRateLimit(clientKey: string): boolean {
    const now = Date.now();
    const recent = (this.loginFailures.get(clientKey) ?? []).filter(
      (ts) => now - ts < LOGIN_WINDOW_MS,
    );
    this.loginFailures.set(clientKey, recent);
    return recent.length < MAX_FAILED_LOGINS;
  }

  recordLoginFailure(clientKey: string): void {
    const now = Date.now();
    const recent = (this.loginFailures.get(clientKey) ?? []).filter(
      (ts) => now - ts < LOGIN_WINDOW_MS,
    );
    recent.push(now);
    this.loginFailures.set(clientKey, recent);
  }

  clearLoginFailures(clientKey: string): void {
    this.loginFailures.delete(clientKey);
  }
}
