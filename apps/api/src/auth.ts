import crypto from "node:crypto";
import type { Context } from "hono";
import type { RegistryStore } from "@vpsagent/shared";

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

function sha256Hex(value: string): string {
  return crypto.createHash("sha256").update(value, "utf8").digest("hex");
}

function timingSafeHexEqual(aHex: string, bHex: string): boolean {
  const a = Buffer.from(aHex, "utf8");
  const b = Buffer.from(bHex, "utf8");
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(a, b);
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
    return "localhost";
  }
}

export function getRequestProtocol(c: Context, trustProxy: boolean): string {
  if (trustProxy) {
    const fwdProto = c.req.header("x-forwarded-proto")?.split(",")[0]?.trim();
    if (fwdProto) return fwdProto.toLowerCase();
  }
  try {
    return new URL(c.req.url).protocol.replace(/:$/, "").toLowerCase();
  } catch {
    return "http";
  }
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

    if (this.envClaimTokenHash && timingSafeHexEqual(candidateHash, this.envClaimTokenHash)) {
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
