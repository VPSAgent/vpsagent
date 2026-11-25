import dns from "node:dns";
import fs from "node:fs";
import net from "node:net";
import path from "node:path";

const SLUG_PATTERN = /^[a-z0-9][a-z0-9-]{0,46}[a-z0-9]$/;
const DOMAIN_PATTERN =
  /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/i;
const ENV_KEY_PATTERN = /^[A-Za-z_][A-Za-z0-9_]{0,127}$/;
const DOCKER_IMAGE_REF_PATTERN = /^[a-zA-Z0-9][a-zA-Z0-9._/:@-]{1,200}$/;
const GIT_BRANCH_PATTERN = /^[A-Za-z0-9._/-]{1,120}$/;
const DOCKERFILE_PATH_PATTERN = /^[A-Za-z0-9._/-]{1,200}$/;

const FORBIDDEN_APP_ENV_PREFIXES = ["VPSAGENT_", "VPS_OS_", "DOCKER_", "LD_"];
const FORBIDDEN_APP_ENV_EXACT = new Set([
  "PATH",
  "HOME",
  "HOSTALIASES",
  "IFS",
  "ENV",
  "BASH_ENV",
]);

const RESERVED_SLUGS = new Set([
  "core",
  "vpsagent",
  "vps-os",
  "caddy",
  "api",
  "dashboard",
  "agent",
  "system",
  "root",
  "admin",
]);

const ENV_OR_YAML_SECRET_PATTERN =
  /\b([A-Za-z0-9_]*(?:key|token|secret|password|passwd|pass|passphrase|credential|auth)[A-Za-z0-9_]*)\s*([:=])\s*(?!\[REDACTED\]@)("[^"]*"|'[^']*'|[^\s,;]+)/gi;
const JSON_SECRET_PATTERN =
  /"([A-Za-z0-9_]*(?:key|token|secret|password|passwd|pass|passphrase|credential|auth)[A-Za-z0-9_]*)"\s*:\s*"([^"]*)"/gi;
const AUTH_HEADER_PATTERN = /\b(Bearer|Basic)\s+[A-Za-z0-9._~+/=-]{6,}/gi;
const KNOWN_TOKEN_PREFIX_PATTERN =
  /\b(sk-ant-[A-Za-z0-9_-]{8,}|sk-[A-Za-z0-9_-]{8,}|gh[pousr]_[A-Za-z0-9]{10,}|github_pat_[A-Za-z0-9_]{12,}|xox[baprs]-[A-Za-z0-9-]{10,}|AIza[0-9A-Za-z_-]{20,}|vpsmcp_[A-Za-z0-9_-]{16,}|\d{6,12}:AA[A-Za-z0-9_-]{25,})\b/g;
const PEM_KEY_PATTERN =
  /-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY-----/g;
const URL_CREDENTIALS_PATTERN = /\b(https?:\/\/)([^:@\s/]+):([^@\s/]+)@/gi;
const GIT_TOKEN_PATTERN = /^[A-Za-z0-9_.-]{8,512}$/;
const GITHUB_OWNER_REPO_SEGMENT = /^[A-Za-z0-9._-]+$/;

const BLOCKED_METADATA_HOSTS = new Set([
  "169.254.169.254",
  "metadata.google.internal",
  "metadata",
  "100.100.100.200",
]);

const SENSITIVE_FIELD_KEY_PATTERN =
  /^(?:.*(?:secret|password|passwd|passphrase|credential|private[_-]?key|api[_-]?key|access[_-]?token|refresh[_-]?token|auth[_-]?token|bot[_-]?token|bearer[_-]?token|session[_-]?token|git[_-]?token|github[_-]?token|authorization|database_url|redis_url)|token)$/i;

/**
 * Validates that an application slug is safe for folder names,
 * Docker Compose project names, and internal DNS labels.
 */
export function validateAppSlug(slug: string): string {
  if (!SLUG_PATTERN.test(slug)) {
    throw new Error(
      `Invalid app slug "${slug}": must be 2-48 lowercase letters, numbers, or hyphens.`,
    );
  }
  if (RESERVED_SLUGS.has(slug)) {
    throw new Error(`Reserved app slug "${slug}" cannot be used.`);
  }
  return slug;
}

/**
 * Resolves an isolated app folder under `appsRoot`, rejecting path traversal
 * and any symlink that points outside `appsRoot`.
 */
export function resolveScopedAppDir(appsRoot: string, slug: string): string {
  const safeSlug = validateAppSlug(slug);
  const resolvedRoot = path.resolve(appsRoot);
  const candidate = path.resolve(resolvedRoot, safeSlug);
  const relative = path.relative(resolvedRoot, candidate);

  if (
    !relative ||
    relative.startsWith("..") ||
    path.isAbsolute(relative) ||
    relative !== safeSlug
  ) {
    throw new Error(
      `Security boundary violation: resolved path escapes apps root "${resolvedRoot}".`,
    );
  }

  if (fs.existsSync(resolvedRoot)) {
    const rootStat = fs.lstatSync(resolvedRoot);
    if (!rootStat.isDirectory() || rootStat.isSymbolicLink()) {
      throw new Error(
        `Security boundary violation: apps root "${resolvedRoot}" must be a real directory.`,
      );
    }

    const realRoot = fs.realpathSync(resolvedRoot);
    try {
      const candidateStat = fs.lstatSync(candidate);
      if (candidateStat.isSymbolicLink()) {
        throw new Error(
          `Security boundary violation: target "${candidate}" cannot be a symbolic link.`,
        );
      }
      const realCandidate = fs.realpathSync(candidate);
      if (realCandidate !== path.join(realRoot, safeSlug)) {
        throw new Error(
          `Security boundary violation: real path "${realCandidate}" escapes apps root.`,
        );
      }
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code !== "ENOENT") {
        throw err;
      }
    }
  }

  return candidate;
}

/**
 * Validates a public domain name before writing reverse-proxy routes.
 * Prevents control characters, paths, or Caddyfile syntax injection.
 */
export function validateDomain(domain: string): string {
  const normalized = domain.trim().toLowerCase();
  if (!DOMAIN_PATTERN.test(normalized)) {
    throw new Error(`Invalid domain name "${domain}".`);
  }
  return normalized;
}

/**
 * Validates an environment variable key name.
 */
export function validateEnvKey(key: string): string {
  if (!ENV_KEY_PATTERN.test(key)) {
    throw new Error(
      `Invalid environment variable key "${key}": use letters, numbers, and underscores only.`,
    );
  }
  return key;
}

/**
 * Returns true if an environment variable key is reserved/forbidden inside user apps
 * (such as host control-plane prefixes or dynamic linker variables).
 */
export function isForbiddenAppEnvKey(key: string): boolean {
  return (
    FORBIDDEN_APP_ENV_EXACT.has(key) ||
    FORBIDDEN_APP_ENV_PREFIXES.some((prefix) => key.startsWith(prefix))
  );
}

/**
 * Validates a Docker image reference (registry/name:tag or @digest).
 */
export function validateDockerImageRef(image: string): string {
  const trimmed = image.trim();
  if (
    !DOCKER_IMAGE_REF_PATTERN.test(trimmed) ||
    trimmed.includes("..") ||
    trimmed.includes("$")
  ) {
    throw new Error(`Invalid Docker image reference "${image}".`);
  }
  return trimmed;
}

/**
 * Validates a Git branch or tag name, blocking flag injection (`-`), traversal (`..`),
 * and control characters.
 */
export function validateGitBranch(branch: string): string {
  const trimmed = branch.trim();
  if (
    !GIT_BRANCH_PATTERN.test(trimmed) ||
    trimmed.startsWith("-") ||
    trimmed.startsWith("/") ||
    trimmed.endsWith("/") ||
    trimmed.endsWith(".lock") ||
    trimmed.includes("..") ||
    trimmed.includes("//") ||
    trimmed.includes("@{")
  ) {
    throw new Error(`Invalid Git branch name "${branch}".`);
  }
  return trimmed;
}

/**
 * Validates a relative Dockerfile path inside a repository (e.g. `Dockerfile` or `docker/Dockerfile.prod`).
 */
export function validateDockerfilePath(dockerfilePath: string): string {
  const trimmed = dockerfilePath.trim();
  if (
    !DOCKERFILE_PATH_PATTERN.test(trimmed) ||
    trimmed.startsWith("/") ||
    trimmed.startsWith("-") ||
    trimmed.includes("\\") ||
    trimmed.includes("..") ||
    trimmed.split("/").some((segment) => segment === "" || segment === "." || segment === "..")
  ) {
    throw new Error(
      `Invalid Dockerfile path "${dockerfilePath}": must be a safe relative path inside the repository.`,
    );
  }
  return trimmed;
}

/**
 * Quotes a single `.env` value literally so special characters (`$`, `#`, spaces,
 * quotes, backslashes, newlines) are preserved verbatim by Docker Compose.
 */
export function quoteEnvValue(value: string): string {
  if (value.includes("\0")) {
    throw new Error("Environment variable values cannot contain null bytes.");
  }
  // Single quotes preserve everything literally in Docker Compose .env files
  // as long as the value has no single quotes or newlines.
  if (!value.includes("'") && !value.includes("\n") && !value.includes("\r")) {
    return `'${value}'`;
  }
  // Fall back to double-quoted string with strict escaping (including `$` -> `$$`
  // or literal backslash-escaped control chars).
  const escaped = value
    .replace(/\\/g, "\\\\")
    .replace(/"/g, '\\"')
    .replace(/\r/g, "\\r")
    .replace(/\n/g, "\\n");
  return `"${escaped}"`;
}

export const MAX_APP_ENV_BYTES = 64 * 1024;

/**
 * Serializes a map of environment variables into a deterministic, literally-quoted
 * `.env` file string, enforcing the 64 KiB size limit before anything is written.
 */
export function formatEnvFile(vars: Record<string, string>): string {
  const keys = Object.keys(vars).sort();
  if (keys.length === 0) {
    return "";
  }
  const lines = keys.map((key) => {
    const safeKey = validateEnvKey(key);
    const rawValue = vars[key] ?? "";
    return `${safeKey}=${quoteEnvValue(rawValue)}`;
  });
  const encoded = `${lines.join("\n")}\n`;
  if (Buffer.byteLength(encoded, "utf8") > MAX_APP_ENV_BYTES) {
    throw new Error(
      `Environment file exceeds maximum allowed size of ${MAX_APP_ENV_BYTES} bytes.`,
    );
  }
  return encoded;
}

/**
 * Returns true if the given hostname or Host header refers to local loopback.
 */
export function isLoopbackHost(hostHeader: string): boolean {
  const trimmed = hostHeader.trim().toLowerCase();
  // Strip port if present (handling bracketed IPv6 like [::1]:3001)
  let host = trimmed;
  if (host.startsWith("[")) {
    const endBracket = host.indexOf("]");
    host = endBracket !== -1 ? host.slice(1, endBracket) : host;
  } else {
    const colonIdx = host.indexOf(":");
    if (colonIdx !== -1) {
      host = host.slice(0, colonIdx);
    }
  }
  host = host.replace(/\.+$/, "");
  return (
    host === "localhost" ||
    host.endsWith(".localhost") ||
    host === "127.0.0.1" ||
    host === "::1"
  );
}

/**
 * Enforces HTTPS-only access for non-loopback hosts (e.g. Remote MCP `/mcp`).
 */
export function assertHttpsForRemoteHost(
  hostHeader: string,
  protocol: string,
): void {
  const normalizedProto = protocol.trim().toLowerCase().replace(/:$/, "");
  if (normalizedProto === "https") {
    return;
  }
  if (isLoopbackHost(hostHeader)) {
    return;
  }
  throw new Error(
    `HTTPS is required for remote host "${hostHeader}". Plain HTTP is only allowed on localhost.`,
  );
}

function expandIpv6Groups(rawIp: string): number[] | null {
  const withoutZone = rawIp.split("%")[0] ?? rawIp;
  const doubleColonParts = withoutZone.split("::");
  if (doubleColonParts.length > 2) {
    return null;
  }

  const parseSegmentList = (part: string): number[] | null => {
    if (!part) return [];
    const tokens = part.split(":");
    const groups: number[] = [];
    for (let i = 0; i < tokens.length; i++) {
      const token = tokens[i]!;
      if (token.includes(".")) {
        if (i !== tokens.length - 1 || !net.isIPv4(token)) {
          return null;
        }
        const octets = token.split(".").map(Number);
        groups.push((octets[0]! << 8) | octets[1]!, (octets[2]! << 8) | octets[3]!);
      } else {
        if (!/^[0-9a-f]{1,4}$/i.test(token)) {
          return null;
        }
        groups.push(Number.parseInt(token, 16));
      }
    }
    return groups;
  };

  if (doubleColonParts.length === 1) {
    const groups = parseSegmentList(doubleColonParts[0]!);
    return groups && groups.length === 8 ? groups : null;
  }

  const head = parseSegmentList(doubleColonParts[0]!);
  const tail = parseSegmentList(doubleColonParts[1]!);
  if (!head || !tail || head.length + tail.length > 7) {
    return null;
  }
  const missing = 8 - head.length - tail.length;
  return [...head, ...Array<number>(missing).fill(0), ...tail];
}

function extractIpv4Octets(
  host: string,
  ipv6Groups: number[] | null,
): [number, number, number, number] | null {
  if (net.isIPv4(host)) {
    const parts = host.split(".").map(Number);
    if (parts.length === 4) {
      return [parts[0]!, parts[1]!, parts[2]!, parts[3]!];
    }
    return null;
  }
  if (!ipv6Groups) {
    return null;
  }
  const isV4Mapped =
    ipv6Groups[0] === 0 &&
    ipv6Groups[1] === 0 &&
    ipv6Groups[2] === 0 &&
    ipv6Groups[3] === 0 &&
    ipv6Groups[4] === 0 &&
    ipv6Groups[5] === 0xffff;
  const isV4Compatible =
    ipv6Groups[0] === 0 &&
    ipv6Groups[1] === 0 &&
    ipv6Groups[2] === 0 &&
    ipv6Groups[3] === 0 &&
    ipv6Groups[4] === 0 &&
    ipv6Groups[5] === 0 &&
    (ipv6Groups[6] !== 0 || (ipv6Groups[7] ?? 0) > 1);
  if (isV4Mapped || isV4Compatible) {
    return [
      (ipv6Groups[6]! >> 8) & 0xff,
      ipv6Groups[6]! & 0xff,
      (ipv6Groups[7]! >> 8) & 0xff,
      ipv6Groups[7]! & 0xff,
    ];
  }
  return null;
}

function isMetadataIpv4(octets: [number, number, number, number]): boolean {
  const [a, b, c, d] = octets;
  if (a === 169 && b === 254) {
    return true;
  }
  return a === 100 && b === 100 && c === 100 && d === 200;
}

function isPrivateOrReservedIpv4(
  octets: [number, number, number, number],
): boolean {
  const [a, b] = octets;
  if (a === 127 || a === 0 || a === 10) {
    return true;
  }
  if (a === 172 && b >= 16 && b <= 31) {
    return true;
  }
  if (a === 192 && b === 168) {
    return true;
  }
  if (a === 100 && b >= 64 && b <= 127) {
    return true;
  }
  return false;
}

export type HostLookupFn = (
  hostname: string,
) => Promise<Array<{ address: string; family: number }>>;

/**
 * Validates that a resolved or literal IP address is allowed for outbound requests.
 * Always blocks cloud metadata endpoints and link-local IPv6 (`fe80::/10`).
 * When `allowPrivateNetwork` is false, also blocks loopback, RFC1918, CGNAT, and IPv6 ULA/unspecified.
 */
export function assertAllowedIpAddress(
  ip: string,
  rawHost: string,
  options?: { allowPrivateNetwork?: boolean },
): void {
  const cleanIp =
    ip.trim().toLowerCase().replace(/^\[|\]$/g, "").split("%")[0] ?? "";
  const ipv6Groups = cleanIp.includes(":") ? expandIpv6Groups(cleanIp) : null;
  const ipv4Octets = extractIpv4Octets(cleanIp, ipv6Groups);

  if (
    cleanIp.startsWith("169.254.") ||
    (ipv4Octets && isMetadataIpv4(ipv4Octets))
  ) {
    throw new Error(`Blocked cloud metadata host "${rawHost}".`);
  }

  if (
    ipv6Groups &&
    ipv6Groups[0] === 0xfd00 &&
    ipv6Groups[1] === 0x0ec2 &&
    ipv6Groups[2] === 0 &&
    ipv6Groups[3] === 0 &&
    ipv6Groups[4] === 0 &&
    ipv6Groups[5] === 0 &&
    ipv6Groups[6] === 0 &&
    ipv6Groups[7] === 0x0254
  ) {
    throw new Error(`Blocked cloud metadata host "${rawHost}".`);
  }

  if (
    /^fe[89ab][0-9a-f]:/i.test(cleanIp) ||
    (ipv6Groups && (ipv6Groups[0]! & 0xffc0) === 0xfe80)
  ) {
    throw new Error(`Blocked link-local IPv6 host "${rawHost}".`);
  }

  const allowPrivateNetwork = options?.allowPrivateNetwork ?? true;
  if (!allowPrivateNetwork) {
    if (ipv4Octets && isPrivateOrReservedIpv4(ipv4Octets)) {
      throw new Error(`Blocked private network host "${rawHost}".`);
    }
    if (ipv6Groups) {
      const isLoopbackV6 =
        ipv6Groups[0] === 0 &&
        ipv6Groups[1] === 0 &&
        ipv6Groups[2] === 0 &&
        ipv6Groups[3] === 0 &&
        ipv6Groups[4] === 0 &&
        ipv6Groups[5] === 0 &&
        ipv6Groups[6] === 0 &&
        ipv6Groups[7] === 1;
      const isUnspecifiedV6 = ipv6Groups.every((g) => g === 0);
      if (isLoopbackV6 || isUnspecifiedV6) {
        throw new Error(`Blocked loopback IPv6 host "${rawHost}".`);
      }
      if ((ipv6Groups[0]! & 0xfe00) === 0xfc00) {
        throw new Error(`Blocked private IPv6 ULA host "${rawHost}".`);
      }
    }
  }
}

/**
 * Validates an HTTP(S) URL, rejecting embedded credentials, cloud metadata targets,
 * and (when `allowPrivateNetwork` is false) private/loopback/single-label internal hosts.
 */
export function validateHttpBaseUrl(
  rawUrl: string,
  options?: { allowPrivateNetwork?: boolean; preserveTrailingSlash?: boolean },
): string {
  const trimmed = rawUrl.trim();
  let parsed: URL;
  try {
    parsed = new URL(trimmed);
  } catch {
    throw new Error(`Invalid URL "${rawUrl}".`);
  }
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    throw new Error("URL must use http:// or https://.");
  }
  if (parsed.username || parsed.password) {
    throw new Error("URL must not embed credentials.");
  }

  const rawHostname = parsed.hostname.toLowerCase();
  const host = rawHostname.replace(/^\[|\]$/g, "").replace(/\.+$/, "");

  if (BLOCKED_METADATA_HOSTS.has(host)) {
    throw new Error(`Blocked cloud metadata host "${rawHostname}".`);
  }

  if (net.isIP(host) !== 0 || host.includes(":")) {
    assertAllowedIpAddress(host, rawHostname, options);
  }

  const allowPrivateNetwork = options?.allowPrivateNetwork ?? true;
  if (!allowPrivateNetwork) {
    if (host === "localhost" || host.endsWith(".localhost")) {
      throw new Error(`Blocked loopback host "${rawHostname}".`);
    }
    if (net.isIP(host) === 0 && !host.includes(":")) {
      if (!host.includes(".")) {
        throw new Error(`Blocked single-label internal host "${rawHostname}".`);
      }
    }
  }

  return options?.preserveTrailingSlash
    ? parsed.toString()
    : parsed.toString().replace(/\/+$/, "");
}

/**
 * Validates an outbound HTTP(S) URL AND resolves its DNS records (checking every
 * returned IP address) against the metadata/private-network IP policy.
 */
export async function validateHttpTargetWithDns(
  rawUrl: string,
  options?: {
    allowPrivateNetwork?: boolean;
    lookupFn?: HostLookupFn;
    preserveTrailingSlash?: boolean;
  },
): Promise<string> {
  const normalized = validateHttpBaseUrl(rawUrl, options);
  const parsed = new URL(normalized);
  const rawHostname = parsed.hostname.toLowerCase();
  const host = rawHostname.replace(/^\[|\]$/g, "").replace(/\.+$/, "");

  if (net.isIP(host) !== 0 || host.includes(":")) {
    return normalized;
  }

  const records = options?.lookupFn
    ? await options.lookupFn(host)
    : await dns.promises.lookup(host, { all: true, verbatim: true });

  if (!Array.isArray(records) || records.length === 0) {
    throw new Error(`Could not resolve host "${rawHostname}".`);
  }

  for (const record of records) {
    assertAllowedIpAddress(record.address, rawHostname, options);
  }

  return normalized;
}

/**
 * Validates a public Git repository URL: requires `https://`, no embedded credentials,
 * and DNS resolution checks blocking private/loopback/cloud-metadata networks.
 */
export async function validateGitRepoUrl(
  rawUrl: string,
  options?: { lookupFn?: HostLookupFn },
): Promise<string> {
  const trimmed = rawUrl.trim();
  let parsed: URL;
  try {
    parsed = new URL(trimmed);
  } catch {
    throw new Error(`Invalid Git repository URL "${rawUrl}".`);
  }
  if (parsed.protocol !== "https:") {
    throw new Error("Git repository URL must use https://.");
  }
  const dnsOptions = options?.lookupFn
    ? { allowPrivateNetwork: false, lookupFn: options.lookupFn }
    : { allowPrivateNetwork: false };
  return validateHttpTargetWithDns(trimmed, dnsOptions);
}

/**
 * Returns true strictly for credential-free `https://github.com` URLs on default HTTPS port 443.
 */
export function isGithubHttpsRepoUrl(rawUrl: string): boolean {
  let parsed: URL;
  try {
    parsed = new URL(rawUrl.trim());
  } catch {
    return false;
  }
  if (parsed.protocol !== "https:") {
    return false;
  }
  if (parsed.username || parsed.password) {
    return false;
  }
  const host = parsed.hostname.toLowerCase().replace(/\.+$/, "");
  if (host !== "github.com") {
    return false;
  }
  return parsed.port === "" || parsed.port === "443";
}

/**
 * Extracts `{ owner, repo }` from a valid `https://github.com/<owner>/<repo>` URL, or returns null.
 */
export function parseGithubRepoOwnerAndName(
  rawUrl: string,
): { owner: string; repo: string } | null {
  if (!isGithubHttpsRepoUrl(rawUrl)) {
    return null;
  }
  const parsed = new URL(rawUrl.trim());
  const segments = parsed.pathname.split("/").filter(Boolean);
  if (segments.length < 2) {
    return null;
  }
  const owner = segments[0]!;
  let repo = segments[1]!;
  if (repo.toLowerCase().endsWith(".git")) {
    repo = repo.slice(0, -4);
  }
  if (
    !owner ||
    !repo ||
    !GITHUB_OWNER_REPO_SEGMENT.test(owner) ||
    !GITHUB_OWNER_REPO_SEGMENT.test(repo)
  ) {
    return null;
  }
  return { owner, repo };
}

/**
 * Validates a GitHub Personal Access Token (blocks whitespace, newlines, quotes, colons,
 * brackets, and control characters so tokens can never inject Git config directives).
 */
export function validateGitAccessToken(rawToken: string): string {
  const trimmed = rawToken.trim();
  if (!GIT_TOKEN_PATTERN.test(trimmed)) {
    throw new Error(
      "Invalid GitHub access token format: expected 8-512 characters using letters, numbers, '_', '-', or '.'.",
    );
  }
  return trimmed;
}

/**
 * Formats a safe display hint for a stored GitHub token without exposing the secret.
 */
export function formatGitTokenHint(rawToken: string): string {
  const trimmed = rawToken.trim();
  const last4 = trimmed.slice(-4);
  if (trimmed.startsWith("github_pat_")) {
    return `github_pat_••••${last4}`;
  }
  const classicMatch = trimmed.match(/^(gh[pousr]_)/);
  if (classicMatch) {
    return `${classicMatch[1]}••••${last4}`;
  }
  return `••••${last4}`;
}

/**
 * Redacts common secret patterns (env/YAML/JSON keys, auth headers, URL credentials, bearer tokens
 * including `vpsmcp_*`, and PEM private key blocks) before logging or returning to clients.
 */
export function redactSecrets(input: string): string {
  return input
    .replace(PEM_KEY_PATTERN, "[REDACTED_PRIVATE_KEY]")
    .replace(URL_CREDENTIALS_PATTERN, "$1$2:[REDACTED]@")
    .replace(AUTH_HEADER_PATTERN, "$1 [REDACTED]")
    .replace(JSON_SECRET_PATTERN, '"$1":"[REDACTED]"')
    .replace(
      ENV_OR_YAML_SECRET_PATTERN,
      (_match, key: string, sep: string) =>
        `${key}${sep}${sep === ":" ? " " : ""}[REDACTED]`,
    )
    .replace(KNOWN_TOKEN_PREFIX_PATTERN, "[REDACTED]");
}

/**
 * Redacts standard secret patterns AND any exact occurrences of a specific raw token
 * or its HTTP Basic base64 (`x-access-token:<token>`) representation.
 */
export function scrubTokenFromText(
  text: string,
  token?: string | null,
): string {
  let out = redactSecrets(text);
  const clean = token?.trim();
  if (clean) {
    out = out.split(clean).join("[REDACTED]");
    const basicB64 = Buffer.from(`x-access-token:${clean}`, "utf8").toString(
      "base64",
    );
    if (basicB64) {
      out = out.split(basicB64).join("[REDACTED]");
    }
  }
  return out;
}

/**
 * Recursively redacts structured JS values before JSON serialization so regexes
 * never corrupt JSON syntax, while also masking string values under sensitive key names.
 */
export function redactStructuredValue(
  value: unknown,
  seen = new WeakSet<object>(),
): unknown {
  if (typeof value === "string") {
    return redactSecrets(value);
  }
  if (value === null || typeof value !== "object") {
    return value;
  }
  if (seen.has(value)) {
    return "[Circular]";
  }
  seen.add(value);
  if (Array.isArray(value)) {
    return value.map((item) => redactStructuredValue(item, seen));
  }
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
    if (
      SENSITIVE_FIELD_KEY_PATTERN.test(k) &&
      typeof v === "string" &&
      v.length > 0
    ) {
      out[k] = "[REDACTED]";
    } else {
      out[k] = redactStructuredValue(v, seen);
    }
  }
  return out;
}
