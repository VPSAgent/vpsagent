export const BUILD_TIME_PUBLIC_ENV_PREFIXES = [
  "NEXT_PUBLIC_",
  "VITE_",
  "PUBLIC_",
  "NUXT_PUBLIC_",
  "REACT_APP_",
  "EXPO_PUBLIC_",
  "GATSBY_",
] as const;

const ENV_KEY_PATTERN = /^[A-Za-z_][A-Za-z0-9_]{0,127}$/;
const FORBIDDEN_APP_ENV_PREFIXES = ["VPSAGENT_", "VPS_OS_", "DOCKER_", "LD_"];
const FORBIDDEN_APP_ENV_EXACT = new Set([
  "PATH",
  "HOME",
  "HOSTALIASES",
  "IFS",
  "ENV",
  "BASH_ENV",
]);
const SECRET_KEY_HINT =
  /(?:key|token|secret|password|passwd|pass|passphrase|credential|auth|private|database_url|redis_url)/i;

export function isForbiddenAppEnvKey(key: string): boolean {
  return (
    FORBIDDEN_APP_ENV_EXACT.has(key) ||
    FORBIDDEN_APP_ENV_PREFIXES.some((prefix) => key.startsWith(prefix))
  );
}

export function isBuildTimePublicEnvKey(key: string): boolean {
  if (!ENV_KEY_PATTERN.test(key) || isForbiddenAppEnvKey(key)) {
    return false;
  }
  return BUILD_TIME_PUBLIC_ENV_PREFIXES.some((prefix) => key.startsWith(prefix));
}

export function isLikelySecretEnvKey(key: string): boolean {
  if (isBuildTimePublicEnvKey(key)) {
    return false;
  }
  return SECRET_KEY_HINT.test(key);
}

export interface ParsedEnvEntry {
  key: string;
  value: string;
  isSecret: boolean;
  isBuildTime: boolean;
}

export interface ParsedEnvError {
  line: number;
  message: string;
}

/**
 * Parses a multi-line `.env` block pasted by the user (or loaded from a `.env` file).
 * Supports comments (`#`), blank lines, optional `export ` prefix, single/double quotes,
 * and inline `#` comments on unquoted values. Later lines override earlier duplicates.
 */
export function parseEnvBlock(rawText: string): {
  vars: ParsedEnvEntry[];
  errors: ParsedEnvError[];
} {
  const byKey = new Map<string, string>();
  const errors: ParsedEnvError[] = [];
  const lines = rawText.split(/\r?\n/);

  for (let i = 0; i < lines.length; i += 1) {
    const lineNo = i + 1;
    let trimmed = lines[i]!.trim();
    if (!trimmed || trimmed.startsWith("#")) {
      continue;
    }
    if (trimmed.startsWith("export ")) {
      trimmed = trimmed.slice("export ".length).trim();
    }
    const eqIdx = trimmed.indexOf("=");
    if (eqIdx <= 0) {
      errors.push({
        line: lineNo,
        message: `Line ${lineNo}: expected NAME=value format.`,
      });
      continue;
    }
    const key = trimmed.slice(0, eqIdx).trim();
    if (!ENV_KEY_PATTERN.test(key)) {
      errors.push({
        line: lineNo,
        message: `Line ${lineNo}: "${key}" is not a valid setting name (use letters, numbers, and underscores).`,
      });
      continue;
    }
    if (isForbiddenAppEnvKey(key)) {
      errors.push({
        line: lineNo,
        message: `Line ${lineNo}: "${key}" is reserved by the server and cannot be set.`,
      });
      continue;
    }
    let rawVal = trimmed.slice(eqIdx + 1).trim();
    let value: string;
    if (rawVal.length >= 2 && rawVal.startsWith('"') && rawVal.endsWith('"')) {
      value = rawVal
        .slice(1, -1)
        .replace(/\\n/g, "\n")
        .replace(/\\r/g, "\r")
        .replace(/\\t/g, "\t")
        .replace(/\\"/g, '"')
        .replace(/\\\\/g, "\\");
    } else if (
      rawVal.length >= 2 &&
      rawVal.startsWith("'") &&
      rawVal.endsWith("'")
    ) {
      value = rawVal.slice(1, -1);
    } else {
      const commentIdx = rawVal.search(/\s+#/);
      if (commentIdx >= 0) {
        rawVal = rawVal.slice(0, commentIdx).trimEnd();
      }
      value = rawVal;
    }
    if (value.includes("\0")) {
      errors.push({
        line: lineNo,
        message: `Line ${lineNo}: value for "${key}" cannot contain null bytes.`,
      });
      continue;
    }
    byKey.set(key, value);
  }

  return {
    vars: Array.from(byKey.entries()).map(([key, value]) => ({
      key,
      value,
      isSecret: isLikelySecretEnvKey(key),
      isBuildTime: isBuildTimePublicEnvKey(key),
    })),
    errors,
  };
}
