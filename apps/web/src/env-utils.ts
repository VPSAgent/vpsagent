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

function parseQuotedEnvValue(
  rawVal: string,
  lineNo: number,
  key: string,
): { value: string } | { error: string } {
  const quote = rawVal[0];
  if (quote === '"') {
    let decoded = "";
    let i = 1;
    while (i < rawVal.length) {
      const ch = rawVal[i]!;
      if (ch === "\\") {
        if (i + 1 >= rawVal.length) {
          return {
            error: `Line ${lineNo}: unterminated double-quoted value for "${key}".`,
          };
        }
        const next = rawVal[i + 1]!;
        if (next === "n") decoded += "\n";
        else if (next === "r") decoded += "\r";
        else if (next === "t") decoded += "\t";
        else if (next === '"') decoded += '"';
        else if (next === "\\") decoded += "\\";
        else decoded += `\\${next}`;
        i += 2;
        continue;
      }
      if (ch === '"') {
        const suffix = rawVal.slice(i + 1).trim();
        if (suffix.length > 0 && !suffix.startsWith("#")) {
          return {
            error: `Line ${lineNo}: unexpected characters after closing quote for "${key}".`,
          };
        }
        return { value: decoded };
      }
      decoded += ch;
      i += 1;
    }
    return {
      error: `Line ${lineNo}: unterminated double-quoted value for "${key}".`,
    };
  }
  if (quote === "'") {
    let decoded = "";
    let i = 1;
    while (i < rawVal.length) {
      const ch = rawVal[i]!;
      if (ch === "\\" && i + 1 < rawVal.length && rawVal[i + 1] === "'") {
        const afterQuote = rawVal.slice(i + 2);
        const afterTrimmed = afterQuote.trim();
        const isClosingQuote =
          afterTrimmed.length === 0 ||
          (/^\s+#/.test(afterQuote) && afterTrimmed.startsWith("#"));
        if (!isClosingQuote) {
          decoded += "'";
          i += 2;
          continue;
        }
      }
      if (ch === "'") {
        const suffix = rawVal.slice(i + 1).trim();
        if (suffix.length > 0 && !suffix.startsWith("#")) {
          return {
            error: `Line ${lineNo}: unexpected characters after closing quote for "${key}".`,
          };
        }
        return { value: decoded };
      }
      decoded += ch;
      i += 1;
    }
    return {
      error: `Line ${lineNo}: unterminated single-quoted value for "${key}".`,
    };
  }
  let unquoted = rawVal;
  const commentIdx = unquoted.search(/\s+#/);
  if (commentIdx >= 0) {
    unquoted = unquoted.slice(0, commentIdx).trimEnd();
  }
  return { value: unquoted };
}

/**
 * Parses a multi-line `.env` block pasted by the user (or loaded from a `.env` file).
 * Supports comments (`#`), blank lines, optional `export ` prefix, single/double quotes
 * (including trailing `#` comments after the closing quote), and inline `#` comments on
 * unquoted values. Later lines override earlier duplicates.
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
    const rawVal = trimmed.slice(eqIdx + 1).trim();
    const parsedVal = parseQuotedEnvValue(rawVal, lineNo, key);
    if ("error" in parsedVal) {
      errors.push({ line: lineNo, message: parsedVal.error });
      continue;
    }
    const { value } = parsedVal;
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

/**
 * Appends `KEY=` template lines for missing keys that are NOT already present in the
 * current bulk draft, preserving any values the user has already pasted.
 */
export function appendMissingKeysToEnvDraft(
  currentDraft: string,
  missingKeys: string[],
): string {
  const existingKeys = new Set(
    parseEnvBlock(currentDraft).vars.map((entry) => entry.key),
  );
  const toAppend = missingKeys.filter((k) => !existingKeys.has(k));
  if (toAppend.length === 0) {
    return currentDraft;
  }
  const template = toAppend.map((k) => `${k}=`).join("\n");
  return currentDraft.trim()
    ? `${currentDraft.trimEnd()}\n${template}`
    : template;
}
