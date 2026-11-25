import {
  type GithubRepoSummary,
  GithubRepoSummarySchema,
  RuntimeBridgeError,
  isGithubHttpsRepoUrl,
  scrubTokenFromText,
  validateGitAccessToken,
} from "@vpsagent/shared";

const DEFAULT_GITHUB_API_BASE_URL = "https://api.github.com";
const GITHUB_API_TIMEOUT_MS = 12_000;

export interface GithubClientOptions {
  apiBaseUrl?: string | undefined;
  fetchFn?: typeof fetch | undefined;
}

export interface GithubTokenVerificationResult {
  accountLogin: string | null;
  accessibleRepoCount: number;
  hasPrivateAccess: boolean;
  warning: string | null;
}

interface GithubApiUser {
  login?: unknown;
}

interface GithubApiRepo {
  full_name?: unknown;
  name?: unknown;
  owner?: { login?: unknown } | null;
  private?: unknown;
  default_branch?: unknown;
  html_url?: unknown;
  description?: unknown;
  updated_at?: unknown;
}

async function githubApiRequest(
  apiPath: string,
  token: string,
  options?: GithubClientOptions,
): Promise<Response> {
  const safeToken = validateGitAccessToken(token);
  const baseStr = (options?.apiBaseUrl ?? DEFAULT_GITHUB_API_BASE_URL).replace(
    /\/+$/,
    "",
  );
  const baseUrl = new URL(baseStr);
  const targetUrl = new URL(`${baseStr}${apiPath.startsWith("/") ? "" : "/"}${apiPath}`);
  const fetchFn = options?.fetchFn ?? globalThis.fetch;

  let res: Response;
  try {
    res = await fetchFn(targetUrl.toString(), {
      method: "GET",
      redirect: "manual",
      signal: AbortSignal.timeout(GITHUB_API_TIMEOUT_MS),
      headers: {
        authorization: `Bearer ${safeToken}`,
        accept: "application/vnd.github+json",
        "x-github-api-version": "2022-11-28",
        "user-agent": "VPSAgent/2.1",
      },
    });
  } catch (err) {
    const rawMsg = err instanceof Error ? err.message : String(err);
    throw new RuntimeBridgeError(
      502,
      scrubTokenFromText(`Could not reach GitHub API: ${rawMsg}`, safeToken),
    );
  }

  if (res.status >= 300 && res.status < 400) {
    const location = res.headers.get("location");
    if (!location) {
      throw new RuntimeBridgeError(
        502,
        `GitHub API returned an unexpected redirect (${res.status}).`,
      );
    }
    let redirectUrl: URL;
    try {
      redirectUrl = new URL(location, targetUrl);
    } catch {
      throw new RuntimeBridgeError(
        502,
        "GitHub API returned an invalid redirect location.",
      );
    }
    if (redirectUrl.origin !== baseUrl.origin) {
      throw new RuntimeBridgeError(
        502,
        "Blocked off-origin redirect from GitHub API.",
      );
    }
    try {
      const redirected = await fetchFn(redirectUrl.toString(), {
        method: "GET",
        redirect: "manual",
        signal: AbortSignal.timeout(GITHUB_API_TIMEOUT_MS),
        headers: {
          authorization: `Bearer ${safeToken}`,
          accept: "application/vnd.github+json",
          "x-github-api-version": "2022-11-28",
          "user-agent": "VPSAgent/2.1",
        },
      });
      if (redirected.status >= 300 && redirected.status < 400) {
        throw new RuntimeBridgeError(
          502,
          "GitHub API returned multiple redirects.",
        );
      }
      return redirected;
    } catch (err) {
      if (err instanceof RuntimeBridgeError) {
        throw err;
      }
      const rawMsg = err instanceof Error ? err.message : String(err);
      throw new RuntimeBridgeError(
        502,
        scrubTokenFromText(`Could not reach GitHub API: ${rawMsg}`, safeToken),
      );
    }
  }

  return res;
}

/**
 * Verifies a GitHub Personal Access Token against GitHub's API, resolving the
 * GitHub account login (when readable) and repository access visibility.
 */
export async function verifyGithubToken(
  token: string,
  options?: GithubClientOptions,
): Promise<GithubTokenVerificationResult> {
  const safeToken = validateGitAccessToken(token);

  let accountLogin: string | null = null;
  const userRes = await githubApiRequest("/user", safeToken, options);
  if (userRes.status === 401) {
    throw new RuntimeBridgeError(
      401,
      "GitHub rejected this token. Check that you copied the full token and that it has not expired.",
    );
  }
  if (userRes.status === 200) {
    try {
      const userJson = (await userRes.json()) as GithubApiUser;
      if (typeof userJson.login === "string" && userJson.login.trim()) {
        accountLogin = userJson.login.trim();
      }
    } catch {
      accountLogin = null;
    }
  } else if (userRes.status !== 403) {
    throw new RuntimeBridgeError(
      userRes.status >= 400 ? userRes.status : 502,
      `GitHub token verification failed (HTTP ${userRes.status}).`,
    );
  }

  const reposRes = await githubApiRequest(
    "/user/repos?per_page=100&sort=updated&affiliation=owner,collaborator,organization_member",
    safeToken,
    options,
  );
  if (reposRes.status === 401) {
    throw new RuntimeBridgeError(
      401,
      "GitHub rejected this token. Check that you copied the full token and that it has not expired.",
    );
  }

  let accessibleRepoCount = 0;
  let hasPrivateAccess = false;
  let warning: string | null = null;

  if (reposRes.status === 200) {
    try {
      const repoItems = (await reposRes.json()) as unknown;
      if (Array.isArray(repoItems)) {
        for (const item of repoItems as GithubApiRepo[]) {
          if (
            typeof item?.html_url === "string" &&
            isGithubHttpsRepoUrl(item.html_url)
          ) {
            accessibleRepoCount += 1;
            if (item.private === true) {
              hasPrivateAccess = true;
            }
          }
        }
      }
    } catch {
      accessibleRepoCount = 0;
    }
  } else if (reposRes.status === 403) {
    if (!accountLogin) {
      throw new RuntimeBridgeError(
        403,
        "GitHub token does not have permission to read your account or repositories. Ensure Repository Contents (Read-only) is enabled.",
      );
    }
    warning =
      "Connected to GitHub, but repository listing returned 403. Make sure your token has Repository permissions → Contents: Read-only (or Metadata: Read-only) for the repos you want to deploy.";
  } else {
    throw new RuntimeBridgeError(
      reposRes.status >= 400 ? reposRes.status : 502,
      `Could not list GitHub repositories (HTTP ${reposRes.status}).`,
    );
  }

  return {
    accountLogin,
    accessibleRepoCount,
    hasPrivateAccess,
    warning,
  };
}

/**
 * Lists GitHub repositories visible to a single stored GitHub token.
 */
export async function listGithubReposForToken(
  token: string,
  meta: { credentialId: string; credentialLabel: string },
  options?: GithubClientOptions & {
    query?: string | undefined;
    limit?: number | undefined;
  },
): Promise<GithubRepoSummary[]> {
  const safeToken = validateGitAccessToken(token);
  const res = await githubApiRequest(
    "/user/repos?per_page=100&sort=updated&affiliation=owner,collaborator,organization_member",
    safeToken,
    options,
  );
  if (res.status === 401) {
    throw new RuntimeBridgeError(
      401,
      `GitHub token "${meta.credentialLabel}" was rejected or expired. Update or re-test it in AI Keys & Settings.`,
    );
  }
  if (res.status === 403) {
    throw new RuntimeBridgeError(
      403,
      `GitHub token "${meta.credentialLabel}" does not have permission to list repositories.`,
    );
  }
  if (!res.ok) {
    throw new RuntimeBridgeError(
      res.status >= 400 ? res.status : 502,
      `GitHub repository listing failed (HTTP ${res.status}).`,
    );
  }

  const rawList = (await res.json()) as unknown;
  if (!Array.isArray(rawList)) {
    return [];
  }

  const needle = options?.query?.trim().toLowerCase() || "";
  const limit = Math.min(Math.max(options?.limit ?? 50, 1), 100);
  const results: GithubRepoSummary[] = [];

  for (const item of rawList as GithubApiRepo[]) {
    if (
      !item ||
      typeof item.full_name !== "string" ||
      typeof item.name !== "string" ||
      typeof item.html_url !== "string" ||
      !isGithubHttpsRepoUrl(item.html_url)
    ) {
      continue;
    }
    const owner =
      typeof item.owner?.login === "string" && item.owner.login.trim()
        ? item.owner.login.trim()
        : item.full_name.split("/")[0] || "";
    if (!owner) {
      continue;
    }
    const description =
      typeof item.description === "string" && item.description.trim()
        ? item.description.trim()
        : null;
    if (needle) {
      const hay = `${item.full_name} ${item.name} ${description ?? ""}`.toLowerCase();
      if (!hay.includes(needle)) {
        continue;
      }
    }
    const parsed = GithubRepoSummarySchema.parse({
      fullName: item.full_name,
      name: item.name,
      owner,
      private: Boolean(item.private),
      defaultBranch:
        typeof item.default_branch === "string" && item.default_branch.trim()
          ? item.default_branch.trim()
          : null,
      htmlUrl: item.html_url.replace(/\/+$/, ""),
      description,
      updatedAt:
        typeof item.updated_at === "string" && item.updated_at.trim()
          ? item.updated_at.trim()
          : null,
      credentialId: meta.credentialId,
      credentialLabel: meta.credentialLabel,
    });
    results.push(parsed);
    if (results.length >= limit) {
      break;
    }
  }

  return results;
}
