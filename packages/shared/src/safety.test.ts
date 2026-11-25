import { describe, expect, it } from "vitest";
import {
  assertHttpsForRemoteHost,
  formatEnvFile,
  formatGitTokenHint,
  isGithubHttpsRepoUrl,
  isLoopbackHost,
  parseGithubRepoOwnerAndName,
  quoteEnvValue,
  redactSecrets,
  redactStructuredValue,
  scrubTokenFromText,
  validateAppSlug,
  validateDomain,
  validateEnvKey,
  validateGitAccessToken,
  validateGitRepoUrl,
} from "./safety.js";

describe("safety validators and secret redaction", () => {
  it("validates app slugs and rejects reserved or unsafe names", () => {
    expect(validateAppSlug("my-app-1")).toBe("my-app-1");
    expect(() => validateAppSlug("core")).toThrow(/Reserved/);
    expect(() => validateAppSlug("vpsagent")).toThrow(/Reserved/);
    expect(() => validateAppSlug("../escape")).toThrow(/Invalid app slug/);
    expect(() => validateAppSlug("UPPER")).toThrow(/Invalid app slug/);
  });

  it("validates domains and blocks injection", () => {
    expect(validateDomain("App.Example.COM")).toBe("app.example.com");
    expect(() => validateDomain("bad domain\n{}")).toThrow(/Invalid domain/);
    expect(() => validateDomain("localhost")).toThrow(/Invalid domain/);
  });

  it("literally quotes .env values so special characters never break", () => {
    expect(validateEnvKey("DATABASE_URL")).toBe("DATABASE_URL");
    expect(() => validateEnvKey("BAD-KEY")).toThrow(/Invalid environment/);

    expect(quoteEnvValue("p@ss$word#123 with spaces")).toBe(
      "'p@ss$word#123 with spaces'",
    );
    expect(quoteEnvValue("it's\nmultiline")).toBe('"it\'s\\nmultiline"');

    const envFile = formatEnvFile({
      Z_VAR: "hello $WORLD #comment",
      A_VAR: "simple",
    });
    expect(envFile).toBe("A_VAR='simple'\nZ_VAR='hello $WORLD #comment'\n");
  });

  it("enforces HTTPS-only for non-loopback hosts", () => {
    expect(isLoopbackHost("localhost:3001")).toBe(true);
    expect(isLoopbackHost("127.0.0.1:3001")).toBe(true);
    expect(isLoopbackHost("[::1]:3001")).toBe(true);
    expect(isLoopbackHost("vps.example.com")).toBe(false);

    expect(() => assertHttpsForRemoteHost("localhost:3001", "http")).not.toThrow();
    expect(() => assertHttpsForRemoteHost("vps.example.com", "https")).not.toThrow();
    expect(() => assertHttpsForRemoteHost("vps.example.com", "http")).toThrow(
      /HTTPS is required/,
    );
  });

  it("DNS-checks Git repo URLs and blocks private/metadata IPs", async () => {
    const publicLookup = async () => [{ address: "140.82.121.4", family: 4 }];
    const privateLookup = async () => [{ address: "10.0.0.5", family: 4 }];
    const metadataLookup = async () => [{ address: "169.254.169.254", family: 4 }];

    await expect(
      validateGitRepoUrl("https://github.com/acme/demo.git", {
        lookupFn: publicLookup,
      }),
    ).resolves.toBe("https://github.com/acme/demo.git");

    await expect(
      validateGitRepoUrl("http://github.com/acme/demo.git", {
        lookupFn: publicLookup,
      }),
    ).rejects.toThrow(/must use https/);

    await expect(
      validateGitRepoUrl("https://user:pass@github.com/acme/demo.git", {
        lookupFn: publicLookup,
      }),
    ).rejects.toThrow(/must not embed credentials/);

    await expect(
      validateGitRepoUrl("https://evil.example.com/repo.git", {
        lookupFn: privateLookup,
      }),
    ).rejects.toThrow(/Blocked private network host/);

    await expect(
      validateGitRepoUrl("https://evil.example.com/repo.git", {
        lookupFn: metadataLookup,
      }),
    ).rejects.toThrow(/Blocked cloud metadata host/);
  });

  it("redacts secrets in plain text and structured objects", () => {
    const raw =
      "Authorization: Bearer vpsmcp_supersecret1234567890abcd API_KEY=sk-1234567890abcdef";
    const redacted = redactSecrets(raw);
    expect(redacted).not.toContain("vpsmcp_supersecret1234567890abcd");
    expect(redacted).not.toContain("sk-1234567890abcdef");
    expect(redacted).toContain("[REDACTED]");

    const structured = redactStructuredValue({
      slug: "demo",
      database_url: "postgres://user:secret@db:5432/app",
      nested: {
        token: "vpsmcp_1234567890abcdefghij",
        note: "normal text",
      },
    }) as Record<string, unknown>;
    expect(structured.slug).toBe("demo");
    expect(structured.database_url).toBe("[REDACTED]");
    expect((structured.nested as Record<string, unknown>).token).toBe("[REDACTED]");
    expect((structured.nested as Record<string, unknown>).note).toBe("normal text");

    // URL credential redaction, Git token field redaction, and basic-auth scrubbing
    const rawWithUrlCreds =
      "fatal: unable to access https://x-access-token:mycustomsecret99@github.com/acme/priv.git";
    const scrubbedUrl = redactSecrets(rawWithUrlCreds);
    expect(scrubbedUrl).not.toContain("mycustomsecret99");
    expect(scrubbedUrl).toContain("https://x-access-token:[REDACTED]@github.com");

    const tok = "custom_pat_token_value_123456";
    const b64 = Buffer.from(`x-access-token:${tok}`, "utf8").toString("base64");
    const scrubbedBoth = scrubTokenFromText(
      `Failed with ${tok} and Authorization: Basic ${b64}`,
      tok,
    );
    expect(scrubbedBoth).not.toContain(tok);
    expect(scrubbedBoth).not.toContain(b64);

    const redStruct = redactStructuredValue({
      gitToken: "secret_value_abc",
      github_token: "secret_value_def",
      slug: "ok",
    }) as Record<string, unknown>;
    expect(redStruct.gitToken).toBe("[REDACTED]");
    expect(redStruct.github_token).toBe("[REDACTED]");
    expect(redStruct.slug).toBe("ok");
  });

  it("validates github.com URLs, extracts owner/repo, and validates Git access tokens", () => {
    expect(isGithubHttpsRepoUrl("https://github.com/acme/private-app")).toBe(true);
    expect(isGithubHttpsRepoUrl("https://github.com/acme/private-app.git")).toBe(
      true,
    );
    expect(isGithubHttpsRepoUrl("https://github.com:443/acme/private-app")).toBe(
      true,
    );
    expect(isGithubHttpsRepoUrl("https://gitlab.com/acme/private-app")).toBe(false);
    expect(isGithubHttpsRepoUrl("https://github.com:8443/acme/private-app")).toBe(
      false,
    );
    expect(isGithubHttpsRepoUrl("https://user:pass@github.com/acme/repo")).toBe(
      false,
    );
    expect(isGithubHttpsRepoUrl("http://github.com/acme/repo")).toBe(false);

    expect(parseGithubRepoOwnerAndName("https://github.com/Acme/My-Repo.git")).toEqual({
      owner: "Acme",
      repo: "My-Repo",
    });
    expect(parseGithubRepoOwnerAndName("https://gitlab.com/Acme/My-Repo")).toBeNull();

    expect(validateGitAccessToken("  github_pat_11ABCDEF_1234567890  ")).toBe(
      "github_pat_11ABCDEF_1234567890",
    );
    expect(() => validateGitAccessToken("bad token\nwith newline")).toThrow(
      /Invalid GitHub access token/,
    );
    expect(() => validateGitAccessToken('ghp_abc"quoted')).toThrow(
      /Invalid GitHub access token/,
    );
    expect(() => validateGitAccessToken("short")).toThrow(
      /Invalid GitHub access token/,
    );

    expect(formatGitTokenHint("github_pat_11ABC_9876")).toBe(
      "github_pat_••••9876",
    );
    expect(formatGitTokenHint("ghp_abcdef123456wxyz")).toBe("ghp_••••wxyz");
    expect(formatGitTokenHint("customtokenvalue9999")).toBe("••••9999");
  });
});
