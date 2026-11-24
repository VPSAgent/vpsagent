import { describe, expect, it } from "vitest";
import {
  assertHttpsForRemoteHost,
  formatEnvFile,
  isLoopbackHost,
  quoteEnvValue,
  redactSecrets,
  redactStructuredValue,
  validateAppSlug,
  validateDomain,
  validateEnvKey,
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
  });
});
