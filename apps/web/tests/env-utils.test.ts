import assert from "node:assert/strict";
import { describe, it } from "node:test";
import {
  isBuildTimePublicEnvKey,
  isLikelySecretEnvKey,
  parseEnvBlock,
} from "../src/env-utils.ts";

describe("Dashboard env-utils", () => {
  it("identifies public build-time env prefixes and never marks them as secrets", () => {
    assert.equal(isBuildTimePublicEnvKey("NEXT_PUBLIC_SUPABASE_URL"), true);
    assert.equal(
      isBuildTimePublicEnvKey("NEXT_PUBLIC_SUPABASE_ANON_KEY"),
      true,
    );
    assert.equal(isBuildTimePublicEnvKey("VITE_API_URL"), true);
    assert.equal(isBuildTimePublicEnvKey("PUBLIC_APP_NAME"), true);
    assert.equal(isBuildTimePublicEnvKey("NUXT_PUBLIC_SITE_URL"), true);
    assert.equal(isBuildTimePublicEnvKey("REACT_APP_STRIPE_KEY"), true);
    assert.equal(isBuildTimePublicEnvKey("EXPO_PUBLIC_API"), true);
    assert.equal(isBuildTimePublicEnvKey("GATSBY_SITE_URL"), true);

    assert.equal(isBuildTimePublicEnvKey("SUPABASE_SERVICE_ROLE_KEY"), false);
    assert.equal(isBuildTimePublicEnvKey("POLAR_ACCESS_TOKEN"), false);
    assert.equal(isBuildTimePublicEnvKey("DATABASE_URL"), false);
    assert.equal(isBuildTimePublicEnvKey("VPSAGENT_SECRET"), false);

    assert.equal(
      isLikelySecretEnvKey("NEXT_PUBLIC_SUPABASE_ANON_KEY"),
      false,
    );
    assert.equal(isLikelySecretEnvKey("SUPABASE_SERVICE_ROLE_KEY"), true);
    assert.equal(isLikelySecretEnvKey("POLAR_WEBHOOK_SECRET"), true);
  });

  it("parses standard .env blocks with comments, export prefixes, quotes, and '=' in values", () => {
    const raw = [
      "# Supabase settings",
      "NEXT_PUBLIC_SUPABASE_URL=https://abc.supabase.co",
      'export NEXT_PUBLIC_SUPABASE_ANON_KEY="eyJhbGciOiJIUzI1NiJ9.payload=="',
      "SUPABASE_SERVICE_ROLE_KEY='secret-with-#-and-spaces'",
      "POLAR_ACCESS_TOKEN=polar_oat_12345 # inline comment",
      "DUP_KEY=first",
      "DUP_KEY=second",
      "",
    ].join("\n");

    const parsed = parseEnvBlock(raw);
    assert.equal(parsed.errors.length, 0);
    assert.deepEqual(
      parsed.vars.map((v) => [v.key, v.value, v.isBuildTime, v.isSecret]),
      [
        ["NEXT_PUBLIC_SUPABASE_URL", "https://abc.supabase.co", true, false],
        [
          "NEXT_PUBLIC_SUPABASE_ANON_KEY",
          "eyJhbGciOiJIUzI1NiJ9.payload==",
          true,
          false,
        ],
        ["SUPABASE_SERVICE_ROLE_KEY", "secret-with-#-and-spaces", false, true],
        ["POLAR_ACCESS_TOKEN", "polar_oat_12345", false, true],
        ["DUP_KEY", "second", false, true],
      ],
    );
  });

  it("reports clear line-level errors for invalid or forbidden keys", () => {
    const parsed = parseEnvBlock(
      "BAD LINE WITHOUT EQUALS\n123_INVALID=abc\nVPSAGENT_SECRET=nope\nGOOD_KEY=ok",
    );
    assert.equal(parsed.vars.length, 1);
    assert.equal(parsed.vars[0]?.key, "GOOD_KEY");
    assert.equal(parsed.errors.length, 3);
    assert.equal(parsed.errors[0]?.line, 1);
    assert.equal(parsed.errors[1]?.line, 2);
    assert.equal(parsed.errors[2]?.line, 3);
  });
});
