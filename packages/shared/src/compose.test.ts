import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";
import {
  generateApartmentBlueprint,
  getAppContainerName,
  getAppNetworkName,
  getBuiltGitImageTag,
  writeApartmentBlueprint,
} from "./compose.js";

describe("Locked Apartment Blueprint generator", () => {
  it("generates a hardened Compose blueprint for prebuilt images with literal-quoted .env", () => {
    const bp = generateApartmentBlueprint({
      slug: "hello-web",
      sourceType: "image",
      image: "nginxinc/nginx-unprivileged:alpine",
      internalPort: 8080,
      cpuLimit: "0.75",
      memoryLimitMb: 256,
      envVars: {
        API_SECRET: "p@ss$word#123 with spaces",
        MULTILINE_NOTE: "it's\nmultiline",
      },
    });

    expect(bp.projectName).toBe("vpsagent-hello-web");
    expect(bp.containerName).toBe(getAppContainerName("hello-web"));
    expect(bp.networkName).toBe(getAppNetworkName("hello-web"));
    expect(bp.imageRef).toBe("nginxinc/nginx-unprivileged:alpine");

    // Locked Apartment invariants
    expect(bp.composeYaml).toContain("cap_drop:\n      - ALL");
    expect(bp.composeYaml).toContain("security_opt:\n      - no-new-privileges:true");
    expect(bp.composeYaml).toContain('cpus: "0.75"');
    expect(bp.composeYaml).toContain('mem_limit: "256m"');
    expect(bp.composeYaml).toContain("networks:\n      - app_net");
    expect(bp.composeYaml).toContain("networks:\n  app_net:\n    driver: bridge");
    expect(bp.composeYaml).not.toContain("docker.sock");
    expect(bp.composeYaml).not.toMatch(/^\s*ports:/m);
    expect(bp.composeYaml).not.toMatch(/^\s*privileged:/m);

    // Literal-quoted .env injection
    expect(bp.envFile).toContain("API_SECRET='p@ss$word#123 with spaces'");
    expect(bp.envFile).toContain('MULTILINE_NOTE="it\'s\\nmultiline"');
    expect(bp.envFile).toContain("APP_SLUG='hello-web'");
    expect(bp.envFile).toContain("APP_PORT='8080'");
    expect(bp.envFile).toContain("PORT='8080'");

    // Recurring HTTP health checks are performed from the host Runtime Bridge via probe.json
    // so minimal/distroless/scratch images with no curl/wget/sh work without failing Docker
    // healthchecks, and special paths like `/health(v2)` never touch a shell.
    const specialProbeBp = generateApartmentBlueprint({
      slug: "probe-app",
      sourceType: "image",
      image: "hashicorp/http-echo:latest",
      internalPort: 8080,
      probeHttp: true,
      probePath: "/health(v2)",
    });
    expect(specialProbeBp.probeHttp).toBe(true);
    expect(specialProbeBp.probePath).toBe("/health(v2)");
    expect(specialProbeBp.composeYaml).not.toMatch(/^\s*healthcheck:/m);
    expect(specialProbeBp.composeYaml).not.toContain("nc -z");
    expect(specialProbeBp.composeYaml).not.toContain("No HTTP healthcheck client");
  });

  it("generates a Git Dockerfile blueprint with isolated Postgres and Redis companions", () => {
    const bp = generateApartmentBlueprint({
      slug: "shop-api",
      sourceType: "git",
      gitRepoUrl: "https://github.com/acme/shop-api.git",
      gitBranch: "main",
      dockerfilePath: "docker/Dockerfile.prod",
      internalPort: 3000,
      cpuLimit: "1.0",
      memoryLimitMb: 512,
      companions: [
        { type: "postgres", version: "16-alpine", envKey: "DATABASE_URL" },
        { type: "redis", version: "7-alpine", envKey: "CACHE_REDIS_URL" },
      ],
      companionSecrets: {
        postgresPassword: "pg_test_password_1234",
        redisPassword: "redis_test_password_5678",
      },
    });

    expect(bp.imageRef).toBe(getBuiltGitImageTag("shop-api"));
    expect(bp.composeYaml).toContain(`image: "${getBuiltGitImageTag("shop-api")}"`);
    expect(bp.composeYaml).toContain('image: "postgres:16-alpine"');
    expect(bp.composeYaml).toContain('container_name: "vpsagent-app-shop-api-postgres"');
    expect(bp.composeYaml).toContain('image: "redis:7-alpine"');
    expect(bp.composeYaml).toContain('container_name: "vpsagent-app-shop-api-redis"');
    expect(bp.composeYaml).toContain("depends_on:");
    expect(bp.composeYaml).toContain("condition: service_healthy");
    expect(bp.composeYaml).not.toContain("pg_test_password_1234");
    expect(bp.composeYaml).not.toContain("redis_test_password_5678");

    expect(bp.envVars.DATABASE_URL).toBe(
      "postgresql://vps_shop_api:pg_test_password_1234@postgres:5432/app_shop_api",
    );
    expect(bp.envVars.CACHE_REDIS_URL).toBe(
      "redis://:redis_test_password_5678@redis:6379/0",
    );
    expect(bp.requiredDataDirs).toEqual(["data", "data/postgres", "data/redis"]);
  });

  it("rejects forbidden env keys, duplicate companions, unsafe Dockerfile paths, and bad limits", () => {
    expect(() =>
      generateApartmentBlueprint({
        slug: "demo-app",
        sourceType: "image",
        image: "nginx:alpine",
        envVars: { DOCKER_HOST: "tcp://evil:2375" },
      }),
    ).toThrow(/reserved and cannot be set/);

    expect(() =>
      generateApartmentBlueprint({
        slug: "demo-app",
        sourceType: "image",
        image: "nginx:alpine",
        envVars: { VPSAGENT_RUNTIME_TOKEN: "leak" },
      }),
    ).toThrow(/reserved and cannot be set/);

    expect(() =>
      generateApartmentBlueprint({
        slug: "demo-app",
        sourceType: "git",
        gitRepoUrl: "https://github.com/acme/demo.git",
        dockerfilePath: "../../etc/passwd",
      }),
    ).toThrow(/Invalid Dockerfile path/);

    expect(() =>
      generateApartmentBlueprint({
        slug: "demo-app",
        sourceType: "git",
        gitRepoUrl: "https://github.com/acme/demo.git",
        gitBranch: "--upload-pack=evil",
      }),
    ).toThrow(/Invalid Git branch/);

    expect(() =>
      generateApartmentBlueprint({
        slug: "demo-app",
        sourceType: "image",
        image: "nginx:alpine",
        companions: [{ type: "postgres" }, { type: "postgres" }],
      }),
    ).toThrow(/Duplicate companion/);

    expect(() =>
      generateApartmentBlueprint({
        slug: "demo-app",
        sourceType: "image",
        image: "nginx:alpine",
        dataMountTarget: "/var/run/docker.sock",
      }),
    ).toThrow(/Unsafe dataMountTarget/);
  });

  it("writes docker-compose.yml, 0600 .env, and data dirs safely while blocking symlinks", () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "vpsagent-bp-"));
    const appsRoot = path.join(tmpDir, "apps");
    fs.mkdirSync(appsRoot, { recursive: true });

    try {
      const bp = generateApartmentBlueprint({
        slug: "notes-app",
        sourceType: "image",
        image: "nginxinc/nginx-unprivileged:alpine",
        internalPort: 8080,
        probeHttp: true,
        probePath: "/health(v2)",
        companions: [{ type: "postgres" }],
      });

      const written = writeApartmentBlueprint(appsRoot, bp);
      expect(fs.existsSync(written.composePath)).toBe(true);
      expect(fs.existsSync(written.envPath)).toBe(true);
      expect(fs.existsSync(written.probeConfigPath)).toBe(true);
      expect(JSON.parse(fs.readFileSync(written.probeConfigPath, "utf8"))).toEqual({
        probeHttp: true,
        internalPort: 8080,
        probePath: "/health(v2)",
      });
      expect(fs.existsSync(path.join(written.appDir, "data", "postgres"))).toBe(true);

      const envMode = fs.statSync(written.envPath).mode & 0o777;
      expect(envMode).toBe(0o600);

      // Symlink escape on app directory must be rejected
      const outside = path.join(tmpDir, "outside");
      fs.mkdirSync(outside, { recursive: true });
      fs.symlinkSync(outside, path.join(appsRoot, "sym-app"));

      const symBp = generateApartmentBlueprint({
        slug: "sym-app",
        sourceType: "image",
        image: "nginxinc/nginx-unprivileged:alpine",
      });
      expect(() => writeApartmentBlueprint(appsRoot, symBp)).toThrow(/symbolic link/);
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });
});
