#!/usr/bin/env python3
"""Unit tests for bootstrap/runtime-bridge.py (VPSAgent v2 Host Runtime Bridge)."""

from __future__ import annotations

import http.server
import importlib.util
import json
import os
import shutil
import stat
import sys
import tempfile
import threading
import unittest
from pathlib import Path

BRIDGE_PATH = Path(__file__).resolve().parent / "runtime-bridge.py"
SPEC = importlib.util.spec_from_file_location("runtime_bridge", BRIDGE_PATH)
assert SPEC and SPEC.loader
rb = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(rb)


def _write_fake_git_and_docker(tmp_dir: str, *, build_sleep_s: float = 0.0, create_dockerfile: bool = True) -> tuple[str, str]:
    git_py = os.path.join(tmp_dir, "fake_git.py")
    with open(git_py, "w", encoding="utf-8") as fh:
        fh.write(
            f"""import os, sys
args = sys.argv[1:]
if "clone" in args:
    dst = args[-1]
    os.makedirs(dst, exist_ok=True)
    if {create_dockerfile!r}:
        with open(os.path.join(dst, "Dockerfile"), "w", encoding="utf-8") as df:
            df.write("FROM alpine:3.20\\n")
    sys.exit(0)
if "rev-parse" in args:
    print("abc1234567890def1234567890abcdef12345678")
    sys.exit(0)
sys.exit(0)
"""
        )
    git_sh = os.path.join(tmp_dir, "fake-git")
    with open(git_sh, "w", encoding="utf-8") as fh:
        fh.write(f'#!/usr/bin/env sh\nexec "{sys.executable}" "{git_py}" "$@"\n')
    os.chmod(git_sh, 0o755)

    docker_py = os.path.join(tmp_dir, "fake_docker.py")
    with open(docker_py, "w", encoding="utf-8") as fh:
        fh.write(
            f"""import json, sys, time
args = sys.argv[1:]
if args[:1] == ["build"]:
    if {build_sleep_s!r} > 0:
        time.sleep({build_sleep_s!r})
    print("Built image ok token=vpsmcp_1234567890abcdefghij")
    sys.exit(0)
if args[:1] == ["ps"]:
    print("cid-test")
    sys.exit(0)
if args[:1] == ["inspect"]:
    print(json.dumps([{{
        "Id": "1234567890abcdef",
        "Name": "/vpsagent-app-demo-api",
        "RestartCount": 0,
        "Config": {{"Image": "vpsagent-app-demo-api:latest"}},
        "State": {{"Status": "running", "Running": True, "ExitCode": 0, "Health": {{"Status": "none"}}}},
        "HostConfig": {{
            "CapDrop": ["ALL"],
            "SecurityOpt": ["no-new-privileges:true"],
            "Privileged": False,
            "Memory": 268435456,
            "NanoCpus": 500000000,
            "Binds": [],
        }},
        "Mounts": [],
        "NetworkSettings": {{"Networks": {{"vpsagent-demo-api_app_net": {{"IPAddress": "127.0.0.1"}}}}}},
    }}]))
    sys.exit(0)
sys.exit(0)
"""
        )
    docker_sh = os.path.join(tmp_dir, "fake-docker")
    with open(docker_sh, "w", encoding="utf-8") as fh:
        fh.write(f'#!/usr/bin/env sh\nexec "{sys.executable}" "{docker_py}" "$@"\n')
    os.chmod(docker_sh, 0o755)
    return git_sh, docker_sh


class TestRuntimeBridgeSecurityAndFeatures(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp(prefix="vpsagent-py-test-")
        self.apps_root = os.path.join(self.tmp, "apps")
        self.caddy_dir = os.path.join(self.tmp, "caddy")
        os.makedirs(self.apps_root, exist_ok=True)
        os.makedirs(self.caddy_dir, exist_ok=True)

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_dns_checked_git_repo_url_blocks_private_loopback_and_metadata(self) -> None:
        public_dns = lambda host, port: ["140.82.121.4"]
        private_dns = lambda host, port: ["10.0.0.42"]
        cgnat_dns = lambda host, port: ["100.64.0.12"]
        metadata_dns = lambda host, port: ["169.254.169.254"]
        mapped_v6_dns = lambda host, port: ["::ffff:169.254.169.254"]
        ula_v6_dns = lambda host, port: ["fd12:3456:789a::1"]
        aws_v6_meta = lambda host, port: ["fd00:ec2::254"]

        self.assertEqual(
            rb.validate_git_repo_url("https://github.com/acme/demo.git", dns_resolver=public_dns),
            "https://github.com/acme/demo.git",
        )

        # Scheme, credentials, single-label, loopback
        for bad_url in [
            "http://github.com/acme/demo.git",
            "file:///etc/passwd",
            "ssh://git@github.com/acme/demo.git",
            "https://user:pass@github.com/acme/demo.git",
            "https://localhost/acme/demo.git",
            "https://internal-git/acme/demo.git",
            "https://169.254.169.254/latest/meta-data",
            "https://127.0.0.1/repo.git",
            "https://[::1]/repo.git",
        ]:
            with self.assertRaises(rb.BridgeRequestError, msg=f"Expected rejection for {bad_url}"):
                rb.validate_git_repo_url(bad_url, dns_resolver=public_dns)

        # DNS rebinding / private resolutions
        for resolver in [private_dns, cgnat_dns, metadata_dns, mapped_v6_dns, ula_v6_dns, aws_v6_meta]:
            with self.assertRaises(rb.BridgeRequestError):
                rb.validate_git_repo_url("https://evil.example.com/repo.git", dns_resolver=resolver)

    def test_env_parser_preserves_literal_quotes_and_blocks_forbidden_keys(self) -> None:
        env_text = (
            "APP_SLUG='my-app'\n"
            "APP_PORT='3000'\n"
            "SECRET_VAL='p@ss$word#123 with spaces'\n"
            'MULTI="it\'s\\nline2"\n'
        )
        parsed = rb.parse_and_validate_env_file(env_text, "my-app")
        self.assertEqual(parsed["SECRET_VAL"], "p@ss$word#123 with spaces")
        self.assertEqual(parsed["MULTI"], "it's\nline2")

        with self.assertRaises(rb.BridgeRequestError):
            rb.parse_and_validate_env_file("VPSAGENT_RUNTIME_TOKEN='abc'\n", "my-app")
        with self.assertRaises(rb.BridgeRequestError):
            rb.parse_and_validate_env_file("DOCKER_HOST='tcp://1.2.3.4:2375'\n", "my-app")
        with self.assertRaises(rb.BridgeRequestError):
            rb.parse_and_validate_env_file("APP_SLUG='wrong-slug'\n", "my-app")

    def test_compose_validator_accepts_locked_apartment_with_companions_and_rejects_escapes(self) -> None:
        app_dir = os.path.join(self.apps_root, "shop-api")
        os.makedirs(os.path.join(app_dir, "data", "postgres"), exist_ok=True)
        os.makedirs(os.path.join(app_dir, "data", "redis"), exist_ok=True)

        compose = """services:
  app:
    image: "vpsagent-app-shop-api:latest"
    container_name: "vpsagent-app-shop-api"
    restart: unless-stopped
    init: true
    env_file:
      - .env
    volumes:
      - ./data:/app/data:rw
    cpus: "0.5"
    mem_limit: "512m"
    cap_drop:
      - ALL
    security_opt:
      - no-new-privileges:true
    depends_on:
      postgres:
        condition: service_healthy
      redis:
        condition: service_healthy
    networks:
      - app_net
  postgres:
    image: "postgres:16-alpine"
    container_name: "vpsagent-app-shop-api-postgres"
    restart: unless-stopped
    user: "70:70"
    environment:
      POSTGRES_DB: "${POSTGRES_DB}"
      POSTGRES_USER: "${POSTGRES_USER}"
      POSTGRES_PASSWORD: "${POSTGRES_PASSWORD}"
    volumes:
      - ./data/postgres:/var/lib/postgresql/data:rw
    cpus: "0.5"
    mem_limit: "256m"
    cap_drop:
      - ALL
    security_opt:
      - no-new-privileges:true
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U ${POSTGRES_USER} -d ${POSTGRES_DB}"]
      interval: "5s"
      timeout: "5s"
      retries: 10
    networks:
      - app_net
  redis:
    image: "redis:7-alpine"
    container_name: "vpsagent-app-shop-api-redis"
    restart: unless-stopped
    user: "999:999"
    command: ["redis-server", "--requirepass", "${REDIS_PASSWORD}"]
    environment:
      REDISCLI_AUTH: "${REDIS_PASSWORD}"
    volumes:
      - ./data/redis:/data:rw
    cpus: "0.25"
    mem_limit: "128m"
    cap_drop:
      - ALL
    security_opt:
      - no-new-privileges:true
    networks:
      - app_net
networks:
  app_net:
    driver: bridge
"""
        env_map = {
            "APP_PORT": "8080",
            "TRICKY_LITERAL": "it's ${APP_PORT}\nline2\\end",
            "POSTGRES_DB": "app_shop_api",
            "POSTGRES_USER": "vps_shop_api",
            "POSTGRES_PASSWORD": "p$ss#word_with_dollar",
            "REDIS_PASSWORD": "r$dis_pass",
        }
        rendered = rb.validate_and_render_compose(compose, "shop-api", app_dir, env_map, None)
        # Literal `$` inside resolved passwords & injected app env is escaped as `$$` so Docker Compose never expands `${APP_PORT}`!
        self.assertEqual(rendered["services"]["postgres"]["environment"]["POSTGRES_PASSWORD"], "p$$ss#word_with_dollar")
        self.assertEqual(rendered["services"]["redis"]["command"][-1], "r$$dis_pass")
        self.assertNotIn("env_file", rendered["services"]["app"])
        self.assertEqual(
            rendered["services"]["app"]["environment"]["TRICKY_LITERAL"],
            "it's $${APP_PORT}\nline2\\end",
        )

        # Root user must be rejected
        root_compose = compose.replace('user: "70:70"', 'user: "0:0"')
        with self.assertRaises(rb.BridgeRequestError):
            rb.validate_and_render_compose(root_compose, "shop-api", app_dir, env_map, None)

        # Missing cpus/mem_limit must be rejected
        no_caps = compose.replace('    cpus: "0.5"\n', "", 1)
        with self.assertRaises(rb.BridgeRequestError):
            rb.validate_and_render_compose(no_caps, "shop-api", app_dir, env_map, None)

        # docker.sock volume mount must be rejected
        sock_compose = compose.replace("./data:/app/data:rw", "/var/run/docker.sock:/var/run/docker.sock")
        with self.assertRaises(rb.BridgeRequestError):
            rb.validate_and_render_compose(sock_compose, "shop-api", app_dir, env_map, None)

    def test_build_git_succeeds_redacts_logs_and_enforces_timeout_and_missing_dockerfile(self) -> None:
        git_sh, docker_sh = _write_fake_git_and_docker(self.tmp)
        svc = rb.RuntimeService(
            apps_root=self.apps_root,
            caddy_apps_dir=self.caddy_dir,
            caddy_container="vpsagent-caddy",
            docker_bin=docker_sh,
            git_bin=git_sh,
            runtime_token="secret-token-for-unit-test-1234",
            dns_resolver=lambda host, port: ["140.82.121.4"],
        )

        res = svc.build_git(
            {
                "slug": "demo-api",
                "gitRepoUrl": "https://github.com/acme/demo-api.git",
                "gitBranch": "main",
                "dockerfilePath": "Dockerfile",
                "timeoutSeconds": 20,
            }
        )
        self.assertTrue(res["ok"])
        self.assertEqual(res["image"], "vpsagent-app-demo-api:latest")
        self.assertEqual(res["commitSha"], "abc1234567890def1234567890abcdef12345678")
        joined = "\n".join(res["buildLogTail"])
        self.assertNotIn("vpsmcp_1234567890abcdefghij", joined)
        self.assertIn("[REDACTED]", joined)

        # Missing Dockerfile -> 400
        git_missing, docker_ok = _write_fake_git_and_docker(
            tempfile.mkdtemp(dir=self.tmp), create_dockerfile=False
        )
        svc_missing = rb.RuntimeService(
            apps_root=self.apps_root,
            caddy_apps_dir=self.caddy_dir,
            caddy_container="vpsagent-caddy",
            docker_bin=docker_ok,
            git_bin=git_missing,
            runtime_token="secret-token-for-unit-test-1234",
            dns_resolver=lambda host, port: ["140.82.121.4"],
        )
        with self.assertRaises(rb.BridgeRequestError) as ctx:
            svc_missing.build_git(
                {
                    "slug": "demo-api",
                    "gitRepoUrl": "https://github.com/acme/demo-api.git",
                }
            )
        self.assertEqual(ctx.exception.status_code, 400)

    def test_readiness_retries_500_and_accepts_4xx_api_root_and_times_out_on_persistent_500(self) -> None:
        git_sh, docker_sh = _write_fake_git_and_docker(self.tmp)
        svc = rb.RuntimeService(
            apps_root=self.apps_root,
            caddy_apps_dir=self.caddy_dir,
            caddy_container="vpsagent-caddy",
            docker_bin=docker_sh,
            git_bin=git_sh,
            runtime_token="secret-token-for-unit-test-1234",
        )

        # Mock HTTP server: first 2 calls -> 503, 3rd call -> 401 (auth-gated API root!)
        state = {"hits": 0, "always_500": False}

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, format: str, *args: object) -> None:
                return

            def do_GET(self) -> None:
                state["hits"] += 1
                if state["always_500"] or state["hits"] < 3:
                    self.send_response(503)
                else:
                    self.send_response(401)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(b'{"status":"api"}')

        srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        port = srv.server_address[1]
        t = threading.Thread(target=srv.serve_forever, daemon=True)
        t.start()
        try:
            ready = svc.check_readiness(
                {
                    "slug": "demo-api",
                    "internalPort": port,
                    "timeoutSeconds": 3.0,
                    "pollIntervalMs": 20,
                }
            )
            self.assertTrue(ready["ready"])
            self.assertEqual(ready["attempts"], 3)
            self.assertEqual(ready["httpProbe"]["statusCode"], 401)

            # Persistent 503 times out cleanly
            state["always_500"] = True
            timed_out = svc.check_readiness(
                {
                    "slug": "demo-api",
                    "internalPort": port,
                    "timeoutSeconds": 0.2,
                    "pollIntervalMs": 30,
                }
            )
            self.assertFalse(timed_out["ready"])
            self.assertGreaterEqual(timed_out["attempts"], 2)
            self.assertIn("Timed out", timed_out["reason"])
        finally:
            srv.shutdown()
            srv.server_close()

    def test_host_stats_and_secret_redaction(self) -> None:
        stats = rb.collect_host_stats("/")
        self.assertGreaterEqual(stats["metrics"]["cpuCount"], 1)
        self.assertGreaterEqual(stats["metrics"]["memoryUsagePercent"], 0)
        self.assertLessEqual(stats["metrics"]["memoryUsagePercent"], 100)
        self.assertGreater(stats["disk"]["totalGb"], 0)

        redacted = rb.redact_secrets(
            "Bearer vpsmcp_supersecret1234567890abcd passphrase=mysecretvalue"
        )
        self.assertNotIn("vpsmcp_supersecret1234567890abcd", redacted)
        self.assertNotIn("mysecretvalue", redacted)

    def test_core_domain_routing_and_atomic_rollback(self) -> None:
        core_dir = os.path.join(self.tmp, "caddy-core")
        os.makedirs(core_dir, exist_ok=True)
        fail_flag = os.path.join(self.tmp, "fail-validate")
        docker_py = os.path.join(self.tmp, "caddy_docker.py")
        with open(docker_py, "w", encoding="utf-8") as fh:
            fh.write(
                f"""import os, sys
args = sys.argv[1:]
if "validate" in args and os.path.exists({fail_flag!r}):
    sys.stderr.write("invalid caddy config\\n")
    sys.exit(1)
sys.exit(0)
"""
            )
        docker_sh = os.path.join(self.tmp, "caddy-docker")
        with open(docker_sh, "w", encoding="utf-8") as fh:
            fh.write(f'#!/usr/bin/env sh\nexec "{sys.executable}" "{docker_py}" "$@"\n')
        os.chmod(docker_sh, 0o755)

        tls_state = {"result": (True, "active", None)}
        svc = rb.RuntimeService(
            apps_root=self.apps_root,
            caddy_apps_dir=self.caddy_dir,
            caddy_core_dir=core_dir,
            caddy_container="vpsagent-caddy",
            docker_bin=docker_sh,
            runtime_token="secret-token-for-unit-test-1234",
            tls_checker=lambda domain, timeout: tls_state["result"],
        )

        # Successful TLS verification reports httpsActive=True, tlsStatus="active"
        res = svc.route_core_domain({"domain": "vps.example.com", "acmeEmail": "ops@example.com"})
        self.assertTrue(res["httpsActive"])
        self.assertEqual(res["tlsStatus"], "active")
        dash_caddy = os.path.join(core_dir, "dashboard.caddy")
        content = Path(dash_caddy).read_text(encoding="utf-8")
        self.assertIn("vps.example.com {", content)
        self.assertIn("tls ops@example.com", content)

        # Failed TLS issuance reports httpsActive=False and tlsStatus="failed" even though Caddy reloaded
        tls_state["result"] = (False, "failed", "TLS handshake failed: unknown ca")
        res_failed_tls = svc.route_core_domain({"domain": "pending.example.com", "acmeEmail": None})
        self.assertFalse(res_failed_tls["httpsActive"])
        self.assertEqual(res_failed_tls["tlsStatus"], "failed")
        self.assertIn("TLS handshake failed", res_failed_tls["tlsError"])

        # Restore vps.example.com before testing rollback
        tls_state["result"] = (True, "active", None)
        svc.route_core_domain({"domain": "vps.example.com", "acmeEmail": "ops@example.com"})

        # Failed caddy validate restores prior working dashboard.caddy
        Path(fail_flag).write_text("1", encoding="utf-8")
        with self.assertRaises(rb.BridgeRequestError) as ctx:
            svc.route_core_domain({"domain": "broken.example.com", "acmeEmail": None})
        self.assertEqual(ctx.exception.status_code, 422)
        self.assertIn("vps.example.com {", Path(dash_caddy).read_text(encoding="utf-8"))

        # Conflict with an app domain returns 409
        Path(fail_flag).unlink()
        Path(os.path.join(self.caddy_dir, "blog.caddy")).write_text(
            "blog.example.com {\n\treverse_proxy vpsagent-app-blog:3000\n}\n", encoding="utf-8"
        )
        with self.assertRaises(rb.BridgeRequestError) as ctx2:
            svc.route_core_domain({"domain": "blog.example.com"})
        self.assertEqual(ctx2.exception.status_code, 409)

    def test_companion_volume_ownership_and_private_permissions(self) -> None:
        from unittest import mock

        app_dir = os.path.join(self.apps_root, "db-app")
        os.makedirs(app_dir, exist_ok=True)
        chown_calls: list[tuple[str, int, int]] = []

        def fake_chown(p: str, uid: int, gid: int) -> None:
            chown_calls.append((p, uid, gid))

        with mock.patch.object(os, "geteuid", return_value=0), mock.patch.object(
            os, "chown", side_effect=fake_chown
        ):
            pg_dir = rb._prepare_service_volume_dir(app_dir, "data/postgres", "70:70", "db-app")
            redis_dir = rb._prepare_service_volume_dir(app_dir, "data/redis", "999:999", "db-app")

        self.assertEqual(stat.S_IMODE(os.stat(os.path.join(app_dir, "data")).st_mode), 0o755)
        self.assertEqual(stat.S_IMODE(os.stat(pg_dir).st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(os.stat(redis_dir).st_mode), 0o700)
        self.assertIn((pg_dir, 70, 70), chown_calls)
        self.assertIn((redis_dir, 999, 999), chown_calls)

    def test_pinned_git_connect_proxy_enforces_host_and_public_ip(self) -> None:
        import socket as sock_mod

        with rb._PinnedGitConnectProxy("github.com", 443, ["140.82.121.4"], connect_timeout=1.0) as proxy:
            # Connecting to a mismatched host via CONNECT must return 403 Forbidden
            with sock_mod.create_connection(("127.0.0.1", proxy.port), timeout=2.0) as conn:
                conn.sendall(b"CONNECT evil.internal:443 HTTP/1.1\r\nHost: evil.internal:443\r\n\r\n")
                resp = conn.recv(1024).decode("latin-1")
                self.assertIn("403 Forbidden", resp)

        # Even if a private IP were passed, proxy re-asserts public IP at connect time -> 502
        with rb._PinnedGitConnectProxy("rebind.example.com", 443, ["127.0.0.1"], connect_timeout=1.0) as proxy2:
            with sock_mod.create_connection(("127.0.0.1", proxy2.port), timeout=2.0) as conn:
                conn.sendall(b"CONNECT rebind.example.com:443 HTTP/1.1\r\nHost: rebind.example.com:443\r\n\r\n")
                resp = conn.recv(1024).decode("latin-1")
                self.assertIn("502 Bad Gateway", resp)

    def test_compose_context_separates_app_env_and_omits_cli_env_file(self) -> None:
        app_dir = os.path.join(self.apps_root, "iso-app")
        os.makedirs(os.path.join(app_dir, "data"), exist_ok=True)
        Path(os.path.join(app_dir, ".env")).write_text("APP_SLUG='iso-app'\nSECRET='a$b'\n", encoding="utf-8")
        Path(os.path.join(app_dir, "docker-compose.yml")).write_text(
            'services:\n  app:\n    image: "nginx:alpine"\n    env_file:\n      - .env\n    cpus: "0.5"\n    mem_limit: "128m"\n    cap_drop:\n      - ALL\n    security_opt:\n      - no-new-privileges:true\n    networks:\n      - app_net\nnetworks:\n  app_net:\n    driver: bridge\n',
            encoding="utf-8",
        )
        svc = rb.RuntimeService(
            apps_root=self.apps_root,
            caddy_apps_dir=self.caddy_dir,
            caddy_container="vpsagent-caddy",
            runtime_token="secret-token-for-unit-test-1234",
        )
        with svc._validated_compose_context(app_dir, "iso-app") as (compose_path, project_dir):
            self.assertNotEqual(project_dir, app_dir)
            self.assertFalse(os.path.exists(os.path.join(project_dir, ".env")))
            self.assertFalse(os.path.exists(os.path.join(project_dir, "app.env")))
            rendered = json.loads(Path(compose_path).read_text(encoding="utf-8"))
            self.assertEqual(rendered["services"]["app"]["environment"]["SECRET"], "a$$b")
            cmd = svc._compose_cmd_base("iso-app", project_dir, compose_path)
            self.assertNotIn("--env-file", cmd)
            self.assertEqual(cmd[cmd.index("--project-directory") + 1], project_dir)

    def test_logs_budget_and_readiness_starting_healthcheck_and_worker(self) -> None:
        # 1. Byte-budgeted logs
        app_dir = os.path.join(self.apps_root, "noisy-app")
        os.makedirs(app_dir, exist_ok=True)
        Path(os.path.join(app_dir, "docker-compose.yml")).write_text(
            'services:\n  app:\n    image: "nginx:alpine"\n    cpus: "0.5"\n    mem_limit: "128m"\n    cap_drop:\n      - ALL\n    security_opt:\n      - no-new-privileges:true\n    networks:\n      - app_net\nnetworks:\n  app_net:\n    driver: bridge\n',
            encoding="utf-8",
        )
        health_state_file = os.path.join(self.tmp, "health-state.txt")
        Path(health_state_file).write_text("starting", encoding="utf-8")
        docker_py = os.path.join(self.tmp, "noisy_docker.py")
        with open(docker_py, "w", encoding="utf-8") as fh:
            fh.write(
                f"""import json, sys
from pathlib import Path
args = sys.argv[1:]
if "logs" in args:
    for i in range(120):
        print(f"line-{{i:04d}}-" + ("x" * 1000))
    sys.exit(0)
if args[:1] == ["ps"]:
    print("cid-noisy")
    sys.exit(0)
if args[:1] == ["inspect"]:
    h = Path({health_state_file!r}).read_text().strip()
    print(json.dumps([{{
        "Id": "1234567890abcdef",
        "Name": "/vpsagent-app-noisy-app",
        "RestartCount": 0,
        "Config": {{"Image": "nginx:alpine"}},
        "State": {{"Status": "running", "Running": True, "ExitCode": 0, "Health": {{"Status": h}}}},
        "HostConfig": {{"CapDrop": ["ALL"], "SecurityOpt": ["no-new-privileges:true"], "Privileged": False, "Binds": []}},
        "Mounts": [],
        "NetworkSettings": {{"Networks": {{"vpsagent-noisy-app_app_net": {{"IPAddress": "127.0.0.1"}}}}}},
    }}]))
    sys.exit(0)
sys.exit(0)
"""
            )
        docker_sh = os.path.join(self.tmp, "noisy-docker")
        with open(docker_sh, "w", encoding="utf-8") as fh:
            fh.write(f'#!/usr/bin/env sh\nexec "{sys.executable}" "{docker_py}" "$@"\n')
        os.chmod(docker_sh, 0o755)

        svc = rb.RuntimeService(
            apps_root=self.apps_root,
            caddy_apps_dir=self.caddy_dir,
            caddy_container="vpsagent-caddy",
            docker_bin=docker_sh,
            runtime_token="secret-token-for-unit-test-1234",
        )

        log_res = svc.logs({"slug": "noisy-app", "tail": 200})
        self.assertTrue(log_res["truncated"])
        self.assertLessEqual(len(json.dumps(log_res).encode("utf-8")), rb.MAX_LOGS_RESPONSE_BYTES + 256)

        # 2. Readiness must NOT return ready while Docker healthStatus is still "starting"
        starting_res = svc.check_readiness(
            {"slug": "noisy-app", "internalPort": 8080, "probeHttp": False, "timeoutSeconds": 0.4, "pollIntervalMs": 30}
        )
        self.assertFalse(starting_res["ready"])
        self.assertIn("starting", starting_res["reason"])

        # 3. Once Docker healthStatus transitions to "healthy", non-HTTP worker succeeds with probeHttp=False
        Path(health_state_file).write_text("healthy", encoding="utf-8")
        healthy_worker = svc.check_readiness(
            {"slug": "noisy-app", "internalPort": 8080, "probeHttp": False, "timeoutSeconds": 1.0, "pollIntervalMs": 20}
        )
        self.assertTrue(healthy_worker["ready"])
        self.assertIsNone(healthy_worker["httpProbe"])

        # 4. Delayed inspection that exceeds timeoutSeconds MUST return ready=False (never ready=True past deadline!),
        # AND a still-starting container preserves its "starting" diagnostic even when the deadline expires mid-inspect.
        from unittest import mock

        def slow_inspect(payload: dict, *, timeout_budget_s: float | None = None, **_kwargs: object) -> dict:
            import time as _t
            _t.sleep(0.14)
            return {
                "slug": "noisy-app",
                "status": "running",
                "containers": [{"healthStatus": "healthy"}],
                "httpProbe": {"attempted": True, "ok": True, "statusCode": 200, "error": None},
            }

        def slow_starting_inspect(payload: dict, *, timeout_budget_s: float | None = None, **_kwargs: object) -> dict:
            import time as _t
            _t.sleep(0.14)
            return {
                "slug": "noisy-app",
                "status": "running",
                "containers": [{"healthStatus": "starting"}],
                "httpProbe": None,
            }

        with mock.patch.object(svc, "inspect_workload", side_effect=slow_inspect):
            overdue = svc.check_readiness(
                {"slug": "noisy-app", "internalPort": 8080, "probeHttp": True, "timeoutSeconds": 0.1, "pollIntervalMs": 20}
            )
            self.assertFalse(overdue["ready"])
            self.assertIn("deadline", overdue["reason"])

        with mock.patch.object(svc, "inspect_workload", side_effect=slow_starting_inspect):
            overdue_starting = svc.check_readiness(
                {"slug": "noisy-app", "internalPort": 8080, "probeHttp": False, "timeoutSeconds": 0.1, "pollIntervalMs": 20}
            )
            self.assertFalse(overdue_starting["ready"])
            self.assertIn("starting", overdue_starting["reason"])

    def test_host_recurring_http_health_minimal_image_and_special_path(self) -> None:
        """
        Minimal/distroless/scratch images have no curl/wget/node/python3/sh inside the container
        and therefore no in-container Docker HEALTHCHECK (`healthStatus == "none"`).
        VPSAgent's host Runtime Bridge performs both startup readiness and recurring HTTP health
        checks directly against the container's private IP (including special paths like `/health(v2)`).
        """
        app_dir = os.path.join(self.apps_root, "mini-http")
        os.makedirs(app_dir, exist_ok=True)
        Path(os.path.join(app_dir, "docker-compose.yml")).write_text(
            'services:\n  app:\n    image: "hashicorp/http-echo:latest"\n    cpus: "0.5"\n    mem_limit: "128m"\n    cap_drop:\n      - ALL\n    security_opt:\n      - no-new-privileges:true\n    networks:\n      - app_net\nnetworks:\n  app_net:\n    driver: bridge\n',
            encoding="utf-8",
        )

        # Live local HTTP server simulating a minimal container with NO in-container tools
        state = {"status": 200, "paths": []}

        class _MinimalAppHandler(http.server.BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                state["paths"].append(self.path)
                code = state["status"]
                body = b"ok" if code == 200 else b"broken"
                self.send_response(code)
                self.send_header("Content-Type", "text/plain")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, format: str, *args: object) -> None:
                return

        srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _MinimalAppHandler)
        port = srv.server_address[1]
        t = threading.Thread(target=srv.serve_forever, daemon=True)
        t.start()
        try:
            Path(os.path.join(app_dir, "probe.json")).write_text(
                json.dumps(
                    {
                        "probeHttp": True,
                        "internalPort": port,
                        "probePath": "/health(v2)",
                    }
                ),
                encoding="utf-8",
            )

            docker_py = os.path.join(self.tmp, "mini_docker.py")
            with open(docker_py, "w", encoding="utf-8") as fh:
                fh.write(
                    """import json, sys
args = sys.argv[1:]
if "ps" in args and "--format" in args and "json" in args:
    print(json.dumps([{"State": "running", "Health": "", "ExitCode": 0}]))
    sys.exit(0)
if args[:1] == ["ps"]:
    print("cid-mini")
    sys.exit(0)
if args[:1] == ["inspect"]:
    # Note: NO State.Health block (container has no in-container HEALTHCHECK)
    print(json.dumps([{
        "Id": "abcdef1234567890",
        "Name": "/vpsagent-app-mini-http",
        "RestartCount": 0,
        "Config": {"Image": "hashicorp/http-echo:latest"},
        "State": {"Status": "running", "Running": True, "ExitCode": 0},
        "HostConfig": {"CapDrop": ["ALL"], "SecurityOpt": ["no-new-privileges:true"], "Privileged": False, "Binds": []},
        "Mounts": [],
        "NetworkSettings": {"Networks": {"vpsagent-mini-http_app_net": {"IPAddress": "127.0.0.1"}}},
    }]))
    sys.exit(0)
sys.exit(0)
"""
                )
            docker_sh = os.path.join(self.tmp, "mini-docker")
            with open(docker_sh, "w", encoding="utf-8") as fh:
                fh.write(f'#!/usr/bin/env sh\nexec "{sys.executable}" "{docker_py}" "$@"\n')
            os.chmod(docker_sh, 0o755)

            svc = rb.RuntimeService(
                apps_root=self.apps_root,
                caddy_apps_dir=self.caddy_dir,
                caddy_container="vpsagent-caddy",
                docker_bin=docker_sh,
                runtime_token="secret-token-for-unit-test-1234",
                health_retries=3,
            )

            # 1. Startup readiness succeeds for minimal image with special path `/health(v2)`
            ready = svc.check_readiness(
                {
                    "slug": "mini-http",
                    "internalPort": port,
                    "probeHttp": True,
                    "probePath": "/health(v2)",
                    "timeoutSeconds": 2.0,
                    "pollIntervalMs": 20,
                }
            )
            self.assertTrue(ready["ready"])
            self.assertEqual(ready["httpProbe"]["statusCode"], 200)
            self.assertIn("/health(v2)", state["paths"])

            inspected_ok = svc.inspect_workload(
                {
                    "slug": "mini-http",
                    "internalPort": port,
                    "probeHttp": True,
                    "probePath": "/health(v2)",
                }
            )
            self.assertEqual(inspected_ok["status"], "running")
            self.assertEqual(inspected_ok["containers"][0]["healthStatus"], "none")
            self.assertEqual(inspected_ok["hostHttpHealth"]["status"], "healthy")
            self.assertIn("/health(v2)", inspected_ok["hostHttpHealth"]["lastOutput"])

            # 2. Recurring host health monitor detects 3 consecutive HTTP 500s -> marks unhealthy/error
            state["status"] = 500
            r1 = svc.run_recurring_health_check_once("mini-http")
            r2 = svc.run_recurring_health_check_once("mini-http")
            self.assertEqual(r1["consecutiveFailures"], 1)
            self.assertEqual(r2["consecutiveFailures"], 2)
            self.assertEqual(svc.statuses({"slugs": ["mini-http"]})["statuses"]["mini-http"], "running")

            r3 = svc.run_recurring_health_check_once("mini-http")
            self.assertEqual(r3["status"], "unhealthy")
            self.assertEqual(r3["consecutiveFailures"], 3)
            self.assertEqual(svc.statuses({"slugs": ["mini-http"]})["statuses"]["mini-http"], "error")

            inspected_bad = svc.inspect_workload(
                {
                    "slug": "mini-http",
                    "internalPort": port,
                    "probeHttp": False,
                }
            )
            self.assertEqual(inspected_bad["status"], "error")
            self.assertEqual(inspected_bad["containers"][0]["healthStatus"], "none")
            self.assertEqual(inspected_bad["hostHttpHealth"]["status"], "unhealthy")

            # 3. Initial deploy readiness of a broken minimal image returning 500 NEVER falsely succeeds
            broken_ready = svc.check_readiness(
                {
                    "slug": "mini-http",
                    "internalPort": port,
                    "probeHttp": True,
                    "probePath": "/health(v2)",
                    "timeoutSeconds": 0.2,
                    "pollIntervalMs": 30,
                }
            )
            self.assertFalse(broken_ready["ready"])
            self.assertIn("500", broken_ready["reason"])

            # 4. Once HTTP 200 returns, recurring host check recovers status to running/healthy
            state["status"] = 200
            r_ok = svc.run_recurring_health_check_once("mini-http")
            self.assertEqual(r_ok["status"], "healthy")
            self.assertEqual(r_ok["consecutiveFailures"], 0)
            self.assertEqual(svc.statuses({"slugs": ["mini-http"]})["statuses"]["mini-http"], "running")
        finally:
            srv.shutdown()
            srv.server_close()

    def test_docker_healthy_vs_host_http_three_failures_and_recovery(self) -> None:
        """
        When an image has its own Docker liveness check reporting 'healthy' while
        VPSAgent's host HTTP check fails 3 times, both `/v1/apps/statuses` (Apps list)
        and `/v1/apps/inspect` (Safety Check) must agree on overall status='error',
        while reporting Docker liveness ('healthy') separately from host HTTP health
        ('unhealthy'), and both must recover together when HTTP 200 returns.
        """
        app_dir = os.path.join(self.apps_root, "dual-check")
        os.makedirs(app_dir, exist_ok=True)
        Path(os.path.join(app_dir, "docker-compose.yml")).write_text(
            'services:\n  app:\n    image: "nginx:alpine"\n    cpus: "0.5"\n    mem_limit: "128m"\n    cap_drop:\n      - ALL\n    security_opt:\n      - no-new-privileges:true\n    networks:\n      - app_net\nnetworks:\n  app_net:\n    driver: bridge\n',
            encoding="utf-8",
        )

        http_state = {"status": 200}

        class _DualHandler(http.server.BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                code = http_state["status"]
                body = b"ok" if code == 200 else b"fail"
                self.send_response(code)
                self.send_header("Content-Type", "text/plain")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, format: str, *args: object) -> None:
                return

        srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _DualHandler)
        port = srv.server_address[1]
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            Path(os.path.join(app_dir, "probe.json")).write_text(
                json.dumps(
                    {
                        "probeHttp": True,
                        "internalPort": port,
                        "probePath": "/health(v2)",
                    }
                ),
                encoding="utf-8",
            )

            docker_py = os.path.join(self.tmp, "dual_docker.py")
            with open(docker_py, "w", encoding="utf-8") as fh:
                fh.write(
                    """import json, sys
args = sys.argv[1:]
if "ps" in args and "--format" in args and "json" in args:
    print(json.dumps([{"State": "running", "Health": "healthy", "ExitCode": 0}]))
    sys.exit(0)
if args[:1] == ["ps"]:
    print("cid-dual")
    sys.exit(0)
if args[:1] == ["inspect"]:
    print(json.dumps([{
        "Id": "fedcba0987654321",
        "Name": "/vpsagent-app-dual-check",
        "RestartCount": 0,
        "Config": {"Image": "nginx:alpine"},
        "State": {"Status": "running", "Running": True, "ExitCode": 0, "Health": {"Status": "healthy"}},
        "HostConfig": {"CapDrop": ["ALL"], "SecurityOpt": ["no-new-privileges:true"], "Privileged": False, "Binds": []},
        "Mounts": [],
        "NetworkSettings": {"Networks": {"vpsagent-dual-check_app_net": {"IPAddress": "127.0.0.1"}}},
    }]))
    sys.exit(0)
sys.exit(0)
"""
                )
            docker_sh = os.path.join(self.tmp, "dual-docker")
            with open(docker_sh, "w", encoding="utf-8") as fh:
                fh.write(f'#!/usr/bin/env sh\nexec "{sys.executable}" "{docker_py}" "$@"\n')
            os.chmod(docker_sh, 0o755)

            svc = rb.RuntimeService(
                apps_root=self.apps_root,
                caddy_apps_dir=self.caddy_dir,
                caddy_container="vpsagent-caddy",
                docker_bin=docker_sh,
                runtime_token="secret-token-for-unit-test-1234",
                health_retries=3,
            )

            # Healthy start: both Docker liveness and host HTTP agree on running/healthy
            ready = svc.check_readiness(
                {
                    "slug": "dual-check",
                    "internalPort": port,
                    "probeHttp": True,
                    "probePath": "/health(v2)",
                    "timeoutSeconds": 2.0,
                    "pollIntervalMs": 20,
                }
            )
            self.assertTrue(ready["ready"])
            self.assertEqual(svc.statuses({"slugs": ["dual-check"]})["statuses"]["dual-check"], "running")
            ins_ok = svc.inspect_workload(
                {"slug": "dual-check", "internalPort": port, "probeHttp": True, "probePath": "/health(v2)"}
            )
            self.assertEqual(ins_ok["status"], "running")
            self.assertEqual(ins_ok["containers"][0]["healthStatus"], "healthy")
            self.assertEqual(ins_ok["hostHttpHealth"]["status"], "healthy")
            self.assertEqual(ins_ok["httpProbe"]["statusCode"], 200)

            # Fail host HTTP 3 times while Docker liveness stays 'healthy'
            http_state["status"] = 500
            svc.run_recurring_health_check_once("dual-check")
            svc.run_recurring_health_check_once("dual-check")
            self.assertEqual(svc.statuses({"slugs": ["dual-check"]})["statuses"]["dual-check"], "running")
            svc.run_recurring_health_check_once("dual-check")

            # Both Apps list (`statuses`) and Safety Check (`inspect_workload`) MUST report 'error'
            list_status = svc.statuses({"slugs": ["dual-check"]})["statuses"]["dual-check"]
            ins_fail = svc.inspect_workload(
                {"slug": "dual-check", "internalPort": port, "probeHttp": True, "probePath": "/health(v2)"}
            )
            self.assertEqual(list_status, "error")
            self.assertEqual(ins_fail["status"], "error")
            # Docker liveness and host HTTP health remain reported separately
            self.assertEqual(ins_fail["containers"][0]["healthStatus"], "healthy")
            self.assertEqual(ins_fail["hostHttpHealth"]["status"], "unhealthy")
            self.assertEqual(ins_fail["hostHttpHealth"]["consecutiveFailures"], 3)
            self.assertEqual(ins_fail["httpProbe"]["statusCode"], 500)

            # Recover to HTTP 200: both Apps list and Safety Check recover together
            http_state["status"] = 200
            svc.run_recurring_health_check_once("dual-check")
            list_recovered = svc.statuses({"slugs": ["dual-check"]})["statuses"]["dual-check"]
            ins_recovered = svc.inspect_workload(
                {"slug": "dual-check", "internalPort": port, "probeHttp": True, "probePath": "/health(v2)"}
            )
            self.assertEqual(list_recovered, "running")
            self.assertEqual(ins_recovered["status"], "running")
            self.assertEqual(ins_recovered["containers"][0]["healthStatus"], "healthy")
            self.assertEqual(ins_recovered["hostHttpHealth"]["status"], "healthy")
            self.assertEqual(ins_recovered["hostHttpHealth"]["consecutiveFailures"], 0)
            self.assertEqual(ins_recovered["httpProbe"]["statusCode"], 200)

            # Before first monitor pass (e.g. right after bridge restart), a live HTTP 500
            # must NOT be counted as a monitor failure: hostHttpHealth stays starting with 0 failures.
            svc._clear_host_health("dual-check")
            http_state["status"] = 500
            ins_before_first_pass = svc.inspect_workload(
                {"slug": "dual-check", "internalPort": port, "probeHttp": True, "probePath": "/health(v2)"}
            )
            self.assertEqual(ins_before_first_pass["status"], "running")
            self.assertEqual(ins_before_first_pass["httpProbe"]["statusCode"], 500)
            self.assertFalse(ins_before_first_pass["httpProbe"]["ok"])
            self.assertEqual(ins_before_first_pass["hostHttpHealth"]["status"], "starting")
            self.assertEqual(ins_before_first_pass["hostHttpHealth"]["consecutiveFailures"], 0)
            self.assertIsNone(ins_before_first_pass["hostHttpHealth"]["lastOutput"])

            # When monitoring is disabled in probe.json (`probeHttp: false`), hostHttpHealth is None.
            Path(os.path.join(app_dir, "probe.json")).write_text(
                json.dumps({"probeHttp": False, "internalPort": port, "probePath": "/health(v2)"}),
                encoding="utf-8",
            )
            ins_disabled = svc.inspect_workload(
                {"slug": "dual-check", "internalPort": port, "probeHttp": False}
            )
            self.assertEqual(ins_disabled["status"], "running")
            self.assertIsNone(ins_disabled["hostHttpHealth"])
            self.assertIsNone(ins_disabled["httpProbe"])
        finally:
            srv.shutdown()
            srv.server_close()

    def test_inspect_and_auto_detect_build_without_dockerfile_and_failure_logs(self) -> None:
        # 1. Next.js repo with .env.example (no Dockerfile) -> auto-detected port 3000, postgres hint, key-only env extraction
        next_dir = tempfile.mkdtemp(dir=self.tmp)
        docker_seen_file = os.path.join(next_dir, "captured-dockerfile.txt")
        git_py = os.path.join(next_dir, "fake_git.py")
        Path(git_py).write_text(
            """import json, os, sys
args = sys.argv[1:]
if "clone" in args:
    dst = args[-1]
    os.makedirs(dst, exist_ok=True)
    with open(os.path.join(dst, "package.json"), "w", encoding="utf-8") as fh:
        json.dump({
            "name": "cool-next-app",
            "dependencies": {"next": "15.0.0", "react": "19.0.0", "pg": "8.13.0"},
            "scripts": {"build": "next build", "start": "next start"}
        }, fh)
    with open(os.path.join(dst, "pnpm-lock.yaml"), "w", encoding="utf-8") as fh:
        fh.write("lockfileVersion: '9.0'\\n")
    with open(os.path.join(dst, ".env.example"), "w", encoding="utf-8") as fh:
        fh.write("OPENAI_API_KEY=sk-example-never-return-value\\nDATABASE_URL=postgres://x\\nPUBLIC_TITLE=Hello\\n")
    sys.exit(0)
if "rev-parse" in args:
    if "--abbrev-ref" in args:
        print("main")
    else:
        print("deadbeefcafebabe1234567890abcdef12345678")
    sys.exit(0)
sys.exit(0)
""",
            encoding="utf-8",
        )
        git_sh = os.path.join(next_dir, "fake-git")
        Path(git_sh).write_text(f'#!/usr/bin/env sh\nexec "{sys.executable}" "{git_py}" "$@"\n', encoding="utf-8")
        os.chmod(git_sh, 0o755)

        docker_py = os.path.join(next_dir, "fake_docker.py")
        Path(docker_py).write_text(
            f"""import os, sys
args = sys.argv[1:]
if args[:1] == ["build"] and "-f" in args:
    df_path = args[args.index("-f") + 1]
    with open(df_path, "r", encoding="utf-8") as src:
        content = src.read()
    with open({docker_seen_file!r}, "w", encoding="utf-8") as out:
        out.write(content)
    print("Step 1/4 : FROM node:22-alpine")
    print("Successfully built auto-next")
    sys.exit(0)
sys.exit(0)
""",
            encoding="utf-8",
        )
        docker_sh = os.path.join(next_dir, "fake-docker")
        Path(docker_sh).write_text(f'#!/usr/bin/env sh\nexec "{sys.executable}" "{docker_py}" "$@"\n', encoding="utf-8")
        os.chmod(docker_sh, 0o755)

        svc = rb.RuntimeService(
            apps_root=self.apps_root,
            caddy_apps_dir=self.caddy_dir,
            caddy_container="vpsagent-caddy",
            docker_bin=docker_sh,
            git_bin=git_sh,
            runtime_token="secret-token-for-unit-test-1234",
            dns_resolver=lambda _host, _port: ["140.82.121.4"],
        )

        inspected = svc.inspect_git({"gitRepoUrl": "https://github.com/acme/my-next-app"})
        self.assertEqual(inspected["detectedRuntime"], "nextjs")
        self.assertFalse(inspected["hasDockerfile"])
        self.assertEqual(inspected["suggestedPort"], 3000)
        self.assertEqual(inspected["suggestedSlug"], "my-next-app")
        self.assertIn("postgres", inspected["suggestedCompanions"])
        env_keys = [item["key"] for item in inspected["envExampleKeys"]]
        self.assertEqual(env_keys, ["OPENAI_API_KEY", "DATABASE_URL", "PUBLIC_TITLE"])
        self.assertNotIn("sk-example-never-return-value", json.dumps(inspected))

        built = svc.build_git(
            {
                "slug": "my-next-app",
                "gitRepoUrl": "https://github.com/acme/my-next-app",
                "dockerfilePath": "auto",
            }
        )
        self.assertTrue(built["ok"])
        self.assertTrue(built["usedAutoDockerfile"])
        self.assertEqual(built["detectedRuntime"], "nextjs")
        self.assertEqual(built["suggestedPort"], 3000)
        self.assertIn("OPENAI_API_KEY", built["envExampleKeys"])
        generated_df = Path(docker_seen_file).read_text(encoding="utf-8")
        self.assertIn("USER node", generated_df)
        self.assertIn("pnpm", generated_df)

        # 2. Failed Docker build preserves redacted buildLogTail on BridgeRequestError
        fail_docker_py = os.path.join(next_dir, "fail_docker.py")
        Path(fail_docker_py).write_text(
            """import sys
print("Step 1/2 : RUN npm run build")
sys.stderr.write("ERROR: failed with API_KEY=sk-never-leak-build-err-12345\\n")
sys.exit(1)
""",
            encoding="utf-8",
        )
        fail_docker_sh = os.path.join(next_dir, "fail-docker")
        Path(fail_docker_sh).write_text(f'#!/usr/bin/env sh\nexec "{sys.executable}" "{fail_docker_py}" "$@"\n', encoding="utf-8")
        os.chmod(fail_docker_sh, 0o755)
        svc_fail = rb.RuntimeService(
            apps_root=self.apps_root,
            caddy_apps_dir=self.caddy_dir,
            caddy_container="vpsagent-caddy",
            docker_bin=fail_docker_sh,
            git_bin=git_sh,
            runtime_token="secret-token-for-unit-test-1234",
            dns_resolver=lambda _host, _port: ["140.82.121.4"],
        )
        with self.assertRaises(rb.BridgeRequestError) as ctx:
            svc_fail.build_git(
                {
                    "slug": "my-next-app",
                    "gitRepoUrl": "https://github.com/acme/my-next-app",
                    "dockerfilePath": "auto",
                }
            )
        self.assertEqual(ctx.exception.status_code, 502)
        self.assertTrue(len(ctx.exception.build_log_tail) >= 1)
        joined_tail = "\n".join(ctx.exception.build_log_tail)
        self.assertNotIn("sk-never-leak-build-err-12345", joined_tail)
        self.assertIn("[REDACTED]", joined_tail)

    def test_vps_manager_host_exec_files_and_protections(self) -> None:
        svc = rb.RuntimeService(
            apps_root=self.apps_root,
            caddy_apps_dir=self.caddy_dir,
            caddy_container="vpsagent-caddy",
            allow_unauthenticated=True,
            allowed_file_roots=[self.apps_root],
        )

        # 1. host_exec runs commands and redacts secrets in stdout
        res = svc.host_exec(
            {
                "command": "echo 'hello-vps' && echo 'API_KEY=sk-live-secret-1234567890'",
                "cwd": self.tmp,
                "timeoutSeconds": 10,
            }
        )
        self.assertEqual(res["exitCode"], 0)
        self.assertIn("hello-vps", res["stdout"])
        self.assertNotIn("sk-live-secret-1234567890", res["stdout"])

        # 1b. Noisy command output is bounded while streaming (not buffered unbounded)
        noisy = svc.host_exec(
            {
                "command": "python3 -c \"print('A' * 120000)\"",
                "timeoutSeconds": 10,
            }
        )
        self.assertEqual(noisy["exitCode"], 0)
        self.assertTrue(noisy["truncated"])
        self.assertLessEqual(len(noisy["stdout"].encode("utf-8")), rb.MAX_COMMAND_OUTPUT_BYTES + 128)

        # 1c. Timeout kills the subprocess group and returns 504
        with self.assertRaises(rb.BridgeRequestError) as ctx_to:
            svc.host_exec({"command": "sleep 30", "timeoutSeconds": 1})
        self.assertEqual(ctx_to.exception.status_code, 504)

        # 2. write_file -> list_files -> read_file -> delete_file lifecycle inside allowed root
        nested_file = os.path.join(self.apps_root, "managed", "notes.txt")
        written = svc.write_file(
            {
                "path": nested_file,
                "content": "line1\nline2\nTOKEN=vpsmcp_secret1234567890123456\n",
                "createDirs": True,
            }
        )
        self.assertTrue(written["ok"])
        self.assertGreater(written["bytesWritten"], 0)

        listed = svc.list_files({"path": os.path.join(self.apps_root, "managed")})
        self.assertEqual(len(listed["entries"]), 1)
        self.assertEqual(listed["entries"][0]["name"], "notes.txt")

        read_back = svc.read_file({"path": nested_file, "startLine": 1, "endLine": 3})
        self.assertIn("line1", read_back["content"])
        self.assertNotIn("vpsmcp_secret1234567890123456", read_back["content"])

        # 2b. Large disposable file (> MAX_READ_SCAN_BYTES) is capped before reading whole file
        big_file = os.path.join(self.apps_root, "managed", "big.log")
        Path(big_file).write_text("X" * (rb.MAX_READ_SCAN_BYTES + 4096), encoding="utf-8")
        big_read = svc.read_file({"path": big_file})
        self.assertTrue(big_read["truncated"])

        deleted = svc.delete_file({"path": nested_file})
        self.assertTrue(deleted["ok"])
        self.assertEqual(deleted["deletedType"], "file")
        self.assertFalse(os.path.exists(nested_file))

        # 3. Allowlist blocks paths outside allowed roots and symlinks escaping allowed roots
        outside_file = os.path.join(self.tmp, "outside.txt")
        Path(outside_file).write_text("outside", encoding="utf-8")
        with self.assertRaises(rb.BridgeRequestError) as ctx_out:
            svc.read_file({"path": outside_file})
        self.assertEqual(ctx_out.exception.status_code, 403)

        escape_link = os.path.join(self.apps_root, "managed", "escape-link")
        os.symlink(outside_file, escape_link)
        with self.assertRaises(rb.BridgeRequestError) as ctx_link:
            svc.read_file({"path": escape_link})
        self.assertEqual(ctx_link.exception.status_code, 403)

        # 4. Secret files (.env, *.key, registry.db) are blocked, including inside recursive delete
        secret_dir = os.path.join(self.apps_root, "has-secret")
        os.makedirs(secret_dir, exist_ok=True)
        secret_env = os.path.join(secret_dir, ".env")
        Path(secret_env).write_text("SECRET=123\n", encoding="utf-8")
        with self.assertRaises(rb.BridgeRequestError) as ctx_read:
            svc.read_file({"path": secret_env})
        self.assertEqual(ctx_read.exception.status_code, 403)

        reg_db = os.path.join(self.apps_root, "registry.db")
        Path(reg_db).write_text("sqlite", encoding="utf-8")
        with self.assertRaises(rb.BridgeRequestError) as ctx_db:
            svc.read_file({"path": reg_db})
        self.assertEqual(ctx_db.exception.status_code, 403)

        with self.assertRaises(rb.BridgeRequestError) as ctx_rec:
            svc.delete_file({"path": secret_dir, "recursive": True})
        self.assertEqual(ctx_rec.exception.status_code, 403)

        with self.assertRaises(rb.BridgeRequestError) as ctx_write:
            svc.write_file({"path": os.path.join(self.apps_root, "server.key"), "content": "nope"})
        self.assertEqual(ctx_write.exception.status_code, 403)

        # 5. Protected system paths and allowlist roots cannot be deleted
        with self.assertRaises(rb.BridgeRequestError) as ctx_del:
            svc.delete_file({"path": "/", "recursive": True})
        self.assertEqual(ctx_del.exception.status_code, 403)
        with self.assertRaises(rb.BridgeRequestError) as ctx_root:
            svc.delete_file({"path": self.apps_root, "recursive": True})
        self.assertEqual(ctx_root.exception.status_code, 403)

        # 6. Protected vpsagent-runtime service cannot be stopped or disabled
        with self.assertRaises(rb.BridgeRequestError) as ctx_svc:
            svc.manage_service({"service": "vpsagent-runtime.service", "action": "stop"})
        self.assertEqual(ctx_svc.exception.status_code, 403)


if __name__ == "__main__":
    unittest.main()
