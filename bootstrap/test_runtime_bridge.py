#!/usr/bin/env python3
"""Unit tests for bootstrap/runtime-bridge.py (VPSAgent v2 Host Runtime Bridge)."""

from __future__ import annotations

import http.server
import importlib.util
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import time
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

        # 7. exec_in_app timeout stops the command INSIDE the container (delayed marker never appears)
        app_slug = "timeout-exec-app"
        app_dir = os.path.join(self.apps_root, app_slug)
        os.makedirs(app_dir, exist_ok=True)
        Path(os.path.join(app_dir, "docker-compose.yml")).write_text(
            (
                "services:\n"
                "  app:\n"
                "    image: alpine:3.20\n"
                f"    container_name: vpsagent-app-{app_slug}\n"
                "    cap_drop:\n"
                "      - ALL\n"
                "    security_opt:\n"
                "      - no-new-privileges:true\n"
                "    mem_limit: 256m\n"
                "    cpus: '0.5'\n"
                "    networks:\n"
                "      - app_net\n"
                "networks:\n"
                "  app_net:\n"
                "    driver: bridge\n"
            ),
            encoding="utf-8",
        )
        exec_docker_py = os.path.join(self.tmp, "exec_docker.py")
        Path(exec_docker_py).write_text(
            """import subprocess, sys
args = sys.argv[1:]
if "exec" in args:
    idx = args.index("exec")
    # Forward everything after `-T <service>` directly to local sh to simulate in-container exec
    inner = args[idx + 3:]
    proc = subprocess.run(inner)
    sys.exit(proc.returncode)
sys.exit(0)
""",
            encoding="utf-8",
        )
        exec_docker_sh = os.path.join(self.tmp, "exec-docker")
        Path(exec_docker_sh).write_text(
            f'#!/usr/bin/env sh\nexec "{sys.executable}" "{exec_docker_py}" "$@"\n',
            encoding="utf-8",
        )
        os.chmod(exec_docker_sh, 0o755)
        svc_exec = rb.RuntimeService(
            apps_root=self.apps_root,
            caddy_apps_dir=self.caddy_dir,
            caddy_container="vpsagent-caddy",
            docker_bin=exec_docker_sh,
            allow_unauthenticated=True,
            allowed_file_roots=[self.apps_root],
        )
        # 7a. Ordinary `exit 124` is NOT misreported as a timeout
        res_124 = svc_exec.exec_in_app(
            {"slug": app_slug, "command": "exit 124", "timeoutSeconds": 5}
        )
        self.assertEqual(res_124["exitCode"], 124)

        # 7b. exec_in_app timeout stops the ENTIRE command tree (parent + spawned child)
        parent_marker = os.path.join(self.apps_root, "parent-never.marker")
        child_marker = os.path.join(self.apps_root, "child-never.marker")
        with self.assertRaises(rb.BridgeRequestError) as ctx_exec_to:
            svc_exec.exec_in_app(
                {
                    "slug": app_slug,
                    "command": f"(sleep 2 && touch {child_marker}) & sleep 2 && touch {parent_marker}",
                    "timeoutSeconds": 1,
                }
            )
        self.assertEqual(ctx_exec_to.exception.status_code, 504)
        # Wait past both delayed sleeps and verify NEITHER parent nor child wrote its marker
        time.sleep(2.4)
        self.assertFalse(os.path.exists(parent_marker))
        self.assertFalse(os.path.exists(child_marker))

    def test_core_update_check_and_apply_and_dirty_guard(self) -> None:
        import subprocess

        remote_dir = os.path.join(self.tmp, "remote.git")
        work_dir = os.path.join(self.tmp, "upstream-work")
        clone_dir = os.path.join(self.tmp, "vpsagent-clone")
        vpsagent_root = os.path.join(self.tmp, "vpsagent-root")
        os.makedirs(os.path.join(vpsagent_root, "apps"), exist_ok=True)
        os.makedirs(os.path.join(vpsagent_root, "caddy", "apps.d"), exist_ok=True)
        os.makedirs(os.path.join(vpsagent_root, "run"), exist_ok=True)
        Path(os.path.join(vpsagent_root, ".env")).write_text(
            "VPSAGENT_RUNTIME_TOKEN=test-secret-token-value-123456\n",
            encoding="utf-8",
        )

        git_env = {
            **os.environ,
            "GIT_AUTHOR_NAME": "Test",
            "GIT_AUTHOR_EMAIL": "test@example.com",
            "GIT_COMMITTER_NAME": "Test",
            "GIT_COMMITTER_EMAIL": "test@example.com",
        }
        subprocess.run(["git", "init", "--bare", remote_dir], check=True, env=git_env)
        subprocess.run(["git", "clone", remote_dir, work_dir], check=True, env=git_env)
        subprocess.run(["git", "-C", work_dir, "checkout", "-b", "main"], check=True, env=git_env)
        os.makedirs(os.path.join(work_dir, "bootstrap", "caddy", "apps.d"), exist_ok=True)
        Path(os.path.join(work_dir, "package.json")).write_text(
            json.dumps({"name": "vpsagent", "version": "2.0.0-alpha.1"}),
            encoding="utf-8",
        )
        Path(os.path.join(work_dir, "bootstrap", "docker-compose.core.yml")).write_text(
            "services:\n  vpsagent-core:\n    image: vpsagent/core:local\n",
            encoding="utf-8",
        )
        Path(os.path.join(work_dir, "bootstrap", "Caddyfile")).write_text(
            "# v1\n", encoding="utf-8"
        )
        Path(os.path.join(work_dir, "bootstrap", "caddy", "apps.d", "00-default.caddy")).write_text(
            "# default\n", encoding="utf-8"
        )
        Path(os.path.join(work_dir, "bootstrap", "runtime-bridge.py")).write_text(
            "# bridge v1\n", encoding="utf-8"
        )
        subprocess.run(["git", "-C", work_dir, "add", "."], check=True, env=git_env)
        subprocess.run(["git", "-C", work_dir, "commit", "-m", "initial release"], check=True, env=git_env)
        subprocess.run(["git", "-C", work_dir, "push", "-u", "origin", "main"], check=True, env=git_env)
        subprocess.run(
            ["git", "--git-dir", remote_dir, "symbolic-ref", "HEAD", "refs/heads/main"],
            check=True,
            env=git_env,
        )

        # Clone initial revision as server's VPSAGENT_REPO_DIR
        subprocess.run(["git", "clone", "--branch", "main", remote_dir, clone_dir], check=True, env=git_env)
        Path(os.path.join(vpsagent_root, "runtime-bridge.py")).write_text(
            "# bridge v1\n", encoding="utf-8"
        )
        Path(os.path.join(vpsagent_root, "Caddyfile")).write_text(
            "# v1\n", encoding="utf-8"
        )
        Path(os.path.join(vpsagent_root, "docker-compose.yml")).write_text(
            "services:\n  vpsagent-core:\n    image: vpsagent/core:local\n",
            encoding="utf-8",
        )
        # Seed a live per-app route for slug "00-default" to ensure updates never overwrite it
        app_default_route = os.path.join(vpsagent_root, "caddy", "apps.d", "00-default.caddy")
        Path(app_default_route).write_text(
            "default.example.com {\n  reverse_proxy vpsagent-app-00-default:8080\n}\n",
            encoding="utf-8",
        )

        # Push a newer commit to remote (changing Caddyfile & docker-compose.core.yml too)
        Path(os.path.join(work_dir, "package.json")).write_text(
            json.dumps({"name": "vpsagent", "version": "2.0.0-alpha.2"}),
            encoding="utf-8",
        )
        Path(os.path.join(work_dir, "bootstrap", "Caddyfile")).write_text(
            "# v2\n", encoding="utf-8"
        )
        Path(os.path.join(work_dir, "bootstrap", "docker-compose.core.yml")).write_text(
            "services:\n  vpsagent-core:\n    image: vpsagent/core:v2\n",
            encoding="utf-8",
        )
        Path(os.path.join(work_dir, "bootstrap", "runtime-bridge.py")).write_text(
            "# bridge v2\n", encoding="utf-8"
        )
        subprocess.run(["git", "-C", work_dir, "add", "."], check=True, env=git_env)
        subprocess.run(
            ["git", "-C", work_dir, "commit", "-m", "feat: add self-update v2"],
            check=True,
            env=git_env,
        )
        subprocess.run(["git", "-C", work_dir, "push", "origin", "main"], check=True, env=git_env)

        docker_log = os.path.join(self.tmp, "docker-calls.log")
        docker_fail_flag = os.path.join(self.tmp, "docker-fail.flag")
        docker_dirty_edit_flag = os.path.join(self.tmp, "docker-dirty-edit.flag")
        docker_installed_cfg_edit_flag = os.path.join(self.tmp, "docker-installed-cfg-edit.flag")
        systemctl_log = os.path.join(self.tmp, "systemctl-calls.log")

        fake_docker_py = os.path.join(self.tmp, "update_fake_docker.py")
        Path(fake_docker_py).write_text(
            f"""import os, sys
with open({docker_log!r}, "a", encoding="utf-8") as fh:
    fh.write(" ".join(sys.argv[1:]) + "\\n")
if os.path.exists({docker_installed_cfg_edit_flag!r}):
    with open({os.path.join(vpsagent_root, "Caddyfile")!r}, "w", encoding="utf-8") as ef:
        ef.write("# owner live caddy edit\\n")
    sys.stderr.write("simulated build fail after live caddy edit\\n")
    sys.exit(1)
if os.path.exists({docker_dirty_edit_flag!r}):
    with open({os.path.join(clone_dir, "bootstrap", "Caddyfile")!r}, "w", encoding="utf-8") as ef:
        ef.write("# owner mid-build edit\\n")
    sys.stderr.write("simulated build fail after mid-build edit\\n")
    sys.exit(1)
if os.path.exists({docker_fail_flag!r}):
    sys.stderr.write("simulated docker build failure\\n")
    sys.exit(1)
print("Rebuilt vpsagent-core ok")
sys.exit(0)
""",
            encoding="utf-8",
        )
        fake_docker_sh = os.path.join(self.tmp, "update-fake-docker")
        Path(fake_docker_sh).write_text(
            f'#!/usr/bin/env sh\nexec "{sys.executable}" "{fake_docker_py}" "$@"\n',
            encoding="utf-8",
        )
        os.chmod(fake_docker_sh, 0o755)

        fake_sys_py = os.path.join(self.tmp, "update_fake_systemctl.py")
        Path(fake_sys_py).write_text(
            f"""import sys
with open({systemctl_log!r}, "a", encoding="utf-8") as fh:
    fh.write(" ".join(sys.argv[1:]) + "\\n")
if sys.argv[1:2] == ["is-active"]:
    print("active")
sys.exit(0)
""",
            encoding="utf-8",
        )
        fake_sys_sh = os.path.join(self.tmp, "update-fake-systemctl")
        Path(fake_sys_sh).write_text(
            f'#!/usr/bin/env sh\nexec "{sys.executable}" "{fake_sys_py}" "$@"\n',
            encoding="utf-8",
        )
        os.chmod(fake_sys_sh, 0o755)

        svc = rb.RuntimeService(
            apps_root=os.path.join(vpsagent_root, "apps"),
            caddy_apps_dir=os.path.join(vpsagent_root, "caddy", "apps.d"),
            caddy_container="vpsagent-caddy",
            docker_bin=fake_docker_sh,
            systemctl_bin=fake_sys_sh,
            vpsagent_root=vpsagent_root,
            repo_dir=clone_dir,
            allow_unauthenticated=True,
        )

        # 1. Check for updates sees 1 new commit
        checked = svc.core_update_status(check_remote=True)
        self.assertTrue(checked["canUpdate"])
        self.assertTrue(checked["updateAvailable"])
        self.assertEqual(checked["commitsBehind"], 1)
        self.assertEqual(checked["currentVersion"], "2.0.0-alpha.1")
        self.assertEqual(checked["latestCommitSubject"], "feat: add self-update v2")

        # 1b. Failed Docker build rolls back checkout AND restores installed Caddyfile & docker-compose.yml
        Path(docker_fail_flag).write_text("fail", encoding="utf-8")
        failed_start = svc.start_core_update({})
        self.assertTrue(failed_start["ok"])
        deadline = time.monotonic() + 10.0
        failed_status = failed_start["status"]
        while time.monotonic() < deadline:
            failed_status = svc.core_update_status(check_remote=False)
            if failed_status["state"] in ("succeeded", "failed"):
                break
            time.sleep(0.05)
        self.assertEqual(failed_status["state"], "failed")
        self.assertEqual(failed_status["currentVersion"], "2.0.0-alpha.1")
        self.assertEqual(
            Path(os.path.join(vpsagent_root, "Caddyfile")).read_text(encoding="utf-8"),
            "# v1\n",
        )
        self.assertIn(
            "vpsagent/core:local",
            Path(os.path.join(vpsagent_root, "docker-compose.yml")).read_text(encoding="utf-8"),
        )
        rechecked_after_fail = svc.core_update_status(check_remote=True)
        self.assertTrue(rechecked_after_fail["updateAvailable"])
        self.assertEqual(rechecked_after_fail["commitsBehind"], 1)
        os.unlink(docker_fail_flag)

        # 1c. If owner edits a tracked file mid-build and Docker fails, rollback must NOT discard their edit
        Path(docker_dirty_edit_flag).write_text("dirty", encoding="utf-8")
        dirty_fail_start = svc.start_core_update({})
        self.assertTrue(dirty_fail_start["ok"])
        deadline = time.monotonic() + 10.0
        dirty_fail_status = dirty_fail_start["status"]
        while time.monotonic() < deadline:
            dirty_fail_status = svc.core_update_status(check_remote=False)
            if dirty_fail_status["state"] in ("succeeded", "failed"):
                break
            time.sleep(0.05)
        self.assertEqual(dirty_fail_status["state"], "failed")
        self.assertEqual(
            Path(os.path.join(clone_dir, "bootstrap", "Caddyfile")).read_text(encoding="utf-8"),
            "# owner mid-build edit\n",
        )
        self.assertEqual(
            Path(os.path.join(vpsagent_root, "Caddyfile")).read_text(encoding="utf-8"),
            "# v1\n",
        )
        os.unlink(docker_dirty_edit_flag)
        # Clean up simulated owner edit and reset back to v1 before testing installed-config protection
        subprocess.run(["git", "-C", clone_dir, "reset", "--hard", "HEAD~1"], check=True, env=git_env)

        # 1d. If owner edits an installed config file (Caddyfile) mid-build and Docker fails, preserve that edit
        Path(docker_installed_cfg_edit_flag).write_text("cfg-edit", encoding="utf-8")
        cfg_edit_start = svc.start_core_update({})
        self.assertTrue(cfg_edit_start["ok"])
        deadline = time.monotonic() + 10.0
        cfg_edit_status = cfg_edit_start["status"]
        while time.monotonic() < deadline:
            cfg_edit_status = svc.core_update_status(check_remote=False)
            if cfg_edit_status["state"] in ("succeeded", "failed"):
                break
            time.sleep(0.05)
        self.assertEqual(cfg_edit_status["state"], "failed")
        self.assertEqual(
            Path(os.path.join(vpsagent_root, "Caddyfile")).read_text(encoding="utf-8"),
            "# owner live caddy edit\n",
        )
        # Unmodified docker-compose.yml was still restored to v1
        self.assertIn(
            "vpsagent/core:local",
            Path(os.path.join(vpsagent_root, "docker-compose.yml")).read_text(encoding="utf-8"),
        )
        self.assertTrue(
            any("Preserved Caddyfile" in line for line in cfg_edit_status["logs"]),
            cfg_edit_status["logs"],
        )
        os.unlink(docker_installed_cfg_edit_flag)
        Path(os.path.join(vpsagent_root, "Caddyfile")).write_text("# v1\n", encoding="utf-8")

        # 2. Apply update succeeds, preserves 00-default.caddy, and survives bridge restart recovery
        started = svc.start_core_update({})
        self.assertTrue(started["ok"])
        self.assertTrue(started["started"])

        deadline = time.monotonic() + 10.0
        final_status = started["status"]
        while time.monotonic() < deadline:
            final_status = svc.core_update_status(check_remote=False)
            if final_status["state"] in ("succeeded", "failed"):
                break
            time.sleep(0.05)

        self.assertEqual(final_status["state"], "succeeded", final_status)
        self.assertEqual(final_status["currentVersion"], "2.0.0-alpha.2")
        self.assertFalse(final_status["updateAvailable"])
        self.assertEqual(final_status["commitsBehind"], 0)
        docker_calls_text = Path(docker_log).read_text(encoding="utf-8")
        self.assertIn("up -d --build", docker_calls_text)
        self.assertIn("exec vpsagent-caddy caddy validate", docker_calls_text)
        self.assertIn("exec vpsagent-caddy caddy reload", docker_calls_text)
        self.assertEqual(
            Path(os.path.join(vpsagent_root, "runtime-bridge.py")).read_text(encoding="utf-8"),
            "# bridge v2\n",
        )
        # Live app route for slug "00-default" must be untouched!
        self.assertIn(
            "default.example.com",
            Path(app_default_route).read_text(encoding="utf-8"),
        )
        # Wait deterministically for the post-success --no-block systemctl restart
        sys_deadline = time.monotonic() + 5.0
        sys_log_text = ""
        while time.monotonic() < sys_deadline:
            if os.path.isfile(systemctl_log):
                sys_log_text = Path(systemctl_log).read_text(encoding="utf-8")
                if "restart --no-block vpsagent-runtime.service" in sys_log_text:
                    break
            time.sleep(0.05)
        self.assertIn(
            "restart --no-block vpsagent-runtime.service",
            sys_log_text,
        )

        # Simulate restarted bridge loading persisted update state cleanly
        restarted_svc = rb.RuntimeService(
            apps_root=os.path.join(vpsagent_root, "apps"),
            caddy_apps_dir=os.path.join(vpsagent_root, "caddy", "apps.d"),
            caddy_container="vpsagent-caddy",
            docker_bin=fake_docker_sh,
            systemctl_bin=fake_sys_sh,
            vpsagent_root=vpsagent_root,
            repo_dir=clone_dir,
            allow_unauthenticated=True,
        )
        recovered = restarted_svc.core_update_status(check_remote=False)
        self.assertEqual(recovered["state"], "succeeded")
        self.assertEqual(recovered["currentVersion"], "2.0.0-alpha.2")

        # 3. Diverged branch (local commit + upstream commit) is rejected cleanly instead of advertising unusable update
        Path(os.path.join(work_dir, "package.json")).write_text(
            json.dumps({"name": "vpsagent", "version": "2.0.0-alpha.3"}),
            encoding="utf-8",
        )
        subprocess.run(["git", "-C", work_dir, "add", "."], check=True, env=git_env)
        subprocess.run(
            ["git", "-C", work_dir, "commit", "-m", "upstream v3"],
            check=True,
            env=git_env,
        )
        subprocess.run(["git", "-C", work_dir, "push", "origin", "main"], check=True, env=git_env)

        Path(os.path.join(clone_dir, "local-note.txt")).write_text("local commit\n", encoding="utf-8")
        subprocess.run(["git", "-C", clone_dir, "add", "local-note.txt"], check=True, env=git_env)
        subprocess.run(
            ["git", "-C", clone_dir, "commit", "-m", "local diverged commit"],
            check=True,
            env=git_env,
        )
        diverged = restarted_svc.core_update_status(check_remote=True)
        self.assertFalse(diverged["canUpdate"])
        self.assertFalse(diverged["updateAvailable"])
        self.assertIn("diverged", (diverged["unavailableReason"] or "").lower())

        # 4. Dirty working tree blocks self-update safely
        Path(os.path.join(clone_dir, "package.json")).write_text(
            '{"name":"vpsagent","version":"dirty"}\n', encoding="utf-8"
        )
        dirty_status = restarted_svc.core_update_status(check_remote=False)
        self.assertFalse(dirty_status["canUpdate"])
        self.assertTrue(dirty_status["dirtyWorkingTree"])
        with self.assertRaises(rb.BridgeRequestError) as ctx_dirty:
            restarted_svc.start_core_update({})
        self.assertEqual(ctx_dirty.exception.status_code, 400)

    def test_run_repo_git_drops_privileges_for_user_owned_checkout(self) -> None:
        from types import SimpleNamespace
        from unittest import mock

        svc = rb.RuntimeService(
            apps_root=self.apps_root,
            caddy_apps_dir=self.caddy_dir,
            caddy_container="vpsagent-caddy",
            repo_dir=self.tmp,
            allow_unauthenticated=True,
        )
        fake_stat = SimpleNamespace(st_uid=1000, st_gid=1000)
        fake_pw = SimpleNamespace(pw_name="ubuntu", pw_dir="/home/ubuntu")
        fake_proc = SimpleNamespace(returncode=0, stdout="main\n", stderr="")

        with (
            mock.patch.object(rb.os, "geteuid", return_value=0),
            mock.patch.object(rb.os, "stat", return_value=fake_stat),
            mock.patch.object(rb.pwd, "getpwuid", return_value=fake_pw),
            mock.patch.object(rb.subprocess, "run", return_value=fake_proc) as run_mock,
        ):
            proc = svc._run_repo_git(self.tmp, ["rev-parse", "--abbrev-ref", "HEAD"])

        self.assertEqual(proc.returncode, 0)
        run_mock.assert_called_once()
        _, kwargs = run_mock.call_args
        self.assertEqual(kwargs["user"], 1000)
        self.assertEqual(kwargs["group"], 1000)
        self.assertEqual(kwargs["env"]["HOME"], "/home/ubuntu")
        self.assertEqual(kwargs["env"]["USER"], "ubuntu")
        self.assertEqual(kwargs["env"]["LOGNAME"], "ubuntu")
        self.assertEqual(kwargs["env"]["GIT_TERMINAL_PROMPT"], "0")

    def test_core_update_restores_config_when_write_fails_after_truncation(self) -> None:
        import builtins
        import subprocess
        from unittest import mock

        remote_dir = os.path.join(self.tmp, "wfail-remote.git")
        work_dir = os.path.join(self.tmp, "wfail-work")
        clone_dir = os.path.join(self.tmp, "wfail-clone")
        vpsagent_root = os.path.join(self.tmp, "wfail-root")
        os.makedirs(os.path.join(vpsagent_root, "apps"), exist_ok=True)
        os.makedirs(os.path.join(vpsagent_root, "caddy", "apps.d"), exist_ok=True)
        os.makedirs(os.path.join(vpsagent_root, "run"), exist_ok=True)
        Path(os.path.join(vpsagent_root, ".env")).write_text(
            "VPSAGENT_RUNTIME_TOKEN=test-secret-token-value-123456\n", encoding="utf-8"
        )
        caddy_dst = os.path.join(vpsagent_root, "Caddyfile")
        Path(caddy_dst).write_text("# original v1 caddyfile\n", encoding="utf-8")

        git_env = {
            **os.environ,
            "GIT_AUTHOR_NAME": "Test",
            "GIT_AUTHOR_EMAIL": "test@example.com",
            "GIT_COMMITTER_NAME": "Test",
            "GIT_COMMITTER_EMAIL": "test@example.com",
        }
        subprocess.run(["git", "init", "--bare", remote_dir], check=True, env=git_env)
        subprocess.run(["git", "clone", remote_dir, work_dir], check=True, env=git_env)
        subprocess.run(["git", "-C", work_dir, "checkout", "-b", "main"], check=True, env=git_env)
        os.makedirs(os.path.join(work_dir, "bootstrap"), exist_ok=True)
        Path(os.path.join(work_dir, "bootstrap", "Caddyfile")).write_text("# v1\n", encoding="utf-8")
        Path(os.path.join(work_dir, "bootstrap", "docker-compose.core.yml")).write_text("services: {}\n", encoding="utf-8")
        subprocess.run(["git", "-C", work_dir, "add", "."], check=True, env=git_env)
        subprocess.run(["git", "-C", work_dir, "commit", "-m", "v1"], check=True, env=git_env)
        subprocess.run(["git", "-C", work_dir, "push", "-u", "origin", "main"], check=True, env=git_env)
        subprocess.run(["git", "--git-dir", remote_dir, "symbolic-ref", "HEAD", "refs/heads/main"], check=True, env=git_env)
        subprocess.run(["git", "clone", "--branch", "main", remote_dir, clone_dir], check=True, env=git_env)

        Path(os.path.join(work_dir, "bootstrap", "Caddyfile")).write_text("# v2\n", encoding="utf-8")
        subprocess.run(["git", "-C", work_dir, "add", "."], check=True, env=git_env)
        subprocess.run(["git", "-C", work_dir, "commit", "-m", "v2"], check=True, env=git_env)
        subprocess.run(["git", "-C", work_dir, "push", "origin", "main"], check=True, env=git_env)

        svc = rb.RuntimeService(
            apps_root=os.path.join(vpsagent_root, "apps"),
            caddy_apps_dir=os.path.join(vpsagent_root, "caddy", "apps.d"),
            caddy_container="vpsagent-caddy",
            vpsagent_root=vpsagent_root,
            repo_dir=clone_dir,
            allow_unauthenticated=True,
        )

        real_open = builtins.open
        fail_once = {"triggered": False}

        class FailingWriter:
            def __init__(self, inner: object) -> None:
                self._inner = inner

            def __enter__(self) -> "FailingWriter":
                return self

            def __exit__(self, *args: object) -> None:
                self._inner.close()  # type: ignore[attr-defined]

            def write(self, _data: bytes) -> int:
                raise OSError("simulated disk full after truncation")

        def guarded_open(file: object, mode: str = "r", *args: object, **kwargs: object) -> object:
            fh = real_open(file, mode, *args, **kwargs)  # type: ignore[call-overload]
            if (
                not fail_once["triggered"]
                and mode == "wb"
                and os.path.abspath(str(file)) == os.path.abspath(caddy_dst)
            ):
                fail_once["triggered"] = True
                return FailingWriter(fh)
            return fh

        with mock.patch.object(builtins, "open", side_effect=guarded_open):
            svc._run_core_update_worker(clone_dir, "main")

        self.assertTrue(fail_once["triggered"])
        self.assertEqual(
            Path(caddy_dst).read_text(encoding="utf-8"),
            "# original v1 caddyfile\n",
        )
        self.assertEqual(svc.core_update_status(check_remote=False)["state"], "failed")

    def test_private_github_clone_auth_pinning_cleanup_and_redaction(self) -> None:
        import base64

        priv_dir = os.path.join(self.tmp, "private-git")
        os.makedirs(priv_dir, exist_ok=True)
        record_file = os.path.join(priv_dir, "git_seen.json")
        docker_seen_file = os.path.join(priv_dir, "docker_seen.json")

        token = "github_pat_11PRIVATETOKEN_99887766"
        expected_b64 = base64.b64encode(f"x-access-token:{token}".encode("utf-8")).decode("ascii")

        git_py = os.path.join(priv_dir, "fake_git.py")
        Path(git_py).write_text(
            f"""import json, os, stat, sys
args = sys.argv[1:]
if "clone" in args:
    cfg_path = os.environ.get("GIT_CONFIG_GLOBAL", "")
    cfg_text = ""
    cfg_mode = None
    if cfg_path and os.path.exists(cfg_path):
        cfg_mode = stat.S_IMODE(os.stat(cfg_path).st_mode)
        with open(cfg_path, "r", encoding="utf-8") as fh:
            cfg_text = fh.read()
    dst = args[-1]
    os.makedirs(dst, exist_ok=True)
    with open(os.path.join(dst, "Dockerfile"), "w", encoding="utf-8") as df:
        df.write("FROM alpine:3.20\\nEXPOSE 8080\\n")
    with open({record_file!r}, "w", encoding="utf-8") as out:
        json.dump({{
            "args": args,
            "cfgPath": cfg_path,
            "cfgInsideClone": bool(cfg_path and os.path.abspath(cfg_path).startswith(os.path.abspath(dst))),
            "cfgMode": cfg_mode,
            "cfgText": cfg_text,
            "envVals": list(os.environ.values()),
        }}, out)
    sys.exit(0)
if "rev-parse" in args:
    if "--abbrev-ref" in args:
        print("main")
    else:
        print("11223344556677889900aabbccddeeff00112233")
    sys.exit(0)
sys.exit(0)
""",
            encoding="utf-8",
        )
        git_sh = os.path.join(priv_dir, "fake-git")
        Path(git_sh).write_text(f'#!/usr/bin/env sh\nexec "{sys.executable}" "{git_py}" "$@"\n', encoding="utf-8")
        os.chmod(git_sh, 0o755)

        docker_py = os.path.join(priv_dir, "fake_docker.py")
        Path(docker_py).write_text(
            f"""import json, os, sys
args = sys.argv[1:]
if args[:1] == ["build"]:
    ctx_dir = args[-1]
    parent_dir = os.path.dirname(ctx_dir)
    auth_conf_exists = os.path.exists(os.path.join(parent_dir, "git-auth.conf"))
    with open({docker_seen_file!r}, "w", encoding="utf-8") as out:
        json.dump({{"authConfStillPresent": auth_conf_exists, "filesInCtx": os.listdir(ctx_dir)}}, out)
    print("Built private app image")
    sys.exit(0)
sys.exit(0)
""",
            encoding="utf-8",
        )
        docker_sh = os.path.join(priv_dir, "fake-docker")
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

        inspected = svc.inspect_git(
            {"gitRepoUrl": "https://github.com/acme/private-demo", "gitToken": token}
        )
        self.assertTrue(inspected["usedAuth"])
        self.assertEqual(inspected["detectedRuntime"], "dockerfile")
        seen = json.loads(Path(record_file).read_text(encoding="utf-8"))
        self.assertFalse(seen["cfgInsideClone"])
        self.assertEqual(seen["cfgMode"], 0o600)
        self.assertIn('[http "https://github.com/"]', seen["cfgText"])
        self.assertIn(f"Authorization: Basic {expected_b64}", seen["cfgText"])
        self.assertFalse(any(token in a for a in seen["args"]))
        self.assertFalse(any(token in v for v in seen["envVals"]))

        built = svc.build_git(
            {
                "slug": "priv-demo",
                "gitRepoUrl": "https://github.com/acme/private-demo",
                "gitToken": token,
            }
        )
        self.assertTrue(built["ok"])
        self.assertTrue(built["usedAuth"])
        docker_seen = json.loads(Path(docker_seen_file).read_text(encoding="utf-8"))
        self.assertFalse(docker_seen["authConfStillPresent"])
        self.assertNotIn("git-auth.conf", docker_seen["filesInCtx"])

        # Token cannot be sent to non-github.com hosts or non-443 ports
        for bad_url in (
            "https://gitlab.com/acme/private-demo",
            "https://github.com:8443/acme/private-demo",
        ):
            with self.assertRaises(rb.BridgeRequestError) as host_ctx:
                svc.inspect_git({"gitRepoUrl": bad_url, "gitToken": token})
            self.assertEqual(host_ctx.exception.status_code, 400)

        # Invalid token characters (newlines / quotes / spaces) rejected
        for bad_tok in ("bad token\n[http]", 'ghp_1234"quote', "short"):
            with self.assertRaises(rb.BridgeRequestError) as tok_ctx:
                svc.inspect_git(
                    {"gitRepoUrl": "https://github.com/acme/private-demo", "gitToken": bad_tok}
                )
            self.assertEqual(tok_ctx.exception.status_code, 400)

        # Git 401/403 errors return HTTP 401 and scrub both raw token and basic base64
        fail_git_py = os.path.join(priv_dir, "fail_git.py")
        Path(fail_git_py).write_text(
            f"""import sys
sys.stderr.write("remote: Repository not found. fatal: Authentication failed for token={token} basic={expected_b64}\\n")
sys.exit(128)
""",
            encoding="utf-8",
        )
        fail_git_sh = os.path.join(priv_dir, "fail-git")
        Path(fail_git_sh).write_text(f'#!/usr/bin/env sh\nexec "{sys.executable}" "{fail_git_py}" "$@"\n', encoding="utf-8")
        os.chmod(fail_git_sh, 0o755)
        svc_fail = rb.RuntimeService(
            apps_root=self.apps_root,
            caddy_apps_dir=self.caddy_dir,
            caddy_container="vpsagent-caddy",
            docker_bin=docker_sh,
            git_bin=fail_git_sh,
            runtime_token="secret-token-for-unit-test-1234",
            dns_resolver=lambda _host, _port: ["140.82.121.4"],
        )
        with self.assertRaises(rb.BridgeRequestError) as anon_ctx:
            svc_fail.inspect_git({"gitRepoUrl": "https://github.com/acme/private-demo"})
        self.assertEqual(anon_ctx.exception.status_code, 401)

        with self.assertRaises(rb.BridgeRequestError) as auth_ctx:
            svc_fail.inspect_git(
                {"gitRepoUrl": "https://github.com/acme/private-demo", "gitToken": token}
            )
        self.assertEqual(auth_ctx.exception.status_code, 401)
        self.assertNotIn(token, str(auth_ctx.exception))
        self.assertNotIn(expected_b64, str(auth_ctx.exception))

        # Docker build output also scrubs raw token and basic base64
        leak_docker_py = os.path.join(priv_dir, "leak_docker.py")
        Path(leak_docker_py).write_text(
            f"""import sys
print("Step 1: token={token}")
sys.stderr.write("ERROR basic={expected_b64}\\n")
sys.exit(1)
""",
            encoding="utf-8",
        )
        leak_docker_sh = os.path.join(priv_dir, "leak-docker")
        Path(leak_docker_sh).write_text(f'#!/usr/bin/env sh\nexec "{sys.executable}" "{leak_docker_py}" "$@"\n', encoding="utf-8")
        os.chmod(leak_docker_sh, 0o755)
        svc_leak = rb.RuntimeService(
            apps_root=self.apps_root,
            caddy_apps_dir=self.caddy_dir,
            caddy_container="vpsagent-caddy",
            docker_bin=leak_docker_sh,
            git_bin=git_sh,
            runtime_token="secret-token-for-unit-test-1234",
            dns_resolver=lambda _host, _port: ["140.82.121.4"],
        )
        with self.assertRaises(rb.BridgeRequestError) as leak_ctx:
            svc_leak.build_git(
                {
                    "slug": "priv-demo",
                    "gitRepoUrl": "https://github.com/acme/private-demo",
                    "gitToken": token,
                }
            )
        self.assertEqual(leak_ctx.exception.status_code, 502)
        joined = "\n".join([str(leak_ctx.exception), *leak_ctx.exception.build_log_tail])
        self.assertNotIn(token, joined)
        self.assertNotIn(expected_b64, joined)

    def test_real_git_sends_basic_auth_header_from_git_config_global(self) -> None:
        """
        Verify the real system `git` binary reads our GIT_CONFIG_GLOBAL file format
        and transmits the expected `Authorization: Basic ...` header over HTTP(S).
        """
        import base64
        import shutil
        import subprocess

        git_bin = shutil.which("git")
        if not git_bin:
            self.skipTest("git binary not available")

        token = "github_pat_11REALGIT_AUTH_TEST_9999"
        expected_b64 = base64.b64encode(f"x-access-token:{token}".encode("utf-8")).decode("ascii")
        captured: dict[str, str | None] = {"auth": None, "path": None}

        class _GitAuthHandler(http.server.BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                captured["auth"] = self.headers.get("Authorization")
                captured["path"] = self.path
                # Return 401 so git stops cleanly right after sending the request
                self.send_response(401)
                self.send_header("Content-Length", "0")
                self.end_headers()

            def log_message(self, format: str, *args: object) -> None:
                return

        srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _GitAuthHandler)
        port = srv.server_address[1]
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            cfg_path = os.path.join(self.tmp, "real-git-auth.conf")
            base_url = f"http://127.0.0.1:{port}/"
            fd = os.open(cfg_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            try:
                os.write(
                    fd,
                    (
                        f'[http "{base_url}"]\n'
                        f"\textraHeader = Authorization: Basic {expected_b64}\n"
                    ).encode("utf-8"),
                )
            finally:
                os.close(fd)

            env = {
                "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
                "HOME": self.tmp,
                "GIT_TERMINAL_PROMPT": "0",
                "GIT_CONFIG_NOSYSTEM": "1",
                "GIT_CONFIG_GLOBAL": cfg_path,
            }
            subprocess.run(
                [git_bin, "ls-remote", f"{base_url}acme/private-demo.git"],
                env=env,
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
            self.assertEqual(captured["auth"], f"Basic {expected_b64}")
            self.assertIn("/acme/private-demo.git/info/refs", captured["path"] or "")
        finally:
            srv.shutdown()
            srv.server_close()

    def test_static_build_strips_git_dir_and_blocks_dotfiles(self) -> None:
        """
        Static auto-detected deployments must strip `.git`, create a protective `.dockerignore`
        excluding dotfiles/repo metadata, and configure Nginx to deny dotfile requests.
        """
        static_dir = os.path.join(self.tmp, "static-sec-test")
        os.makedirs(static_dir, exist_ok=True)
        docker_seen_file = os.path.join(static_dir, "docker_seen.json")

        git_py = os.path.join(static_dir, "fake_static_git.py")
        Path(git_py).write_text(
            """import os, sys
args = sys.argv[1:]
if "clone" in args:
    dst = args[-1]
    os.makedirs(os.path.join(dst, ".git"), exist_ok=True)
    with open(os.path.join(dst, ".git", "config"), "w", encoding="utf-8") as fh:
        fh.write("[core]\\n")
    with open(os.path.join(dst, "index.html"), "w", encoding="utf-8") as fh:
        fh.write("<h1>Hello</h1>\\n")
    with open(os.path.join(dst, ".env"), "w", encoding="utf-8") as fh:
        fh.write("SECRET=should-not-ship\\n")
    with open(os.path.join(dst, "README.md"), "w", encoding="utf-8") as fh:
        fh.write("# Private Repo Notes\\n")
    sys.exit(0)
if "rev-parse" in args:
    print("main" if "--abbrev-ref" in args else "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
    sys.exit(0)
sys.exit(0)
""",
            encoding="utf-8",
        )
        git_sh = os.path.join(static_dir, "fake-static-git")
        Path(git_sh).write_text(f'#!/usr/bin/env sh\nexec "{sys.executable}" "{git_py}" "$@"\n', encoding="utf-8")
        os.chmod(git_sh, 0o755)

        docker_py = os.path.join(static_dir, "fake_static_docker.py")
        Path(docker_py).write_text(
            f"""import json, os, sys
args = sys.argv[1:]
if args[:1] == ["build"]:
    ctx_dir = args[-1]
    df_path = args[args.index("-f") + 1]
    dockerignore_path = os.path.join(ctx_dir, ".dockerignore")
    with open({docker_seen_file!r}, "w", encoding="utf-8") as out:
        json.dump({{
            "hasGitDir": os.path.exists(os.path.join(ctx_dir, ".git")),
            "dockerignore": open(dockerignore_path, "r", encoding="utf-8").read() if os.path.exists(dockerignore_path) else "",
            "dockerfile": open(df_path, "r", encoding="utf-8").read(),
        }}, out)
    sys.exit(0)
sys.exit(0)
""",
            encoding="utf-8",
        )
        docker_sh = os.path.join(static_dir, "fake-static-docker")
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

        built = svc.build_git(
            {
                "slug": "static-private",
                "gitRepoUrl": "https://github.com/acme/static-site",
                "gitToken": "github_pat_11STATIC_TEST_TOKEN_1234",
            }
        )
        self.assertTrue(built["ok"])
        self.assertEqual(built["detectedRuntime"], "static")
        seen = json.loads(Path(docker_seen_file).read_text(encoding="utf-8"))
        self.assertFalse(seen["hasGitDir"])
        self.assertIn(".git", seen["dockerignore"])
        self.assertIn(".*", seen["dockerignore"])
        self.assertIn("**/.*", seen["dockerignore"])
        self.assertIn("**/.*/**", seen["dockerignore"])
        self.assertIn("!.well-known", seen["dockerignore"])
        self.assertIn("!.well-known/**", seen["dockerignore"])
        self.assertIn(".well-known/.*", seen["dockerignore"])
        self.assertIn(".well-known/**/.*", seen["dockerignore"])
        self.assertIn("README*", seen["dockerignore"])

        # Execute the generated Dockerfile's `printf` command to render the real nginx config
        # and verify its dotfile location regex against root /.well-known vs nested/hidden paths.
        run_lines = [
            line[len("RUN ") :].strip()
            for line in seen["dockerfile"].splitlines()
            if line.startswith("RUN printf ")
        ]
        self.assertEqual(len(run_lines), 1)
        printf_cmd = run_lines[0].split(" > ", 1)[0]
        rendered_conf = subprocess.run(
            ["/bin/sh", "-c", printf_cmd],
            check=True,
            capture_output=True,
            text=True,
        ).stdout
        m = re.search(r"location\s+~\s+(\S+)\s+\{", rendered_conf)
        self.assertIsNotNone(m, f"Expected location regex in rendered nginx config: {rendered_conf!r}")
        deny_re = re.compile(m.group(1))
        for allowed_path in (
            "/index.html",
            "/assets/v1.2/app.js",
            "/.well-known/assetlinks.json",
            "/.well-known/apple-app-site-association",
            "/.well-known/acme-challenge/token123",
        ):
            self.assertIsNone(deny_re.search(allowed_path), f"Should allow {allowed_path}")
        for blocked_path in (
            "/.git/HEAD",
            "/.env",
            "/sub/.env",
            "/nested/.well-known/secret.txt",
            "/a/b/.well-known/assetlinks.json",
            "/.well-known/.env",
            "/.well-known/sub/.hidden",
            "/.well-known-fake/file.txt",
        ):
            self.assertIsNotNone(deny_re.search(blocked_path), f"Should block {blocked_path}")

        # Custom static Dockerfile that does NOT use git must still strip `.git` to prevent leaks
        static_df_git_py = os.path.join(static_dir, "fake_static_df_git.py")
        Path(static_df_git_py).write_text(
            """import os, sys
args = sys.argv[1:]
if "clone" in args:
    dst = args[-1]
    os.makedirs(os.path.join(dst, ".git"), exist_ok=True)
    with open(os.path.join(dst, ".git", "HEAD"), "w", encoding="utf-8") as fh:
        fh.write("ref: refs/heads/main\\n")
    with open(os.path.join(dst, "Dockerfile"), "w", encoding="utf-8") as fh:
        fh.write("FROM nginx:alpine\\nCOPY . /usr/share/nginx/html\\nEXPOSE 80\\n")
    sys.exit(0)
if "rev-parse" in args:
    print("main" if "--abbrev-ref" in args else "cccccccccccccccccccccccccccccccccccccccc")
    sys.exit(0)
sys.exit(0)
""",
            encoding="utf-8",
        )
        static_df_git_sh = os.path.join(static_dir, "fake-static-df-git")
        Path(static_df_git_sh).write_text(
            f'#!/usr/bin/env sh\nexec "{sys.executable}" "{static_df_git_py}" "$@"\n',
            encoding="utf-8",
        )
        os.chmod(static_df_git_sh, 0o755)
        svc_static_df = rb.RuntimeService(
            apps_root=self.apps_root,
            caddy_apps_dir=self.caddy_dir,
            caddy_container="vpsagent-caddy",
            docker_bin=docker_sh,
            git_bin=static_df_git_sh,
            runtime_token="secret-token-for-unit-test-1234",
            dns_resolver=lambda _host, _port: ["140.82.121.4"],
        )
        built_static_df = svc_static_df.build_git(
            {
                "slug": "custom-static-df",
                "gitRepoUrl": "https://github.com/acme/custom-static",
                "gitToken": "github_pat_11STATIC_TEST_TOKEN_1234",
            }
        )
        self.assertTrue(built_static_df["ok"])
        self.assertFalse(built_static_df["usedAutoDockerfile"])
        seen_static_df = json.loads(Path(docker_seen_file).read_text(encoding="utf-8"))
        self.assertFalse(seen_static_df["hasGitDir"])

        # Repository-supplied Dockerfile that explicitly copies .git / invokes git preserves `.git`
        df_git_py = os.path.join(static_dir, "fake_df_git.py")
        Path(df_git_py).write_text(
            """import os, sys
args = sys.argv[1:]
if "clone" in args:
    dst = args[-1]
    os.makedirs(os.path.join(dst, ".git"), exist_ok=True)
    with open(os.path.join(dst, ".git", "HEAD"), "w", encoding="utf-8") as fh:
        fh.write("ref: refs/heads/main\\n")
    with open(os.path.join(dst, "Dockerfile"), "w", encoding="utf-8") as fh:
        fh.write("FROM alpine:3.20\\nCOPY .git /tmp/.git\\nRUN git rev-parse --short HEAD > /version.txt\\nEXPOSE 8080\\n")
    sys.exit(0)
if "rev-parse" in args:
    print("main" if "--abbrev-ref" in args else "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
    sys.exit(0)
sys.exit(0)
""",
            encoding="utf-8",
        )
        df_git_sh = os.path.join(static_dir, "fake-df-git")
        Path(df_git_sh).write_text(f'#!/usr/bin/env sh\nexec "{sys.executable}" "{df_git_py}" "$@"\n', encoding="utf-8")
        os.chmod(df_git_sh, 0o755)
        svc_df = rb.RuntimeService(
            apps_root=self.apps_root,
            caddy_apps_dir=self.caddy_dir,
            caddy_container="vpsagent-caddy",
            docker_bin=docker_sh,
            git_bin=df_git_sh,
            runtime_token="secret-token-for-unit-test-1234",
            dns_resolver=lambda _host, _port: ["140.82.121.4"],
        )
        built_df = svc_df.build_git(
            {
                "slug": "custom-df-version",
                "gitRepoUrl": "https://github.com/acme/versioned-app",
                "gitToken": "github_pat_11STATIC_TEST_TOKEN_1234",
            }
        )
        self.assertTrue(built_df["ok"])
        self.assertFalse(built_df["usedAutoDockerfile"])
        seen_df = json.loads(Path(docker_seen_file).read_text(encoding="utf-8"))
        self.assertTrue(seen_df["hasGitDir"])

    def test_release_semver_checksum_and_safe_tarball_helpers(self) -> None:
        import io
        import tarfile

        # SemVer ordering & prerelease rules
        self.assertEqual(rb.compare_versions("2.0.0-alpha.1", "v2.0.0-alpha.2"), -1)
        self.assertEqual(rb.compare_versions("2.0.0-alpha.2", "v2.0.0-alpha.10"), -1)
        self.assertEqual(rb.compare_versions("2.0.0-alpha.1", "v2.0.0"), -1)
        self.assertEqual(rb.compare_versions("v2.1.0", "2.1.0+build123"), 0)
        self.assertTrue(rb.is_release_newer("2.0.0-alpha.1", "v2.0.0"))
        self.assertTrue(rb.is_release_newer("2.0.0-alpha.1", "v2.0.0-alpha.2"))
        self.assertFalse(rb.is_release_newer("2.1.0", "v2.0.9"))
        self.assertFalse(
            rb.is_release_newer("2.1.0", "v2.1.0", current_release_tag="v2.1.0")
        )

        # Checksum parsing across GNU, BSD, and bare hash modes
        digest = "a" * 64
        self.assertEqual(
            rb.parse_sha256_checksum(
                f"{digest}  ./vpsagent-v2.1.0.tar.gz\n", "vpsagent-v2.1.0.tar.gz"
            ),
            digest,
        )
        self.assertEqual(
            rb.parse_sha256_checksum(
                f"SHA256 (vpsagent-v2.1.0.tar.gz) = {digest.upper()}\n",
                "vpsagent-v2.1.0.tar.gz",
            ),
            digest,
        )
        self.assertIsNone(
            rb.parse_sha256_checksum(digest, "vpsagent-v2.1.0.tar.gz", allow_bare_hash=False)
        )
        self.assertEqual(
            rb.parse_sha256_checksum(digest, "vpsagent-v2.1.0.tar.gz", allow_bare_hash=True),
            digest,
        )
        self.assertIsNone(
            rb.parse_sha256_checksum(f"{digest}  other-file.tar.gz\n", "vpsagent-v2.1.0.tar.gz")
        )

        def _make_tar_bytes(entries: list[tuple[str, bytes, str]]) -> bytes:
            buf = io.BytesIO()
            with tarfile.open(fileobj=buf, mode="w:gz") as tf:
                for name, data, kind in entries:
                    ti = tarfile.TarInfo(name=name)
                    if kind == "sym":
                        ti.type = tarfile.SYMTYPE
                        ti.linkname = "/etc/passwd"
                        tf.addfile(ti)
                    elif kind == "hard":
                        ti.type = tarfile.LNKTYPE
                        ti.linkname = "package.json"
                        tf.addfile(ti)
                    else:
                        ti.size = len(data)
                        ti.mode = 0o755 if name.endswith(".sh") else 0o644
                        tf.addfile(ti, io.BytesIO(data))
            return buf.getvalue()

        # Reject path traversal
        traversal_tar = os.path.join(self.tmp, "traversal.tar.gz")
        Path(traversal_tar).write_bytes(
            _make_tar_bytes([("vpsagent-v2.1.0/../../evil", b"x", "file")])
        )
        with self.assertRaises(RuntimeError):
            rb.safe_extract_release_tarball(traversal_tar, os.path.join(self.tmp, "ext1"))

        # Reject symlinks
        symlink_tar = os.path.join(self.tmp, "symlink.tar.gz")
        Path(symlink_tar).write_bytes(
            _make_tar_bytes([("vpsagent-v2.1.0/leak", b"", "sym")])
        )
        with self.assertRaises(RuntimeError):
            rb.safe_extract_release_tarball(symlink_tar, os.path.join(self.tmp, "ext2"))

        # Reject hardlinks
        hardlink_tar = os.path.join(self.tmp, "hardlink.tar.gz")
        Path(hardlink_tar).write_bytes(
            _make_tar_bytes([("vpsagent-v2.1.0/link", b"", "hard")])
        )
        with self.assertRaises(RuntimeError):
            rb.safe_extract_release_tarball(hardlink_tar, os.path.join(self.tmp, "ext3"))

        # Reject incomplete archive missing bootstrap files
        incomplete_tar = os.path.join(self.tmp, "incomplete.tar.gz")
        Path(incomplete_tar).write_bytes(
            _make_tar_bytes(
                [("vpsagent-v2.1.0/package.json", b'{"name":"vpsagent","version":"2.1.0"}', "file")]
            )
        )
        with self.assertRaises(RuntimeError):
            rb.safe_extract_release_tarball(incomplete_tar, os.path.join(self.tmp, "ext4"))

        # Valid archive strips top-level directory cleanly
        good_tar = os.path.join(self.tmp, "good.tar.gz")
        Path(good_tar).write_bytes(
            _make_tar_bytes(
                [
                    ("vpsagent-v2.1.0/package.json", b'{"name":"vpsagent","version":"2.1.0"}', "file"),
                    ("vpsagent-v2.1.0/bootstrap/Dockerfile", b"FROM node:24-alpine\n", "file"),
                    ("vpsagent-v2.1.0/bootstrap/docker-compose.core.yml", b"services: {}\n", "file"),
                    ("vpsagent-v2.1.0/bootstrap/Caddyfile", b"# caddy\n", "file"),
                    ("vpsagent-v2.1.0/bootstrap/runtime-bridge.py", b"# bridge\n", "file"),
                ]
            )
        )
        out_dir = os.path.join(self.tmp, "ext-good")
        info = rb.safe_extract_release_tarball(good_tar, out_dir)
        self.assertEqual(info["version"], "2.1.0")
        self.assertTrue(os.path.isfile(os.path.join(out_dir, "bootstrap", "runtime-bridge.py")))

    def test_github_release_check_verify_apply_fallback_and_cli(self) -> None:
        import hashlib
        import io
        import subprocess
        import tarfile

        def _build_release_archive(version: str, marker: str) -> tuple[bytes, str]:
            buf = io.BytesIO()
            prefix = f"vpsagent-v{version}"
            files = {
                f"{prefix}/package.json": json.dumps(
                    {"name": "vpsagent", "version": version}
                ).encode("utf-8"),
                f"{prefix}/bootstrap/Dockerfile": b"FROM node:24-alpine\n",
                f"{prefix}/bootstrap/docker-compose.core.yml": (
                    f"services:\n  vpsagent-core:\n    image: vpsagent/core:{version}\n"
                ).encode("utf-8"),
                f"{prefix}/bootstrap/Caddyfile": f"# caddy {version}\n".encode("utf-8"),
                f"{prefix}/bootstrap/runtime-bridge.py": f"# {marker}\n".encode("utf-8"),
            }
            with tarfile.open(fileobj=buf, mode="w:gz") as tf:
                for name, content in files.items():
                    ti = tarfile.TarInfo(name=name)
                    ti.size = len(content)
                    ti.mode = 0o644
                    tf.addfile(ti, io.BytesIO(content))
            raw = buf.getvalue()
            return raw, hashlib.sha256(raw).hexdigest()

        tar_v210, sha_v210 = _build_release_archive("2.1.0", "bridge-release-2.1.0")
        tar_pre, sha_pre = _build_release_archive("2.0.0-alpha.2", "bridge-pre-2.0.0a2")

        mock_state: dict[str, object] = {
            "mode": "release_v210",
            "tamper_checksum": False,
            "api_auth_seen": [],
            "cdn_auth_seen": [],
        }

        class MockGitHubServer(http.server.BaseHTTPRequestHandler):
            def log_message(self, *_args: object) -> None:
                return

            def do_GET(self) -> None:
                mode = str(mock_state["mode"])
                if self.path.startswith("/repos/"):
                    cast_list = mock_state["api_auth_seen"]
                    assert isinstance(cast_list, list)
                    cast_list.append(self.headers.get("Authorization"))
                    if mode == "no_releases":
                        self.send_response(404)
                        self.end_headers()
                        self.wfile.write(b'{"message":"Not Found"}')
                        return
                    if mode == "prerelease_only":
                        if self.path.endswith("/releases/latest"):
                            self.send_response(404)
                            self.end_headers()
                            self.wfile.write(b'{"message":"Not Found"}')
                            return
                        payload = [
                            {
                                "tag_name": "v2.0.0-alpha.2",
                                "name": "VPSAgent v2.0.0-alpha.2",
                                "html_url": "https://github.com/VPSAgent/vpsagent/releases/tag/v2.0.0-alpha.2",
                                "body": "Preview bug fixes",
                                "published_at": "2026-11-26T12:00:00Z",
                                "prerelease": True,
                                "draft": False,
                                "assets": [
                                    {
                                        "name": "vpsagent-v2.0.0-alpha.2.tar.gz",
                                        "browser_download_url": f"http://127.0.0.1:{cdn_port}/dl/vpsagent-v2.0.0-alpha.2.tar.gz",
                                    },
                                    {
                                        "name": "SHA256SUMS",
                                        "browser_download_url": f"http://127.0.0.1:{cdn_port}/dl/SHA256SUMS-pre",
                                    },
                                ],
                            }
                        ]
                        raw = json.dumps(payload).encode("utf-8")
                        self.send_response(200)
                        self.send_header("Content-Type", "application/json")
                        self.send_header("Content-Length", str(len(raw)))
                        self.end_headers()
                        self.wfile.write(raw)
                        return

                    if self.path.endswith("/releases/latest"):
                        rel = {
                            "tag_name": "v2.1.0",
                            "name": "VPSAgent v2.1.0",
                            "html_url": "https://github.com/VPSAgent/vpsagent/releases/tag/v2.1.0",
                            "body": "Adds one-click release updates.",
                            "published_at": "2026-11-26T12:00:00Z",
                            "prerelease": False,
                            "draft": False,
                            "assets": [
                                {
                                    "name": "vpsagent-v2.1.0.tar.gz",
                                    "browser_download_url": f"http://127.0.0.1:{api_port}/redirect/v210",
                                },
                                {
                                    "name": "SHA256SUMS",
                                    "browser_download_url": f"http://127.0.0.1:{cdn_port}/dl/SHA256SUMS",
                                },
                            ],
                        }
                        raw = json.dumps(rel).encode("utf-8")
                        self.send_response(200)
                        self.send_header("Content-Type", "application/json")
                        self.send_header("Content-Length", str(len(raw)))
                        self.end_headers()
                        self.wfile.write(raw)
                        return

                if self.path == "/redirect/v210":
                    self.send_response(302)
                    self.send_header(
                        "Location", f"http://127.0.0.1:{cdn_port}/dl/vpsagent-v2.1.0.tar.gz"
                    )
                    self.end_headers()
                    return
                if self.path == "/redirect/bad-host":
                    self.send_response(302)
                    self.send_header("Location", "https://evil.example.com/archive.tar.gz")
                    self.end_headers()
                    return

                self.send_response(404)
                self.end_headers()

        class MockCdnServer(http.server.BaseHTTPRequestHandler):
            def log_message(self, *_args: object) -> None:
                return

            def do_GET(self) -> None:
                cast_list = mock_state["cdn_auth_seen"]
                assert isinstance(cast_list, list)
                cast_list.append(self.headers.get("Authorization"))
                if self.path == "/dl/vpsagent-v2.1.0.tar.gz":
                    self.send_response(200)
                    self.send_header("Content-Length", str(len(tar_v210)))
                    self.end_headers()
                    self.wfile.write(tar_v210)
                    return
                if self.path == "/dl/vpsagent-v2.0.0-alpha.2.tar.gz":
                    self.send_response(200)
                    self.send_header("Content-Length", str(len(tar_pre)))
                    self.end_headers()
                    self.wfile.write(tar_pre)
                    return
                if self.path == "/dl/SHA256SUMS":
                    digest = ("f" * 64) if mock_state["tamper_checksum"] else sha_v210
                    body = f"{digest}  vpsagent-v2.1.0.tar.gz\n".encode("utf-8")
                    self.send_response(200)
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                    return
                if self.path == "/dl/SHA256SUMS-pre":
                    body = f"{sha_pre}  vpsagent-v2.0.0-alpha.2.tar.gz\n".encode("utf-8")
                    self.send_response(200)
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                    return
                self.send_response(404)
                self.end_headers()

        api_srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), MockGitHubServer)
        cdn_srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), MockCdnServer)
        api_port = int(api_srv.server_address[1])
        cdn_port = int(cdn_srv.server_address[1])
        threading.Thread(target=api_srv.serve_forever, daemon=True).start()
        threading.Thread(target=cdn_srv.serve_forever, daemon=True).start()

        try:
            vpsagent_root = os.path.join(self.tmp, "rel-vpsagent-root")
            current_repo = os.path.join(self.tmp, "rel-git-checkout")
            remote_dir = os.path.join(self.tmp, "rel-remote.git")
            work_dir = os.path.join(self.tmp, "rel-work")
            os.makedirs(os.path.join(vpsagent_root, "apps"), exist_ok=True)
            os.makedirs(os.path.join(vpsagent_root, "caddy", "apps.d"), exist_ok=True)
            os.makedirs(os.path.join(vpsagent_root, "run"), exist_ok=True)
            env_file = os.path.join(vpsagent_root, ".env")
            initial_env = (
                f"VPSAGENT_REPO_DIR={current_repo}\n"
                "VPSAGENT_RUNTIME_TOKEN=test-secret-token-value-123456\n"
                "VPSAGENT_SESSION_SECRET=keep-session-secret-intact\n"
                "VPSAGENT_ENCRYPTION_SECRET=keep-encryption-secret-intact\n"
            )
            Path(env_file).write_text(initial_env, encoding="utf-8")
            os.chmod(env_file, 0o600)
            Path(os.path.join(vpsagent_root, "Caddyfile")).write_text("# v1\n", encoding="utf-8")
            Path(os.path.join(vpsagent_root, "docker-compose.yml")).write_text(
                "services:\n  vpsagent-core:\n    image: vpsagent/core:local\n",
                encoding="utf-8",
            )
            app_default_route = os.path.join(vpsagent_root, "caddy", "apps.d", "00-default.caddy")
            Path(app_default_route).write_text(
                "app.example.com {\n  reverse_proxy vpsagent-app-00-default:8080\n}\n",
                encoding="utf-8",
            )

            git_env = {
                **os.environ,
                "GIT_AUTHOR_NAME": "Test",
                "GIT_AUTHOR_EMAIL": "test@example.com",
                "GIT_COMMITTER_NAME": "Test",
                "GIT_COMMITTER_EMAIL": "test@example.com",
            }
            subprocess.run(["git", "init", "--bare", remote_dir], check=True, env=git_env)
            subprocess.run(["git", "clone", remote_dir, work_dir], check=True, env=git_env)
            subprocess.run(["git", "-C", work_dir, "checkout", "-b", "main"], check=True, env=git_env)
            os.makedirs(os.path.join(work_dir, "bootstrap"), exist_ok=True)
            Path(os.path.join(work_dir, "package.json")).write_text(
                json.dumps({"name": "vpsagent", "version": "2.0.0-alpha.1"}),
                encoding="utf-8",
            )
            Path(os.path.join(work_dir, "bootstrap", "Caddyfile")).write_text("# v1\n", encoding="utf-8")
            Path(os.path.join(work_dir, "bootstrap", "docker-compose.core.yml")).write_text(
                "services:\n  vpsagent-core:\n    image: vpsagent/core:local\n",
                encoding="utf-8",
            )
            Path(os.path.join(work_dir, "bootstrap", "runtime-bridge.py")).write_text(
                "# bridge v1\n", encoding="utf-8"
            )
            subprocess.run(["git", "-C", work_dir, "add", "."], check=True, env=git_env)
            subprocess.run(["git", "-C", work_dir, "commit", "-m", "v1"], check=True, env=git_env)
            subprocess.run(["git", "-C", work_dir, "push", "-u", "origin", "main"], check=True, env=git_env)
            subprocess.run(
                ["git", "--git-dir", remote_dir, "symbolic-ref", "HEAD", "refs/heads/main"],
                check=True,
                env=git_env,
            )
            subprocess.run(["git", "clone", "--branch", "main", remote_dir, current_repo], check=True, env=git_env)

            docker_fail_flag = os.path.join(self.tmp, "rel-docker-fail.flag")
            docker_call_log = os.path.join(self.tmp, "rel-docker-calls.log")
            docker_py = os.path.join(self.tmp, "rel_fake_docker.py")
            Path(docker_py).write_text(
                f"""import os, sys
with open({docker_call_log!r}, "a", encoding="utf-8") as fh:
    fh.write(" ".join(sys.argv[1:]) + "\\n")
if os.path.exists({docker_fail_flag!r}):
    sys.stderr.write("simulated release docker fail\\n")
    sys.exit(1)
print("Release container rebuilt")
sys.exit(0)
""",
                encoding="utf-8",
            )
            docker_sh = os.path.join(self.tmp, "rel-fake-docker")
            Path(docker_sh).write_text(
                f'#!/usr/bin/env sh\nexec "{sys.executable}" "{docker_py}" "$@"\n',
                encoding="utf-8",
            )
            os.chmod(docker_sh, 0o755)

            systemctl_log = os.path.join(self.tmp, "rel-systemctl.log")
            sys_py = os.path.join(self.tmp, "rel_fake_sys.py")
            Path(sys_py).write_text(
                f"""import sys
with open({systemctl_log!r}, "a", encoding="utf-8") as fh:
    fh.write(" ".join(sys.argv[1:]) + "\\n")
if sys.argv[1:2] == ["is-active"]:
    print("active")
sys.exit(0)
""",
                encoding="utf-8",
            )
            sys_sh = os.path.join(self.tmp, "rel-fake-sys")
            Path(sys_sh).write_text(
                f'#!/usr/bin/env sh\nexec "{sys.executable}" "{sys_py}" "$@"\n',
                encoding="utf-8",
            )
            os.chmod(sys_sh, 0o755)

            svc = rb.RuntimeService(
                apps_root=os.path.join(vpsagent_root, "apps"),
                caddy_apps_dir=os.path.join(vpsagent_root, "caddy", "apps.d"),
                caddy_container="vpsagent-caddy",
                docker_bin=docker_sh,
                systemctl_bin=sys_sh,
                vpsagent_root=vpsagent_root,
                repo_dir=current_repo,
                release_repo="VPSAgent/vpsagent",
                release_api_base=f"http://127.0.0.1:{api_port}",
                release_github_token="ghp_test_release_token_12345678",
                allow_unauthenticated=True,
            )

            # 1. Check finds v2.1.0 release and strips token on redirected CDN
            checked = svc.core_update_status(check_remote=True)
            self.assertEqual(checked["updateSource"], "release")
            self.assertEqual(checked["releaseStatus"], "available")
            self.assertTrue(checked["updateAvailable"])
            self.assertTrue(checked["canUpdate"])
            self.assertEqual(checked["latestReleaseTag"], "v2.1.0")
            self.assertEqual(checked["latestVersion"], "2.1.0")
            self.assertTrue(checked["checksumAvailable"])
            self.assertEqual(checked["checksumStatus"], "available")

            # 2. Tampered SHA256SUMS aborts cleanly before extracting or editing .env/Caddyfile
            mock_state["tamper_checksum"] = True
            bad_cs_start = svc.start_core_update({"source": "release"})
            self.assertTrue(bad_cs_start["ok"])
            deadline = time.monotonic() + 10.0
            bad_cs_status = bad_cs_start["status"]
            while time.monotonic() < deadline:
                bad_cs_status = svc.core_update_status(check_remote=False)
                if bad_cs_status["state"] in ("succeeded", "failed"):
                    break
                time.sleep(0.05)
            self.assertEqual(bad_cs_status["state"], "failed")
            self.assertEqual(bad_cs_status["checksumStatus"], "failed")
            self.assertIn("checksum", (bad_cs_status["error"] or "").lower())
            self.assertEqual(Path(env_file).read_text(encoding="utf-8"), initial_env)
            self.assertEqual(
                Path(os.path.join(vpsagent_root, "Caddyfile")).read_text(encoding="utf-8"),
                "# v1\n",
            )
            # Confirm Authorization header was sent to API host and NEVER sent to redirected CDN host
            self.assertTrue(
                any(v == "Bearer ghp_test_release_token_12345678" for v in mock_state["api_auth_seen"])  # type: ignore[arg-type]
            )
            self.assertTrue(all(v is None for v in mock_state["cdn_auth_seen"]))  # type: ignore[arg-type]
            mock_state["tamper_checksum"] = False

            # Redirect safety: disallowed non-GitHub redirect host is blocked even in loopback test mode
            with self.assertRaises(RuntimeError):
                svc._fetch_release_http(f"http://127.0.0.1:{api_port}/redirect/bad-host")

            # 3. Valid checksum + simulated Docker failure restores Caddyfile & compose, removes release dir, keeps .env intact
            Path(docker_fail_flag).write_text("fail", encoding="utf-8")
            fail_start = svc.start_core_update({"source": "release"})
            deadline = time.monotonic() + 10.0
            fail_status = fail_start["status"]
            while time.monotonic() < deadline:
                fail_status = svc.core_update_status(check_remote=False)
                if fail_status["state"] in ("succeeded", "failed"):
                    break
                time.sleep(0.05)
            self.assertEqual(fail_status["state"], "failed")
            self.assertFalse(os.path.exists(os.path.join(vpsagent_root, "releases", "v2.1.0")))
            self.assertEqual(Path(env_file).read_text(encoding="utf-8"), initial_env)
            self.assertEqual(
                Path(os.path.join(vpsagent_root, "Caddyfile")).read_text(encoding="utf-8"),
                "# v1\n",
            )
            os.unlink(docker_fail_flag)

            # 4. Successful release apply updates VPSAGENT_REPO_DIR cleanly while keeping secrets, 0600 perms, and 00-default.caddy
            ok_start = svc.start_core_update({"source": "release"})
            self.assertTrue(ok_start["ok"])
            deadline = time.monotonic() + 10.0
            ok_status = ok_start["status"]
            while time.monotonic() < deadline:
                ok_status = svc.core_update_status(check_remote=False)
                if ok_status["state"] in ("succeeded", "failed"):
                    break
                time.sleep(0.05)
            self.assertEqual(ok_status["state"], "succeeded", ok_status)
            self.assertEqual(ok_status["checksumStatus"], "verified")
            self.assertEqual(ok_status["checksumSha256"], sha_v210)
            self.assertEqual(ok_status["currentVersion"], "2.1.0")
            self.assertEqual(ok_status["currentReleaseTag"], "v2.1.0")
            self.assertEqual(ok_status["installedFrom"], "release")
            self.assertFalse(ok_status["updateAvailable"])

            expected_rel_dir = os.path.join(vpsagent_root, "releases", "v2.1.0")
            # Core .env must remain byte-for-byte untouched and 0600 (never read/rewritten by bridge)
            self.assertEqual(stat.S_IMODE(os.stat(env_file).st_mode), 0o600)
            self.assertEqual(Path(env_file).read_text(encoding="utf-8"), initial_env)

            active_source_file = os.path.join(vpsagent_root, "active-source.json")
            self.assertEqual(stat.S_IMODE(os.stat(active_source_file).st_mode), 0o644)
            active_source = json.loads(
                Path(active_source_file).read_text(encoding="utf-8")
            )
            self.assertEqual(active_source["repoDir"], expected_rel_dir)
            self.assertEqual(active_source["releaseTag"], "v2.1.0")
            self.assertEqual(active_source["releaseRepo"], "VPSAgent/vpsagent")
            self.assertNotIn("keep-session-secret-intact", Path(active_source_file).read_text(encoding="utf-8"))

            rel_docker_text = Path(docker_call_log).read_text(encoding="utf-8")
            self.assertIn("exec vpsagent-caddy caddy validate", rel_docker_text)
            self.assertIn("exec vpsagent-caddy caddy reload", rel_docker_text)

            self.assertEqual(
                Path(os.path.join(vpsagent_root, "runtime-bridge.py")).read_text(encoding="utf-8"),
                "# bridge-release-2.1.0\n",
            )
            self.assertIn("app.example.com", Path(app_default_route).read_text(encoding="utf-8"))

            sys_deadline = time.monotonic() + 5.0
            sys_log = ""
            while time.monotonic() < sys_deadline:
                if os.path.isfile(systemctl_log):
                    sys_log = Path(systemctl_log).read_text(encoding="utf-8")
                    if "restart --no-block vpsagent-runtime.service" in sys_log:
                        break
                time.sleep(0.05)
            self.assertIn("restart --no-block vpsagent-runtime.service", sys_log)

            # Restarted service (even with stale VPSAGENT_REPO_DIR in env) reads active-source.json
            from unittest import mock

            with mock.patch.dict(os.environ, {"VPSAGENT_REPO_DIR": current_repo}):
                restarted_svc = rb.RuntimeService(
                    apps_root=os.path.join(vpsagent_root, "apps"),
                    caddy_apps_dir=os.path.join(vpsagent_root, "caddy", "apps.d"),
                    caddy_container="vpsagent-caddy",
                    docker_bin=docker_sh,
                    systemctl_bin=sys_sh,
                    vpsagent_root=vpsagent_root,
                    repo_dir=None,
                    release_repo="VPSAgent/vpsagent",
                    release_api_base=f"http://127.0.0.1:{api_port}",
                    allow_unauthenticated=True,
                )
                self.assertEqual(restarted_svc.repo_dir, os.path.abspath(expected_rel_dir))
                rechecked = restarted_svc.core_update_status(check_remote=True)
                self.assertEqual(rechecked["releaseStatus"], "up_to_date")
                self.assertFalse(rechecked["updateAvailable"])
                self.assertTrue(rechecked["canUpdate"])
                self.assertEqual(rechecked["installedFrom"], "release")

            # 5. CLI --check-update --json discovers active-source.json WITHOUT --repo-dir
            import contextlib
            stdout_buf = io.StringIO()
            with contextlib.redirect_stdout(stdout_buf):
                exit_code = rb.main(
                    [
                        "--apps-root",
                        os.path.join(vpsagent_root, "apps"),
                        "--caddy-apps-dir",
                        os.path.join(vpsagent_root, "caddy", "apps.d"),
                        "--vpsagent-root",
                        vpsagent_root,
                        "--release-repo",
                        "VPSAgent/vpsagent",
                        "--release-api-base",
                        f"http://127.0.0.1:{api_port}",
                        "--check-update",
                        "--json",
                    ]
                )
            self.assertEqual(exit_code, 0)
            cli_payload = json.loads(stdout_buf.getvalue())
            self.assertEqual(cli_payload["repoDir"], os.path.abspath(expected_rel_dir))
            self.assertEqual(cli_payload["currentVersion"], "2.1.0")
            self.assertEqual(cli_payload["latestReleaseTag"], "v2.1.0")
            self.assertEqual(cli_payload["releaseStatus"], "up_to_date")

            # 6. Prerelease-only repo picks v2.0.0-alpha.2 > 2.0.0-alpha.1
            mock_state["mode"] = "prerelease_only"
            svc_git = rb.RuntimeService(
                apps_root=os.path.join(vpsagent_root, "apps"),
                caddy_apps_dir=os.path.join(vpsagent_root, "caddy", "apps.d"),
                caddy_container="vpsagent-caddy",
                docker_bin=docker_sh,
                systemctl_bin=sys_sh,
                vpsagent_root=vpsagent_root,
                repo_dir=current_repo,
                release_repo="VPSAgent/vpsagent",
                release_api_base=f"http://127.0.0.1:{api_port}",
                allow_unauthenticated=True,
            )
            pre_res = svc_git.core_update_status(check_remote=True)
            self.assertEqual(pre_res["updateSource"], "release")
            self.assertEqual(pre_res["latestReleaseTag"], "v2.0.0-alpha.2")
            self.assertTrue(pre_res["latestReleasePrerelease"])
            self.assertTrue(pre_res["updateAvailable"])

            # 7. No published GitHub releases yet falls back cleanly to Git branch tracking
            mock_state["mode"] = "no_releases"
            Path(os.path.join(work_dir, "package.json")).write_text(
                json.dumps({"name": "vpsagent", "version": "2.0.0-alpha.2"}),
                encoding="utf-8",
            )
            subprocess.run(["git", "-C", work_dir, "add", "."], check=True, env=git_env)
            subprocess.run(["git", "-C", work_dir, "commit", "-m", "branch fallback commit"], check=True, env=git_env)
            subprocess.run(["git", "-C", work_dir, "push", "origin", "main"], check=True, env=git_env)

            fallback_res = svc_git.core_update_status(check_remote=True)
            self.assertEqual(fallback_res["releaseStatus"], "no_releases")
            self.assertEqual(fallback_res["updateSource"], "git")
            self.assertTrue(fallback_res["updateAvailable"])
            self.assertEqual(fallback_res["commitsBehind"], 1)
            self.assertIn("no github release", (fallback_res["releaseNote"] or "").lower())
        finally:
            api_srv.shutdown()
            api_srv.server_close()
            cdn_srv.shutdown()
            cdn_srv.server_close()

    def test_release_downgrade_prevention_and_local_rebuild(self) -> None:
        import hashlib
        import io
        import tarfile

        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w:gz") as tf:
            for name, content in {
                "vpsagent-v1.9.0/package.json": b'{"name":"vpsagent","version":"1.9.0"}',
                "vpsagent-v1.9.0/bootstrap/Dockerfile": b"FROM node:24-alpine\n",
                "vpsagent-v1.9.0/bootstrap/docker-compose.core.yml": b"services: {}\n",
                "vpsagent-v1.9.0/bootstrap/Caddyfile": b"# v1.9\n",
                "vpsagent-v1.9.0/bootstrap/runtime-bridge.py": b"# bridge v1.9\n",
            }.items():
                ti = tarfile.TarInfo(name=name)
                ti.size = len(content)
                ti.mode = 0o644
                tf.addfile(ti, io.BytesIO(content))
        old_tar = buf.getvalue()
        old_sha = hashlib.sha256(old_tar).hexdigest()

        download_hits: list[str] = []

        class MockServer(http.server.BaseHTTPRequestHandler):
            def log_message(self, *_args: object) -> None:
                return

            def do_GET(self) -> None:
                if self.path.endswith("/releases/latest"):
                    rel = {
                        "tag_name": "v1.9.0",
                        "name": "VPSAgent v1.9.0",
                        "html_url": "https://github.com/VPSAgent/vpsagent/releases/tag/v1.9.0",
                        "body": "Older stable release.",
                        "published_at": "2026-10-01T12:00:00Z",
                        "prerelease": False,
                        "draft": False,
                        "assets": [
                            {
                                "name": "vpsagent-v1.9.0.tar.gz",
                                "browser_download_url": f"http://127.0.0.1:{srv_port}/dl/vpsagent-v1.9.0.tar.gz",
                            },
                            {
                                "name": "SHA256SUMS",
                                "browser_download_url": f"http://127.0.0.1:{srv_port}/dl/SHA256SUMS",
                            },
                        ],
                    }
                    raw = json.dumps(rel).encode("utf-8")
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(raw)))
                    self.end_headers()
                    self.wfile.write(raw)
                    return
                if self.path.startswith("/dl/"):
                    download_hits.append(self.path)
                    body = (
                        f"{old_sha}  vpsagent-v1.9.0.tar.gz\n".encode("utf-8")
                        if self.path.endswith("SHA256SUMS")
                        else old_tar
                    )
                    self.send_response(200)
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                    return
                self.send_response(404)
                self.end_headers()

        srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), MockServer)
        srv_port = int(srv.server_address[1])
        threading.Thread(target=srv.serve_forever, daemon=True).start()

        try:
            vpsagent_root = os.path.join(self.tmp, "dg-root")
            rel_dir = os.path.join(vpsagent_root, "releases", "v2.0.0-beta.1")
            os.makedirs(os.path.join(vpsagent_root, "apps"), exist_ok=True)
            os.makedirs(os.path.join(vpsagent_root, "caddy", "apps.d"), exist_ok=True)
            os.makedirs(os.path.join(vpsagent_root, "run"), exist_ok=True)
            os.makedirs(os.path.join(rel_dir, "bootstrap"), exist_ok=True)
            Path(os.path.join(vpsagent_root, ".env")).write_text(
                "VPSAGENT_RUNTIME_TOKEN=test-secret-token-value-123456\n", encoding="utf-8"
            )
            Path(os.path.join(vpsagent_root, "Caddyfile")).write_text("# beta1\n", encoding="utf-8")
            Path(os.path.join(vpsagent_root, "docker-compose.yml")).write_text(
                "services:\n  vpsagent-core:\n    image: vpsagent/core:beta1\n", encoding="utf-8"
            )
            Path(os.path.join(rel_dir, "package.json")).write_text(
                json.dumps({"name": "vpsagent", "version": "2.0.0-beta.1"}), encoding="utf-8"
            )
            Path(os.path.join(rel_dir, ".vpsagent-release.json")).write_text(
                json.dumps({"tag": "v2.0.0-beta.1", "version": "2.0.0-beta.1", "releaseRepo": "VPSAgent/vpsagent"}),
                encoding="utf-8",
            )
            Path(os.path.join(rel_dir, "bootstrap", "Caddyfile")).write_text("# beta1\n", encoding="utf-8")
            Path(os.path.join(rel_dir, "bootstrap", "docker-compose.core.yml")).write_text(
                "services:\n  vpsagent-core:\n    image: vpsagent/core:beta1\n", encoding="utf-8"
            )
            Path(os.path.join(rel_dir, "bootstrap", "runtime-bridge.py")).write_text(
                "# bridge beta1\n", encoding="utf-8"
            )
            Path(os.path.join(vpsagent_root, "runtime-bridge.py")).write_text(
                "# bridge beta1\n", encoding="utf-8"
            )

            docker_calls = os.path.join(self.tmp, "dg-docker.log")
            docker_py = os.path.join(self.tmp, "dg_fake_docker.py")
            Path(docker_py).write_text(
                f"""import os, sys
with open({docker_calls!r}, "a", encoding="utf-8") as fh:
    fh.write(os.environ.get("VPSAGENT_REPO_DIR", "") + "::" + " ".join(sys.argv[1:]) + "\\n")
sys.exit(0)
""",
                encoding="utf-8",
            )
            docker_sh = os.path.join(self.tmp, "dg-fake-docker")
            Path(docker_sh).write_text(
                f'#!/usr/bin/env sh\nexec "{sys.executable}" "{docker_py}" "$@"\n', encoding="utf-8"
            )
            os.chmod(docker_sh, 0o755)

            svc = rb.RuntimeService(
                apps_root=os.path.join(vpsagent_root, "apps"),
                caddy_apps_dir=os.path.join(vpsagent_root, "caddy", "apps.d"),
                caddy_container="vpsagent-caddy",
                docker_bin=docker_sh,
                vpsagent_root=vpsagent_root,
                repo_dir=rel_dir,
                release_repo="VPSAgent/vpsagent",
                release_api_base=f"http://127.0.0.1:{srv_port}",
                allow_unauthenticated=True,
            )

            status = svc.core_update_status(check_remote=True)
            self.assertEqual(status["releaseStatus"], "up_to_date")
            self.assertFalse(status["updateAvailable"])
            self.assertTrue(status["canUpdate"])
            self.assertEqual(status["checksumStatus"], "none")
            self.assertIn("newer than", (status["releaseNote"] or "").lower())

            # Explicit release apply refuses downgrade to v1.9.0
            with self.assertRaises(rb.BridgeRequestError) as ctx:
                svc.start_core_update({"source": "release"})
            self.assertEqual(ctx.exception.status_code, 400)
            self.assertIn("downgrade", str(ctx.exception).lower())
            self.assertEqual(download_hits, [])

            # Rebuild action ("auto") rebuilds local v2.0.0-beta.1 without downloading v1.9.0
            rebuild_start = svc.start_core_update({"source": "auto"})
            self.assertTrue(rebuild_start["ok"])
            deadline = time.monotonic() + 10.0
            rebuild_res = rebuild_start["status"]
            while time.monotonic() < deadline:
                rebuild_res = svc.core_update_status(check_remote=False)
                if rebuild_res["state"] in ("succeeded", "failed"):
                    break
                time.sleep(0.05)
            self.assertEqual(rebuild_res["state"], "succeeded", rebuild_res)
            self.assertEqual(rebuild_res["currentReleaseTag"], "v2.0.0-beta.1")
            self.assertEqual(rebuild_res["currentVersion"], "2.0.0-beta.1")
            self.assertEqual(download_hits, [])
            docker_log_text = Path(docker_calls).read_text(encoding="utf-8")
            self.assertIn(f"{os.path.abspath(rel_dir)}::compose", docker_log_text)
        finally:
            srv.shutdown()
            srv.server_close()

    def test_release_private_repo_api_asset_download_and_tag_version_priority(self) -> None:
        import hashlib
        import io
        import tarfile

        # Build release archive tagged v2.0.0-alpha.2 where package.json was still left at 2.0.0-alpha.1
        buf = io.BytesIO()
        prefix = "vpsagent-v2.0.0-alpha.2"
        with tarfile.open(fileobj=buf, mode="w:gz") as tf:
            for name, content in {
                f"{prefix}/package.json": b'{"name":"vpsagent","version":"2.0.0-alpha.1"}',
                f"{prefix}/bootstrap/Dockerfile": b"FROM node:24-alpine\n",
                f"{prefix}/bootstrap/docker-compose.core.yml": b"services: {}\n",
                f"{prefix}/bootstrap/Caddyfile": b"# caddy a2\n",
                f"{prefix}/bootstrap/runtime-bridge.py": b"# bridge a2\n",
            }.items():
                ti = tarfile.TarInfo(name=name)
                ti.size = len(content)
                ti.mode = 0o644
                tf.addfile(ti, io.BytesIO(content))
        tar_bytes = buf.getvalue()
        tar_sha = hashlib.sha256(tar_bytes).hexdigest()

        asset_accept_seen: list[str | None] = []
        cdn_auth_seen: list[str | None] = []
        token = "ghp_private_repo_token_9988776655"

        class PrivateApiServer(http.server.BaseHTTPRequestHandler):
            def log_message(self, *_args: object) -> None:
                return

            def do_GET(self) -> None:
                if self.headers.get("Authorization") != f"Bearer {token}":
                    self.send_response(401)
                    self.end_headers()
                    return
                if self.path.endswith("/releases/latest"):
                    rel = {
                        "tag_name": "v2.0.0-alpha.2",
                        "name": "VPSAgent v2.0.0-alpha.2",
                        "html_url": "https://github.com/VPSAgent/private-vpsagent/releases/tag/v2.0.0-alpha.2",
                        "body": "Private release",
                        "published_at": "2026-11-26T12:00:00Z",
                        "prerelease": True,
                        "draft": False,
                        "assets": [
                            {
                                "name": "vpsagent-v2.0.0-alpha.2.tar.gz",
                                "url": f"http://127.0.0.1:{api_port}/repos/VPSAgent/private-vpsagent/releases/assets/101",
                                "browser_download_url": f"http://127.0.0.1:{cdn_port}/blocked-browser/tar",
                            },
                            {
                                "name": "SHA256SUMS",
                                "url": f"http://127.0.0.1:{api_port}/repos/VPSAgent/private-vpsagent/releases/assets/102",
                                "browser_download_url": f"http://127.0.0.1:{cdn_port}/blocked-browser/sums",
                            },
                        ],
                    }
                    raw = json.dumps(rel).encode("utf-8")
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(raw)))
                    self.end_headers()
                    self.wfile.write(raw)
                    return
                if self.path.endswith("/releases/assets/101"):
                    asset_accept_seen.append(self.headers.get("Accept"))
                    if self.headers.get("Accept") != "application/octet-stream":
                        self.send_response(406)
                        self.end_headers()
                        return
                    self.send_response(302)
                    self.send_header("Location", f"http://127.0.0.1:{cdn_port}/signed/tar")
                    self.end_headers()
                    return
                if self.path.endswith("/releases/assets/102"):
                    asset_accept_seen.append(self.headers.get("Accept"))
                    if self.headers.get("Accept") != "application/octet-stream":
                        self.send_response(406)
                        self.end_headers()
                        return
                    self.send_response(302)
                    self.send_header("Location", f"http://127.0.0.1:{cdn_port}/signed/sums")
                    self.end_headers()
                    return
                self.send_response(404)
                self.end_headers()

        class PrivateCdnServer(http.server.BaseHTTPRequestHandler):
            def log_message(self, *_args: object) -> None:
                return

            def do_GET(self) -> None:
                if self.path.startswith("/blocked-browser/"):
                    self.send_response(404)
                    self.end_headers()
                    return
                cdn_auth_seen.append(self.headers.get("Authorization"))
                if self.path == "/signed/tar":
                    self.send_response(200)
                    self.send_header("Content-Length", str(len(tar_bytes)))
                    self.end_headers()
                    self.wfile.write(tar_bytes)
                    return
                if self.path == "/signed/sums":
                    body = f"{tar_sha}  vpsagent-v2.0.0-alpha.2.tar.gz\n".encode("utf-8")
                    self.send_response(200)
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                    return
                self.send_response(404)
                self.end_headers()

        api_srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), PrivateApiServer)
        cdn_srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), PrivateCdnServer)
        api_port = int(api_srv.server_address[1])
        cdn_port = int(cdn_srv.server_address[1])
        threading.Thread(target=api_srv.serve_forever, daemon=True).start()
        threading.Thread(target=cdn_srv.serve_forever, daemon=True).start()

        try:
            vpsagent_root = os.path.join(self.tmp, "priv-rel-root")
            os.makedirs(os.path.join(vpsagent_root, "apps"), exist_ok=True)
            os.makedirs(os.path.join(vpsagent_root, "caddy", "apps.d"), exist_ok=True)
            os.makedirs(os.path.join(vpsagent_root, "run"), exist_ok=True)
            Path(os.path.join(vpsagent_root, ".env")).write_text(
                "VPSAGENT_RUNTIME_TOKEN=test-secret-token-value-123456\n", encoding="utf-8"
            )
            Path(os.path.join(vpsagent_root, "Caddyfile")).write_text("# old\n", encoding="utf-8")
            Path(os.path.join(vpsagent_root, "docker-compose.yml")).write_text(
                "services:\n  vpsagent-core:\n    image: vpsagent/core:local\n", encoding="utf-8"
            )

            docker_sh = os.path.join(self.tmp, "priv-rel-docker")
            Path(docker_sh).write_text("#!/usr/bin/env sh\nexit 0\n", encoding="utf-8")
            os.chmod(docker_sh, 0o755)

            svc = rb.RuntimeService(
                apps_root=os.path.join(vpsagent_root, "apps"),
                caddy_apps_dir=os.path.join(vpsagent_root, "caddy", "apps.d"),
                caddy_container="vpsagent-caddy",
                docker_bin=docker_sh,
                vpsagent_root=vpsagent_root,
                release_repo="VPSAgent/private-vpsagent",
                release_api_base=f"http://127.0.0.1:{api_port}",
                release_github_token=token,
                allow_unauthenticated=True,
            )

            started = svc.start_core_update({"source": "release"})
            self.assertTrue(started["ok"])
            deadline = time.monotonic() + 10.0
            res = started["status"]
            while time.monotonic() < deadline:
                res = svc.core_update_status(check_remote=False)
                if res["state"] in ("succeeded", "failed"):
                    break
                time.sleep(0.05)

            self.assertEqual(res["state"], "succeeded", res)
            self.assertEqual(res["checksumStatus"], "verified")
            self.assertEqual(res["currentReleaseTag"], "v2.0.0-alpha.2")
            self.assertEqual(res["currentVersion"], "2.0.0-alpha.2")
            self.assertEqual(asset_accept_seen, ["application/octet-stream", "application/octet-stream"])
            self.assertTrue(all(v is None for v in cdn_auth_seen))
        finally:
            api_srv.shutdown()
            api_srv.server_close()
            cdn_srv.shutdown()
            cdn_srv.server_close()

    def test_release_post_activation_bridge_failure_rollback_preserves_valid_source(self) -> None:
        import builtins
        import hashlib
        import io
        import tarfile
        from unittest import mock

        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w:gz") as tf:
            for name, content in {
                "vpsagent-v2.1.0/package.json": b'{"name":"vpsagent","version":"2.1.0"}',
                "vpsagent-v2.1.0/bootstrap/Dockerfile": b"FROM node:24-alpine\n",
                "vpsagent-v2.1.0/bootstrap/docker-compose.core.yml": b"services: { v: 2 }\n",
                "vpsagent-v2.1.0/bootstrap/Caddyfile": b"# caddy 2.1\n",
                "vpsagent-v2.1.0/bootstrap/runtime-bridge.py": b"# bridge 2.1\n",
            }.items():
                ti = tarfile.TarInfo(name=name)
                ti.size = len(content)
                ti.mode = 0o644
                tf.addfile(ti, io.BytesIO(content))
        tar_bytes = buf.getvalue()
        tar_sha = hashlib.sha256(tar_bytes).hexdigest()

        class MockServer(http.server.BaseHTTPRequestHandler):
            def log_message(self, *_args: object) -> None:
                return

            def do_GET(self) -> None:
                if self.path.endswith("/releases/latest"):
                    rel = {
                        "tag_name": "v2.1.0",
                        "name": "VPSAgent v2.1.0",
                        "html_url": "https://github.com/VPSAgent/vpsagent/releases/tag/v2.1.0",
                        "body": "v2.1.0",
                        "published_at": "2026-11-26T12:00:00Z",
                        "prerelease": False,
                        "draft": False,
                        "assets": [
                            {
                                "name": "vpsagent-v2.1.0.tar.gz",
                                "browser_download_url": f"http://127.0.0.1:{srv_port}/dl/v2.1.0.tar.gz",
                            },
                            {
                                "name": "SHA256SUMS",
                                "browser_download_url": f"http://127.0.0.1:{srv_port}/dl/SHA256SUMS",
                            },
                        ],
                    }
                    raw = json.dumps(rel).encode("utf-8")
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(raw)))
                    self.end_headers()
                    self.wfile.write(raw)
                    return
                if self.path == "/dl/v2.1.0.tar.gz":
                    self.send_response(200)
                    self.send_header("Content-Length", str(len(tar_bytes)))
                    self.end_headers()
                    self.wfile.write(tar_bytes)
                    return
                if self.path == "/dl/SHA256SUMS":
                    body = f"{tar_sha}  vpsagent-v2.1.0.tar.gz\n".encode("utf-8")
                    self.send_response(200)
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                    return
                self.send_response(404)
                self.end_headers()

        srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), MockServer)
        srv_port = int(srv.server_address[1])
        threading.Thread(target=srv.serve_forever, daemon=True).start()

        try:
            vpsagent_root = os.path.join(self.tmp, "postfail-root")
            prev_rel_dir = os.path.join(vpsagent_root, "releases", "v2.0.0")
            os.makedirs(os.path.join(vpsagent_root, "apps"), exist_ok=True)
            os.makedirs(os.path.join(vpsagent_root, "caddy", "apps.d"), exist_ok=True)
            os.makedirs(os.path.join(vpsagent_root, "run"), exist_ok=True)
            os.makedirs(os.path.join(prev_rel_dir, "bootstrap"), exist_ok=True)
            Path(os.path.join(vpsagent_root, ".env")).write_text(
                "VPSAGENT_RUNTIME_TOKEN=test-secret-token-value-123456\n", encoding="utf-8"
            )
            Path(os.path.join(vpsagent_root, "Caddyfile")).write_text("# v2.0\n", encoding="utf-8")
            Path(os.path.join(vpsagent_root, "docker-compose.yml")).write_text(
                "services: { v: 1 }\n", encoding="utf-8"
            )
            Path(os.path.join(vpsagent_root, "runtime-bridge.py")).write_text(
                "# bridge 2.0\n", encoding="utf-8"
            )
            Path(os.path.join(prev_rel_dir, "package.json")).write_text(
                '{"name":"vpsagent","version":"2.0.0"}', encoding="utf-8"
            )
            Path(os.path.join(prev_rel_dir, ".vpsagent-release.json")).write_text(
                '{"tag":"v2.0.0","version":"2.0.0"}', encoding="utf-8"
            )
            Path(os.path.join(prev_rel_dir, "bootstrap", "docker-compose.core.yml")).write_text(
                "services: { v: 1 }\n", encoding="utf-8"
            )
            rb._write_active_source_file(vpsagent_root, prev_rel_dir, release_tag="v2.0.0")

            docker_calls = os.path.join(self.tmp, "postfail-docker.log")
            rollback_compose_fail = os.path.join(self.tmp, "postfail-rb-fail.flag")
            docker_py = os.path.join(self.tmp, "postfail_fake_docker.py")
            Path(docker_py).write_text(
                f"""import os, sys
repo = os.environ.get("VPSAGENT_REPO_DIR", "")
with open({docker_calls!r}, "a", encoding="utf-8") as fh:
    fh.write(repo + "::" + " ".join(sys.argv[1:]) + "\\n")
if repo == {os.path.abspath(prev_rel_dir)!r} and os.path.exists({rollback_compose_fail!r}):
    sys.exit(1)
sys.exit(0)
""",
                encoding="utf-8",
            )
            docker_sh = os.path.join(self.tmp, "postfail-fake-docker")
            Path(docker_sh).write_text(
                f'#!/usr/bin/env sh\nexec "{sys.executable}" "{docker_py}" "$@"\n', encoding="utf-8"
            )
            os.chmod(docker_sh, 0o755)

            svc = rb.RuntimeService(
                apps_root=os.path.join(vpsagent_root, "apps"),
                caddy_apps_dir=os.path.join(vpsagent_root, "caddy", "apps.d"),
                caddy_container="vpsagent-caddy",
                docker_bin=docker_sh,
                vpsagent_root=vpsagent_root,
                release_repo="VPSAgent/vpsagent",
                release_api_base=f"http://127.0.0.1:{srv_port}",
                allow_unauthenticated=True,
            )

            target_meta = svc._fetch_latest_github_release("VPSAgent/vpsagent")
            real_open = builtins.open

            class FailBridgeWriter:
                def __init__(self, inner: object) -> None:
                    self._inner = inner

                def __enter__(self) -> "FailBridgeWriter":
                    return self

                def __exit__(self, *args: object) -> None:
                    self._inner.close()  # type: ignore[attr-defined]

                def write(self, _data: bytes) -> int:
                    raise OSError("ENOSPC simulated during runtime-bridge.py write")

            def fail_bridge_open(file: object, mode: str = "r", *args: object, **kwargs: object) -> object:
                fh = real_open(file, mode, *args, **kwargs)  # type: ignore[call-overload]
                if mode == "wb" and os.path.basename(str(file)).startswith("runtime-bridge.py.tmp."):
                    return FailBridgeWriter(fh)
                return fh

            with mock.patch.object(builtins, "open", side_effect=fail_bridge_open):
                svc._run_core_update_release_worker(target_meta)

            res = svc.core_update_status(check_remote=False)
            self.assertEqual(res["state"], "failed")
            # Active source and Caddyfile/compose must remain cleanly pointing to prev_rel_dir
            self.assertEqual(svc.repo_dir, os.path.abspath(prev_rel_dir))
            self.assertTrue(os.path.isdir(svc.repo_dir))
            self.assertFalse(os.path.exists(os.path.join(vpsagent_root, "releases", "v2.1.0")))
            self.assertEqual(
                json.loads(Path(os.path.join(vpsagent_root, "active-source.json")).read_text(encoding="utf-8"))["repoDir"],
                os.path.abspath(prev_rel_dir),
            )
            self.assertEqual(Path(os.path.join(vpsagent_root, "Caddyfile")).read_text(encoding="utf-8"), "# v2.0\n")
            docker_log_text = Path(docker_calls).read_text(encoding="utf-8")
            self.assertIn(f"{os.path.abspath(prev_rel_dir)}::compose", docker_log_text)

            # When rollback compose fails after activation, v2.1.0 is preserved rather than leaving a dangling path
            Path(rollback_compose_fail).write_text("1", encoding="utf-8")
            with mock.patch.object(builtins, "open", side_effect=fail_bridge_open):
                svc._run_core_update_release_worker(target_meta)
            res2 = svc.core_update_status(check_remote=False)
            self.assertEqual(res2["state"], "failed")
            self.assertTrue(os.path.isdir(os.path.join(vpsagent_root, "releases", "v2.1.0")))
            self.assertTrue(os.path.isdir(svc.repo_dir))
        finally:
            srv.shutdown()
            srv.server_close()

    def test_sync_core_configs_partial_failure_restores_caddyfile(self) -> None:
        import builtins
        from unittest import mock

        vpsagent_root = os.path.join(self.tmp, "partial-sync-root")
        src_dir = os.path.join(self.tmp, "partial-sync-src")
        os.makedirs(os.path.join(vpsagent_root, "apps"), exist_ok=True)
        os.makedirs(os.path.join(vpsagent_root, "caddy", "apps.d"), exist_ok=True)
        os.makedirs(os.path.join(vpsagent_root, "run"), exist_ok=True)
        os.makedirs(os.path.join(src_dir, "bootstrap"), exist_ok=True)

        caddy_dst = os.path.join(vpsagent_root, "Caddyfile")
        compose_dst = os.path.join(vpsagent_root, "docker-compose.yml")
        Path(caddy_dst).write_text("# original v1 caddyfile\n", encoding="utf-8")
        Path(compose_dst).write_text("services: { v: 1 }\n", encoding="utf-8")
        Path(os.path.join(src_dir, "bootstrap", "Caddyfile")).write_text("# new v2 caddyfile\n", encoding="utf-8")
        Path(os.path.join(src_dir, "bootstrap", "docker-compose.core.yml")).write_text(
            "services: { v: 2 }\n", encoding="utf-8"
        )

        svc = rb.RuntimeService(
            apps_root=os.path.join(vpsagent_root, "apps"),
            caddy_apps_dir=os.path.join(vpsagent_root, "caddy", "apps.d"),
            caddy_container="vpsagent-caddy",
            vpsagent_root=vpsagent_root,
            allow_unauthenticated=True,
        )

        real_open = builtins.open
        fail_once = {"triggered": False}

        class FailWriter:
            def __init__(self, inner: object) -> None:
                self._inner = inner

            def __enter__(self) -> "FailWriter":
                return self

            def __exit__(self, *args: object) -> None:
                self._inner.close()  # type: ignore[attr-defined]

            def write(self, _data: bytes) -> int:
                raise OSError("simulated compose write error")

        def fail_compose_open(file: object, mode: str = "r", *args: object, **kwargs: object) -> object:
            fh = real_open(file, mode, *args, **kwargs)  # type: ignore[call-overload]
            if (
                not fail_once["triggered"]
                and mode == "wb"
                and os.path.abspath(str(file)) == os.path.abspath(compose_dst)
            ):
                fail_once["triggered"] = True
                return FailWriter(fh)
            return fh

        with mock.patch.object(builtins, "open", side_effect=fail_compose_open):
            with self.assertRaises(OSError):
                svc._sync_core_configs(src_dir)

        self.assertTrue(fail_once["triggered"])
        self.assertEqual(Path(caddy_dst).read_text(encoding="utf-8"), "# original v1 caddyfile\n")
        self.assertEqual(Path(compose_dst).read_text(encoding="utf-8"), "services: { v: 1 }\n")

    def test_release_check_skips_git_fetch_when_newer_release_found(self) -> None:
        import subprocess
        from unittest import mock

        class ReleaseOnlyServer(http.server.BaseHTTPRequestHandler):
            def log_message(self, *_args: object) -> None:
                return

            def do_GET(self) -> None:
                if self.path.endswith("/releases/latest"):
                    rel = {
                        "tag_name": "v9.9.9",
                        "name": "VPSAgent v9.9.9",
                        "html_url": "https://github.com/VPSAgent/vpsagent/releases/tag/v9.9.9",
                        "body": "Major update",
                        "published_at": "2026-11-26T12:00:00Z",
                        "prerelease": False,
                        "draft": False,
                        "assets": [
                            {
                                "name": "vpsagent-v9.9.9.tar.gz",
                                "browser_download_url": "https://github.com/VPSAgent/vpsagent/releases/download/v9.9.9/vpsagent-v9.9.9.tar.gz",
                            }
                        ],
                    }
                    raw = json.dumps(rel).encode("utf-8")
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(raw)))
                    self.end_headers()
                    self.wfile.write(raw)
                    return
                self.send_response(404)
                self.end_headers()

        srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), ReleaseOnlyServer)
        srv_port = int(srv.server_address[1])
        threading.Thread(target=srv.serve_forever, daemon=True).start()

        try:
            vpsagent_root = os.path.join(self.tmp, "skipfetch-root")
            repo_dir = os.path.join(self.tmp, "skipfetch-repo")
            os.makedirs(os.path.join(vpsagent_root, "apps"), exist_ok=True)
            os.makedirs(os.path.join(vpsagent_root, "caddy", "apps.d"), exist_ok=True)
            os.makedirs(os.path.join(vpsagent_root, "run"), exist_ok=True)
            os.makedirs(repo_dir, exist_ok=True)
            Path(os.path.join(vpsagent_root, ".env")).write_text(
                "VPSAGENT_RUNTIME_TOKEN=test-secret-token-value-123456\n", encoding="utf-8"
            )
            git_env = {
                **os.environ,
                "GIT_AUTHOR_NAME": "Test",
                "GIT_AUTHOR_EMAIL": "test@example.com",
                "GIT_COMMITTER_NAME": "Test",
                "GIT_COMMITTER_EMAIL": "test@example.com",
            }
            subprocess.run(["git", "-C", repo_dir, "init", "-b", "main"], check=True, env=git_env)
            Path(os.path.join(repo_dir, "package.json")).write_text(
                '{"name":"vpsagent","version":"2.0.0-alpha.1"}', encoding="utf-8"
            )
            subprocess.run(["git", "-C", repo_dir, "add", "package.json"], check=True, env=git_env)
            subprocess.run(["git", "-C", repo_dir, "commit", "-m", "init"], check=True, env=git_env)
            subprocess.run(
                ["git", "-C", repo_dir, "remote", "add", "origin", "https://github.com/VPSAgent/vpsagent.git"],
                check=True,
                env=git_env,
            )

            svc = rb.RuntimeService(
                apps_root=os.path.join(vpsagent_root, "apps"),
                caddy_apps_dir=os.path.join(vpsagent_root, "caddy", "apps.d"),
                caddy_container="vpsagent-caddy",
                vpsagent_root=vpsagent_root,
                repo_dir=repo_dir,
                release_repo="VPSAgent/vpsagent",
                release_api_base=f"http://127.0.0.1:{srv_port}",
                allow_unauthenticated=True,
            )

            seen_git_cmds: list[list[str]] = []
            orig_run_git = svc._run_repo_git

            def spy_git(rdir: str, args: list[str], *, timeout: float = 30) -> subprocess.CompletedProcess[str]:
                seen_git_cmds.append(list(args))
                return orig_run_git(rdir, args, timeout=timeout)

            with mock.patch.object(svc, "_run_repo_git", side_effect=spy_git):
                res = svc.core_update_status(check_remote=True)

            self.assertEqual(res["updateSource"], "release")
            self.assertEqual(res["latestReleaseTag"], "v9.9.9")
            self.assertTrue(res["updateAvailable"])
            self.assertFalse(any(cmd and cmd[0] == "fetch" for cmd in seen_git_cmds), seen_git_cmds)
        finally:
            srv.shutdown()
            srv.server_close()


class TestRuntimeBridgeTailscale(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp_dir = tempfile.mkdtemp(prefix="vpsagent-ts-py-test-")
        self.apps_root = os.path.join(self.tmp_dir, "apps")
        self.caddy_dir = os.path.join(self.tmp_dir, "caddy-apps")
        os.makedirs(self.apps_root, exist_ok=True)
        os.makedirs(self.caddy_dir, exist_ok=True)
        self.git_sh, self.docker_sh = _write_fake_git_and_docker(self.tmp_dir)

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def _make_fake_tailscale(
        self,
        *,
        status_rc: int = 0,
        status_stdout: str = "",
        status_stderr: str = "",
        serve_stdout: str = "{}",
        up_rc: int = 0,
        up_stdout: str = "",
        up_stderr: str = "",
        serve_cmd_rc: int = 0,
        serve_cmd_stderr: str = "",
        systemctl_active: bool = False,
        serve_stateful: bool = False,
        keep_funnel_on_serve: bool = False,
    ) -> tuple[str, str, str, str]:
        sub_dir = tempfile.mkdtemp(dir=self.tmp_dir)
        calls_file = os.path.join(sub_dir, "ts-calls.jsonl")
        seen_key_file = os.path.join(sub_dir, "ts-seen-key.txt")
        serve_state_file = os.path.join(sub_dir, "ts-serve-state.json")
        Path(serve_state_file).write_text(serve_stdout, encoding="utf-8")
        ts_py = os.path.join(sub_dir, "fake_tailscale.py")
        Path(ts_py).write_text(
            f"""import json, os, sys
args = sys.argv[1:]
with open({calls_file!r}, "a", encoding="utf-8") as fh:
    fh.write(json.dumps(args) + "\\n")

if args == ["status", "--json"]:
    sys.stdout.write({status_stdout!r})
    sys.stderr.write({status_stderr!r})
    sys.exit({status_rc!r})

if args == ["serve", "status", "--json"]:
    if {serve_stateful!r} and os.path.exists({serve_state_file!r}):
        sys.stdout.write(open({serve_state_file!r}, "r", encoding="utf-8").read())
    else:
        sys.stdout.write({serve_stdout!r})
    sys.exit(0)

if args[:1] == ["up"]:
    for arg in args[1:]:
        if arg.startswith("--auth-key=file:"):
            path = arg.split(":", 1)[1]
            with open(path, "r", encoding="utf-8") as fh:
                content = fh.read()
            with open({seen_key_file!r}, "w", encoding="utf-8") as out:
                out.write(content)
    sys.stdout.write({up_stdout!r})
    sys.stderr.write({up_stderr!r})
    sys.exit({up_rc!r})

if args[:1] == ["serve"]:
    if {serve_stateful!r} and {serve_cmd_rc!r} == 0 and not {serve_cmd_stderr!r}:
        data = json.loads(open({serve_state_file!r}, "r", encoding="utf-8").read() or "{{}}")
        web = data.setdefault("Web", {{}})
        host_key = "my-vps.tail42.ts.net:443"
        entry = web.setdefault(host_key, {{}})
        handlers = entry.setdefault("Handlers", {{}})
        if args == ["serve", "--https=443", "--set-path=/", "off"]:
            handlers.pop("/", None)
        elif args == ["serve", "--https=443", "--set-path=/mcp", "off"]:
            handlers.pop("/mcp", None)
        elif len(args) >= 4 and args[1] == "--bg" and args[2] == "--https=443":
            handlers["/"] = {{"Proxy": args[3]}}
            if not {keep_funnel_on_serve!r} and isinstance(data.get("AllowFunnel"), dict):
                data["AllowFunnel"][host_key] = False
        open({serve_state_file!r}, "w", encoding="utf-8").write(json.dumps(data))
    sys.stderr.write({serve_cmd_stderr!r})
    sys.exit({serve_cmd_rc!r})

sys.exit(0)
""",
            encoding="utf-8",
        )
        ts_sh = os.path.join(sub_dir, "fake-tailscale")
        Path(ts_sh).write_text(
            f'#!/usr/bin/env sh\nexec "{sys.executable}" "{ts_py}" "$@"\n',
            encoding="utf-8",
        )
        os.chmod(ts_sh, 0o755)

        sys_py = os.path.join(sub_dir, "fake_systemctl.py")
        Path(sys_py).write_text(
            f"""import sys
args = sys.argv[1:]
if args[:2] == ["is-active", "tailscaled"]:
    if {systemctl_active!r}:
        print("active")
        sys.exit(0)
    print("inactive")
    sys.exit(3)
sys.exit(0)
""",
            encoding="utf-8",
        )
        sys_sh = os.path.join(sub_dir, "fake-systemctl")
        Path(sys_sh).write_text(
            f'#!/usr/bin/env sh\nexec "{sys.executable}" "{sys_py}" "$@"\n',
            encoding="utf-8",
        )
        os.chmod(sys_sh, 0o755)
        return ts_sh, sys_sh, calls_file, seen_key_file

    def _service(
        self,
        *,
        tailscale_bin: str,
        systemctl_bin: str = "systemctl",
        target_reachable: bool = True,
    ) -> rb.RuntimeService:
        return rb.RuntimeService(
            apps_root=self.apps_root,
            caddy_apps_dir=self.caddy_dir,
            caddy_container="vpsagent-caddy",
            docker_bin=self.docker_sh,
            git_bin=self.git_sh,
            systemctl_bin=systemctl_bin,
            tailscale_bin=tailscale_bin,
            tailscale_target_url="http://127.0.0.1:3001",
            tailscale_target_checker=lambda _h, _p: target_reachable,
            runtime_token="secret-token-for-unit-test-1234",
        )

    def test_tailscale_key_redaction(self) -> None:
        raw = "auth=tskey-auth-kSecret1234567890 api=tskey-api-kApiSecret987654"
        redacted = rb.redact_secrets(raw)
        self.assertNotIn("tskey-auth-kSecret1234567890", redacted)
        self.assertNotIn("tskey-api-kApiSecret987654", redacted)
        self.assertIn("[REDACTED]", redacted)

    def test_tailscale_status_variants(self) -> None:
        # 1. Not installed
        svc_missing = self._service(
            tailscale_bin=os.path.join(self.tmp_dir, "does-not-exist-tailscale")
        )
        missing_status = svc_missing.tailscale_status()
        self.assertFalse(missing_status["installed"])
        self.assertFalse(missing_status["connected"])
        self.assertEqual(missing_status["backendState"], "not_installed")

        # 2. Daemon stopped (non-JSON error)
        ts_stopped, sys_stopped, _, _ = self._make_fake_tailscale(
            status_rc=1,
            status_stderr="failed to connect to local tailscaled; it doesn't appear to be running",
        )
        stopped_status = self._service(
            tailscale_bin=ts_stopped, systemctl_bin=sys_stopped
        ).tailscale_status()
        self.assertTrue(stopped_status["installed"])
        self.assertFalse(stopped_status["serviceActive"])
        self.assertFalse(stopped_status["connected"])
        self.assertEqual(stopped_status["backendState"], "stopped")

        # 3. NeedsLogin with loginUrl (must NOT redact loginUrl!) and non-zero rc
        ts_login, sys_login, _, _ = self._make_fake_tailscale(
            status_rc=1,
            status_stdout=json.dumps(
                {
                    "Version": "1.78.0",
                    "BackendState": "NeedsLogin",
                    "AuthURL": "https://login.tailscale.com/a/abc987def",
                    "Self": {"HostName": "box", "DNSName": "", "TailscaleIPs": []},
                    "CertDomains": [],
                }
            ),
        )
        login_status = self._service(
            tailscale_bin=ts_login, systemctl_bin=sys_login
        ).tailscale_status()
        self.assertTrue(login_status["installed"])
        self.assertTrue(login_status["serviceActive"])
        self.assertFalse(login_status["connected"])
        self.assertEqual(login_status["backendState"], "needs_login")
        self.assertEqual(
            login_status["loginUrl"], "https://login.tailscale.com/a/abc987def"
        )

        # 4. Connected without Serve
        running_json = json.dumps(
            {
                "Version": "1.78.0",
                "BackendState": "Running",
                "Self": {
                    "HostName": "my-vps",
                    "DNSName": "my-vps.tail42.ts.net.",
                    "TailscaleIPs": ["100.64.10.5", "fd7a:115c:a1e0::5"],
                },
                "CurrentTailnet": {
                    "Name": "tail42.ts.net",
                    "MagicDNSSuffix": "tail42.ts.net",
                    "MagicDNSEnabled": True,
                },
                "CertDomains": ["my-vps.tail42.ts.net"],
            }
        )
        ts_conn, sys_conn, _, _ = self._make_fake_tailscale(
            status_stdout=running_json, serve_stdout="{}"
        )
        conn_status = self._service(
            tailscale_bin=ts_conn, systemctl_bin=sys_conn
        ).tailscale_status()
        self.assertTrue(conn_status["connected"])
        self.assertEqual(conn_status["tailscaleIp"], "100.64.10.5")
        self.assertEqual(conn_status["dnsName"], "my-vps.tail42.ts.net")
        self.assertTrue(conn_status["magicDnsEnabled"])
        self.assertTrue(conn_status["httpsCertsAvailable"])
        self.assertFalse(conn_status["serveEnabled"])
        self.assertIsNone(conn_status["serveConflict"])

        # 5. Connected with Serve matching http://127.0.0.1:3001
        ts_serve, sys_serve, _, _ = self._make_fake_tailscale(
            status_stdout=running_json,
            serve_stdout=json.dumps(
                {
                    "Web": {
                        "my-vps.tail42.ts.net:443": {
                            "Handlers": {"/": {"Proxy": "http://127.0.0.1:3001"}}
                        }
                    }
                }
            ),
        )
        serve_status = self._service(
            tailscale_bin=ts_serve, systemctl_bin=sys_serve
        ).tailscale_status()
        self.assertTrue(serve_status["serveEnabled"])
        self.assertEqual(serve_status["serveUrl"], "https://my-vps.tail42.ts.net")
        self.assertEqual(serve_status["mcpUrl"], "https://my-vps.tail42.ts.net/mcp")
        self.assertIsNone(serve_status["serveConflict"])

        # 6. Connected with port 443 conflict
        ts_conflict, sys_conflict, _, _ = self._make_fake_tailscale(
            status_stdout=running_json,
            serve_stdout=json.dumps(
                {
                    "Web": {
                        "my-vps.tail42.ts.net:443": {
                            "Handlers": {"/": {"Proxy": "http://127.0.0.1:9000"}}
                        }
                    }
                }
            ),
        )
        conflict_status = self._service(
            tailscale_bin=ts_conflict, systemctl_bin=sys_conflict
        ).tailscale_status()
        self.assertFalse(conflict_status["serveEnabled"])
        self.assertEqual(conflict_status["serveConflict"], "http://127.0.0.1:9000")

    def test_set_tailscale_serve_enable_disable_conflict_and_errors(self) -> None:
        running_json = json.dumps(
            {
                "BackendState": "Running",
                "Self": {
                    "HostName": "my-vps",
                    "DNSName": "my-vps.tail42.ts.net.",
                    "TailscaleIPs": ["100.64.10.5"],
                },
                "CurrentTailnet": {"Name": "tail42.ts.net", "MagicDNSEnabled": True},
                "CertDomains": ["my-vps.tail42.ts.net"],
            }
        )

        # Enable succeeds and passes --bg --https=443 http://127.0.0.1:3001
        ts_ok, sys_ok, calls_file, _ = self._make_fake_tailscale(
            status_stdout=running_json, serve_stdout="{}", serve_stateful=True
        )
        svc_ok = self._service(tailscale_bin=ts_ok, systemctl_bin=sys_ok)
        res_on = svc_ok.set_tailscale_serve({"enabled": True})
        self.assertTrue(res_on["ok"])
        res_off = svc_ok.set_tailscale_serve({"enabled": False})
        self.assertTrue(res_off["ok"])
        calls = [
            json.loads(line)
            for line in Path(calls_file).read_text(encoding="utf-8").splitlines()
        ]
        self.assertIn(
            ["serve", "--bg", "--https=443", "http://127.0.0.1:3001"], calls
        )
        self.assertIn(["serve", "--https=443", "--set-path=/", "off"], calls)

        # /mcp path conflict is detected even when / points to VPSAgent, and force=True clears /mcp
        ts_mcp_conflict, sys_mcp_conflict, calls_mcp_conflict, _ = self._make_fake_tailscale(
            status_stdout=running_json,
            serve_stateful=True,
            serve_stdout=json.dumps(
                {
                    "Web": {
                        "my-vps.tail42.ts.net:443": {
                            "Handlers": {
                                "/": {"Proxy": "http://127.0.0.1:3001"},
                                "/mcp": {"Proxy": "http://127.0.0.1:9000"},
                            }
                        }
                    }
                }
            ),
        )
        svc_mcp_conflict = self._service(
            tailscale_bin=ts_mcp_conflict, systemctl_bin=sys_mcp_conflict
        )
        mcp_conflict_status = svc_mcp_conflict.tailscale_status()
        self.assertFalse(mcp_conflict_status["serveEnabled"])
        self.assertEqual(
            mcp_conflict_status["serveConflict"], "/mcp -> http://127.0.0.1:9000"
        )
        with self.assertRaises(rb.BridgeRequestError) as cm_mcp_conflict:
            svc_mcp_conflict.set_tailscale_serve({"enabled": True})
        self.assertEqual(cm_mcp_conflict.exception.status_code, 409)
        svc_mcp_conflict.set_tailscale_serve({"enabled": True, "force": True})
        mcp_calls = [
            json.loads(line)
            for line in Path(calls_mcp_conflict).read_text(encoding="utf-8").splitlines()
        ]
        serve_idx = mcp_calls.index(
            ["serve", "--bg", "--https=443", "http://127.0.0.1:3001"]
        )
        rm_mcp_idx = mcp_calls.index(
            ["serve", "--https=443", "--set-path=/mcp", "off"]
        )
        self.assertLess(serve_idx, rm_mcp_idx)

        # Conflict returns 409 unless force=True
        ts_conflict, sys_conflict, calls_conflict, _ = self._make_fake_tailscale(
            status_stdout=running_json,
            serve_stateful=True,
            serve_stdout=json.dumps(
                {
                    "Web": {
                        "my-vps.tail42.ts.net:443": {
                            "Handlers": {"/": {"Proxy": "http://127.0.0.1:9000"}}
                        }
                    }
                }
            ),
        )
        svc_conflict = self._service(
            tailscale_bin=ts_conflict, systemctl_bin=sys_conflict
        )
        with self.assertRaises(rb.BridgeRequestError) as cm_conflict:
            svc_conflict.set_tailscale_serve({"enabled": True})
        self.assertEqual(cm_conflict.exception.status_code, 409)
        forced = svc_conflict.set_tailscale_serve({"enabled": True, "force": True})
        self.assertTrue(forced["ok"])
        conflict_calls = [
            json.loads(line)
            for line in Path(calls_conflict).read_text(encoding="utf-8").splitlines()
        ]
        self.assertIn(
            ["serve", "--bg", "--https=443", "http://127.0.0.1:3001"], conflict_calls
        )

        # Unreachable loopback target returns 422
        svc_unreach = self._service(
            tailscale_bin=ts_ok, systemctl_bin=sys_ok, target_reachable=False
        )
        with self.assertRaises(rb.BridgeRequestError) as cm_unreach:
            svc_unreach.set_tailscale_serve({"enabled": True})
        self.assertEqual(cm_unreach.exception.status_code, 422)

        # Tailscale admin enablement link surfaced cleanly on error
        ts_admin_err, sys_admin_err, _, _ = self._make_fake_tailscale(
            status_stdout=running_json,
            serve_stdout="{}",
            serve_cmd_rc=1,
            serve_cmd_stderr="Serve is not enabled on your tailnet. To enable, visit: https://login.tailscale.com/f/serve?node=n123",
        )
        svc_admin_err = self._service(
            tailscale_bin=ts_admin_err, systemctl_bin=sys_admin_err
        )
        with self.assertRaises(rb.BridgeRequestError) as cm_admin:
            svc_admin_err.set_tailscale_serve({"enabled": True})
        self.assertEqual(cm_admin.exception.status_code, 422)
        self.assertIn(
            "https://login.tailscale.com/f/serve?node=n123",
            str(cm_admin.exception),
        )

        # Even when tailscale serve exits 0 after printing instructions, must fail closed (422)
        ts_zero_exit, sys_zero_exit, _, _ = self._make_fake_tailscale(
            status_stdout=running_json,
            serve_stdout="{}",
            serve_cmd_rc=0,
            serve_cmd_stderr="To enable Serve, visit: https://login.tailscale.com/f/serve?node=zero",
        )
        svc_zero_exit = self._service(
            tailscale_bin=ts_zero_exit, systemctl_bin=sys_zero_exit
        )
        with self.assertRaises(rb.BridgeRequestError) as cm_zero:
            svc_zero_exit.set_tailscale_serve({"enabled": True})
        self.assertEqual(cm_zero.exception.status_code, 422)
        self.assertIn(
            "https://login.tailscale.com/f/serve?node=zero",
            str(cm_zero.exception),
        )

    def test_connect_tailscale_login_and_authkey_security(self) -> None:
        needs_login_json = json.dumps(
            {
                "BackendState": "Stopped",
                "Self": {"HostName": "my-vps", "DNSName": "", "TailscaleIPs": []},
            }
        )
        ts_login, sys_login, _, _ = self._make_fake_tailscale(
            status_stdout=needs_login_json,
            up_rc=0,
            up_stderr="To authenticate, visit:\n\thttps://login.tailscale.com/a/interactive777\n",
        )
        svc_login = self._service(tailscale_bin=ts_login, systemctl_bin=sys_login)
        login_res = svc_login.connect_tailscale({"mode": "login"})
        self.assertTrue(login_res["ok"])
        self.assertEqual(
            login_res["loginUrl"], "https://login.tailscale.com/a/interactive777"
        )

        # authkey uses --auth-key=file:<tmp>, deletes temp file, and scrubs key from errors
        secret_key = "tskey-auth-kSuperSecretUnitKey-9999"
        ts_key_err, sys_key_err, calls_file, seen_key_file = self._make_fake_tailscale(
            status_stdout=needs_login_json,
            up_rc=1,
            up_stderr=f"invalid key {secret_key}",
        )
        svc_key_err = self._service(
            tailscale_bin=ts_key_err, systemctl_bin=sys_key_err
        )
        with self.assertRaises(rb.BridgeRequestError) as cm_err:
            svc_key_err.connect_tailscale({"mode": "authkey", "authKey": secret_key})
        self.assertEqual(cm_err.exception.status_code, 422)
        self.assertNotIn(secret_key, str(cm_err.exception))

        calls = [
            json.loads(line)
            for line in Path(calls_file).read_text(encoding="utf-8").splitlines()
        ]
        up_call = next(c for c in calls if c[:1] == ["up"])
        auth_arg = next(a for a in up_call if a.startswith("--auth-key=file:"))
        self.assertNotIn(secret_key, " ".join(up_call))
        temp_key_path = auth_arg.split(":", 1)[1]
        self.assertFalse(os.path.exists(temp_key_path))
        self.assertEqual(
            Path(seen_key_file).read_text(encoding="utf-8"),
            secret_key,
        )

        # Invalid authKey returns 400
        with self.assertRaises(rb.BridgeRequestError) as cm_bad:
            svc_key_err.connect_tailscale(
                {"mode": "authkey", "authKey": "bad-invalid-key"}
            )
        self.assertEqual(cm_bad.exception.status_code, 400)

    def test_tailscale_serve_explicit_mcp_mount_and_bare_mcp_rejection(self) -> None:
        running_json = json.dumps(
            {
                "BackendState": "Running",
                "Self": {
                    "HostName": "my-vps",
                    "DNSName": "my-vps.tail42.ts.net.",
                    "TailscaleIPs": ["100.64.10.5"],
                },
                "CurrentTailnet": {"Name": "tail42.ts.net", "MagicDNSEnabled": True},
                "CertDomains": ["my-vps.tail42.ts.net"],
            }
        )

        # Explicit /mcp -> http://127.0.0.1:3001/mcp is accepted as working alongside sibling /wiki,
        # and disabling Serve removes both / and /mcp while keeping /wiki.
        ts_explicit, sys_explicit, calls_explicit, _ = self._make_fake_tailscale(
            status_stdout=running_json,
            serve_stateful=True,
            serve_stdout=json.dumps(
                {
                    "Web": {
                        "my-vps.tail42.ts.net:443": {
                            "Handlers": {
                                "/": {"Proxy": "http://127.0.0.1:3001"},
                                "/mcp": {"Proxy": "http://127.0.0.1:3001/mcp"},
                                "/wiki": {"Proxy": "http://127.0.0.1:8080"},
                            }
                        }
                    }
                }
            ),
        )
        svc_explicit = self._service(
            tailscale_bin=ts_explicit, systemctl_bin=sys_explicit
        )
        explicit_status = svc_explicit.tailscale_status()
        self.assertTrue(explicit_status["serveEnabled"])
        self.assertIsNone(explicit_status["serveConflict"])

        off_res = svc_explicit.set_tailscale_serve({"enabled": False})
        self.assertTrue(off_res["ok"])
        self.assertFalse(off_res["status"]["serveEnabled"])
        explicit_calls = [
            json.loads(line)
            for line in Path(calls_explicit).read_text(encoding="utf-8").splitlines()
        ]
        self.assertIn(["serve", "--https=443", "--set-path=/", "off"], explicit_calls)
        self.assertIn(["serve", "--https=443", "--set-path=/mcp", "off"], explicit_calls)

        # Bare /mcp -> http://127.0.0.1:3001 (missing /mcp suffix) is flagged as a conflict
        # because Tailscale strips /mcp before proxying upstream.
        ts_bare, sys_bare, _, _ = self._make_fake_tailscale(
            status_stdout=running_json,
            serve_stdout=json.dumps(
                {
                    "Web": {
                        "my-vps.tail42.ts.net:443": {
                            "Handlers": {
                                "/": {"Proxy": "http://127.0.0.1:3001"},
                                "/mcp": {"Proxy": "http://127.0.0.1:3001"},
                            }
                        }
                    }
                }
            ),
        )
        bare_status = self._service(
            tailscale_bin=ts_bare, systemctl_bin=sys_bare
        ).tailscale_status()
        self.assertFalse(bare_status["serveEnabled"])
        self.assertEqual(bare_status["serveConflict"], "/mcp -> http://127.0.0.1:3001")

    def test_tailscale_serve_failed_replacement_preserves_existing_mcp_route(
        self,
    ) -> None:
        running_json = json.dumps(
            {
                "BackendState": "Running",
                "Self": {
                    "HostName": "my-vps",
                    "DNSName": "my-vps.tail42.ts.net.",
                    "TailscaleIPs": ["100.64.10.5"],
                },
                "CurrentTailnet": {"Name": "tail42.ts.net", "MagicDNSEnabled": True},
                "CertDomains": ["my-vps.tail42.ts.net"],
            }
        )
        initial_serve = json.dumps(
            {
                "Web": {
                    "my-vps.tail42.ts.net:443": {
                        "Handlers": {
                            "/mcp": {"Proxy": "http://127.0.0.1:9000"},
                        }
                    }
                }
            }
        )

        # Zero-exit with HTTPS approval link must fail closed AND never delete existing /mcp route
        ts_https_req, sys_https_req, calls_https_req, _ = self._make_fake_tailscale(
            status_stdout=running_json,
            serve_stateful=True,
            serve_stdout=initial_serve,
            serve_cmd_rc=0,
            serve_cmd_stderr="To enable HTTPS, visit: https://login.tailscale.com/f/serve?node=httpsreq",
        )
        svc_https_req = self._service(
            tailscale_bin=ts_https_req, systemctl_bin=sys_https_req
        )
        with self.assertRaises(rb.BridgeRequestError) as cm_https:
            svc_https_req.set_tailscale_serve({"enabled": True, "force": True})
        self.assertEqual(cm_https.exception.status_code, 422)
        self.assertIn(
            "https://login.tailscale.com/f/serve?node=httpsreq",
            str(cm_https.exception),
        )
        calls_zero = [
            json.loads(line)
            for line in Path(calls_https_req).read_text(encoding="utf-8").splitlines()
        ]
        self.assertNotIn(
            ["serve", "--https=443", "--set-path=/mcp", "off"], calls_zero
        )
        preserved = svc_https_req.tailscale_status()
        self.assertEqual(preserved["serveConflict"], "/mcp -> http://127.0.0.1:9000")

        # Non-zero serve failure must likewise leave existing /mcp route intact
        ts_err, sys_err, calls_err, _ = self._make_fake_tailscale(
            status_stdout=running_json,
            serve_stateful=True,
            serve_stdout=initial_serve,
            serve_cmd_rc=1,
            serve_cmd_stderr="HTTPS cert approval pending",
        )
        svc_err = self._service(tailscale_bin=ts_err, systemctl_bin=sys_err)
        with self.assertRaises(rb.BridgeRequestError) as cm_err:
            svc_err.set_tailscale_serve({"enabled": True, "force": True})
        self.assertEqual(cm_err.exception.status_code, 422)
        calls_rc1 = [
            json.loads(line)
            for line in Path(calls_err).read_text(encoding="utf-8").splitlines()
        ]
        self.assertNotIn(
            ["serve", "--https=443", "--set-path=/mcp", "off"], calls_rc1
        )
        self.assertEqual(
            svc_err.tailscale_status()["serveConflict"],
            "/mcp -> http://127.0.0.1:9000",
        )

    def test_tailscale_funnel_and_credential_redaction_in_conflicts(self) -> None:
        running_json = json.dumps(
            {
                "BackendState": "Running",
                "Self": {
                    "HostName": "my-vps",
                    "DNSName": "my-vps.tail42.ts.net.",
                    "TailscaleIPs": ["100.64.10.5"],
                },
                "CurrentTailnet": {"Name": "tail42.ts.net", "MagicDNSEnabled": True},
                "CertDomains": ["my-vps.tail42.ts.net"],
            }
        )

        # Public Funnel active -> serveEnabled must be False until switched to private Serve
        ts_funnel, sys_funnel, _, _ = self._make_fake_tailscale(
            status_stdout=running_json,
            serve_stateful=True,
            serve_stdout=json.dumps(
                {
                    "Web": {
                        "my-vps.tail42.ts.net:443": {
                            "Handlers": {"/": {"Proxy": "http://127.0.0.1:3001"}}
                        }
                    },
                    "AllowFunnel": {"my-vps.tail42.ts.net:443": True},
                }
            ),
        )
        svc_funnel = self._service(tailscale_bin=ts_funnel, systemctl_bin=sys_funnel)
        funnel_status = svc_funnel.tailscale_status()
        self.assertFalse(funnel_status["serveEnabled"])
        self.assertIsNone(funnel_status["serveUrl"])
        self.assertIsNone(funnel_status["mcpUrl"])
        self.assertIsNone(funnel_status["serveConflict"])
        self.assertIn("Funnel", funnel_status["detail"] or "")

        switched = svc_funnel.set_tailscale_serve({"enabled": True})
        self.assertTrue(switched["ok"])
        self.assertTrue(switched["status"]["serveEnabled"])
        self.assertEqual(switched["status"]["serveUrl"], "https://my-vps.tail42.ts.net")

        # If Funnel stays active after serve command, fail closed with 422
        ts_stuck, sys_stuck, _, _ = self._make_fake_tailscale(
            status_stdout=running_json,
            serve_stateful=True,
            keep_funnel_on_serve=True,
            serve_stdout=json.dumps(
                {
                    "Web": {
                        "my-vps.tail42.ts.net:443": {
                            "Handlers": {"/": {"Proxy": "http://127.0.0.1:3001"}}
                        }
                    },
                    "AllowFunnel": {"my-vps.tail42.ts.net:443": True},
                }
            ),
        )
        svc_stuck = self._service(tailscale_bin=ts_stuck, systemctl_bin=sys_stuck)
        with self.assertRaises(rb.BridgeRequestError) as cm_stuck:
            svc_stuck.set_tailscale_serve({"enabled": True})
        self.assertEqual(cm_stuck.exception.status_code, 422)
        self.assertIn("Funnel", str(cm_stuck.exception))

        # Proxy URL credentials & query secrets are redacted from status and 409 conflict messages
        ts_creds, sys_creds, _, _ = self._make_fake_tailscale(
            status_stdout=running_json,
            serve_stdout=json.dumps(
                {
                    "Web": {
                        "my-vps.tail42.ts.net:443": {
                            "Handlers": {
                                "/": {
                                    "Proxy": "http://admin:supersecret@127.0.0.1:9000/app?token=querysecret"
                                },
                                "/mcp": {
                                    "Proxy": "http://tokensecret@127.0.0.1:9000/mcp?code=fragsecret#hash"
                                },
                            }
                        }
                    }
                }
            ),
        )
        svc_creds = self._service(tailscale_bin=ts_creds, systemctl_bin=sys_creds)
        cred_status = svc_creds.tailscale_status()
        self.assertIn("[REDACTED]@127.0.0.1:9000/mcp", cred_status["serveConflict"] or "")
        for leaked in (
            "admin",
            "supersecret",
            "querysecret",
            "tokensecret",
            "fragsecret",
            "hash",
        ):
            self.assertNotIn(leaked, str(cred_status))
        with self.assertRaises(rb.BridgeRequestError) as cm_cred_409:
            svc_creds.set_tailscale_serve({"enabled": True})
        self.assertEqual(cm_cred_409.exception.status_code, 409)
        for leaked in ("tokensecret", "fragsecret", "hash"):
            self.assertNotIn(leaked, str(cm_cred_409.exception))

        # Root-only proxy URL with credentials & query string also redacts cleanly
        ts_root_creds, sys_root_creds, _, _ = self._make_fake_tailscale(
            status_stdout=running_json,
            serve_stdout=json.dumps(
                {
                    "Web": {
                        "my-vps.tail42.ts.net:443": {
                            "Handlers": {
                                "/": {
                                    "Proxy": "http://admin:supersecret@127.0.0.1:9000/app?token=querysecret#frag"
                                }
                            }
                        }
                    }
                }
            ),
        )
        root_cred_status = self._service(
            tailscale_bin=ts_root_creds, systemctl_bin=sys_root_creds
        ).tailscale_status()
        self.assertEqual(
            root_cred_status["serveConflict"],
            "http://[REDACTED]@127.0.0.1:9000/app",
        )
        for leaked in ("admin", "supersecret", "querysecret", "frag"):
            self.assertNotIn(leaked, str(root_cred_status))


if __name__ == "__main__":
    unittest.main()
