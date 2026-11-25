#!/usr/bin/env python3
"""
VPSAgent v2 Host Runtime Bridge (`vpsagent-runtime`).

Runs on the Ubuntu host as a privileged systemd daemon listening exclusively on a
permission-scoped Unix domain socket (/var/lib/vpsagent/run/runtime.sock) mounted into
the core control container — never exposing /var/run/docker.sock to any container.

Exposes a strict, schema-validated allowlist of operations:
  - GET  /health               (unauthenticated liveness check)
  - GET  /v1/host/stats        (host CPU, RAM, uptime, and disk metrics)
  - POST /v1/apps/lifecycle    (start | stop | restart | status)
  - POST /v1/apps/build-git    (DNS-checked HTTPS Git clone + Dockerfile build with timeout)
  - POST /v1/apps/logs         (tail bounded & secret-redacted logs)
  - POST /v1/apps/route-caddy  (attach network, write scoped .caddy, validate & reload)
  - POST /v1/apps/remove       (compose down, remove route, optional folder cleanup)
  - POST /v1/apps/statuses     (batch live Compose status lookup with overall deadline)
  - POST /v1/apps/inspect      (live container, Locked Apartment security audit, HTTP probe)
  - POST /v1/apps/readiness    (bounded startup readiness retries accepting 4xx API roots)
"""

from __future__ import annotations

import argparse
from concurrent.futures import ALL_COMPLETED, ThreadPoolExecutor, wait as wait_futures
from contextlib import contextmanager
from datetime import datetime, timezone
import hmac
import http.client
import ipaddress
import json
import os
import platform
import re
import select
import shutil
import signal
import socket
import socketserver
import ssl
import stat
import subprocess
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler
from typing import Any, Callable, Iterator
from urllib.parse import urlparse

MAX_BODY_BYTES = 512 * 1024
MAX_COMMAND_OUTPUT_BYTES = 48 * 1024
MAX_HOST_CMD_TIMEOUT_S = 180
DEFAULT_HOST_CMD_TIMEOUT_S = 30
MAX_READ_FILE_BYTES = 128 * 1024
MAX_WRITE_FILE_BYTES = 256 * 1024

SERVICE_UNIT_PATTERN = re.compile(r"^[A-Za-z0-9@._-]{1,128}$")
ALLOWED_SERVICE_ACTIONS = frozenset(
    {"start", "stop", "restart", "reload", "enable", "disable", "status"}
)
PROTECTED_SERVICES = frozenset({"vpsagent-runtime", "vpsagent-runtime.service"})
PROTECTED_DELETE_PATHS = frozenset(
    {
        "/",
        "/bin",
        "/boot",
        "/dev",
        "/etc",
        "/home",
        "/lib",
        "/lib64",
        "/opt",
        "/proc",
        "/root",
        "/run",
        "/sbin",
        "/srv",
        "/sys",
        "/tmp",
        "/usr",
        "/var",
        "/var/lib",
        "/var/lib/vpsagent",
    }
)
SECRET_FILE_BASENAMES = frozenset(
    {
        ".env",
        "shadow",
        "gshadow",
        "id_rsa",
        "id_ed25519",
        "id_ecdsa",
        "id_dsa",
        "runtime.token",
        "registry.db",
        "registry.db-wal",
        "registry.db-shm",
        "registry.sqlite",
        "registry.sqlite-wal",
        "registry.sqlite-shm",
    }
)
MAX_READ_SCAN_BYTES = 256 * 1024
MAX_COMPOSE_BYTES = 512 * 1024
MAX_ENV_BYTES = 64 * 1024
MAX_LOG_LINE_CHARS = 2000
MAX_LOGS_RESPONSE_BYTES = 64 * 1024
MAX_TAIL_LINES = 500
MAX_STATUS_SLUGS = 100
DEFAULT_STATUS_DEADLINE_S = 25.0
MAX_PROBE_BODY_BYTES = 4096
MAX_PROBE_CONFIG_BYTES = 4 * 1024
DEFAULT_PROBE_TIMEOUT_S = 3.0
DEFAULT_HEALTH_INTERVAL_S = 15.0
DEFAULT_HEALTH_RETRIES = 3
DEFAULT_READINESS_TIMEOUT_S = 15.0
DEFAULT_READINESS_POLL_MS = 500
DEFAULT_BUILD_TIMEOUT_S = 300
MIN_BUILD_TIMEOUT_S = 10
MAX_BUILD_TIMEOUT_S = 600
MAX_BUILD_LOG_LINES = 80

PROBE_PATH_PATTERN = re.compile(r"^/[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=-]{0,127}$")
SLUG_PATTERN = re.compile(r"^[a-z0-9][a-z0-9-]{0,46}[a-z0-9]$")
DOMAIN_PATTERN = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$"
)
EMAIL_PATTERN = re.compile(
    r"^[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,190}\.[A-Za-z]{2,63}$"
)
CONTAINER_NAME_PATTERN = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,62}$")
SERVICE_NAME_PATTERN = re.compile(r"^[a-z0-9][a-z0-9_-]{0,47}$")
IMAGE_REF_PATTERN = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._/:@-]{1,200}$")
ENV_KEY_PATTERN = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,127}$")
GIT_BRANCH_PATTERN = re.compile(r"^[A-Za-z0-9._/-]{1,120}$")
DOCKERFILE_PATH_PATTERN = re.compile(r"^[A-Za-z0-9._/-]{1,200}$")
MEM_LIMIT_PATTERN = re.compile(r"^(\d+)([kmgKMG]?)$")
NUMERIC_USER_PATTERN = re.compile(r"^(\d+)(?::(\d+))?$")
RELATIVE_MOUNT_PATTERN = re.compile(
    r"^\./(?:data|workspace)(?:/[A-Za-z0-9._-]+)*:/[A-Za-z0-9._/-]+(?::(?:ro|rw))?$"
)
INTERPOLATION_RE = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)(?::-([^}]*))?\}")

RESERVED_SLUGS = frozenset(
    {
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
    }
)

BLOCKED_METADATA_HOSTS = frozenset(
    {
        "169.254.169.254",
        "metadata.google.internal",
        "metadata",
        "100.100.100.200",
    }
)

ALLOWED_LIFECYCLE_ACTIONS = frozenset({"start", "stop", "restart", "status"})
ALLOWED_TOP_LEVEL_COMPOSE_KEYS = frozenset({"services", "networks"})
ALLOWED_SERVICE_KEYS = frozenset(
    {
        "image",
        "container_name",
        "restart",
        "working_dir",
        "command",
        "user",
        "init",
        "env_file",
        "environment",
        "volumes",
        "cpus",
        "mem_limit",
        "cap_drop",
        "security_opt",
        "networks",
        "healthcheck",
        "depends_on",
    }
)
ALLOWED_HEALTHCHECK_KEYS = frozenset(
    {"test", "interval", "timeout", "retries", "start_period"}
)
ALLOWED_DEPENDS_ON_CONDITIONS = frozenset(
    {"service_started", "service_healthy", "service_completed_successfully"}
)
ALLOWED_ENV_INTERPOLATION_VARS = frozenset(
    {
        "APP_SLUG",
        "APP_PORT",
        "POSTGRES_DB",
        "POSTGRES_USER",
        "POSTGRES_PASSWORD",
        "REDIS_PASSWORD",
    }
)
ALLOWED_COMMAND_INTERPOLATION_VARS = frozenset(
    {"APP_SLUG", "APP_PORT", "REDIS_PASSWORD"}
)

DISALLOWED_ENV_PREFIXES = ("VPSAGENT_", "VPS_OS_", "DOCKER_", "LD_")
DISALLOWED_ENV_EXACT = frozenset(
    {"PATH", "HOME", "HOSTALIASES", "IFS", "ENV", "BASH_ENV"}
)

PEM_KEY_RE = re.compile(
    r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY-----"
)
AUTH_HEADER_RE = re.compile(
    r"\b(Bearer|Basic)\s+[A-Za-z0-9._~+/=-]{6,}", re.IGNORECASE
)
JSON_SECRET_RE = re.compile(
    r'"([A-Za-z0-9_]*(?:key|token|secret|password|passwd|pass|passphrase|credential|auth)[A-Za-z0-9_]*)"\s*:\s*"([^"]*)"',
    re.IGNORECASE,
)
ENV_OR_YAML_SECRET_RE = re.compile(
    r'\b([A-Za-z0-9_]*(?:key|token|secret|password|passwd|pass|passphrase|credential|auth)[A-Za-z0-9_]*)\s*([:=])\s*("[^"]*"|\'[^\']*\'|[^\s,;]+)',
    re.IGNORECASE,
)
KNOWN_TOKEN_RE = re.compile(
    r"\b(sk-ant-[A-Za-z0-9_-]{8,}|sk-[A-Za-z0-9_-]{8,}|gh[pousr]_[A-Za-z0-9]{10,}|github_pat_[A-Za-z0-9_]{12,}|xox[baprs]-[A-Za-z0-9-]{10,}|AIza[0-9A-Za-z_-]{20,}|vpsmcp_[A-Za-z0-9_-]{16,}|\d{6,12}:AA[A-Za-z0-9_-]{25,})\b"
)

DnsResolver = Callable[[str, int], list[str]]
TlsChecker = Callable[[str, float], tuple[bool, str, str | None]]


def default_tls_checker(
    domain: str, timeout_s: float = 4.0
) -> tuple[bool, str, str | None]:
    """
    Verifies a live TLS certificate handshake against `(domain, 443)` with full
    hostname verification. Returns `(https_active, tls_status, tls_error)`.
    """
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((domain, 443), timeout=timeout_s) as raw_sock:
            with ctx.wrap_socket(raw_sock, server_hostname=domain):
                return True, "active", None
    except ssl.SSLError as exc:
        return False, "failed", redact_secrets(f"TLS handshake failed: {exc}")
    except OSError as exc:
        return False, "pending", redact_secrets(f"HTTPS not reachable yet: {exc}")


class BridgeRequestError(Exception):
    def __init__(
        self,
        status_code: int,
        message: str,
        build_log_tail: list[str] | None = None,
    ) -> None:
        super().__init__(redact_secrets(message))
        self.status_code = status_code
        self.build_log_tail = [
            redact_secrets(line)[:MAX_LOG_LINE_CHARS]
            for line in (build_log_tail or [])
        ][-MAX_BUILD_LOG_LINES:]


def redact_secrets(text: str) -> str:
    if not text:
        return ""
    result = PEM_KEY_RE.sub("[REDACTED_PRIVATE_KEY]", text)
    result = AUTH_HEADER_RE.sub(r"\1 [REDACTED]", result)
    result = JSON_SECRET_RE.sub(r'"\1":"[REDACTED]"', result)
    result = ENV_OR_YAML_SECRET_RE.sub(
        lambda m: f"{m.group(1)}{m.group(2)}{' ' if m.group(2) == ':' else ''}[REDACTED]",
        result,
    )
    return KNOWN_TOKEN_RE.sub("[REDACTED]", result)


def validate_slug(raw: Any) -> str:
    if not isinstance(raw, str):
        raise BridgeRequestError(400, "Field 'slug' must be a string.")
    if not SLUG_PATTERN.match(raw):
        raise BridgeRequestError(
            400,
            f'Invalid app slug "{raw}": must be 2-48 lowercase alphanumeric characters or hyphens.',
        )
    if raw in RESERVED_SLUGS:
        raise BridgeRequestError(400, f'Reserved app slug "{raw}" cannot be used.')
    return raw


def validate_domain(raw: Any) -> str:
    if not isinstance(raw, str):
        raise BridgeRequestError(400, "Field 'domain' must be a string or null.")
    normalized = raw.strip().lower()
    if not DOMAIN_PATTERN.match(normalized):
        raise BridgeRequestError(400, f'Invalid domain name "{raw}".')
    try:
        ipaddress.ip_address(normalized)
        raise BridgeRequestError(400, "IP addresses cannot be used as domain names.")
    except ValueError:
        pass
    return normalized


def validate_email(raw: Any) -> str | None:
    if raw is None:
        return None
    if not isinstance(raw, str):
        raise BridgeRequestError(400, "Field 'acmeEmail' must be a string or null.")
    trimmed = raw.strip()
    if not trimmed:
        return None
    if not EMAIL_PATTERN.match(trimmed):
        raise BridgeRequestError(400, f'Invalid email address "{raw}".')
    return trimmed


def validate_port(raw: Any) -> int:
    if not isinstance(raw, int) or isinstance(raw, bool) or raw < 1 or raw > 65535:
        raise BridgeRequestError(
            400, "Field 'internalPort' must be an integer between 1 and 65535."
        )
    return raw


def validate_tail(raw: Any) -> int:
    if raw is None:
        return 100
    if (
        not isinstance(raw, int)
        or isinstance(raw, bool)
        or raw < 1
        or raw > MAX_TAIL_LINES
    ):
        raise BridgeRequestError(
            400, f"Field 'tail' must be an integer between 1 and {MAX_TAIL_LINES}."
        )
    return raw


def validate_probe_path(raw: Any) -> str:
    if raw is None:
        return "/"
    if not isinstance(raw, str):
        raise BridgeRequestError(
            400, "Field 'probePath' must be a valid HTTP path starting with '/'."
        )
    if (
        not raw
        or any(ch.isspace() for ch in raw)
        or not PROBE_PATH_PATTERN.match(raw)
    ):
        raise BridgeRequestError(
            400, "Field 'probePath' must be a valid HTTP path starting with '/'."
        )
    return raw


def validate_git_branch(raw: Any) -> str | None:
    if raw is None:
        return None
    if not isinstance(raw, str):
        raise BridgeRequestError(400, "Field 'gitBranch' must be a string or null.")
    trimmed = raw.strip()
    if not trimmed:
        return None
    if (
        not GIT_BRANCH_PATTERN.match(trimmed)
        or trimmed.startswith("-")
        or trimmed.startswith("/")
        or trimmed.endswith("/")
        or trimmed.endswith(".lock")
        or ".." in trimmed
        or "//" in trimmed
        or "@{" in trimmed
    ):
        raise BridgeRequestError(400, f'Invalid Git branch name "{raw}".')
    return trimmed


ENV_SECRET_KEY_HINT_RE = re.compile(
    r"(?:key|token|secret|password|passwd|pass|passphrase|credential|auth|private|database_url|redis_url)",
    re.IGNORECASE,
)
EXPOSE_PORT_RE = re.compile(r"^\s*EXPOSE\s+(\d{1,5})(?:/tcp)?(?:\s|$)", re.IGNORECASE | re.MULTILINE)
MAX_INSPECT_FILE_BYTES = 256 * 1024
MAX_ENV_EXAMPLE_BYTES = 32 * 1024


def _derive_slug_and_name_from_repo_url(repo_url: str) -> tuple[str, str]:
    parsed = urlparse(repo_url)
    segments = [seg for seg in parsed.path.split("/") if seg]
    raw_repo = segments[-1] if segments else "github-app"
    if raw_repo.lower().endswith(".git"):
        raw_repo = raw_repo[:-4]
    cleaned = re.sub(r"[^a-z0-9]+", "-", raw_repo.lower()).strip("-")
    if len(cleaned) < 2:
        cleaned = f"{cleaned or 'my'}-app"
    slug = cleaned[:48].rstrip("-")
    if len(slug) < 2 or not SLUG_PATTERN.match(slug) or slug in RESERVED_SLUGS:
        base = re.sub(r"[^a-z0-9-]", "", slug)[:40].strip("-") or "repo"
        slug = f"{base}-app"
        if slug in RESERVED_SLUGS:
            slug = "github-app"
    words = [w for w in re.split(r"[-_.\s]+", raw_repo) if w]
    display_name = " ".join(w[:1].upper() + w[1:] for w in words)[:100] or "GitHub App"
    return slug, display_name


def _is_regular_file_inside(repo_root: str, rel_path: str) -> str | None:
    real_root = os.path.realpath(repo_root)
    current = real_root
    for part in rel_path.split("/"):
        current = os.path.join(current, part)
        if os.path.islink(current):
            return None
    if not os.path.isfile(current):
        return None
    real_target = os.path.realpath(current)
    if not real_target.startswith(real_root + os.sep):
        return None
    return real_target


def _safe_read_repo_text(repo_root: str, rel_path: str, max_bytes: int) -> str | None:
    target = _is_regular_file_inside(repo_root, rel_path)
    if target is None:
        return None
    try:
        return _read_regular_file_nofollow(target, max_bytes, rel_path)
    except BridgeRequestError:
        return None


def _extract_env_example_keys(repo_root: str) -> list[dict[str, Any]]:
    seen: set[str] = set()
    keys: list[dict[str, Any]] = []
    for candidate in (".env.example", ".env.sample", ".env.template", "env.example"):
        content = _safe_read_repo_text(repo_root, candidate, MAX_ENV_EXAMPLE_BYTES)
        if not content:
            continue
        for raw_line in content.splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith("export "):
                line = line[len("export ") :].strip()
            if "=" not in line:
                continue
            key = line.split("=", 1)[0].strip()
            if not key or not ENV_KEY_PATTERN.match(key):
                continue
            if key in DISALLOWED_ENV_EXACT or any(
                key.startswith(prefix) for prefix in DISALLOWED_ENV_PREFIXES
            ):
                continue
            if key in seen:
                continue
            seen.add(key)
            keys.append(
                {
                    "key": key,
                    "isSecret": bool(ENV_SECRET_KEY_HINT_RE.search(key)),
                }
            )
            if len(keys) >= 60:
                return keys
    return keys


def _detect_dockerfile_exposed_port(dockerfile_text: str) -> int:
    match = EXPOSE_PORT_RE.search(dockerfile_text)
    if match:
        port = int(match.group(1))
        if 1 <= port <= 65535:
            return port
    return 8080


def _build_node_install_lines(pkg_manager: str) -> list[str]:
    if pkg_manager == "pnpm":
        return [
            "RUN corepack enable",
            "COPY package.json pnpm-lock.yaml* ./",
            "RUN pnpm install --frozen-lockfile || pnpm install",
        ]
    if pkg_manager == "yarn":
        return [
            "RUN corepack enable",
            "COPY package.json yarn.lock* ./",
            "RUN yarn install --frozen-lockfile || yarn install",
        ]
    return [
        "COPY package.json package-lock.json* ./",
        "RUN if [ -f package-lock.json ]; then npm ci; else npm install; fi",
    ]


def _inspect_cloned_repo(
    clone_dir: str,
    repo_url: str,
    resolved_branch: str | None,
    commit_sha: str | None,
    dockerfile_rel: str,
) -> dict[str, Any]:
    """
    Safely inspects a cloned public repository (strictly no symlink escapes, bounded reads,
    never extracts .env.example values) to detect its runtime, port, companion databases,
    required env key names, and optional auto-generated Locked-Apartment Dockerfile.
    """
    suggested_slug, suggested_name = _derive_slug_and_name_from_repo_url(repo_url)
    env_example_keys = _extract_env_example_keys(clone_dir)
    env_key_names = {item["key"] for item in env_example_keys}
    notes: list[str] = []

    check_df_rel = "Dockerfile" if dockerfile_rel == "auto" else dockerfile_rel
    # Verify explicit dockerfile path does not escape via symlinks
    real_clone_dir = os.path.realpath(clone_dir)
    df_current = real_clone_dir
    for part in check_df_rel.split("/"):
        df_current = os.path.join(df_current, part)
        if os.path.islink(df_current):
            raise BridgeRequestError(
                400,
                f'Security boundary violation: Dockerfile path "{check_df_rel}" contains a symlink.',
            )
    has_dockerfile = os.path.isfile(df_current) and os.path.realpath(
        df_current
    ).startswith(real_clone_dir + os.sep)

    # Gather dependency hints from package.json and Python files for companion suggestions
    pkg_text = _safe_read_repo_text(clone_dir, "package.json", MAX_INSPECT_FILE_BYTES)
    pkg_data: dict[str, Any] | None = None
    if pkg_text:
        try:
            loaded = json.loads(pkg_text)
            if isinstance(loaded, dict):
                pkg_data = loaded
        except json.JSONDecodeError:
            pkg_data = None

    deps: dict[str, Any] = {}
    scripts: dict[str, str] = {}
    if pkg_data is not None:
        for field in ("dependencies", "devDependencies"):
            val = pkg_data.get(field)
            if isinstance(val, dict):
                deps.update(val)
        raw_scripts = pkg_data.get("scripts")
        if isinstance(raw_scripts, dict):
            scripts = {
                str(k): str(v) for k, v in raw_scripts.items() if isinstance(v, str)
            }

    req_text = _safe_read_repo_text(clone_dir, "requirements.txt", MAX_INSPECT_FILE_BYTES) or ""
    pyproject_text = _safe_read_repo_text(clone_dir, "pyproject.toml", MAX_INSPECT_FILE_BYTES) or ""
    py_deps_lower = f"{req_text}\n{pyproject_text}".lower()

    suggested_companions: list[str] = []
    if (
        any(k in env_key_names or k.startswith("POSTGRES_") for k in ("DATABASE_URL",))
        or any(k.startswith("POSTGRES_") for k in env_key_names)
        or any(d in deps for d in ("pg", "postgres", "prisma", "@prisma/client", "drizzle-orm"))
        or any(p in py_deps_lower for p in ("psycopg", "asyncpg", "sqlalchemy", "sqlmodel"))
    ):
        suggested_companions.append("postgres")
    if (
        "REDIS_URL" in env_key_names
        or any(k.startswith("REDIS_") for k in env_key_names)
        or any(d in deps for d in ("redis", "ioredis", "bullmq"))
        or re.search(r"\bredis\b", py_deps_lower)
    ):
        suggested_companions.append("redis")

    if has_dockerfile:
        df_text = _safe_read_repo_text(clone_dir, check_df_rel, MAX_INSPECT_FILE_BYTES) or ""
        suggested_port = _detect_dockerfile_exposed_port(df_text)
        return {
            "ok": True,
            "gitRepoUrl": repo_url,
            "resolvedBranch": resolved_branch,
            "commitSha": commit_sha,
            "hasDockerfile": True,
            "dockerfilePath": check_df_rel,
            "detectedRuntime": "dockerfile",
            "suggestedPort": suggested_port,
            "suggestedSlug": suggested_slug,
            "suggestedName": suggested_name,
            "envExampleKeys": env_example_keys,
            "suggestedCompanions": suggested_companions,
            "buildPlanSummary": f"Uses repository {check_df_rel} (port {suggested_port}).",
            "notes": notes,
            "generatedDockerfile": None,
        }

    # Auto-detect common runtimes when no Dockerfile exists
    if pkg_data is not None:
        if _is_regular_file_inside(clone_dir, "pnpm-lock.yaml"):
            pkg_manager = "pnpm"
            run_prefix = "pnpm"
        elif _is_regular_file_inside(clone_dir, "yarn.lock"):
            pkg_manager = "yarn"
            run_prefix = "yarn"
        else:
            pkg_manager = "npm"
            run_prefix = "npm run"

        install_lines = _build_node_install_lines(pkg_manager)

        if "next" in deps:
            build_cmd = f"{run_prefix} build" if "build" in scripts else "npx next build"
            start_cmd = (
                '["sh", "-c", "npx next start -H 0.0.0.0 -p ${PORT:-3000}"]'
                if pkg_manager == "npm"
                else f'["sh", "-c", "{pkg_manager} exec next start -H 0.0.0.0 -p ${{PORT:-3000}}"]'
            )
            generated_df = "\n".join(
                [
                    "FROM node:22-alpine",
                    "WORKDIR /app",
                    "ENV NODE_ENV=production NEXT_TELEMETRY_DISABLED=1 PORT=3000 HOSTNAME=0.0.0.0",
                    *install_lines,
                    "COPY . .",
                    f"RUN {build_cmd}",
                    "RUN chown -R node:node /app",
                    "USER node",
                    "EXPOSE 3000",
                    f"CMD {start_cmd}",
                    "",
                ]
            )
            notes.append(
                f"No Dockerfile found — auto-detected Next.js ({pkg_manager}) and generated a non-root Locked-Apartment build recipe."
            )
            return {
                "ok": True,
                "gitRepoUrl": repo_url,
                "resolvedBranch": resolved_branch,
                "commitSha": commit_sha,
                "hasDockerfile": False,
                "dockerfilePath": "auto",
                "detectedRuntime": "nextjs",
                "suggestedPort": 3000,
                "suggestedSlug": suggested_slug,
                "suggestedName": suggested_name,
                "envExampleKeys": env_example_keys,
                "suggestedCompanions": suggested_companions,
                "buildPlanSummary": f"Auto-detected Next.js ({pkg_manager}) — runs on port 3000.",
                "notes": notes,
                "generatedDockerfile": generated_df,
            }

        backend_deps = {
            "express",
            "fastify",
            "hono",
            "@nestjs/core",
            "koa",
            "nuxt",
            "astro",
            "@sveltejs/kit",
        }
        start_script = scripts.get("start", "")
        has_server_start = bool(
            re.search(r"\b(node|tsx|ts-node|bun|fastify|nest)\b", start_script)
        )
        if (
            "vite" in deps
            and "build" in scripts
            and not any(d in deps for d in backend_deps)
            and not has_server_start
        ):
            build_cmd = f"{run_prefix} build"
            generated_df = "\n".join(
                [
                    "FROM node:22-alpine AS builder",
                    "WORKDIR /app",
                    *install_lines,
                    "COPY . .",
                    f"RUN {build_cmd}",
                    "",
                    "FROM nginxinc/nginx-unprivileged:alpine",
                    "COPY --from=builder /app/dist /usr/share/nginx/html",
                    r'RUN printf "server {\n  listen 8080;\n  server_name _;\n  root /usr/share/nginx/html;\n  index index.html;\n  location / {\n    try_files \$uri \$uri/ /index.html;\n  }\n}\n" > /etc/nginx/conf.d/default.conf',
                    "EXPOSE 8080",
                    "",
                ]
            )
            notes.append(
                f"No Dockerfile found — auto-detected Vite web app ({pkg_manager}) and packaged it with an unprivileged static web server."
            )
            return {
                "ok": True,
                "gitRepoUrl": repo_url,
                "resolvedBranch": resolved_branch,
                "commitSha": commit_sha,
                "hasDockerfile": False,
                "dockerfilePath": "auto",
                "detectedRuntime": "vite-static",
                "suggestedPort": 8080,
                "suggestedSlug": suggested_slug,
                "suggestedName": suggested_name,
                "envExampleKeys": env_example_keys,
                "suggestedCompanions": suggested_companions,
                "buildPlanSummary": f"Auto-detected Vite frontend ({pkg_manager}) — builds dist/ and serves on port 8080.",
                "notes": notes,
                "generatedDockerfile": generated_df,
            }

        has_build = "build" in scripts
        if "start" in scripts:
            start_cmd = (
                '["pnpm", "start"]'
                if pkg_manager == "pnpm"
                else '["yarn", "start"]'
                if pkg_manager == "yarn"
                else '["npm", "start"]'
            )
        elif _is_regular_file_inside(clone_dir, "server.js"):
            start_cmd = '["node", "server.js"]'
        elif _is_regular_file_inside(clone_dir, "index.js"):
            start_cmd = '["node", "index.js"]'
        else:
            start_cmd = '["npm", "start"]'

        node_lines = [
            "FROM node:22-alpine",
            "WORKDIR /app",
            "ENV NODE_ENV=production PORT=3000 HOST=0.0.0.0",
            *install_lines,
            "COPY . .",
        ]
        if has_build:
            node_lines.append(f"RUN {run_prefix} build")
        node_lines.extend(
            [
                "RUN chown -R node:node /app",
                "USER node",
                "EXPOSE 3000",
                f"CMD {start_cmd}",
                "",
            ]
        )
        notes.append(
            f"No Dockerfile found — auto-detected Node.js ({pkg_manager}) and generated a non-root Locked-Apartment build recipe."
        )
        return {
            "ok": True,
            "gitRepoUrl": repo_url,
            "resolvedBranch": resolved_branch,
            "commitSha": commit_sha,
            "hasDockerfile": False,
            "dockerfilePath": "auto",
            "detectedRuntime": "node",
            "suggestedPort": 3000,
            "suggestedSlug": suggested_slug,
            "suggestedName": suggested_name,
            "envExampleKeys": env_example_keys,
            "suggestedCompanions": suggested_companions,
            "buildPlanSummary": f"Auto-detected Node.js ({pkg_manager}) — runs on port 3000.",
            "notes": notes,
            "generatedDockerfile": "\n".join(node_lines),
        }

    if req_text or pyproject_text:
        has_main = _is_regular_file_inside(clone_dir, "main.py") is not None
        has_app = _is_regular_file_inside(clone_dir, "app.py") is not None
        has_wsgi = _is_regular_file_inside(clone_dir, "wsgi.py") is not None
        if ("fastapi" in py_deps_lower or "uvicorn" in py_deps_lower) and (
            has_main or has_app
        ):
            mod = "main" if has_main else "app"
            py_cmd = f'["python", "-m", "uvicorn", "{mod}:app", "--host", "0.0.0.0", "--port", "8000"]'
            py_desc = f"FastAPI / Uvicorn ({mod}:app)"
        elif "gunicorn" in py_deps_lower and (has_wsgi or has_app or has_main):
            mod = "wsgi" if has_wsgi else ("app" if has_app else "main")
            py_cmd = f'["python", "-m", "gunicorn", "--bind", "0.0.0.0:8000", "{mod}:app"]'
            py_desc = f"Gunicorn ({mod}:app)"
        elif "flask" in py_deps_lower and (has_app or has_main):
            mod = "app" if has_app else "main"
            py_cmd = f'["python", "-m", "flask", "--app", "{mod}", "run", "--host", "0.0.0.0", "--port", "8000"]'
            py_desc = f"Flask ({mod}.py)"
        elif has_main:
            py_cmd = '["python", "main.py"]'
            py_desc = "Python (main.py)"
        elif has_app:
            py_cmd = '["python", "app.py"]'
            py_desc = "Python (app.py)"
        else:
            py_cmd = '["python", "-m", "http.server", "8000"]'
            py_desc = "Python"

        py_lines = [
            "FROM python:3.12-slim",
            "WORKDIR /app",
            "ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PORT=8000",
            "RUN useradd --create-home --uid 10001 appuser",
            "COPY . .",
        ]
        if req_text:
            py_lines.append(
                "RUN pip install --no-cache-dir -r requirements.txt"
            )
        elif pyproject_text:
            py_lines.append("RUN pip install --no-cache-dir .")
        py_lines.extend(
            [
                "RUN chown -R appuser:appuser /app",
                "USER appuser",
                "EXPOSE 8000",
                f"CMD {py_cmd}",
                "",
            ]
        )
        notes.append(
            f"No Dockerfile found — auto-detected {py_desc} and generated a non-root Locked-Apartment build recipe."
        )
        return {
            "ok": True,
            "gitRepoUrl": repo_url,
            "resolvedBranch": resolved_branch,
            "commitSha": commit_sha,
            "hasDockerfile": False,
            "dockerfilePath": "auto",
            "detectedRuntime": "python",
            "suggestedPort": 8000,
            "suggestedSlug": suggested_slug,
            "suggestedName": suggested_name,
            "envExampleKeys": env_example_keys,
            "suggestedCompanions": suggested_companions,
            "buildPlanSummary": f"Auto-detected {py_desc} — runs on port 8000.",
            "notes": notes,
            "generatedDockerfile": "\n".join(py_lines),
        }

    if _is_regular_file_inside(clone_dir, "index.html"):
        generated_df = "\n".join(
            [
                "FROM nginxinc/nginx-unprivileged:alpine",
                "COPY . /usr/share/nginx/html",
                "EXPOSE 8080",
                "",
            ]
        )
        notes.append(
            "No Dockerfile found — auto-detected static HTML site (index.html) and packaged it with an unprivileged web server."
        )
        return {
            "ok": True,
            "gitRepoUrl": repo_url,
            "resolvedBranch": resolved_branch,
            "commitSha": commit_sha,
            "hasDockerfile": False,
            "dockerfilePath": "auto",
            "detectedRuntime": "static",
            "suggestedPort": 8080,
            "suggestedSlug": suggested_slug,
            "suggestedName": suggested_name,
            "envExampleKeys": env_example_keys,
            "suggestedCompanions": suggested_companions,
            "buildPlanSummary": "Auto-detected static website (index.html) — serves on port 8080.",
            "notes": notes,
            "generatedDockerfile": generated_df,
        }

    notes.append(
        "No Dockerfile found and no Node.js (package.json), Python (requirements.txt/pyproject.toml), or static (index.html) project was detected. Add a Dockerfile to this repository to deploy it."
    )
    return {
        "ok": True,
        "gitRepoUrl": repo_url,
        "resolvedBranch": resolved_branch,
        "commitSha": commit_sha,
        "hasDockerfile": False,
        "dockerfilePath": check_df_rel,
        "detectedRuntime": "unknown",
        "suggestedPort": 8080,
        "suggestedSlug": suggested_slug,
        "suggestedName": suggested_name,
        "envExampleKeys": env_example_keys,
        "suggestedCompanions": suggested_companions,
        "buildPlanSummary": "Could not auto-detect project type — a Dockerfile is required.",
        "notes": notes,
        "generatedDockerfile": None,
    }


def validate_dockerfile_path(raw: Any) -> str:
    if raw is None:
        return "Dockerfile"
    if not isinstance(raw, str):
        raise BridgeRequestError(400, "Field 'dockerfilePath' must be a string.")
    trimmed = raw.strip()
    if (
        not trimmed
        or not DOCKERFILE_PATH_PATTERN.match(trimmed)
        or trimmed.startswith("/")
        or trimmed.startswith("-")
        or "\\" in trimmed
        or ".." in trimmed
        or any(seg in ("", ".", "..") for seg in trimmed.split("/"))
    ):
        raise BridgeRequestError(
            400,
            f'Invalid Dockerfile path "{raw}": must be a safe relative path inside the repository.',
        )
    return trimmed


def _assert_public_ip_address(ip_str: str, raw_host: str) -> None:
    clean_ip = ip_str.strip().strip("[]").split("%", 1)[0]
    try:
        addr = ipaddress.ip_address(clean_ip)
    except ValueError as exc:
        raise BridgeRequestError(
            400, f'Invalid resolved IP address for host "{raw_host}".'
        ) from exc

    # Unwrap IPv4-mapped IPv6 addresses (e.g. ::ffff:169.254.169.254 or ::ffff:10.0.0.1)
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
        addr = addr.ipv4_mapped

    # Cloud metadata checks (AWS/GCP/Azure 169.254.0.0/16, Alibaba 100.100.100.200, AWS IMDSv2 IPv6)
    if isinstance(addr, ipaddress.IPv4Address):
        octets = addr.packed
        if octets[0] == 169 and octets[1] == 254:
            raise BridgeRequestError(400, f'Blocked cloud metadata host "{raw_host}".')
        if (octets[0], octets[1], octets[2], octets[3]) == (100, 100, 100, 200):
            raise BridgeRequestError(400, f'Blocked cloud metadata host "{raw_host}".')
        # CGNAT 100.64.0.0/10
        if octets[0] == 100 and 64 <= octets[1] <= 127:
            raise BridgeRequestError(400, f'Blocked private network host "{raw_host}".')
    else:
        if addr == ipaddress.IPv6Address("fd00:ec2::254"):
            raise BridgeRequestError(400, f'Blocked cloud metadata host "{raw_host}".')

    if addr.is_link_local:
        raise BridgeRequestError(400, f'Blocked link-local host "{raw_host}".')
    if addr.is_loopback or addr.is_unspecified:
        raise BridgeRequestError(400, f'Blocked loopback host "{raw_host}".')
    if addr.is_private or addr.is_multicast or addr.is_reserved:
        raise BridgeRequestError(400, f'Blocked private network host "{raw_host}".')


def default_dns_resolver(hostname: str, port: int) -> list[str]:
    infos = socket.getaddrinfo(hostname, port, type=socket.SOCK_STREAM)
    ips: list[str] = []
    for info in infos:
        sockaddr = info[4]
        if sockaddr and isinstance(sockaddr[0], str):
            ips.append(sockaddr[0])
    return ips


def validate_git_repo_url_with_ips(
    raw: Any, dns_resolver: DnsResolver | None = None
) -> tuple[str, str, int, list[str]]:
    """
    Validates a public HTTPS Git repository URL and returns
    `(normalized_url, host, port, validated_public_ips)` so the subsequent
    TCP connection can be pinned strictly to the validated public IP(s).
    """
    if not isinstance(raw, str) or not raw.strip():
        raise BridgeRequestError(400, "Field 'gitRepoUrl' must be a non-empty string.")
    trimmed = raw.strip()
    if any(ch.isspace() or ord(ch) < 32 for ch in trimmed):
        raise BridgeRequestError(
            400,
            "Git repository URL contains invalid whitespace or control characters.",
        )

    parsed = urlparse(trimmed)
    if parsed.scheme.lower() != "https":
        raise BridgeRequestError(400, "Git repository URL must use https://.")
    if parsed.username or parsed.password:
        raise BridgeRequestError(400, "Git repository URL must not embed credentials.")
    if not parsed.hostname:
        raise BridgeRequestError(400, "Git repository URL is missing a hostname.")

    raw_hostname = parsed.hostname.lower()
    host = raw_hostname.strip("[]").rstrip(".")
    if not host:
        raise BridgeRequestError(400, "Git repository URL is missing a hostname.")
    if host in BLOCKED_METADATA_HOSTS:
        raise BridgeRequestError(400, f'Blocked cloud metadata host "{raw_hostname}".')
    if host == "localhost" or host.endswith(".localhost"):
        raise BridgeRequestError(400, f'Blocked loopback host "{raw_hostname}".')

    try:
        port = parsed.port or 443
    except ValueError as exc:
        raise BridgeRequestError(400, "Git repository URL has an invalid port.") from exc

    is_literal_ip = False
    try:
        ipaddress.ip_address(host.split("%", 1)[0])
        is_literal_ip = True
    except ValueError:
        is_literal_ip = False

    validated_ips: list[str] = []
    if is_literal_ip:
        _assert_public_ip_address(host, raw_hostname)
        validated_ips.append(host.split("%", 1)[0])
    else:
        if "." not in host:
            raise BridgeRequestError(
                400, f'Blocked single-label internal host "{raw_hostname}".'
            )
        resolver = dns_resolver or default_dns_resolver
        try:
            resolved_ips = resolver(host, port)
        except OSError as exc:
            raise BridgeRequestError(
                400, f'Could not resolve Git host "{raw_hostname}": {exc}'
            ) from exc
        if not resolved_ips:
            raise BridgeRequestError(
                400, f'Could not resolve Git host "{raw_hostname}".'
            )
        seen: set[str] = set()
        for ip_str in resolved_ips:
            _assert_public_ip_address(ip_str, raw_hostname)
            clean = ip_str.strip().strip("[]").split("%", 1)[0]
            if clean not in seen:
                seen.add(clean)
                validated_ips.append(clean)

    return trimmed, host, port, validated_ips


def validate_git_repo_url(
    raw: Any, dns_resolver: DnsResolver | None = None
) -> str:
    """
    Validates a public HTTPS Git repository URL and checks every DNS-resolved IP
    against loopback, RFC1918/ULA private networks, CGNAT, and cloud metadata endpoints.
    """
    url, _, _, _ = validate_git_repo_url_with_ips(raw, dns_resolver=dns_resolver)
    return url


class _PinnedGitConnectProxy:
    """
    Single-purpose ephemeral loopback HTTP CONNECT proxy used during `git clone`.
    Enforces that Git/libcurl can ONLY connect to the exact validated hostname,
    port, and pre-validated public IP(s) — eliminating DNS rebinding TOCTOU while
    preserving full hostname SNI and TLS certificate verification.
    """

    def __init__(
        self,
        expected_host: str,
        expected_port: int,
        validated_ips: list[str],
        connect_timeout: float = 15.0,
    ) -> None:
        self.expected_host = expected_host.lower().strip("[]").rstrip(".")
        self.expected_port = expected_port
        self.validated_ips = list(validated_ips)
        self.connect_timeout = connect_timeout
        self._sock: socket.socket | None = None
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self.port = 0

    def __enter__(self) -> "_PinnedGitConnectProxy":
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", 0))
        srv.listen(8)
        srv.settimeout(0.5)
        self._sock = srv
        self.port = int(srv.getsockname()[1])
        self._thread = threading.Thread(target=self._accept_loop, daemon=True)
        self._thread.start()
        return self

    def __exit__(self, *_exc: object) -> None:
        self._stop.set()
        if self._sock is not None:
            try:
                self._sock.close()
            except OSError:
                pass
        if self._thread is not None:
            self._thread.join(timeout=2.0)

    def _accept_loop(self) -> None:
        assert self._sock is not None
        while not self._stop.is_set():
            try:
                client, _ = self._sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(
                target=self._handle_client, args=(client,), daemon=True
            ).start()

    def _handle_client(self, client: socket.socket) -> None:
        upstream: socket.socket | None = None
        try:
            client.settimeout(10.0)
            req_buf = b""
            while b"\r\n\r\n" not in req_buf and len(req_buf) < 8192:
                chunk = client.recv(2048)
                if not chunk:
                    return
                req_buf += chunk
            first_line = req_buf.split(b"\r\n", 1)[0].decode("latin-1", "replace")
            parts = first_line.split()
            if len(parts) < 2 or parts[0].upper() != "CONNECT":
                client.sendall(b"HTTP/1.1 405 Method Not Allowed\r\n\r\n")
                return
            authority = parts[1]
            if authority.startswith("["):
                host_part, _, port_part = authority[1:].partition("]:")
            else:
                host_part, _, port_part = authority.rpartition(":")
            req_host = host_part.lower().rstrip(".")
            try:
                req_port = int(port_part)
            except ValueError:
                client.sendall(b"HTTP/1.1 400 Bad Request\r\n\r\n")
                return
            if req_host != self.expected_host or req_port != self.expected_port:
                client.sendall(b"HTTP/1.1 403 Forbidden\r\n\r\n")
                return

            last_err: OSError | None = None
            for ip in self.validated_ips:
                try:
                    _assert_public_ip_address(ip, self.expected_host)
                    upstream = socket.create_connection(
                        (ip, self.expected_port), timeout=self.connect_timeout
                    )
                    break
                except (OSError, BridgeRequestError) as exc:
                    last_err = exc if isinstance(exc, OSError) else OSError(str(exc))
                    upstream = None
            if upstream is None:
                client.sendall(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
                return

            client.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            client.setblocking(False)
            upstream.setblocking(False)
            sockets = [client, upstream]
            while not self._stop.is_set():
                readable, _, exceptional = select.select(sockets, [], sockets, 1.0)
                if exceptional:
                    break
                for src in readable:
                    dst = upstream if src is client else client
                    try:
                        data = src.recv(16384)
                    except OSError:
                        return
                    if not data:
                        return
                    dst.setblocking(True)
                    dst.settimeout(10.0)
                    dst.sendall(data)
                    dst.setblocking(False)
        except OSError:
            pass
        finally:
            if upstream is not None:
                try:
                    upstream.close()
                except OSError:
                    pass
            try:
                client.close()
            except OSError:
                pass


def _probe_container_http(
    ip_addr: str,
    port: int,
    probe_path: str,
    timeout_s: float = DEFAULT_PROBE_TIMEOUT_S,
) -> dict[str, Any]:
    """
    Probes an app container's private bridge IP over HTTP.
    Treats any non-5xx HTTP status (`100 <= status < 500`, including 4xx API roots)
    as `ok: True` (server is listening and routable).
    """
    try:
        parsed_ip = ipaddress.ip_address(ip_addr)
    except ValueError:
        return {
            "attempted": False,
            "ok": False,
            "statusCode": None,
            "latencyMs": None,
            "contentType": None,
            "error": "Container IP address is invalid.",
        }
    if (
        parsed_ip.is_link_local
        or parsed_ip.is_multicast
        or parsed_ip.is_unspecified
        or not (parsed_ip.is_private or parsed_ip.is_loopback)
    ):
        return {
            "attempted": False,
            "ok": False,
            "statusCode": None,
            "latencyMs": None,
            "contentType": None,
            "error": "Refused HTTP probe against non-private container address.",
        }

    t0 = time.perf_counter()
    conn: http.client.HTTPConnection | None = None
    try:
        conn = http.client.HTTPConnection(ip_addr, port, timeout=timeout_s)
        conn.request(
            "GET",
            probe_path,
            headers={
                "Host": "localhost",
                "User-Agent": "vpsagent-probe/2",
                "Connection": "close",
            },
        )
        resp = conn.getresponse()
        resp.read(MAX_PROBE_BODY_BYTES)
        elapsed_ms = round((time.perf_counter() - t0) * 1000, 2)
        return {
            "attempted": True,
            "ok": 100 <= resp.status < 500,
            "statusCode": resp.status,
            "latencyMs": elapsed_ms,
            "contentType": resp.getheader("Content-Type"),
            "error": None,
        }
    except (OSError, http.client.HTTPException) as exc:
        elapsed_ms = round((time.perf_counter() - t0) * 1000, 2)
        return {
            "attempted": True,
            "ok": False,
            "statusCode": None,
            "latencyMs": elapsed_ms,
            "contentType": None,
            "error": redact_secrets(str(exc)),
        }
    finally:
        if conn is not None:
            try:
                conn.close()
            except Exception:
                pass


def _sanitized_subprocess_env(extra: dict[str, str] | None = None) -> dict[str, str]:
    """Never inherit core secrets from systemd EnvironmentFile into docker/git subprocesses."""
    allowlist = [
        "PATH",
        "HOME",
        "DOCKER_HOST",
        "DOCKER_CONFIG",
        "TMPDIR",
        "LANG",
        "LC_ALL",
        "SSL_CERT_FILE",
        "SSL_CERT_DIR",
    ]
    if sys.platform == "win32":
        allowlist.extend(["SYSTEMROOT", "PATHEXT", "COMSPEC", "TEMP", "TMP"])
    env = {k: os.environ[k] for k in allowlist if k in os.environ}
    if extra:
        env.update(extra)
    return env


def _read_regular_file_nofollow(path: str, max_bytes: int, label: str) -> str:
    if not os.path.lexists(path):
        raise BridgeRequestError(404, f"{label} does not exist.")
    if os.path.islink(path):
        raise BridgeRequestError(
            400, f"Security boundary violation: {label} cannot be a symlink."
        )
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise BridgeRequestError(400, f"Could not safely open {label}: {exc}") from exc
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise BridgeRequestError(
                400, f"Security boundary violation: {label} must be a regular file."
            )
        if st.st_size > max_bytes:
            raise BridgeRequestError(400, f"{label} exceeds maximum allowed size.")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(fd, 65536)
            if not chunk:
                break
            total += len(chunk)
            if total > max_bytes:
                raise BridgeRequestError(400, f"{label} exceeds maximum allowed size.")
            chunks.append(chunk)
        return b"".join(chunks).decode("utf-8")
    except UnicodeDecodeError as exc:
        raise BridgeRequestError(400, f"{label} must be valid UTF-8 text.") from exc
    finally:
        os.close(fd)


def _strip_yaml_comment(line: str) -> str:
    in_single = False
    in_double = False
    escaped = False
    for idx, ch in enumerate(line):
        if escaped:
            escaped = False
            continue
        if ch == "\\" and in_double:
            escaped = True
            continue
        if ch == "'" and not in_double:
            in_single = not in_single
        elif ch == '"' and not in_single:
            in_double = not in_double
        elif ch == "#" and not in_single and not in_double:
            if idx == 0 or line[idx - 1].isspace():
                return line[:idx]
    return line


def _split_inline_yaml_list(inner: str) -> list[str]:
    items: list[str] = []
    buf: list[str] = []
    in_single = False
    in_double = False
    escaped = False
    for ch in inner:
        if escaped:
            buf.append(ch)
            escaped = False
            continue
        if ch == "\\" and in_double:
            buf.append(ch)
            escaped = True
            continue
        if ch == "'" and not in_double:
            in_single = not in_single
            buf.append(ch)
            continue
        if ch == '"' and not in_single:
            in_double = not in_double
            buf.append(ch)
            continue
        if ch == "," and not in_single and not in_double:
            items.append("".join(buf))
            buf.clear()
            continue
        buf.append(ch)
    if buf or items:
        items.append("".join(buf))
    return items


def _parse_yaml_scalar(raw: str) -> Any:
    val = raw.strip()
    if val == "":
        return None
    if val in ("true", "True", "TRUE"):
        return True
    if val in ("false", "False", "FALSE"):
        return False
    if val in ("null", "Null", "~"):
        return None
    if val.startswith("[") and val.endswith("]"):
        try:
            parsed = json.loads(val)
            if isinstance(parsed, list):
                return parsed
        except json.JSONDecodeError:
            pass
        inner = val[1:-1].strip()
        if not inner:
            return []
        return [_parse_yaml_scalar(part) for part in _split_inline_yaml_list(inner)]
    if (val.startswith('"') and val.endswith('"')) or (
        val.startswith("'") and val.endswith("'")
    ):
        if len(val) >= 2:
            if val.startswith('"'):
                try:
                    return json.loads(val)
                except json.JSONDecodeError:
                    return val[1:-1]
            return val[1:-1]
    if re.fullmatch(r"-?\d+", val):
        return int(val)
    if re.fullmatch(r"-?\d+\.\d+", val):
        return float(val)
    if val.startswith(("&", "*", "!")):
        raise BridgeRequestError(
            400, "YAML anchors, aliases, and custom tags are forbidden."
        )
    return val


def _split_yaml_mapping(text: str) -> tuple[str, str] | None:
    in_single = False
    in_double = False
    escaped = False
    for idx, ch in enumerate(text):
        if escaped:
            escaped = False
            continue
        if ch == "\\" and in_double:
            escaped = True
            continue
        if ch == "'" and not in_double:
            in_single = not in_single
        elif ch == '"' and not in_single:
            in_double = not in_double
        elif ch == ":" and not in_single and not in_double:
            if idx + 1 == len(text) or text[idx + 1].isspace():
                return text[:idx].strip().strip("'\""), text[idx + 1 :].strip()
    return None


def parse_simple_yaml(content: str) -> dict[str, Any]:
    """
    Indentation-aware strict YAML subset parser for Locked Apartment Compose files.
    Rejects anchors, aliases, tags, multi-document streams, and tabs in indentation.
    """
    tokens: list[tuple[int, str]] = []
    for lineno, raw_line in enumerate(content.splitlines(), start=1):
        stripped_comment = _strip_yaml_comment(raw_line).rstrip()
        if not stripped_comment.strip():
            continue
        if stripped_comment.strip() in ("---", "..."):
            raise BridgeRequestError(400, "Multi-document YAML streams are forbidden.")
        leading = len(stripped_comment) - len(stripped_comment.lstrip(" "))
        if "\t" in stripped_comment[:leading] or stripped_comment.startswith("\t"):
            raise BridgeRequestError(
                400, f"Tabs are not permitted in YAML indentation (line {lineno})."
            )
        tokens.append((leading, stripped_comment[leading:]))

    if not tokens:
        raise BridgeRequestError(400, "docker-compose.yml cannot be empty.")

    def parse_block(index: int, expected_indent: int) -> tuple[Any, int]:
        if index >= len(tokens):
            return {}, index
        indent, text = tokens[index]
        if indent < expected_indent:
            return None, index

        if text.startswith("- ") or text == "-":
            items: list[Any] = []
            list_indent = indent
            while index < len(tokens):
                cur_indent, cur_text = tokens[index]
                if cur_indent != list_indent or not (
                    cur_text.startswith("- ") or cur_text == "-"
                ):
                    break
                after_dash = cur_text[1:].strip()
                index += 1
                if not after_dash:
                    nested, index = parse_block(index, list_indent + 1)
                    items.append(nested)
                    continue
                kv = _split_yaml_mapping(after_dash)
                if kv is not None:
                    key, val_part = kv
                    item_dict: dict[str, Any] = {}
                    if val_part == "":
                        nested, index = parse_block(index, list_indent + 2)
                        item_dict[key] = nested if nested is not None else {}
                    else:
                        item_dict[key] = _parse_yaml_scalar(val_part)
                    if index < len(tokens) and tokens[index][0] > list_indent:
                        more, index = parse_block(index, tokens[index][0])
                        if isinstance(more, dict):
                            item_dict.update(more)
                        else:
                            raise BridgeRequestError(
                                400, "Invalid list item mapping in Compose file."
                            )
                    items.append(item_dict)
                else:
                    items.append(_parse_yaml_scalar(after_dash))
            return items, index

        mapping: dict[str, Any] = {}
        map_indent = indent
        while index < len(tokens):
            cur_indent, cur_text = tokens[index]
            if cur_indent < map_indent:
                break
            if cur_indent > map_indent or cur_text.startswith("- ") or cur_text == "-":
                raise BridgeRequestError(
                    400, f"Invalid YAML structure near '{cur_text}'."
                )
            kv = _split_yaml_mapping(cur_text)
            if kv is None:
                raise BridgeRequestError(
                    400, f"Expected key: value mapping near '{cur_text}'."
                )
            key, val_part = kv
            if not key:
                raise BridgeRequestError(400, "Empty YAML key is not allowed.")
            index += 1
            if val_part == "":
                if index < len(tokens) and tokens[index][0] > map_indent:
                    nested, index = parse_block(index, tokens[index][0])
                    mapping[key] = nested
                else:
                    mapping[key] = {}
            else:
                mapping[key] = _parse_yaml_scalar(val_part)
        return mapping, index

    parsed, next_idx = parse_block(0, tokens[0][0])
    if next_idx != len(tokens) or not isinstance(parsed, dict):
        raise BridgeRequestError(
            400, "docker-compose.yml root must be a YAML mapping."
        )
    return parsed


def _unescape_double_quoted_env(inner: str) -> str:
    out: list[str] = []
    i = 0
    n = len(inner)
    while i < n:
        ch = inner[i]
        if ch == "\\" and i + 1 < n:
            nxt = inner[i + 1]
            if nxt == "n":
                out.append("\n")
            elif nxt == "r":
                out.append("\r")
            elif nxt == '"':
                out.append('"')
            elif nxt == "\\":
                out.append("\\")
            else:
                out.append("\\" + nxt)
            i += 2
            continue
        out.append(ch)
        i += 1
    return "".join(out)


def parse_and_validate_env_file(env_text: str, slug: str) -> dict[str, str]:
    env_map: dict[str, str] = {}
    for lineno, raw_line in enumerate(env_text.splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            raise BridgeRequestError(400, f"Invalid .env syntax at line {lineno}.")
        key, val = line.split("=", 1)
        key = key.strip()
        val = val.strip()
        if not ENV_KEY_PATTERN.match(key):
            raise BridgeRequestError(
                400, f'Invalid .env key "{key}" at line {lineno}.'
            )
        if key in DISALLOWED_ENV_EXACT or key.startswith(DISALLOWED_ENV_PREFIXES):
            raise BridgeRequestError(
                400, f'Forbidden environment variable "{key}" in app .env.'
            )
        if "\x00" in val:
            raise BridgeRequestError(
                400, f'Invalid null byte in .env value for "{key}".'
            )
        if len(val) >= 2 and val.startswith("'") and val.endswith("'"):
            val = val[1:-1]
        elif len(val) >= 2 and val.startswith('"') and val.endswith('"'):
            val = _unescape_double_quoted_env(val[1:-1])
        env_map[key] = val

    if "APP_SLUG" in env_map and env_map["APP_SLUG"] != slug:
        raise BridgeRequestError(
            400,
            f'App .env APP_SLUG="{env_map["APP_SLUG"]}" does not match slug "{slug}".',
        )
    if "APP_PORT" in env_map and env_map["APP_PORT"]:
        try:
            validate_port(int(env_map["APP_PORT"]))
        except ValueError as exc:
            raise BridgeRequestError(400, "Invalid APP_PORT in app .env.") from exc
    if "APP_IMAGE" in env_map and env_map["APP_IMAGE"]:
        if "$" in env_map["APP_IMAGE"] or not IMAGE_REF_PATTERN.match(
            env_map["APP_IMAGE"]
        ):
            raise BridgeRequestError(400, "Invalid APP_IMAGE in app .env.")
    return env_map


def _resolve_allowed_vars(
    value: str, env_map: dict[str, str], allowed_vars: frozenset[str] | set[str], field: str
) -> str:
    if "$" not in value:
        return value

    out: list[str] = []
    pos = 0
    for match in INTERPOLATION_RE.finditer(value):
        literal_prefix = value[pos : match.start()]
        if "$" in literal_prefix:
            raise BridgeRequestError(
                400, f"Unsupported variable expansion syntax in Compose {field}."
            )
        out.append(literal_prefix)

        var_name = match.group(1)
        default_val = match.group(2)
        if var_name not in allowed_vars:
            raise BridgeRequestError(
                400, f'Disallowed variable "${{{var_name}}}" in Compose {field}.'
            )
        if var_name in env_map and env_map[var_name] != "":
            out.append(env_map[var_name])
        elif default_val is not None:
            out.append(default_val)
        else:
            raise BridgeRequestError(
                400, f'Missing variable "{var_name}" referenced in Compose {field}.'
            )
        pos = match.end()

    trailing = value[pos:]
    if "$" in trailing:
        raise BridgeRequestError(
            400, f"Unsupported variable expansion syntax in Compose {field}."
        )
    out.append(trailing)
    return "".join(out)


def _validate_cpus(raw: Any, slug: str, svc_name: str) -> str:
    if raw is None or isinstance(raw, bool):
        raise BridgeRequestError(
            400,
            f'Compose isolation policy rejected "{slug}": service "{svc_name}" must specify cpus.',
        )
    try:
        val = float(str(raw).strip())
    except ValueError as exc:
        raise BridgeRequestError(
            400, f'Invalid cpus value for service "{svc_name}".'
        ) from exc
    if val < 0.05 or val > 64.0:
        raise BridgeRequestError(
            400, f'cpus for service "{svc_name}" must be between 0.05 and 64.0.'
        )
    return str(raw).strip()


def _validate_mem_limit(raw: Any, slug: str, svc_name: str) -> str:
    if raw is None or isinstance(raw, bool):
        raise BridgeRequestError(
            400,
            f'Compose isolation policy rejected "{slug}": service "{svc_name}" must specify mem_limit.',
        )
    text = str(raw).strip()
    m = MEM_LIMIT_PATTERN.match(text)
    if not m:
        raise BridgeRequestError(
            400, f'Invalid mem_limit "{raw}" for service "{svc_name}".'
        )
    num = int(m.group(1))
    unit = m.group(2).lower()
    if unit == "g":
        mb = num * 1024
    elif unit == "m":
        mb = num
    elif unit == "k":
        mb = num / 1024.0
    else:
        mb = num / (1024.0 * 1024.0)
    if mb < 16 or mb > 131072:
        raise BridgeRequestError(
            400, f'mem_limit for service "{svc_name}" must be between 16m and 131072m.'
        )
    return text


def _validate_no_symlink_volume_source(app_dir: str, rel_path: str, slug: str) -> str:
    real_app_dir = os.path.realpath(app_dir)
    current = real_app_dir
    for part in rel_path.replace("\\", "/").split("/"):
        if not part or part == ".":
            continue
        current = os.path.join(current, part)
        if os.path.islink(current):
            raise BridgeRequestError(
                400,
                f'Security boundary violation: volume mount path "{rel_path}" for "{slug}" contains a symlink.',
            )
    real_target = os.path.realpath(current)
    if real_target != real_app_dir and not real_target.startswith(
        real_app_dir + os.sep
    ):
        raise BridgeRequestError(
            400,
            f'Security boundary violation: volume mount path "{rel_path}" for "{slug}" escapes workspace.',
        )
    return current


def _prepare_service_volume_dir(
    app_dir: str, rel_path: str, user_spec: str | None, slug: str
) -> str:
    """
    Validates a relative volume mount source has no symlinks and prepares private
    host storage ownership for non-root services (e.g. Postgres 70:70, Redis 999:999).
    """
    abs_src = _validate_no_symlink_volume_source(app_dir, rel_path, slug)
    parts = [p for p in rel_path.replace("\\", "/").split("/") if p and p != "."]
    if parts:
        # Ensure top-level ./data or ./workspace is traversable by non-root companion UIDs
        top_dir = os.path.join(os.path.realpath(app_dir), parts[0])
        if not os.path.exists(top_dir):
            os.makedirs(top_dir, mode=0o755, exist_ok=True)
        if len(parts) > 1:
            try:
                os.chmod(top_dir, 0o755)
            except OSError:
                pass
    if not os.path.exists(abs_src):
        os.makedirs(abs_src, mode=0o700 if user_spec else 0o750, exist_ok=True)

    if user_spec:
        m = NUMERIC_USER_PATTERN.match(user_spec)
        if m:
            uid = int(m.group(1))
            gid = int(m.group(2)) if m.group(2) is not None else uid
            try:
                os.chmod(abs_src, 0o700)
            except OSError:
                pass
            if hasattr(os, "geteuid") and os.geteuid() == 0:
                os.chown(abs_src, uid, gid)
                for root_dir, dirs, files in os.walk(abs_src):
                    if os.path.islink(root_dir):
                        continue
                    os.chown(root_dir, uid, gid)
                    for d in dirs:
                        p = os.path.join(root_dir, d)
                        if not os.path.islink(p):
                            os.chown(p, uid, gid)
                    for f in files:
                        p = os.path.join(root_dir, f)
                        if not os.path.islink(p):
                            os.chown(p, uid, gid)
    return abs_src


def _escape_compose_dollars(value: Any) -> Any:
    """Escape literal `$` as `$$` in rendered Compose values so Docker Compose never re-interpolates."""
    if isinstance(value, str):
        return value.replace("$", "$$")
    if isinstance(value, list):
        return [_escape_compose_dollars(item) for item in value]
    if isinstance(value, dict):
        return {k: _escape_compose_dollars(v) for k, v in value.items()}
    return value


def validate_and_render_compose(
    compose_text: str,
    slug: str,
    app_dir: str,
    env_map: dict[str, str],
    env_file_override: str | None,
    *,
    prepare_volumes: bool = False,
) -> dict[str, Any]:
    """
    Structurally validates every section of an app's docker-compose.yml against
    Locked Apartment boundaries and returns a self-contained JSON-serializable
    Compose structure with canonical host paths inside `app_dir`.
    """
    doc = parse_simple_yaml(compose_text)
    unknown_top = set(doc.keys()) - ALLOWED_TOP_LEVEL_COMPOSE_KEYS
    if unknown_top:
        raise BridgeRequestError(
            400,
            f"Unsupported top-level Compose keys: {', '.join(sorted(unknown_top))}.",
        )

    networks = doc.get("networks")
    if not isinstance(networks, dict) or set(networks.keys()) != {"app_net"}:
        raise BridgeRequestError(
            400,
            'Compose networks must define only isolated bridge network "app_net".',
        )
    app_net_cfg = networks["app_net"]
    if app_net_cfg is not None:
        if not isinstance(app_net_cfg, dict):
            raise BridgeRequestError(400, "Invalid app_net configuration.")
        if set(app_net_cfg.keys()) - {"driver"}:
            raise BridgeRequestError(400, "app_net may only specify driver: bridge.")
        if app_net_cfg.get("driver", "bridge") != "bridge":
            raise BridgeRequestError(400, "app_net must use driver: bridge.")

    services = doc.get("services")
    if not isinstance(services, dict) or not (1 <= len(services) <= 4):
        raise BridgeRequestError(
            400, "Compose services must contain 1-4 service definitions."
        )

    service_names = set(str(k) for k in services.keys())
    vars_ctx = {"APP_SLUG": slug, **env_map}
    rendered_services: dict[str, Any] = {}

    for svc_name, svc_cfg in services.items():
        svc_key = str(svc_name)
        if not SERVICE_NAME_PATTERN.match(svc_key) or not isinstance(svc_cfg, dict):
            raise BridgeRequestError(
                400, f'Invalid Compose service definition "{svc_key}".'
            )
        forbidden_keys = set(svc_cfg.keys()) - ALLOWED_SERVICE_KEYS
        if forbidden_keys:
            raise BridgeRequestError(
                400,
                f'Compose isolation policy rejected "{slug}": forbidden keys ({", ".join(sorted(forbidden_keys))}).',
            )

        out_svc: dict[str, Any] = dict(svc_cfg)

        raw_image = svc_cfg.get("image")
        if not isinstance(raw_image, str):
            raise BridgeRequestError(
                400, f'Service "{svc_key}" must specify an image.'
            )
        resolved_image = _resolve_allowed_vars(
            raw_image, vars_ctx, {"APP_IMAGE"}, f"{svc_key}.image"
        )
        if not IMAGE_REF_PATTERN.match(resolved_image):
            raise BridgeRequestError(
                400, f'Invalid Docker image reference "{resolved_image}".'
            )
        out_svc["image"] = resolved_image

        if "container_name" in svc_cfg:
            raw_cname = svc_cfg["container_name"]
            if not isinstance(raw_cname, str):
                raise BridgeRequestError(400, "container_name must be a string.")
            resolved_cname = _resolve_allowed_vars(
                raw_cname, vars_ctx, {"APP_SLUG"}, f"{svc_key}.container_name"
            )
            expected_prefix = f"vpsagent-app-{slug}"
            if resolved_cname != expected_prefix and not resolved_cname.startswith(
                f"{expected_prefix}-"
            ):
                raise BridgeRequestError(
                    400,
                    f'container_name "{resolved_cname}" must be scoped to "{expected_prefix}".',
                )
            out_svc["container_name"] = resolved_cname

        if "user" in svc_cfg:
            raw_user = str(svc_cfg["user"]).strip()
            m_user = NUMERIC_USER_PATTERN.match(raw_user)
            if not m_user:
                raise BridgeRequestError(
                    400,
                    f'Service "{svc_key}" user must be numeric non-root "uid" or "uid:gid".',
                )
            uid = int(m_user.group(1))
            gid = int(m_user.group(2)) if m_user.group(2) is not None else None
            if uid < 1 or (gid is not None and gid < 1):
                raise BridgeRequestError(
                    400, f'Service "{svc_key}" cannot run as root user "{raw_user}".'
                )
            out_svc["user"] = raw_user

        out_svc["cpus"] = _validate_cpus(svc_cfg.get("cpus"), slug, svc_key)
        out_svc["mem_limit"] = _validate_mem_limit(
            svc_cfg.get("mem_limit"), slug, svc_key
        )

        cap_drop = svc_cfg.get("cap_drop")
        if not isinstance(cap_drop, list) or "ALL" not in [
            str(c).upper() for c in cap_drop
        ]:
            raise BridgeRequestError(
                400,
                f'Compose isolation policy rejected "{slug}": cap_drop must include ALL.',
            )

        sec_opt = svc_cfg.get("security_opt")
        if not isinstance(sec_opt, list):
            raise BridgeRequestError(
                400,
                f'Compose isolation policy rejected "{slug}": security_opt must include no-new-privileges:true.',
            )
        sec_strings = [str(s) for s in sec_opt]
        if "no-new-privileges:true" not in sec_strings or any(
            "unconfined" in s.lower() for s in sec_strings
        ):
            raise BridgeRequestError(
                400,
                f'Compose isolation policy rejected "{slug}": insecure security_opt.',
            )

        svc_nets = svc_cfg.get("networks")
        if svc_nets != ["app_net"] and (
            not isinstance(svc_nets, dict) or set(svc_nets.keys()) != {"app_net"}
        ):
            raise BridgeRequestError(
                400,
                f'Service "{svc_key}" may only connect to isolated network app_net.',
            )

        if "depends_on" in svc_cfg:
            deps = svc_cfg["depends_on"]
            if isinstance(deps, list):
                for dep in deps:
                    dep_name = str(dep)
                    if dep_name not in service_names or dep_name == svc_key:
                        raise BridgeRequestError(
                            400,
                            f'Service "{svc_key}" has invalid depends_on target "{dep_name}".',
                        )
            elif isinstance(deps, dict):
                for dep_name, dep_cfg in deps.items():
                    dep_str = str(dep_name)
                    if dep_str not in service_names or dep_str == svc_key:
                        raise BridgeRequestError(
                            400,
                            f'Service "{svc_key}" has invalid depends_on target "{dep_str}".',
                        )
                    if not isinstance(dep_cfg, dict) or set(dep_cfg.keys()) - {
                        "condition"
                    }:
                        raise BridgeRequestError(
                            400,
                            f'Service "{svc_key}" depends_on.{dep_str} only supports condition.',
                        )
                    cond = dep_cfg.get("condition", "service_started")
                    if cond not in ALLOWED_DEPENDS_ON_CONDITIONS:
                        raise BridgeRequestError(
                            400,
                            f'Service "{svc_key}" depends_on.{dep_str} has unsupported condition "{cond}".',
                        )
            else:
                raise BridgeRequestError(
                    400, f'Service "{svc_key}" depends_on must be a list or mapping.'
                )

        if "command" in svc_cfg:
            cmd_val = svc_cfg["command"]
            if isinstance(cmd_val, list):
                out_svc["command"] = [
                    _resolve_allowed_vars(
                        str(part),
                        vars_ctx,
                        ALLOWED_COMMAND_INTERPOLATION_VARS,
                        f"{svc_key}.command",
                    )
                    for part in cmd_val
                ]
            elif isinstance(cmd_val, str):
                out_svc["command"] = _resolve_allowed_vars(
                    cmd_val,
                    vars_ctx,
                    ALLOWED_COMMAND_INTERPOLATION_VARS,
                    f"{svc_key}.command",
                )
            else:
                raise BridgeRequestError(400, "command must be a string or list.")

        uses_app_env_file = False
        if "env_file" in svc_cfg:
            env_files = svc_cfg["env_file"]
            if not isinstance(env_files, list):
                raise BridgeRequestError(400, "env_file must be a list.")
            for entry in env_files:
                if isinstance(entry, str):
                    if entry != ".env":
                        raise BridgeRequestError(
                            400, "env_file may only reference '.env'."
                        )
                    uses_app_env_file = True
                elif isinstance(entry, dict):
                    if (
                        set(entry.keys()) - {"path", "required"}
                        or entry.get("path") != ".env"
                    ):
                        raise BridgeRequestError(
                            400, "env_file entries may only reference path '.env'."
                        )
                    req_flag = entry.get("required", True)
                    if not isinstance(req_flag, bool):
                        raise BridgeRequestError(
                            400, "env_file.required must be a boolean."
                        )
                    uses_app_env_file = True
                else:
                    raise BridgeRequestError(400, "Invalid env_file entry.")
            # Never pass `.env` to Docker Compose `env_file` (which expands `${VAR}` inside
            # double quotes). Instead inject parsed literal `env_map` values directly into
            # `environment` and escape `$` -> `$$` so every quote, newline, backslash, and
            # `$` arrives verbatim in the container.
            out_svc.pop("env_file", None)

        explicit_env: dict[str, Any] = {}
        if "environment" in svc_cfg:
            env_section = svc_cfg["environment"]
            if isinstance(env_section, dict):
                for ek, ev in env_section.items():
                    ek_str = str(ek)
                    if ek_str in DISALLOWED_ENV_EXACT or ek_str.startswith(
                        DISALLOWED_ENV_PREFIXES
                    ):
                        raise BridgeRequestError(
                            400, f'Forbidden Compose environment key "{ek_str}".'
                        )
                    if isinstance(ev, str):
                        explicit_env[ek_str] = _resolve_allowed_vars(
                            ev,
                            vars_ctx,
                            ALLOWED_ENV_INTERPOLATION_VARS,
                            f"{svc_key}.environment.{ek_str}",
                        )
                    else:
                        explicit_env[ek_str] = ev
            elif isinstance(env_section, list):
                for item in env_section:
                    item_str = str(item)
                    if "=" not in item_str:
                        raise BridgeRequestError(
                            400, f'Compose environment entry "{item_str}" must be KEY=VALUE.'
                        )
                    k, v = item_str.split("=", 1)
                    k = k.strip()
                    if k in DISALLOWED_ENV_EXACT or k.startswith(
                        DISALLOWED_ENV_PREFIXES
                    ):
                        raise BridgeRequestError(
                            400, f'Forbidden Compose environment key "{k}".'
                        )
                    explicit_env[k] = _resolve_allowed_vars(
                        v,
                        vars_ctx,
                        ALLOWED_ENV_INTERPOLATION_VARS,
                        f"{svc_key}.environment.{k}",
                    )
            else:
                raise BridgeRequestError(
                    400, "environment must be a mapping or list."
                )

        if uses_app_env_file or explicit_env:
            merged_env: dict[str, Any] = {}
            if uses_app_env_file:
                merged_env.update(env_map)
            merged_env.update(explicit_env)
            out_svc["environment"] = merged_env

        if "volumes" in svc_cfg:
            vols = svc_cfg["volumes"]
            if not isinstance(vols, list):
                raise BridgeRequestError(400, "volumes must be a list.")
            rewritten_vols: list[str] = []
            for vol in vols:
                if not isinstance(vol, str) or "$" in vol or ".." in vol:
                    raise BridgeRequestError(
                        400,
                        f'Compose isolation policy rejected "{slug}": unsafe volume mount.',
                    )
                if not RELATIVE_MOUNT_PATTERN.match(vol):
                    raise BridgeRequestError(
                        400,
                        f'Compose isolation policy rejected "{slug}": volume "{vol}" escapes ./data or ./workspace.',
                    )
                rel_src, rest = vol.split(":", 1)
                if prepare_volumes:
                    abs_src = _prepare_service_volume_dir(
                        app_dir, rel_src[2:], out_svc.get("user"), slug
                    )
                else:
                    abs_src = _validate_no_symlink_volume_source(
                        app_dir, rel_src[2:], slug
                    )
                rewritten_vols.append(f"{abs_src}:{rest}")
            out_svc["volumes"] = rewritten_vols

        if "healthcheck" in svc_cfg:
            hc = svc_cfg["healthcheck"]
            if not isinstance(hc, dict) or (set(hc.keys()) - ALLOWED_HEALTHCHECK_KEYS):
                raise BridgeRequestError(400, "Invalid healthcheck configuration.")
            hc_allowed = {"APP_PORT", "APP_SLUG", "POSTGRES_USER", "POSTGRES_DB"}
            if isinstance(hc.get("test"), str):
                hc_copy = dict(hc)
                hc_copy["test"] = _resolve_allowed_vars(
                    hc["test"], vars_ctx, hc_allowed, f"{svc_key}.healthcheck.test"
                )
                out_svc["healthcheck"] = hc_copy
            elif isinstance(hc.get("test"), list):
                hc_copy = dict(hc)
                hc_copy["test"] = [
                    _resolve_allowed_vars(
                        str(part),
                        vars_ctx,
                        hc_allowed,
                        f"{svc_key}.healthcheck.test",
                    )
                    for part in hc["test"]
                ]
                out_svc["healthcheck"] = hc_copy

        rendered_services[svc_key] = _escape_compose_dollars(out_svc)

    return {
        "services": rendered_services,
        "networks": {"app_net": {"driver": "bridge"}},
    }


def ensure_real_directory(dir_path: str, label: str) -> str:
    if not os.path.exists(dir_path):
        raise BridgeRequestError(500, f"{label} directory does not exist: {dir_path}")
    if os.path.islink(dir_path) or not os.path.isdir(dir_path):
        raise BridgeRequestError(
            400, f"Security boundary violation: {label} must be a real directory."
        )
    return os.path.realpath(dir_path)


def resolve_scoped_app_dir(
    apps_root: str, slug: str, *, require_exists: bool = True
) -> str:
    safe_slug = validate_slug(slug)
    real_root = ensure_real_directory(apps_root, "appsRoot")
    candidate = os.path.join(real_root, safe_slug)
    if not os.path.lexists(candidate):
        if require_exists:
            raise BridgeRequestError(
                404, f'App workspace "{safe_slug}" does not exist.'
            )
        return candidate
    if os.path.islink(candidate) or not os.path.isdir(candidate):
        raise BridgeRequestError(
            400,
            f'Security boundary violation: workspace "{safe_slug}" is not a real directory.',
        )
    real_candidate = os.path.realpath(candidate)
    if real_candidate != os.path.join(real_root, safe_slug):
        raise BridgeRequestError(
            400,
            f'Security boundary violation: workspace "{safe_slug}" escapes appsRoot.',
        )
    return real_candidate


def parse_compose_ps_output(raw_stdout: str) -> list[dict[str, Any]]:
    text = raw_stdout.strip()
    if not text:
        return []
    if text.startswith("["):
        try:
            parsed = json.loads(text)
            if isinstance(parsed, list):
                return [item for item in parsed if isinstance(item, dict)]
        except json.JSONDecodeError:
            return []
    items: list[dict[str, Any]] = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        try:
            obj = json.loads(stripped)
            if isinstance(obj, dict):
                items.append(obj)
        except json.JSONDecodeError:
            continue
    return items


def derive_app_status(containers: list[dict[str, Any]]) -> str:
    if not containers:
        return "stopped"
    has_running = False
    for entry in containers:
        state = str(entry.get("State", "")).strip().lower()
        health = str(entry.get("Health", "")).strip().lower()
        exit_code = entry.get("ExitCode", 0)
        if state in ("restarting", "dead") or health == "unhealthy":
            return "error"
        if (
            state == "exited"
            and isinstance(exit_code, int)
            and exit_code not in (0, 143)
        ):
            return "error"
        if state == "running":
            has_running = True
    return "running" if has_running else "stopped"


def _extract_domains_from_caddy_text(text: str) -> set[str]:
    domains: set[str] = set()
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.endswith("{"):
            host = line[:-1].strip().lower()
            if DOMAIN_PATTERN.match(host):
                domains.add(host)
    return domains


def collect_host_stats(disk_mount: str = "/") -> dict[str, Any]:
    """Collects host CPU, RAM, uptime, and disk metrics using Python stdlib only."""
    uptime_seconds = 0.0
    try:
        with open("/proc/uptime", "r", encoding="utf-8") as fh:
            uptime_seconds = max(0.0, float(fh.read().split()[0]))
    except (OSError, ValueError, IndexError):
        uptime_seconds = 0.0

    load_1m = 0.0
    if hasattr(os, "getloadavg"):
        try:
            load_1m = max(0.0, round(float(os.getloadavg()[0]), 2))
        except OSError:
            load_1m = 0.0

    mem_total_kb = 0
    mem_avail_kb = 0
    try:
        meminfo: dict[str, int] = {}
        with open("/proc/meminfo", "r", encoding="utf-8") as fh:
            for line in fh:
                parts = line.split(":")
                if len(parts) == 2:
                    key = parts[0].strip()
                    val_tokens = parts[1].strip().split()
                    if val_tokens and val_tokens[0].isdigit():
                        meminfo[key] = int(val_tokens[0])
        mem_total_kb = meminfo.get("MemTotal", 0)
        if "MemAvailable" in meminfo:
            mem_avail_kb = meminfo["MemAvailable"]
        else:
            mem_avail_kb = (
                meminfo.get("MemFree", 0)
                + meminfo.get("Buffers", 0)
                + meminfo.get("Cached", 0)
            )
    except OSError:
        mem_total_kb = 0
        mem_avail_kb = 0

    mem_total_mb = round(mem_total_kb / 1024.0, 1)
    mem_used_mb = round(max(0, mem_total_kb - mem_avail_kb) / 1024.0, 1)
    mem_pct = (
        round(min(100.0, max(0.0, (mem_used_mb / mem_total_mb) * 100.0)), 1)
        if mem_total_mb > 0
        else 0.0
    )

    mount_target = disk_mount if os.path.exists(disk_mount) else "/"
    usage = shutil.disk_usage(mount_target)
    total_gb = round(usage.total / (1024.0**3), 2)
    used_gb = round(usage.used / (1024.0**3), 2)
    free_gb = round(usage.free / (1024.0**3), 2)
    used_pct = (
        round(min(100.0, max(0.0, (usage.used / usage.total) * 100.0)), 1)
        if usage.total > 0
        else 0.0
    )

    return {
        "metrics": {
            "hostname": socket.gethostname(),
            "platform": f"{platform.system().lower()}-{platform.machine()}",
            "uptimeSeconds": round(uptime_seconds, 1),
            "cpuCount": max(1, os.cpu_count() or 1),
            "loadAverage1m": load_1m,
            "memoryTotalMb": mem_total_mb,
            "memoryUsedMb": mem_used_mb,
            "memoryUsagePercent": mem_pct,
            "collectedAt": datetime.now(timezone.utc).isoformat(),
        },
        "disk": {
            "totalGb": total_gb,
            "usedGb": used_gb,
            "freeGb": free_gb,
            "usedPercent": used_pct,
            "mount": mount_target,
        },
    }


class _SlugLockEntry:
    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.refs = 0


class RuntimeService:
    def __init__(
        self,
        *,
        apps_root: str,
        caddy_apps_dir: str,
        caddy_core_dir: str | None = None,
        caddy_container: str,
        docker_bin: str = "docker",
        git_bin: str = "git",
        runtime_token: str | None = None,
        allow_unauthenticated: bool = False,
        status_deadline_s: float = DEFAULT_STATUS_DEADLINE_S,
        health_interval_s: float = DEFAULT_HEALTH_INTERVAL_S,
        health_retries: int = DEFAULT_HEALTH_RETRIES,
        dns_resolver: DnsResolver | None = None,
        tls_checker: TlsChecker | None = None,
        allowed_file_roots: list[str] | None = None,
    ) -> None:
        if not CONTAINER_NAME_PATTERN.match(caddy_container):
            raise ValueError(f"Invalid caddy container name: {caddy_container}")
        if not docker_bin or any(ch.isspace() for ch in docker_bin):
            raise ValueError("Invalid docker binary path.")
        if not git_bin or any(ch.isspace() for ch in git_bin):
            raise ValueError("Invalid git binary path.")
        cleaned_token = (runtime_token or "").strip() or None
        if not cleaned_token and not allow_unauthenticated:
            raise ValueError(
                "RuntimeService requires runtime_token unless allow_unauthenticated=True."
            )
        self.apps_root = apps_root
        self.caddy_apps_dir = caddy_apps_dir
        self.caddy_core_dir = caddy_core_dir or os.path.join(
            os.path.dirname(os.path.abspath(caddy_apps_dir)), "core.d"
        )
        self.caddy_container = caddy_container
        self.docker_bin = docker_bin
        self.git_bin = git_bin
        self.runtime_token = cleaned_token
        self.allow_unauthenticated = allow_unauthenticated
        self.status_deadline_s = max(0.2, float(status_deadline_s))
        self.health_interval_s = max(0.2, float(health_interval_s))
        self.health_retries = max(1, int(health_retries))
        self.dns_resolver = dns_resolver
        self.tls_checker = tls_checker or default_tls_checker
        if allowed_file_roots is not None:
            raw_roots = allowed_file_roots
        else:
            env_roots = os.environ.get("VPSAGENT_ALLOWED_FILE_ROOTS", "").strip()
            raw_roots = (
                [p.strip() for p in env_roots.split(":") if p.strip()]
                if env_roots
                else [apps_root, "/srv", "/opt/apps", "/tmp/vpsagent-work"]
            )
        self.allowed_file_roots: list[str] = [
            os.path.realpath(r) for r in raw_roots if os.path.isabs(r)
        ]
        self._locks_guard = threading.Lock()
        self._slug_locks: dict[str, _SlugLockEntry] = {}
        self._caddy_lock = threading.Lock()
        self._host_health_lock = threading.Lock()
        self._host_health: dict[str, dict[str, Any]] = {}
        self._health_stop_event = threading.Event()
        self._health_thread: threading.Thread | None = None

    def _read_app_probe_config(self, app_dir: str, slug: str) -> dict[str, Any] | None:
        probe_file = os.path.join(app_dir, "probe.json")
        if not os.path.lexists(probe_file):
            return None
        try:
            raw_text = _read_regular_file_nofollow(
                probe_file, MAX_PROBE_CONFIG_BYTES, f'probe.json for "{slug}"'
            )
            data = json.loads(raw_text)
            if not isinstance(data, dict):
                return None
            probe_http = data.get("probeHttp")
            if not isinstance(probe_http, bool):
                return None
            internal_port = validate_port(data.get("internalPort"))
            probe_path = validate_probe_path(data.get("probePath"))
            return {
                "probeHttp": probe_http,
                "internalPort": internal_port,
                "probePath": probe_path,
            }
        except (BridgeRequestError, json.JSONDecodeError, ValueError, TypeError):
            return None

    def _clear_host_health(self, slug: str) -> None:
        with self._host_health_lock:
            self._host_health.pop(slug, None)

    def _get_host_health(self, slug: str) -> dict[str, Any] | None:
        with self._host_health_lock:
            entry = self._host_health.get(slug)
            return dict(entry) if entry is not None else None

    def _resolve_overall_status(self, slug: str, docker_status: str) -> str:
        """
        Single source of truth for overall app status shared by the Apps list
        (`/v1/apps/statuses`), lifecycle status, and Safety Check (`/v1/apps/inspect`).
        """
        if docker_status == "running":
            host_health = self._get_host_health(slug)
            if host_health is not None and host_health.get("status") == "unhealthy":
                return "error"
        return docker_status

    def _record_host_health(
        self, slug: str, probe_path: str, probe_result: dict[str, Any]
    ) -> dict[str, Any]:
        code = probe_result.get("statusCode")
        is_ok = bool(probe_result.get("ok")) or (
            isinstance(code, int) and 100 <= code < 500
        )
        now = time.time()
        with self._host_health_lock:
            prev = self._host_health.get(slug) or {}
            if is_ok:
                entry = {
                    "status": "healthy",
                    "consecutiveFailures": 0,
                    "lastCheckedAt": now,
                    "lastOutput": redact_secrets(
                        f"Host HTTP probe GET {probe_path} -> {code}"
                    )[:300],
                }
            else:
                failures = int(prev.get("consecutiveFailures", 0)) + 1
                detail = probe_result.get("error") or f"HTTP {code}"
                prev_status = str(prev.get("status") or "starting")
                new_status = (
                    "unhealthy" if failures >= self.health_retries else prev_status
                )
                entry = {
                    "status": new_status,
                    "consecutiveFailures": failures,
                    "lastCheckedAt": now,
                    "lastOutput": redact_secrets(
                        f"Host HTTP probe GET {probe_path} failed "
                        f"({failures}/{self.health_retries}): {detail}"
                    )[:300],
                }
            self._host_health[slug] = entry
            return dict(entry)

    def run_recurring_health_check_once(self, slug: str) -> dict[str, Any] | None:
        """
        Runs one host-side HTTP health probe for an app configured via `probe.json`.
        Works identically for minimal/distroless/scratch images with no in-container tools.
        """
        safe_slug = validate_slug(slug)
        app_dir = resolve_scoped_app_dir(self.apps_root, safe_slug, require_exists=False)
        if not os.path.isdir(app_dir):
            self._clear_host_health(safe_slug)
            return None
        cfg = self._read_app_probe_config(app_dir, safe_slug)
        if cfg is None or not cfg["probeHttp"]:
            return None

        inspected = self.inspect_workload(
            {
                "slug": safe_slug,
                "probeHttp": True,
                "internalPort": cfg["internalPort"],
                "probePath": cfg["probePath"],
            },
            timeout_budget_s=min(10.0, self.status_deadline_s),
            _apply_host_health=False,
        )
        containers = inspected.get("containers") or []
        primary = self._select_primary_container(safe_slug, containers)
        if primary is None or not primary.get("running"):
            self._clear_host_health(safe_slug)
            return None

        probe_result = inspected.get("httpProbe") or {
            "attempted": False,
            "ok": False,
            "statusCode": None,
            "error": "No HTTP probe result.",
        }
        return self._record_host_health(safe_slug, cfg["probePath"], probe_result)

    def run_recurring_health_sweep(self) -> dict[str, dict[str, Any]]:
        results: dict[str, dict[str, Any]] = {}
        if not os.path.isdir(self.apps_root):
            return results
        try:
            entries = sorted(os.listdir(self.apps_root))
        except OSError:
            return results
        for name in entries:
            if not SLUG_PATTERN.match(name):
                continue
            app_dir = os.path.join(self.apps_root, name)
            if os.path.islink(app_dir) or not os.path.isdir(app_dir):
                continue
            if not os.path.lexists(os.path.join(app_dir, "probe.json")):
                continue
            try:
                res = self.run_recurring_health_check_once(name)
                if res is not None:
                    results[name] = res
            except (BridgeRequestError, OSError):
                continue
        return results

    def start_health_monitor(self) -> None:
        if self._health_thread is not None and self._health_thread.is_alive():
            return
        self._health_stop_event.clear()

        def _loop() -> None:
            while not self._health_stop_event.wait(self.health_interval_s):
                try:
                    self.run_recurring_health_sweep()
                except Exception:
                    continue

        self._health_thread = threading.Thread(
            target=_loop, name="vpsagent-host-health-monitor", daemon=True
        )
        self._health_thread.start()

    def stop_health_monitor(self) -> None:
        self._health_stop_event.set()
        if self._health_thread is not None and self._health_thread.is_alive():
            self._health_thread.join(timeout=2.0)
        self._health_thread = None

    @contextmanager
    def _lock_for(self, slug: str) -> Iterator[None]:
        with self._locks_guard:
            entry = self._slug_locks.get(slug)
            if entry is None:
                entry = _SlugLockEntry()
                self._slug_locks[slug] = entry
            entry.refs += 1
        try:
            entry.lock.acquire()
            try:
                yield
            finally:
                entry.lock.release()
        finally:
            with self._locks_guard:
                entry.refs -= 1
                if entry.refs == 0:
                    self._slug_locks.pop(slug, None)

    @contextmanager
    def _validated_compose_context(
        self, app_dir: str, slug: str, *, prepare_volumes: bool = False
    ) -> Iterator[tuple[str, str]]:
        """
        Reads `.env` and `docker-compose.yml` with O_NOFOLLOW, structurally
        validates every field, resolves only allowlisted interpolation variables,
        and writes canonical validated copies into a root-owned 0700 temporary
        directory. The container env file is named `app.env` (never `.env`) and
        Docker Compose uses `tmp_dir` as `--project-directory` with NO `--env-file`
        so Compose can never implicitly rediscover or interpolate app secrets.
        """
        compose_path = os.path.join(app_dir, "docker-compose.yml")
        compose_text = _read_regular_file_nofollow(
            compose_path, MAX_COMPOSE_BYTES, f'docker-compose.yml for "{slug}"'
        )
        env_path = os.path.join(app_dir, ".env")
        env_text: str | None = None
        env_map: dict[str, str] = {}
        if os.path.lexists(env_path):
            env_text = _read_regular_file_nofollow(
                env_path, MAX_ENV_BYTES, f'.env for "{slug}"'
            )
            env_map = parse_and_validate_env_file(env_text, slug)

        tmp_dir = tempfile.mkdtemp(prefix=f"vpsagent-{slug}-")
        os.chmod(tmp_dir, 0o700)
        try:
            rendered_doc = validate_and_render_compose(
                compose_text,
                slug,
                app_dir,
                env_map,
                None,
                prepare_volumes=prepare_volumes,
            )
            tmp_compose_path = os.path.join(tmp_dir, "docker-compose.json")
            with open(tmp_compose_path, "w", encoding="utf-8") as fh:
                json.dump(rendered_doc, fh, indent=2)
            os.chmod(tmp_compose_path, 0o600)
            yield tmp_compose_path, tmp_dir
        finally:
            shutil.rmtree(tmp_dir, ignore_errors=True)

    def _run_cmd(
        self,
        cmd: list[str],
        *,
        label: str,
        timeout: float = 120,
        check: bool = True,
        cwd: str | None = None,
        extra_env: dict[str, str] | None = None,
    ) -> subprocess.CompletedProcess[str]:
        try:
            proc = subprocess.run(
                cmd,
                cwd=cwd,
                shell=False,
                env=_sanitized_subprocess_env(extra_env),
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=timeout,
            )
        except FileNotFoundError as exc:
            raise BridgeRequestError(
                503, f"{label} CLI binary not found ({cmd[0]})."
            ) from exc
        except subprocess.TimeoutExpired as exc:
            raise BridgeRequestError(
                504, f"{label} command timed out after {int(timeout)}s."
            ) from exc

        if check and proc.returncode != 0:
            detail = (
                proc.stderr or proc.stdout or f"exit code {proc.returncode}"
            ).strip()
            raise BridgeRequestError(502, redact_secrets(detail))
        return proc

    def _run_docker(
        self,
        args: list[str],
        *,
        timeout: float = 120,
        check: bool = True,
        cwd: str | None = None,
    ) -> subprocess.CompletedProcess[str]:
        return self._run_cmd(
            [self.docker_bin, *args],
            label="Docker",
            timeout=timeout,
            check=check,
            cwd=cwd,
        )

    def _run_git(
        self,
        args: list[str],
        *,
        timeout: float = 120,
        check: bool = True,
        cwd: str | None = None,
    ) -> subprocess.CompletedProcess[str]:
        return self._run_cmd(
            [self.git_bin, *args],
            label="Git",
            timeout=timeout,
            check=check,
            cwd=cwd,
            extra_env={
                "GIT_TERMINAL_PROMPT": "0",
                "GIT_CONFIG_NOSYSTEM": "1",
                "GIT_ALLOW_PROTOCOL": "https",
            },
        )

    def _compose_down_by_project(self, slug: str) -> None:
        with tempfile.TemporaryDirectory(
            prefix=f"vpsagent-down-{slug}-"
        ) as empty_cwd:
            self._run_docker(
                ["compose", "-p", f"vpsagent-{slug}", "down", "--remove-orphans"],
                timeout=60,
                check=True,
                cwd=empty_cwd,
            )

    def _compose_cmd_base(
        self, slug: str, project_dir: str, compose_path: str
    ) -> list[str]:
        return [
            "compose",
            "-p",
            f"vpsagent-{slug}",
            "--project-directory",
            project_dir,
            "-f",
            compose_path,
        ]

    def _compose_status(
        self, slug: str, project_dir: str, compose_path: str
    ) -> str:
        proc = self._run_docker(
            [
                *self._compose_cmd_base(slug, project_dir, compose_path),
                "ps",
                "-a",
                "--format",
                "json",
            ],
            timeout=20,
            check=False,
        )
        if proc.returncode != 0:
            return "error"
        return derive_app_status(parse_compose_ps_output(proc.stdout))

    def host_stats(self) -> dict[str, Any]:
        return collect_host_stats("/")

    def lifecycle(self, payload: dict[str, Any]) -> dict[str, Any]:
        slug = validate_slug(payload.get("slug"))
        action = payload.get("action")
        if not isinstance(action, str) or action not in ALLOWED_LIFECYCLE_ACTIONS:
            raise BridgeRequestError(
                400, "Field 'action' must be one of: start, stop, restart, status."
            )

        with self._lock_for(slug):
            app_dir = resolve_scoped_app_dir(self.apps_root, slug)
            with self._validated_compose_context(
                app_dir, slug, prepare_volumes=(action == "start")
            ) as (
                compose_path,
                project_dir,
            ):
                base = self._compose_cmd_base(slug, project_dir, compose_path)
                if action == "start":
                    self._clear_host_health(slug)
                    self._run_docker(
                        [*base, "up", "-d", "--remove-orphans"], timeout=180
                    )
                elif action == "stop":
                    self._clear_host_health(slug)
                    self._run_docker([*base, "stop"], timeout=60)
                elif action == "restart":
                    self._clear_host_health(slug)
                    self._run_docker([*base, "restart"], timeout=90)

                status = self._compose_status(slug, project_dir, compose_path)
                if action == "status":
                    status = self._resolve_overall_status(slug, status)
                return {
                    "slug": slug,
                    "status": status,
                    "detail": f"Workload {slug} {action} -> {status}",
                }

    def _clone_public_repo(
        self,
        repo_url: str,
        repo_host: str,
        repo_port: int,
        validated_ips: list[str],
        branch: str | None,
        clone_dir: str,
        clone_timeout: float,
    ) -> tuple[str | None, str | None]:
        with _PinnedGitConnectProxy(
            repo_host,
            repo_port,
            validated_ips,
            connect_timeout=min(15.0, clone_timeout),
        ) as proxy:
            clone_args = [
                "clone",
                "--depth",
                "1",
                "--single-branch",
                "-c",
                "protocol.file.allow=never",
                "-c",
                "http.followRedirects=false",
                "-c",
                "core.symlinks=false",
                "-c",
                f"http.proxy=http://127.0.0.1:{proxy.port}",
            ]
            if branch:
                clone_args.extend(["--branch", branch])
            clone_args.extend(["--", repo_url, clone_dir])
            self._run_git(clone_args, timeout=clone_timeout, check=True)

        rev_proc = self._run_git(
            ["-C", clone_dir, "rev-parse", "HEAD"], timeout=10, check=False
        )
        commit_sha = (
            rev_proc.stdout.strip()[:40]
            if rev_proc.returncode == 0 and rev_proc.stdout.strip()
            else None
        )
        branch_proc = self._run_git(
            ["-C", clone_dir, "rev-parse", "--abbrev-ref", "HEAD"],
            timeout=10,
            check=False,
        )
        resolved_branch = (
            branch_proc.stdout.strip()[:120]
            if branch_proc.returncode == 0
            and branch_proc.stdout.strip()
            and branch_proc.stdout.strip() != "HEAD"
            else branch
        )
        return commit_sha, resolved_branch

    def inspect_git(self, payload: dict[str, Any]) -> dict[str, Any]:
        repo_url, repo_host, repo_port, validated_ips = validate_git_repo_url_with_ips(
            payload.get("gitRepoUrl"), dns_resolver=self.dns_resolver
        )
        branch = validate_git_branch(payload.get("gitBranch"))
        dockerfile_rel = validate_dockerfile_path(payload.get("dockerfilePath"))
        raw_timeout = payload.get("timeoutSeconds", 45)
        if (
            not isinstance(raw_timeout, (int, float))
            or isinstance(raw_timeout, bool)
            or raw_timeout < 5
            or raw_timeout > 120
        ):
            raise BridgeRequestError(
                400, "Field 'timeoutSeconds' must be between 5 and 120."
            )

        build_dir = tempfile.mkdtemp(prefix="vpsagent-inspect-")
        os.chmod(build_dir, 0o700)
        clone_dir = os.path.join(build_dir, "repo")
        try:
            commit_sha, resolved_branch = self._clone_public_repo(
                repo_url,
                repo_host,
                repo_port,
                validated_ips,
                branch,
                clone_dir,
                float(raw_timeout),
            )
            info = _inspect_cloned_repo(
                clone_dir, repo_url, resolved_branch, commit_sha, dockerfile_rel
            )
            info.pop("generatedDockerfile", None)
            return info
        finally:
            shutil.rmtree(build_dir, ignore_errors=True)

    def build_git(self, payload: dict[str, Any]) -> dict[str, Any]:
        slug = validate_slug(payload.get("slug"))
        repo_url, repo_host, repo_port, validated_ips = validate_git_repo_url_with_ips(
            payload.get("gitRepoUrl"), dns_resolver=self.dns_resolver
        )
        branch = validate_git_branch(payload.get("gitBranch"))
        raw_df = payload.get("dockerfilePath")
        dockerfile_rel = (
            "auto"
            if isinstance(raw_df, str) and raw_df.strip() == "auto"
            else validate_dockerfile_path(raw_df)
        )
        allow_auto_detect = bool(
            payload.get("allowAutoDetect", dockerfile_rel in ("Dockerfile", "auto"))
        )

        raw_timeout = payload.get("timeoutSeconds", DEFAULT_BUILD_TIMEOUT_S)
        if (
            not isinstance(raw_timeout, (int, float))
            or isinstance(raw_timeout, bool)
            or raw_timeout < MIN_BUILD_TIMEOUT_S
            or raw_timeout > MAX_BUILD_TIMEOUT_S
        ):
            raise BridgeRequestError(
                400,
                f"Field 'timeoutSeconds' must be between {MIN_BUILD_TIMEOUT_S} and {MAX_BUILD_TIMEOUT_S}.",
            )
        total_timeout_s = float(raw_timeout)
        image_tag = f"vpsagent-app-{slug}:latest"

        t0 = time.monotonic()
        deadline = t0 + total_timeout_s

        with self._lock_for(slug):
            build_dir = tempfile.mkdtemp(prefix=f"vpsagent-git-{slug}-")
            os.chmod(build_dir, 0o700)
            clone_dir = os.path.join(build_dir, "repo")
            try:
                clone_timeout = max(5.0, min(total_timeout_s * 0.4, 90.0))
                commit_sha, resolved_branch = self._clone_public_repo(
                    repo_url,
                    repo_host,
                    repo_port,
                    validated_ips,
                    branch,
                    clone_dir,
                    clone_timeout,
                )

                inspected = _inspect_cloned_repo(
                    clone_dir, repo_url, resolved_branch, commit_sha, dockerfile_rel
                )
                real_clone_dir = os.path.realpath(clone_dir)
                used_auto_dockerfile = False
                if inspected["hasDockerfile"]:
                    check_rel = "Dockerfile" if dockerfile_rel == "auto" else dockerfile_rel
                    real_dockerfile = os.path.realpath(
                        os.path.join(real_clone_dir, check_rel)
                    )
                elif (
                    allow_auto_detect
                    and dockerfile_rel in ("Dockerfile", "auto")
                    and inspected.get("generatedDockerfile")
                ):
                    auto_df_path = os.path.join(build_dir, "Dockerfile.vpsagent")
                    with open(auto_df_path, "w", encoding="utf-8") as fh:
                        fh.write(str(inspected["generatedDockerfile"]))
                    os.chmod(auto_df_path, 0o600)
                    real_dockerfile = auto_df_path
                    used_auto_dockerfile = True
                else:
                    raise BridgeRequestError(
                        400,
                        f'Dockerfile "{dockerfile_rel}" was not found in repository, and no supported Node, Python, or static web project was detected.',
                    )

                remaining_s = deadline - time.monotonic()
                if remaining_s < 1.0:
                    raise BridgeRequestError(
                        504,
                        f"Git build timed out after {int(total_timeout_s)}s before Docker build.",
                    )

                build_proc = self._run_docker(
                    [
                        "build",
                        "-t",
                        image_tag,
                        "-f",
                        real_dockerfile,
                        real_clone_dir,
                    ],
                    timeout=remaining_s,
                    check=False,
                )
                combined = "\n".join(
                    p for p in (build_proc.stdout, build_proc.stderr) if p
                )
                redacted = redact_secrets(combined)
                log_tail = [
                    line[:MAX_LOG_LINE_CHARS]
                    for line in redacted.splitlines()
                    if line.strip()
                ][-MAX_BUILD_LOG_LINES:]

                if build_proc.returncode != 0:
                    err_excerpt = log_tail[-1] if log_tail else "unknown Docker build error"
                    raise BridgeRequestError(
                        502,
                        f"Docker build failed (exit {build_proc.returncode}): {err_excerpt}",
                        build_log_tail=log_tail,
                    )

                return {
                    "ok": True,
                    "slug": slug,
                    "image": image_tag,
                    "commitSha": commit_sha,
                    "durationMs": round((time.monotonic() - t0) * 1000, 1),
                    "buildLogTail": log_tail,
                    "detectedRuntime": inspected["detectedRuntime"],
                    "usedAutoDockerfile": used_auto_dockerfile,
                    "suggestedPort": inspected["suggestedPort"],
                    "envExampleKeys": [
                        item["key"] for item in inspected["envExampleKeys"]
                    ],
                }
            finally:
                shutil.rmtree(build_dir, ignore_errors=True)

    def logs(self, payload: dict[str, Any]) -> dict[str, Any]:
        slug = validate_slug(payload.get("slug"))
        tail = validate_tail(payload.get("tail"))

        app_dir = resolve_scoped_app_dir(self.apps_root, slug)
        with self._validated_compose_context(app_dir, slug) as (
            compose_path,
            project_dir,
        ):
            base = self._compose_cmd_base(slug, project_dir, compose_path)
            proc = self._run_docker(
                [*base, "logs", "--no-color", "--tail", str(tail)],
                timeout=20,
            )
            combined = "\n".join(part for part in (proc.stdout, proc.stderr) if part)
            redacted_blob = redact_secrets(combined)
            truncated = False
            raw_lines: list[str] = []
            for line in redacted_blob.splitlines():
                if not line:
                    continue
                if len(line) > MAX_LOG_LINE_CHARS:
                    raw_lines.append(line[:MAX_LOG_LINE_CHARS])
                    truncated = True
                else:
                    raw_lines.append(line)

            if len(raw_lines) > tail:
                raw_lines = raw_lines[-tail:]

            # Enforce strict UTF-8 JSON byte budget on the finished log list (keeping newest lines)
            kept_reversed: list[str] = []
            used_bytes = 256  # overhead for JSON wrapper
            for line in reversed(raw_lines):
                line_bytes = len(json.dumps(line).encode("utf-8")) + 1
                if used_bytes + line_bytes > MAX_LOGS_RESPONSE_BYTES:
                    truncated = True
                    break
                kept_reversed.append(line)
                used_bytes += line_bytes
            kept_reversed.reverse()
            return {"slug": slug, "lines": kept_reversed, "truncated": truncated}

    def _validate_and_reload_caddy(self) -> None:
        self._run_docker(
            [
                "exec",
                self.caddy_container,
                "caddy",
                "validate",
                "--config",
                "/etc/caddy/Caddyfile",
            ],
            timeout=20,
        )
        self._run_docker(
            [
                "exec",
                self.caddy_container,
                "caddy",
                "reload",
                "--config",
                "/etc/caddy/Caddyfile",
            ],
            timeout=20,
        )

    def _resolve_caddy_route_path(self, slug: str) -> str:
        real_caddy_dir = ensure_real_directory(self.caddy_apps_dir, "caddyAppsDir")
        route_path = os.path.join(real_caddy_dir, f"{slug}.caddy")
        if os.path.islink(route_path):
            raise BridgeRequestError(
                400,
                f'Security boundary violation: Caddy route for "{slug}" cannot be a symlink.',
            )
        if os.path.lexists(route_path) and os.path.realpath(
            route_path
        ) != os.path.join(real_caddy_dir, f"{slug}.caddy"):
            raise BridgeRequestError(
                400,
                f'Security boundary violation: Caddy route for "{slug}" escapes directory.',
            )
        return route_path

    def _find_domain_owner(
        self, real_caddy_dir: str, domain: str, exclude_slug: str
    ) -> str | None:
        for entry in os.listdir(real_caddy_dir):
            if not entry.endswith(".caddy"):
                continue
            other_slug = entry[:-6]
            if other_slug == exclude_slug:
                continue
            full_path = os.path.join(real_caddy_dir, entry)
            if os.path.islink(full_path) or not os.path.isfile(full_path):
                continue
            try:
                with open(full_path, "r", encoding="utf-8") as fh:
                    if domain in _extract_domains_from_caddy_text(fh.read()):
                        return other_slug
            except OSError:
                continue
        return None

    def _resolve_core_caddy_path(self) -> str:
        os.makedirs(self.caddy_core_dir, mode=0o755, exist_ok=True)
        real_core_dir = ensure_real_directory(self.caddy_core_dir, "caddyCoreDir")
        route_path = os.path.join(real_core_dir, "dashboard.caddy")
        if os.path.islink(route_path):
            raise BridgeRequestError(
                400,
                "Security boundary violation: core Caddy route cannot be a symlink.",
            )
        return route_path

    def route_core_domain(self, payload: dict[str, Any]) -> dict[str, Any]:
        """
        Applies the dashboard/MCP domain directly to Caddy's core.d/dashboard.caddy,
        validates & reloads Caddy, and atomically restores the prior working config
        if validation or reload fails.
        """
        raw_domain = payload.get("domain")
        domain = None if raw_domain is None else validate_domain(raw_domain)
        acme_email = validate_email(payload.get("acmeEmail"))

        with self._caddy_lock:
            if domain is not None and os.path.isdir(self.caddy_apps_dir):
                real_apps_dir = ensure_real_directory(
                    self.caddy_apps_dir, "caddyAppsDir"
                )
                owner = self._find_domain_owner(real_apps_dir, domain, "__core__")
                if owner is not None:
                    raise BridgeRequestError(
                        409,
                        f'Domain "{domain}" is already routed to app "{owner}".',
                    )

            route_path = self._resolve_core_caddy_path()
            previous_content: str | None = None
            if os.path.exists(route_path):
                with open(route_path, "r", encoding="utf-8") as fh:
                    previous_content = fh.read()

            if domain is not None:
                tls_line = f"\ttls {acme_email}\n" if acme_email else ""
                route_body = (
                    "# Managed by VPSAgent Host Runtime Bridge (Core Dashboard & MCP)\n"
                    f"{domain} {{\n"
                    f"{tls_line}"
                    "\tencode zstd gzip\n"
                    "\thandle /mcp {\n"
                    "\t\treverse_proxy vpsagent-core:3001\n"
                    "\t}\n"
                    "\thandle {\n"
                    "\t\treverse_proxy vpsagent-core:3001\n"
                    "\t}\n"
                    "}\n"
                )
            else:
                route_body = (
                    "# Managed by VPSAgent Host Runtime Bridge (Local-only fallback)\n"
                    "127.0.0.1:80, localhost:80 {\n"
                    "\tencode zstd gzip\n"
                    "\thandle /mcp {\n"
                    "\t\treverse_proxy vpsagent-core:3001\n"
                    "\t}\n"
                    "\thandle {\n"
                    "\t\treverse_proxy vpsagent-core:3001\n"
                    "\t}\n"
                    "}\n"
                )

            try:
                with open(route_path, "w", encoding="utf-8") as fh:
                    fh.write(route_body)
                os.chmod(route_path, 0o644)
                self._validate_and_reload_caddy()
            except Exception as exc:
                if previous_content is not None:
                    with open(route_path, "w", encoding="utf-8") as fh:
                        fh.write(previous_content)
                    os.chmod(route_path, 0o644)
                elif os.path.exists(route_path):
                    os.unlink(route_path)
                if isinstance(exc, BridgeRequestError):
                    raise BridgeRequestError(
                        422, f"Caddy HTTPS domain update failed: {exc}"
                    ) from exc
                raise BridgeRequestError(
                    500, f"Failed updating core Caddy domain: {exc}"
                ) from exc

            if domain is None:
                return {
                    "ok": True,
                    "domain": None,
                    "acmeEmail": None,
                    "httpsActive": False,
                    "tlsStatus": "inactive",
                    "tlsError": None,
                }

            https_active, tls_status, tls_error = self.tls_checker(domain, 4.0)
            return {
                "ok": True,
                "domain": domain,
                "acmeEmail": acme_email,
                "httpsActive": https_active,
                "tlsStatus": tls_status,
                "tlsError": tls_error,
            }

    def check_core_tls(self, payload: dict[str, Any]) -> dict[str, Any]:
        domain = validate_domain(payload.get("domain"))
        https_active, tls_status, tls_error = self.tls_checker(domain, 4.0)
        return {
            "domain": domain,
            "httpsActive": https_active,
            "tlsStatus": tls_status,
            "tlsError": tls_error,
        }

    def route_caddy(self, payload: dict[str, Any]) -> dict[str, Any]:
        slug = validate_slug(payload.get("slug"))
        raw_domain = payload.get("domain")
        domain = None if raw_domain is None else validate_domain(raw_domain)
        internal_port = validate_port(payload.get("internalPort"))
        network_name = f"vpsagent-{slug}_app_net"

        with self._lock_for(slug):
            with self._caddy_lock:
                route_path = self._resolve_caddy_route_path(slug)
                real_caddy_dir = os.path.dirname(route_path)
                previous_content: str | None = None
                if os.path.exists(route_path):
                    with open(route_path, "r", encoding="utf-8") as fh:
                        previous_content = fh.read()

                if domain is None:
                    if os.path.exists(route_path):
                        os.unlink(route_path)
                        try:
                            self._validate_and_reload_caddy()
                        except Exception:
                            if previous_content is not None:
                                with open(route_path, "w", encoding="utf-8") as fh:
                                    fh.write(previous_content)
                                os.chmod(route_path, 0o644)
                            raise
                    self._run_docker(
                        ["network", "disconnect", network_name, self.caddy_container],
                        timeout=15,
                        check=False,
                    )
                    return {"ok": True, "slug": slug, "domain": None, "routed": False}

                owner = self._find_domain_owner(real_caddy_dir, domain, slug)
                if owner is not None:
                    raise BridgeRequestError(
                        409,
                        f'Domain "{domain}" is already routed to app "{owner}".',
                    )

                inspect_proc = self._run_docker(
                    ["network", "inspect", network_name],
                    timeout=15,
                    check=False,
                )
                if inspect_proc.returncode != 0:
                    raise BridgeRequestError(
                        409,
                        f'App "{slug}" is not running yet (network "{network_name}" not found). Start the app before binding a public domain.',
                    )

                connected_here = False
                connect_proc = self._run_docker(
                    ["network", "connect", network_name, self.caddy_container],
                    timeout=15,
                    check=False,
                )
                if connect_proc.returncode == 0:
                    connected_here = True
                else:
                    err_text = (
                        connect_proc.stderr or connect_proc.stdout or ""
                    ).lower()
                    if (
                        "already exists" not in err_text
                        and "already connected" not in err_text
                    ):
                        raise BridgeRequestError(
                            502,
                            redact_secrets(
                                (
                                    connect_proc.stderr
                                    or connect_proc.stdout
                                    or "Failed to attach Caddy network."
                                ).strip()
                            ),
                        )

                route_body = (
                    f"# Managed by VPSAgent Runtime Bridge for app: {slug}\n"
                    f"{domain} {{\n"
                    f"\tencode zstd gzip\n"
                    f"\treverse_proxy vpsagent-app-{slug}:{internal_port}\n"
                    f"}}\n"
                )

                try:
                    with open(route_path, "w", encoding="utf-8") as fh:
                        fh.write(route_body)
                    os.chmod(route_path, 0o644)
                    self._validate_and_reload_caddy()
                except Exception as exc:
                    if previous_content is not None:
                        with open(route_path, "w", encoding="utf-8") as fh:
                            fh.write(previous_content)
                        os.chmod(route_path, 0o644)
                    elif os.path.exists(route_path):
                        os.unlink(route_path)
                    if connected_here:
                        self._run_docker(
                            [
                                "network",
                                "disconnect",
                                network_name,
                                self.caddy_container,
                            ],
                            timeout=15,
                            check=False,
                        )
                    if isinstance(exc, BridgeRequestError):
                        raise BridgeRequestError(
                            422, f"Caddy route validation failed: {exc}"
                        ) from exc
                    raise BridgeRequestError(
                        500, f"Failed writing Caddy route: {exc}"
                    ) from exc

                return {"ok": True, "slug": slug, "domain": domain, "routed": True}

    def remove_workload(self, payload: dict[str, Any]) -> dict[str, Any]:
        slug = validate_slug(payload.get("slug"))
        raw_remove = payload.get("removeFiles", False)
        if not isinstance(raw_remove, bool):
            raise BridgeRequestError(400, "Field 'removeFiles' must be a boolean.")
        remove_files = raw_remove
        network_name = f"vpsagent-{slug}_app_net"

        with self._lock_for(slug):
            app_dir = resolve_scoped_app_dir(
                self.apps_root, slug, require_exists=False
            )
            compose_path = os.path.join(app_dir, "docker-compose.yml")
            if os.path.exists(app_dir) and os.path.lexists(compose_path):
                try:
                    with self._validated_compose_context(app_dir, slug) as (
                        validated_compose,
                        project_dir,
                    ):
                        self._run_docker(
                            [
                                *self._compose_cmd_base(
                                    slug, project_dir, validated_compose
                                ),
                                "down",
                                "--remove-orphans",
                            ],
                            timeout=60,
                            check=True,
                        )
                except BridgeRequestError as exc:
                    if exc.status_code != 400:
                        raise
                    self._compose_down_by_project(slug)
            else:
                self._compose_down_by_project(slug)

            with self._caddy_lock:
                self._run_docker(
                    ["network", "disconnect", network_name, self.caddy_container],
                    timeout=15,
                    check=False,
                )
                route_path = self._resolve_caddy_route_path(slug)
                if os.path.exists(route_path):
                    with open(route_path, "r", encoding="utf-8") as fh:
                        previous_content = fh.read()
                    os.unlink(route_path)
                    try:
                        self._validate_and_reload_caddy()
                    except Exception:
                        with open(route_path, "w", encoding="utf-8") as fh:
                            fh.write(previous_content)
                        os.chmod(route_path, 0o644)
                        raise

            if remove_files and os.path.exists(app_dir):
                shutil.rmtree(app_dir)

            self._clear_host_health(slug)
            return {"ok": True, "slug": slug}

    def _single_status(self, slug: str) -> tuple[str, str]:
        app_dir = resolve_scoped_app_dir(self.apps_root, slug, require_exists=False)
        compose_path = os.path.join(app_dir, "docker-compose.yml")
        if not os.path.exists(app_dir) or not os.path.lexists(compose_path):
            return slug, "stopped"
        try:
            with self._validated_compose_context(app_dir, slug) as (
                validated_compose,
                project_dir,
            ):
                status = self._compose_status(slug, project_dir, validated_compose)
                return slug, self._resolve_overall_status(slug, status)
        except BridgeRequestError:
            return slug, "error"

    def statuses(self, payload: dict[str, Any]) -> dict[str, Any]:
        raw_slugs = payload.get("slugs")
        if not isinstance(raw_slugs, list):
            raise BridgeRequestError(400, "Field 'slugs' must be an array.")
        if len(raw_slugs) > MAX_STATUS_SLUGS:
            raise BridgeRequestError(
                400, f"At most {MAX_STATUS_SLUGS} slugs may be queried at once."
            )

        validated_slugs = [validate_slug(item) for item in raw_slugs]
        if not validated_slugs:
            return {"statuses": {}}

        out: dict[str, str] = {}
        pool = ThreadPoolExecutor(max_workers=4)
        pending_or_timed_out = True
        try:
            futures = {pool.submit(self._single_status, s): s for s in validated_slugs}
            done, not_done = wait_futures(
                futures.keys(),
                timeout=self.status_deadline_s,
                return_when=ALL_COMPLETED,
            )
            if not_done:
                for fut in not_done:
                    fut.cancel()
                raise BridgeRequestError(504, "Status sync exceeded overall deadline.")
            for fut in done:
                resolved_slug, status = fut.result()
                out[resolved_slug] = status
            pending_or_timed_out = False
        finally:
            pool.shutdown(
                wait=not pending_or_timed_out,
                cancel_futures=pending_or_timed_out,
            )
        return {"statuses": out}

    def _select_primary_container(
        self, slug: str, containers: list[dict[str, Any]]
    ) -> dict[str, Any] | None:
        primary_name = f"vpsagent-app-{slug}"
        exact = next(
            (
                c
                for c in containers
                if c["name"] == primary_name and c["running"] and c["ipAddress"]
            ),
            None,
        )
        if exact is not None:
            return exact
        return next((c for c in containers if c["running"] and c["ipAddress"]), None)

    def inspect_workload(
        self,
        payload: dict[str, Any],
        *,
        timeout_budget_s: float | None = None,
        _apply_host_health: bool = True,
    ) -> dict[str, Any]:
        slug = validate_slug(payload.get("slug"))
        raw_probe_http = payload.get("probeHttp", False)
        if not isinstance(raw_probe_http, bool):
            raise BridgeRequestError(400, "Field 'probeHttp' must be a boolean.")
        probe_http = raw_probe_http
        probe_path = validate_probe_path(payload.get("probePath"))
        raw_port = payload.get("internalPort")
        internal_port = 8080 if raw_port is None else validate_port(raw_port)

        deadline = (
            time.monotonic() + max(0.05, float(timeout_budget_s))
            if timeout_budget_s is not None
            else None
        )

        def _budget(default_s: float) -> float:
            if deadline is None:
                return default_s
            rem = deadline - time.monotonic()
            if rem <= 0:
                raise BridgeRequestError(504, "Readiness timeout budget exhausted.")
            return min(default_s, rem)

        app_dir = resolve_scoped_app_dir(self.apps_root, slug, require_exists=False)
        workspace_exists = os.path.isdir(app_dir)
        compose_exists = os.path.lexists(os.path.join(app_dir, "docker-compose.yml"))

        route_path = self._resolve_caddy_route_path(slug)
        caddy_route_configured = os.path.isfile(route_path)
        caddy_domains: list[str] = []
        if caddy_route_configured:
            try:
                route_text = _read_regular_file_nofollow(
                    route_path, MAX_BODY_BYTES, f'Caddy route for "{slug}"'
                )
                caddy_domains = sorted(_extract_domains_from_caddy_text(route_text))
            except BridgeRequestError:
                caddy_domains = []

        ps_proc = self._run_docker(
            [
                "ps",
                "-a",
                "--filter",
                f"label=com.docker.compose.project=vpsagent-{slug}",
                "--format",
                "{{.ID}}",
            ],
            timeout=_budget(15.0),
            check=False,
        )
        targets: list[str] = []
        if ps_proc.returncode == 0 and ps_proc.stdout.strip():
            seen_ids: set[str] = set()
            for raw_line in ps_proc.stdout.splitlines():
                cid = raw_line.strip()
                if cid and cid not in seen_ids:
                    seen_ids.add(cid)
                    targets.append(cid)
                    if len(targets) >= 4:
                        break
        if not targets:
            targets = [f"vpsagent-app-{slug}"]

        inspect_proc = self._run_docker(
            ["inspect", *targets], timeout=_budget(15.0), check=False
        )
        containers: list[dict[str, Any]] = []
        expected_net = f"vpsagent-{slug}_app_net"

        if inspect_proc.returncode == 0 and inspect_proc.stdout.strip():
            try:
                inspected_raw = json.loads(inspect_proc.stdout)
            except json.JSONDecodeError:
                inspected_raw = []
            if isinstance(inspected_raw, list):
                for item in inspected_raw:
                    if not isinstance(item, dict):
                        continue
                    state_obj = item.get("State")
                    if not isinstance(state_obj, dict):
                        state_obj = {}
                    host_cfg = item.get("HostConfig")
                    if not isinstance(host_cfg, dict):
                        host_cfg = {}
                    config_obj = item.get("Config")
                    if not isinstance(config_obj, dict):
                        config_obj = {}
                    net_settings = item.get("NetworkSettings")
                    if not isinstance(net_settings, dict):
                        net_settings = {}
                    networks_map = net_settings.get("Networks")
                    if not isinstance(networks_map, dict):
                        networks_map = {}

                    networks = sorted(str(k) for k in networks_map.keys())
                    ip_address: str | None = None
                    preferred_net = networks_map.get(expected_net)
                    if isinstance(preferred_net, dict):
                        candidate_ip = str(
                            preferred_net.get("IPAddress") or ""
                        ).strip()
                        if candidate_ip:
                            ip_address = candidate_ip
                    if ip_address is None:
                        for net_entry in networks_map.values():
                            if isinstance(net_entry, dict):
                                candidate_ip = str(
                                    net_entry.get("IPAddress") or ""
                                ).strip()
                                if candidate_ip:
                                    ip_address = candidate_ip
                                    break

                    cap_drop_raw = host_cfg.get("CapDrop")
                    cap_drop_list = (
                        [str(x).upper() for x in cap_drop_raw]
                        if isinstance(cap_drop_raw, list)
                        else []
                    )
                    cap_drop_all = "ALL" in cap_drop_list

                    sec_opt_raw = host_cfg.get("SecurityOpt")
                    sec_opt_list = (
                        [str(x).lower() for x in sec_opt_raw]
                        if isinstance(sec_opt_raw, list)
                        else []
                    )
                    no_new_privileges = any(
                        opt in ("no-new-privileges:true", "no-new-privileges=true")
                        for opt in sec_opt_list
                    )
                    privileged = bool(host_cfg.get("Privileged", False))

                    has_docker_socket_mount = False
                    mounts = item.get("Mounts")
                    if isinstance(mounts, list):
                        for mount in mounts:
                            if isinstance(mount, dict):
                                src = str(mount.get("Source") or "")
                                dst = str(mount.get("Destination") or "")
                                if "docker.sock" in src or "docker.sock" in dst:
                                    has_docker_socket_mount = True
                                    break
                    if not has_docker_socket_mount:
                        binds = host_cfg.get("Binds")
                        if isinstance(binds, list):
                            for bind in binds:
                                if "docker.sock" in str(bind):
                                    has_docker_socket_mount = True
                                    break

                    mem_bytes = host_cfg.get("Memory")
                    memory_limit_mb = (
                        round(mem_bytes / (1024 * 1024))
                        if isinstance(mem_bytes, (int, float))
                        and not isinstance(mem_bytes, bool)
                        and mem_bytes > 0
                        else None
                    )
                    nano_cpus_raw = host_cfg.get("NanoCpus")
                    nano_cpus = (
                        int(nano_cpus_raw)
                        if isinstance(nano_cpus_raw, (int, float))
                        and not isinstance(nano_cpus_raw, bool)
                        and nano_cpus_raw > 0
                        else None
                    )

                    isolated_network_only = len(networks) > 0 and all(
                        n == expected_net for n in networks
                    )
                    locked_compliant = (
                        cap_drop_all
                        and no_new_privileges
                        and (not privileged)
                        and (not has_docker_socket_mount)
                        and (not bool(host_cfg.get("CapAdd")))
                        and ((host_cfg.get("PidMode") or "") != "host")
                        and ((host_cfg.get("IpcMode") or "") != "host")
                        and isolated_network_only
                    )

                    health_obj = state_obj.get("Health")
                    if not isinstance(health_obj, dict):
                        health_obj = {}
                    raw_health = str(health_obj.get("Status") or "none").strip().lower()
                    health_status = (
                        raw_health
                        if raw_health in ("healthy", "unhealthy", "starting", "none")
                        else "none"
                    )
                    health_log = health_obj.get("Log")
                    last_health_output: str | None = None
                    if (
                        isinstance(health_log, list)
                        and health_log
                        and isinstance(health_log[-1], dict)
                    ):
                        raw_out = str(health_log[-1].get("Output") or "").strip()
                        if raw_out:
                            last_health_output = redact_secrets(raw_out)[:300] or None

                    raw_state = str(state_obj.get("Status") or "unknown").strip().lower()
                    running = bool(state_obj.get("Running", raw_state == "running"))
                    raw_exit = state_obj.get("ExitCode", 0)
                    exit_code = (
                        int(raw_exit)
                        if isinstance(raw_exit, int) and not isinstance(raw_exit, bool)
                        else 0
                    )
                    raw_restarts = item.get("RestartCount", 0)
                    restart_count = (
                        int(raw_restarts)
                        if isinstance(raw_restarts, int)
                        and not isinstance(raw_restarts, bool)
                        and raw_restarts >= 0
                        else 0
                    )
                    raw_started = state_obj.get("StartedAt")
                    started_at = (
                        raw_started
                        if isinstance(raw_started, str) and raw_started
                        else None
                    )

                    containers.append(
                        {
                            "id": str(item.get("Id") or "")[:12],
                            "name": str(item.get("Name") or "").lstrip("/"),
                            "image": str(config_obj.get("Image") or ""),
                            "state": raw_state,
                            "running": running,
                            "exitCode": exit_code,
                            "restartCount": restart_count,
                            "startedAt": started_at,
                            "healthStatus": health_status,
                            "lastHealthOutput": last_health_output,
                            "networks": networks,
                            "ipAddress": ip_address,
                            "security": {
                                "capDropAll": cap_drop_all,
                                "noNewPrivileges": no_new_privileges,
                                "privileged": privileged,
                                "hasDockerSocketMount": has_docker_socket_mount,
                                "isolatedNetworkOnly": isolated_network_only,
                                "memoryLimitMb": memory_limit_mb,
                                "nanoCpus": nano_cpus,
                                "lockedApartmentCompliant": locked_compliant,
                            },
                        }
                    )

        status = derive_app_status(
            [
                {
                    "State": c["state"],
                    "Health": "" if c["healthStatus"] == "none" else c["healthStatus"],
                    "ExitCode": c["exitCode"],
                }
                for c in containers
            ]
        )
        locked_apartment_compliant = len(containers) > 0 and all(
            c["security"]["lockedApartmentCompliant"] for c in containers
        )

        http_probe: dict[str, Any] | None = None
        target_container = self._select_primary_container(slug, containers)
        if probe_http:
            if target_container is not None:
                if deadline is not None and deadline - time.monotonic() <= 0:
                    http_probe = {
                        "attempted": False,
                        "ok": False,
                        "statusCode": None,
                        "latencyMs": None,
                        "contentType": None,
                        "error": "Readiness timeout budget exhausted before HTTP probe.",
                    }
                else:
                    http_probe = _probe_container_http(
                        str(target_container["ipAddress"]),
                        internal_port,
                        probe_path,
                        timeout_s=_budget(DEFAULT_PROBE_TIMEOUT_S),
                    )
            else:
                http_probe = {
                    "attempted": False,
                    "ok": False,
                    "statusCode": None,
                    "latencyMs": None,
                    "contentType": None,
                    "error": "Container is not running or has no bridge IP.",
                }

        # Keep Docker container liveness (`containers[i].healthStatus`) separate from
        # VPSAgent's recurring host HTTP monitor (`hostHttpHealth`) and the live
        # `httpProbe`, while applying the exact same overall status rule used by
        # `/v1/apps/statuses` so the Apps list and Safety Check never disagree.
        host_http_health: dict[str, Any] | None = None
        if _apply_host_health:
            cached_host_health = self._get_host_health(slug)
            if cached_host_health is not None:
                host_http_health = {
                    "status": str(cached_host_health.get("status") or "none"),
                    "consecutiveFailures": int(
                        cached_host_health.get("consecutiveFailures") or 0
                    ),
                    "lastOutput": cached_host_health.get("lastOutput"),
                }
            else:
                probe_cfg = self._read_app_probe_config(app_dir, slug)
                monitoring_enabled = (
                    probe_cfg["probeHttp"]
                    if probe_cfg is not None
                    else bool(probe_http)
                )
                if monitoring_enabled:
                    # Recurring monitor is enabled but has not completed its first
                    # pass yet — never synthesize a monitor failure from live `httpProbe`.
                    host_http_health = {
                        "status": "starting",
                        "consecutiveFailures": 0,
                        "lastOutput": None,
                    }
            status = self._resolve_overall_status(slug, status)

        return {
            "slug": slug,
            "status": status,
            "workspaceExists": workspace_exists,
            "composeExists": compose_exists,
            "caddyRouteConfigured": caddy_route_configured,
            "caddyDomains": caddy_domains,
            "containers": containers,
            "lockedApartmentCompliant": locked_apartment_compliant,
            "httpProbe": http_probe,
            "hostHttpHealth": host_http_health,
        }

    def check_readiness(self, payload: dict[str, Any]) -> dict[str, Any]:
        """
        Bounded startup readiness wait:
        - Fails fast if container is stopped/error or reports healthStatus == 'unhealthy'.
        - Waits while any configured container health check is still 'starting'.
        - When probeHttp is True (default), retries while the app is still binding its port
          and accepts any non-5xx HTTP response (100 <= status < 500, including 4xx API roots).
        - When probeHttp is False (non-HTTP workers), completes once running and healthy.
        - Strictly budgets remaining time before and after each inspection.
        """
        slug = validate_slug(payload.get("slug"))
        internal_port = validate_port(payload.get("internalPort"))
        raw_probe_http = payload.get("probeHttp", True)
        if not isinstance(raw_probe_http, bool):
            raise BridgeRequestError(400, "Field 'probeHttp' must be a boolean.")
        probe_http = raw_probe_http
        probe_path = validate_probe_path(payload.get("probePath"))

        raw_timeout = payload.get("timeoutSeconds", DEFAULT_READINESS_TIMEOUT_S)
        if (
            not isinstance(raw_timeout, (int, float))
            or isinstance(raw_timeout, bool)
            or raw_timeout < 0.1
            or raw_timeout > 60.0
        ):
            raise BridgeRequestError(
                400, "Field 'timeoutSeconds' must be between 0.1 and 60."
            )
        timeout_s = float(raw_timeout)

        raw_poll_ms = payload.get("pollIntervalMs", DEFAULT_READINESS_POLL_MS)
        if (
            not isinstance(raw_poll_ms, int)
            or isinstance(raw_poll_ms, bool)
            or raw_poll_ms < 10
            or raw_poll_ms > 5000
        ):
            raise BridgeRequestError(
                400, "Field 'pollIntervalMs' must be an integer between 10 and 5000."
            )
        poll_s = raw_poll_ms / 1000.0

        t0 = time.monotonic()
        deadline = t0 + timeout_s
        attempts = 0
        last_status = "stopped"
        last_probe: dict[str, Any] | None = None
        last_reason = "Readiness probe did not succeed before timeout."

        while True:
            remaining_before = deadline - time.monotonic()
            if attempts > 0 and remaining_before <= 0:
                return {
                    "ready": False,
                    "slug": slug,
                    "status": last_status,
                    "attempts": attempts,
                    "elapsedMs": round((time.monotonic() - t0) * 1000, 1),
                    "httpProbe": last_probe,
                    "reason": redact_secrets(
                        f'Timed out waiting for "{slug}" on port {internal_port}: {last_reason}'
                    ),
                }

            attempts += 1
            try:
                inspected = self.inspect_workload(
                    {
                        "slug": slug,
                        "probeHttp": probe_http,
                        "internalPort": internal_port,
                        "probePath": probe_path,
                    },
                    timeout_budget_s=max(0.05, remaining_before),
                    _apply_host_health=False,
                )
            except BridgeRequestError as exc:
                if exc.status_code == 504:
                    if attempts == 1:
                        last_reason = str(exc)
                    return {
                        "ready": False,
                        "slug": slug,
                        "status": last_status,
                        "attempts": attempts,
                        "elapsedMs": round((time.monotonic() - t0) * 1000, 1),
                        "httpProbe": last_probe,
                        "reason": redact_secrets(
                            f'Timed out waiting for "{slug}" on port {internal_port}: {last_reason}'
                        ),
                    }
                raise

            last_status = str(inspected["status"])
            last_probe = inspected.get("httpProbe")
            containers = inspected.get("containers") or []
            any_unhealthy = any(
                c.get("healthStatus") == "unhealthy" for c in containers
            )
            any_starting = any(
                c.get("healthStatus") == "starting" for c in containers
            )

            if last_status != "running" or any_unhealthy:
                reason = (
                    f'Container for "{slug}" failed readiness check '
                    f"(status={last_status}, unhealthy={str(any_unhealthy).lower()})."
                )
                return {
                    "ready": False,
                    "slug": slug,
                    "status": last_status,
                    "attempts": attempts,
                    "elapsedMs": round((time.monotonic() - t0) * 1000, 1),
                    "httpProbe": last_probe,
                    "reason": reason,
                }

            candidate_ready = False
            if any_starting:
                last_reason = "Waiting for container health check to finish starting."
            elif not probe_http:
                candidate_ready = True
            elif isinstance(last_probe, dict) and last_probe.get("attempted"):
                code = last_probe.get("statusCode")
                if last_probe.get("ok") or (
                    isinstance(code, int) and 100 <= code < 500
                ):
                    candidate_ready = True
                elif last_probe.get("error"):
                    last_reason = f"HTTP probe error: {last_probe['error']}"
                else:
                    last_reason = f"HTTP probe returned status {code}."
            elif isinstance(last_probe, dict) and last_probe.get("error"):
                last_reason = str(last_probe["error"])

            # Strictly check remaining deadline AFTER inspection and BEFORE any success return,
            # while preserving any more specific diagnostic (e.g. still starting / probe error).
            remaining_after = deadline - time.monotonic()
            if remaining_after <= 0:
                timeout_detail = (
                    f"readiness deadline ({timeout_s}s) exceeded during inspection."
                    if candidate_ready
                    else last_reason
                )
                return {
                    "ready": False,
                    "slug": slug,
                    "status": last_status,
                    "attempts": attempts,
                    "elapsedMs": round((time.monotonic() - t0) * 1000, 1),
                    "httpProbe": last_probe,
                    "reason": redact_secrets(
                        f'Timed out waiting for "{slug}" on port {internal_port}: {timeout_detail}'
                    ),
                }

            if candidate_ready:
                if probe_http and isinstance(last_probe, dict):
                    self._record_host_health(slug, probe_path, last_probe)
                return {
                    "ready": True,
                    "slug": slug,
                    "status": last_status,
                    "attempts": attempts,
                    "elapsedMs": round((time.monotonic() - t0) * 1000, 1),
                    "httpProbe": last_probe if probe_http else None,
                    "reason": None,
                }

            time.sleep(min(poll_s, remaining_after))

    # -------------------------------------------------------------------------
    # VPS Manager Endpoints (Command Exec, File Management, Services, Cleanup)
    # -------------------------------------------------------------------------

    @staticmethod
    def _truncate_redacted_output(
        text: str, max_bytes: int = MAX_COMMAND_OUTPUT_BYTES
    ) -> tuple[str, bool]:
        redacted = redact_secrets(text)
        encoded = redacted.encode("utf-8", errors="replace")
        if len(encoded) <= max_bytes:
            return redacted, False
        clipped = encoded[:max_bytes].decode("utf-8", errors="ignore")
        return clipped + "\n...[output truncated]", True

    @staticmethod
    def _validate_abs_path(raw: Any, field: str = "path") -> str:
        if not isinstance(raw, str) or not raw.strip():
            raise BridgeRequestError(400, f"Field '{field}' must be a non-empty string.")
        cleaned = raw.strip()
        if "\x00" in cleaned or len(cleaned) > 1024:
            raise BridgeRequestError(400, f"Field '{field}' is invalid.")
        if not os.path.isabs(cleaned):
            raise BridgeRequestError(400, f"Field '{field}' must be an absolute path.")
        return os.path.normpath(cleaned)

    @staticmethod
    def _is_secret_path(target_path: str) -> bool:
        for candidate in (target_path, os.path.realpath(target_path)):
            base = os.path.basename(candidate)
            lower_base = base.lower()
            if (
                base in SECRET_FILE_BASENAMES
                or lower_base == ".env"
                or lower_base.startswith(".env.")
                or lower_base.endswith(".pem")
                or lower_base.endswith(".key")
                or lower_base.endswith(".sqlite")
                or lower_base.endswith(".sqlite-wal")
                or lower_base.endswith(".sqlite-shm")
                or lower_base == "registry.db"
                or lower_base.startswith("registry.db-")
            ):
                return True
            if (
                candidate in ("/etc/shadow", "/etc/gshadow")
                or candidate.startswith("/var/lib/vpsagent/run/")
                or candidate == "/var/lib/vpsagent/run"
                or candidate.startswith("/var/lib/vpsagent/data/")
                or candidate == "/var/lib/vpsagent/data"
            ):
                return True
        return False

    def _assert_not_secret_file(self, abs_path: str) -> None:
        if self._is_secret_path(abs_path):
            raise BridgeRequestError(
                403,
                "Access to sensitive secret or credential files is blocked for safety.",
            )

    def _is_within_allowed_roots(self, resolved_path: str) -> bool:
        for root in self.allowed_file_roots:
            try:
                if os.path.commonpath([resolved_path, root]) == root:
                    return True
            except ValueError:
                continue
        return False

    def _assert_allowed_file_path(
        self, abs_path: str, *, allow_root_self: bool = True
    ) -> str:
        resolved = os.path.realpath(abs_path)
        if not self._is_within_allowed_roots(resolved):
            raise BridgeRequestError(
                403,
                f"Path '{abs_path}' is outside the allowed file directories ({', '.join(self.allowed_file_roots)}).",
            )
        if not allow_root_self and resolved in self.allowed_file_roots:
            raise BridgeRequestError(
                403, f"Refusing to delete an allowed root directory: {abs_path}"
            )
        self._assert_not_secret_file(abs_path)
        return resolved

    def _run_cmd_bounded(
        self,
        cmd: list[str],
        *,
        label: str,
        timeout: float,
        cwd: str | None = None,
        max_bytes: int = MAX_COMMAND_OUTPUT_BYTES,
    ) -> tuple[int, str, str, bool]:
        """Run a subprocess in its own process group, streaming output with a hard memory cap."""
        buf_cap = max_bytes + 4096
        try:
            proc = subprocess.Popen(
                cmd,
                cwd=cwd,
                shell=False,
                env=_sanitized_subprocess_env(),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                start_new_session=True,
            )
        except FileNotFoundError as exc:
            raise BridgeRequestError(
                503, f"{label} CLI binary not found ({cmd[0]})."
            ) from exc

        out_chunks: list[bytes] = []
        err_chunks: list[bytes] = []
        trunc_flags = [False, False]

        def _drain(stream: Any, bucket: list[bytes], flag_idx: int) -> None:
            kept = 0
            try:
                while True:
                    chunk = stream.read(4096)
                    if not chunk:
                        break
                    if kept < buf_cap:
                        take = min(len(chunk), buf_cap - kept)
                        bucket.append(chunk[:take])
                        kept += take
                        if take < len(chunk):
                            trunc_flags[flag_idx] = True
                    else:
                        trunc_flags[flag_idx] = True
            finally:
                try:
                    stream.close()
                except OSError:
                    pass

        t_out = threading.Thread(
            target=_drain, args=(proc.stdout, out_chunks, 0), daemon=True
        )
        t_err = threading.Thread(
            target=_drain, args=(proc.stderr, err_chunks, 1), daemon=True
        )
        t_out.start()
        t_err.start()

        try:
            proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired as exc:
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            except OSError:
                proc.kill()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                pass
            t_out.join(timeout=2)
            t_err.join(timeout=2)
            raise BridgeRequestError(
                504, f"{label} command timed out after {int(timeout)}s."
            ) from exc

        t_out.join(timeout=2)
        t_err.join(timeout=2)
        raw_out = b"".join(out_chunks).decode("utf-8", errors="replace")
        raw_err = b"".join(err_chunks).decode("utf-8", errors="replace")
        stdout, out_trunc = self._truncate_redacted_output(raw_out, max_bytes=max_bytes)
        stderr, err_trunc = self._truncate_redacted_output(raw_err, max_bytes=max_bytes)
        return (
            int(proc.returncode or 0),
            stdout,
            stderr,
            out_trunc or err_trunc or trunc_flags[0] or trunc_flags[1],
        )

    def exec_in_app(self, payload: dict[str, Any]) -> dict[str, Any]:
        slug = validate_slug(payload.get("slug"))
        command = payload.get("command")
        if not isinstance(command, str) or not command.strip() or len(command) > 8000:
            raise BridgeRequestError(
                400, "Field 'command' must be a non-empty string (max 8000 chars)."
            )
        service = payload.get("service", "app")
        if not isinstance(service, str) or not SERVICE_NAME_PATTERN.fullmatch(service):
            raise BridgeRequestError(400, "Field 'service' is invalid.")
        raw_timeout = payload.get("timeoutSeconds", DEFAULT_HOST_CMD_TIMEOUT_S)
        if not isinstance(raw_timeout, (int, float)) or isinstance(raw_timeout, bool):
            raise BridgeRequestError(400, "Field 'timeoutSeconds' must be a number.")
        timeout_s = max(1, min(int(raw_timeout), MAX_HOST_CMD_TIMEOUT_S))

        with self._lock_for(slug):
            app_dir = resolve_scoped_app_dir(self.apps_root, slug)
            with self._validated_compose_context(app_dir, slug) as (
                compose_path,
                project_dir,
            ):
                base = self._compose_cmd_base(slug, project_dir, compose_path)
                # Enforce timeout INSIDE the container as well so timed-out shells
                # are killed inside the container (not only the host docker CLI).
                inner_wrapper = (
                    f"if command -v timeout >/dev/null 2>&1; then "
                    f'exec timeout -k 2 {timeout_s} sh -lc "$1"; '
                    f"else "
                    f'sh -lc "$1" & pid=$!; '
                    f'(sleep {timeout_s}; kill -TERM "$pid" 2>/dev/null; sleep 1; kill -KILL "$pid" 2>/dev/null) & watcher=$!; '
                    f'wait "$pid"; rc=$?; kill "$watcher" 2>/dev/null; '
                    f'if [ "$rc" -eq 143 ] || [ "$rc" -eq 137 ]; then exit 124; fi; exit "$rc"; '
                    f"fi"
                )
                t0 = time.monotonic()
                rc, stdout, stderr, truncated = self._run_cmd_bounded(
                    [
                        self.docker_bin,
                        *base,
                        "exec",
                        "-T",
                        service,
                        "sh",
                        "-c",
                        inner_wrapper,
                        "vpsagent-exec",
                        command,
                    ],
                    label="Docker exec",
                    timeout=timeout_s + 3,
                )
                if rc == 124:
                    raise BridgeRequestError(
                        504,
                        f'Command inside "{slug}" timed out after {timeout_s}s.',
                    )
                elapsed_ms = round((time.monotonic() - t0) * 1000, 1)
                return {
                    "exitCode": rc,
                    "stdout": stdout,
                    "stderr": stderr,
                    "durationMs": elapsed_ms,
                    "truncated": truncated,
                }

    def host_exec(self, payload: dict[str, Any]) -> dict[str, Any]:
        command = payload.get("command")
        if not isinstance(command, str) or not command.strip() or len(command) > 8000:
            raise BridgeRequestError(
                400, "Field 'command' must be a non-empty string (max 8000 chars)."
            )
        cwd_raw = payload.get("cwd")
        cwd: str | None = None
        if cwd_raw is not None:
            cwd = self._validate_abs_path(cwd_raw, "cwd")
            if not os.path.isdir(cwd):
                raise BridgeRequestError(
                    400, f"Working directory does not exist: {cwd}"
                )
        raw_timeout = payload.get("timeoutSeconds", DEFAULT_HOST_CMD_TIMEOUT_S)
        if not isinstance(raw_timeout, (int, float)) or isinstance(raw_timeout, bool):
            raise BridgeRequestError(400, "Field 'timeoutSeconds' must be a number.")
        timeout_s = max(1, min(int(raw_timeout), MAX_HOST_CMD_TIMEOUT_S))

        shell_bin = "/bin/bash" if os.path.exists("/bin/bash") else "/bin/sh"
        t0 = time.monotonic()
        rc, stdout, stderr, truncated = self._run_cmd_bounded(
            [shell_bin, "-lc", command],
            label="Host shell",
            timeout=timeout_s,
            cwd=cwd,
        )
        elapsed_ms = round((time.monotonic() - t0) * 1000, 1)
        return {
            "exitCode": rc,
            "stdout": stdout,
            "stderr": stderr,
            "durationMs": elapsed_ms,
            "truncated": truncated,
        }

    def list_files(self, payload: dict[str, Any]) -> dict[str, Any]:
        target_path = self._validate_abs_path(payload.get("path"))
        self._assert_allowed_file_path(target_path)
        show_hidden = bool(payload.get("showHidden", False))
        raw_max = payload.get("maxEntries", 200)
        if not isinstance(raw_max, int) or isinstance(raw_max, bool):
            raise BridgeRequestError(400, "Field 'maxEntries' must be an integer.")
        max_entries = max(1, min(raw_max, 500))

        if not os.path.exists(target_path):
            raise BridgeRequestError(404, f"Directory not found: {target_path}")
        if not os.path.isdir(target_path):
            raise BridgeRequestError(400, f"Path is not a directory: {target_path}")

        try:
            with os.scandir(target_path) as it:
                raw_entries = list(it)
        except OSError as exc:
            raise BridgeRequestError(500, redact_secrets(str(exc))) from exc

        entries: list[dict[str, Any]] = []
        for item in raw_entries:
            if not show_hidden and item.name.startswith("."):
                continue
            try:
                st = item.stat(follow_symlinks=False)
                if stat.S_ISLNK(st.st_mode):
                    entry_type = "symlink"
                elif stat.S_ISDIR(st.st_mode):
                    entry_type = "dir"
                elif stat.S_ISREG(st.st_mode):
                    entry_type = "file"
                else:
                    entry_type = "other"
                size_bytes = int(st.st_size) if entry_type == "file" else 0
                mod_at = datetime.fromtimestamp(
                    st.st_mtime, tz=timezone.utc
                ).isoformat()
            except OSError:
                entry_type = "other"
                size_bytes = 0
                mod_at = None
            entries.append(
                {
                    "name": item.name,
                    "path": os.path.join(target_path, item.name),
                    "type": entry_type,
                    "sizeBytes": size_bytes,
                    "modifiedAt": mod_at,
                }
            )

        entries.sort(key=lambda e: (0 if e["type"] == "dir" else 1, e["name"].lower()))
        truncated = len(entries) > max_entries
        return {
            "path": target_path,
            "entries": entries[:max_entries],
            "truncated": truncated,
        }

    def read_file(self, payload: dict[str, Any]) -> dict[str, Any]:
        target_path = self._validate_abs_path(payload.get("path"))
        self._assert_allowed_file_path(target_path)

        if not os.path.exists(target_path):
            raise BridgeRequestError(404, f"File not found: {target_path}")
        if not os.path.isfile(target_path):
            raise BridgeRequestError(400, f"Path is not a regular file: {target_path}")

        raw_start = payload.get("startLine", 1)
        raw_end = payload.get("endLine")
        raw_max_bytes = payload.get("maxBytes", 65536)
        if not isinstance(raw_start, int) or isinstance(raw_start, bool) or raw_start < 1:
            raise BridgeRequestError(400, "Field 'startLine' must be an integer >= 1.")
        if raw_end is not None and (
            not isinstance(raw_end, int)
            or isinstance(raw_end, bool)
            or raw_end < raw_start
        ):
            raise BridgeRequestError(
                400, "Field 'endLine' must be an integer >= startLine."
            )
        if not isinstance(raw_max_bytes, int) or isinstance(raw_max_bytes, bool):
            raise BridgeRequestError(400, "Field 'maxBytes' must be an integer.")
        max_bytes = max(256, min(raw_max_bytes, MAX_READ_FILE_BYTES))

        try:
            size_bytes = os.path.getsize(target_path)
            with open(target_path, "rb") as fh:
                raw_chunk = fh.read(MAX_READ_SCAN_BYTES + 1)
        except OSError as exc:
            raise BridgeRequestError(500, redact_secrets(str(exc))) from exc

        scan_truncated = len(raw_chunk) > MAX_READ_SCAN_BYTES
        if scan_truncated:
            raw_chunk = raw_chunk[:MAX_READ_SCAN_BYTES]
        decoded = raw_chunk.decode("utf-8", errors="replace")
        all_lines = decoded.splitlines()

        total_lines = len(all_lines)
        start_idx = raw_start - 1
        end_idx = raw_end if raw_end is not None else total_lines
        selected = all_lines[start_idx:end_idx]
        joined = "\n".join(selected)
        content, truncated = self._truncate_redacted_output(joined, max_bytes=max_bytes)
        actual_end = min(end_idx, total_lines)
        return {
            "path": target_path,
            "content": content,
            "sizeBytes": int(size_bytes),
            "totalLines": total_lines,
            "startLine": raw_start,
            "endLine": actual_end,
            "truncated": scan_truncated or truncated or (actual_end < total_lines),
        }

    def write_file(self, payload: dict[str, Any]) -> dict[str, Any]:
        target_path = self._validate_abs_path(payload.get("path"))
        self._assert_allowed_file_path(target_path)

        content = payload.get("content")
        if not isinstance(content, str):
            raise BridgeRequestError(400, "Field 'content' must be a string.")
        encoded = content.encode("utf-8")
        if len(encoded) > MAX_WRITE_FILE_BYTES:
            raise BridgeRequestError(
                413,
                f"File content exceeds maximum size ({MAX_WRITE_FILE_BYTES} bytes).",
            )
        append = bool(payload.get("append", False))
        create_dirs = bool(payload.get("createDirs", False))

        parent_dir = os.path.dirname(target_path)
        if parent_dir and not os.path.exists(parent_dir):
            if create_dirs:
                os.makedirs(parent_dir, exist_ok=True)
            else:
                raise BridgeRequestError(
                    400, f"Parent directory does not exist: {parent_dir}"
                )
        # Re-verify resolved path after optional parent creation
        self._assert_allowed_file_path(target_path)

        mode = "a" if append else "w"
        try:
            with open(target_path, mode, encoding="utf-8") as fh:
                fh.write(content)
        except OSError as exc:
            raise BridgeRequestError(500, redact_secrets(str(exc))) from exc

        return {
            "ok": True,
            "path": target_path,
            "bytesWritten": len(encoded),
            "appended": append,
        }

    def delete_file(self, payload: dict[str, Any]) -> dict[str, Any]:
        target_path = self._validate_abs_path(payload.get("path"))
        if target_path in PROTECTED_DELETE_PATHS or os.path.realpath(
            target_path
        ) in PROTECTED_DELETE_PATHS:
            raise BridgeRequestError(
                403, f"Refusing to delete protected system path: {target_path}"
            )
        self._assert_allowed_file_path(target_path, allow_root_self=False)

        recursive = bool(payload.get("recursive", False))
        if not os.path.lexists(target_path):
            raise BridgeRequestError(404, f"Path not found: {target_path}")

        if os.path.isdir(target_path) and not os.path.islink(target_path) and recursive:
            for dirpath, dirnames, filenames in os.walk(target_path, followlinks=False):
                for entry_name in (*dirnames, *filenames):
                    entry_path = os.path.join(dirpath, entry_name)
                    if self._is_secret_path(entry_path):
                        raise BridgeRequestError(
                            403,
                            f"Refusing recursive delete because directory contains protected file: {entry_name}",
                        )
                    if not self._is_within_allowed_roots(os.path.realpath(entry_path)):
                        raise BridgeRequestError(
                            403,
                            f"Refusing recursive delete because entry resolves outside allowed directories: {entry_name}",
                        )

        try:
            if os.path.islink(target_path):
                os.unlink(target_path)
                deleted_type = "symlink"
            elif os.path.isdir(target_path):
                if recursive:
                    shutil.rmtree(target_path)
                else:
                    os.rmdir(target_path)
                deleted_type = "dir"
            else:
                os.unlink(target_path)
                deleted_type = "file"
        except OSError as exc:
            raise BridgeRequestError(400, redact_secrets(str(exc))) from exc

        return {
            "ok": True,
            "path": target_path,
            "deletedType": deleted_type,
        }

    def list_services(self, payload: dict[str, Any]) -> dict[str, Any]:
        filter_str = payload.get("filter")
        if filter_str is not None and not isinstance(filter_str, str):
            raise BridgeRequestError(400, "Field 'filter' must be a string.")
        filter_lower = filter_str.strip().lower() if filter_str else ""

        state = payload.get("state", "all")
        if state not in ("all", "running", "failed"):
            raise BridgeRequestError(
                400, "Field 'state' must be one of: all, running, failed."
            )

        raw_limit = payload.get("limit", 100)
        if not isinstance(raw_limit, int) or isinstance(raw_limit, bool):
            raise BridgeRequestError(400, "Field 'limit' must be an integer.")
        limit = max(1, min(raw_limit, 300))

        cmd = [
            "systemctl",
            "list-units",
            "--type=service",
            "--all",
            "--no-pager",
            "--no-legend",
            "--plain",
        ]
        if state == "running":
            cmd.append("--state=running")
        elif state == "failed":
            cmd.append("--state=failed")

        proc = self._run_cmd(cmd, label="systemd", timeout=20, check=False)
        if proc.returncode != 0:
            detail = (proc.stderr or proc.stdout or "systemctl failed").strip()
            raise BridgeRequestError(502, redact_secrets(detail))

        services: list[dict[str, str]] = []
        for line in (proc.stdout or "").splitlines():
            parts = line.strip().split(None, 4)
            if len(parts) < 4:
                continue
            name, load_state, active_state, sub_state = parts[:4]
            description = parts[4] if len(parts) > 4 else ""
            if filter_lower and filter_lower not in name.lower() and filter_lower not in description.lower():
                continue
            services.append(
                {
                    "name": name,
                    "loadState": load_state,
                    "activeState": active_state,
                    "subState": sub_state,
                    "description": redact_secrets(description),
                }
            )

        truncated = len(services) > limit
        return {
            "services": services[:limit],
            "truncated": truncated,
        }

    def manage_service(self, payload: dict[str, Any]) -> dict[str, Any]:
        service = payload.get("service")
        if not isinstance(service, str) or not SERVICE_UNIT_PATTERN.fullmatch(
            service.strip()
        ):
            raise BridgeRequestError(400, "Field 'service' is invalid.")
        service = service.strip()
        action = payload.get("action")
        if not isinstance(action, str) or action not in ALLOWED_SERVICE_ACTIONS:
            raise BridgeRequestError(
                400,
                "Field 'action' must be one of: start, stop, restart, reload, enable, disable, status.",
            )
        if service in PROTECTED_SERVICES and action in ("stop", "disable"):
            raise BridgeRequestError(
                403,
                f"Cannot {action} protected service '{service}' because it would disconnect VPSAgent.",
            )

        cmd = ["systemctl", action, service]
        if action == "status":
            cmd.insert(1, "--no-pager")
        proc = self._run_cmd(cmd, label="systemd", timeout=60, check=False)
        state_proc = self._run_cmd(
            ["systemctl", "is-active", service],
            label="systemd",
            timeout=10,
            check=False,
        )
        active_state = (state_proc.stdout or state_proc.stderr or "unknown").strip()
        raw_out = (proc.stdout or "") + ("\n" + proc.stderr if proc.stderr else "")
        output, _ = self._truncate_redacted_output(raw_out.strip(), max_bytes=16 * 1024)
        ok = proc.returncode == 0 or (action == "status" and proc.returncode in (0, 3))
        return {
            "ok": ok,
            "service": service,
            "action": action,
            "activeState": active_state,
            "output": output,
        }

    def docker_cleanup(self, payload: dict[str, Any]) -> dict[str, Any]:
        prune_images = payload.get("pruneImages", True) is not False
        prune_build_cache = payload.get("pruneBuildCache", True) is not False
        prune_volumes = bool(payload.get("pruneVolumes", False))

        outputs: list[str] = []
        reclaimed_lines: list[str] = []

        steps: list[tuple[str, list[str]]] = [
            ("containers", ["container", "prune", "-f"]),
        ]
        if prune_images:
            steps.append(("images", ["image", "prune", "-af"]))
        if prune_build_cache:
            steps.append(("build-cache", ["builder", "prune", "-f"]))
        if prune_volumes:
            steps.append(("volumes", ["volume", "prune", "-f"]))

        all_ok = True
        failed_steps: list[str] = []
        for label, docker_args in steps:
            proc = self._run_docker(docker_args, timeout=120, check=False)
            if proc.returncode != 0:
                all_ok = False
                failed_steps.append(f"{label} (exit {proc.returncode})")
            combined = ((proc.stdout or "") + "\n" + (proc.stderr or "")).strip()
            outputs.append(f"[{label}] (exit {proc.returncode})\n{combined}")
            for line in combined.splitlines():
                if "reclaimed" in line.lower() or "total" in line.lower():
                    reclaimed_lines.append(f"{label}: {line.strip()}")

        full_output, _ = self._truncate_redacted_output(
            "\n\n".join(outputs), max_bytes=32 * 1024
        )
        if not all_ok:
            reclaimed_summary = (
                f"Docker cleanup failed on: {', '.join(failed_steps)}"
                + (f"; {'; '.join(reclaimed_lines)}" if reclaimed_lines else "")
            )
        else:
            reclaimed_summary = (
                "; ".join(reclaimed_lines)
                if reclaimed_lines
                else "Docker cleanup completed."
            )
        return {
            "ok": all_ok,
            "output": full_output,
            "reclaimedSummary": redact_secrets(reclaimed_summary),
        }


def make_handler(service: RuntimeService) -> type[BaseHTTPRequestHandler]:
    class RuntimeBridgeHandler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"
        timeout = 30

        def version_string(self) -> str:
            return "vpsagent-runtime"

        def address_string(self) -> str:
            if isinstance(self.client_address, tuple) and self.client_address:
                return str(self.client_address[0])
            return "unix-socket"

        def log_message(self, format: str, *args: Any) -> None:
            message = redact_secrets(format % args)
            sys.stderr.write(f"[vpsagent-runtime] {self.address_string()} {message}\n")

        def _send_json(self, status_code: int, body: dict[str, Any]) -> None:
            raw = json.dumps(body).encode("utf-8")
            self.send_response(status_code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(raw)

        def _require_auth(self) -> bool:
            expected = service.runtime_token
            if not expected:
                if service.allow_unauthenticated:
                    return True
                self._send_json(401, {"error": "Unauthorized."})
                return False
            provided = self.headers.get("X-VPSAgent-Runtime-Token", "").strip()
            if not provided:
                auth = self.headers.get("Authorization", "")
                if auth.startswith("Bearer "):
                    provided = auth[7:].strip()
            if not provided:
                self._send_json(401, {"error": "Unauthorized."})
                return False
            try:
                provided_bytes = provided.encode("utf-8")
                expected_bytes = expected.encode("utf-8")
            except UnicodeEncodeError:
                self._send_json(401, {"error": "Unauthorized."})
                return False
            if not hmac.compare_digest(provided_bytes, expected_bytes):
                self._send_json(401, {"error": "Unauthorized."})
                return False
            return True

        def _read_json_body(self) -> dict[str, Any]:
            raw_len = self.headers.get("Content-Length")
            if raw_len is None:
                raise BridgeRequestError(411, "Content-Length header is required.")
            try:
                length = int(raw_len)
            except ValueError as exc:
                raise BridgeRequestError(
                    400, "Invalid Content-Length header."
                ) from exc
            if length < 0 or length > MAX_BODY_BYTES:
                raise BridgeRequestError(413, "Payload too large.")
            raw_bytes = self.rfile.read(length) if length > 0 else b"{}"
            try:
                parsed = json.loads(raw_bytes.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise BridgeRequestError(400, "Invalid JSON payload.") from exc
            if not isinstance(parsed, dict):
                raise BridgeRequestError(400, "JSON body must be an object.")
            return parsed

        def do_GET(self) -> None:
            if self.path == "/health":
                self._send_json(200, {"ok": True, "service": "vpsagent-runtime"})
                return
            if self.path == "/v1/host/stats":
                if not self._require_auth():
                    return
                try:
                    self._send_json(200, service.host_stats())
                except BridgeRequestError as exc:
                    self._send_json(exc.status_code, {"error": str(exc)})
                except Exception as exc:  # pragma: no cover
                    self._send_json(500, {"error": redact_secrets(str(exc))})
                return
            self._send_json(404, {"error": "Not found."})

        def do_POST(self) -> None:
            if not self._require_auth():
                return
            try:
                payload = self._read_json_body()
                if self.path == "/v1/apps/lifecycle":
                    self._send_json(200, service.lifecycle(payload))
                elif self.path == "/v1/apps/build-git":
                    self._send_json(200, service.build_git(payload))
                elif self.path == "/v1/apps/inspect-git":
                    self._send_json(200, service.inspect_git(payload))
                elif self.path == "/v1/apps/logs":
                    self._send_json(200, service.logs(payload))
                elif self.path == "/v1/apps/route-caddy":
                    self._send_json(200, service.route_caddy(payload))
                elif self.path == "/v1/core/route-domain":
                    self._send_json(200, service.route_core_domain(payload))
                elif self.path == "/v1/core/tls-check":
                    self._send_json(200, service.check_core_tls(payload))
                elif self.path == "/v1/apps/remove":
                    self._send_json(200, service.remove_workload(payload))
                elif self.path == "/v1/apps/statuses":
                    self._send_json(200, service.statuses(payload))
                elif self.path == "/v1/apps/inspect":
                    self._send_json(200, service.inspect_workload(payload))
                elif self.path == "/v1/apps/readiness":
                    self._send_json(200, service.check_readiness(payload))
                elif self.path == "/v1/apps/exec":
                    self._send_json(200, service.exec_in_app(payload))
                elif self.path == "/v1/host/exec":
                    self._send_json(200, service.host_exec(payload))
                elif self.path == "/v1/host/files/list":
                    self._send_json(200, service.list_files(payload))
                elif self.path == "/v1/host/files/read":
                    self._send_json(200, service.read_file(payload))
                elif self.path == "/v1/host/files/write":
                    self._send_json(200, service.write_file(payload))
                elif self.path == "/v1/host/files/delete":
                    self._send_json(200, service.delete_file(payload))
                elif self.path == "/v1/host/services/list":
                    self._send_json(200, service.list_services(payload))
                elif self.path == "/v1/host/services/manage":
                    self._send_json(200, service.manage_service(payload))
                elif self.path == "/v1/host/docker/cleanup":
                    self._send_json(200, service.docker_cleanup(payload))
                else:
                    self._send_json(404, {"error": "Not found."})
            except BridgeRequestError as exc:
                err_body: dict[str, Any] = {"error": str(exc)}
                if exc.build_log_tail:
                    err_body["buildLogTail"] = exc.build_log_tail
                self._send_json(exc.status_code, err_body)
            except Exception as exc:  # pragma: no cover - defensive fallback
                self._send_json(500, {"error": redact_secrets(str(exc))})

    return RuntimeBridgeHandler


if hasattr(socketserver, "UnixStreamServer"):

    class ThreadingUnixHttpServer(
        socketserver.ThreadingMixIn, socketserver.UnixStreamServer
    ):
        daemon_threads = True
        request_queue_size = 32


class ThreadingTcpHttpServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True
    request_queue_size = 32


def prepare_unix_socket(socket_path: str) -> None:
    parent = os.path.dirname(os.path.abspath(socket_path))
    os.makedirs(parent, mode=0o750, exist_ok=True)
    os.chmod(parent, 0o750)
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        os.chown(parent, 0, 1000)
    if os.path.lexists(socket_path):
        st = os.lstat(socket_path)
        if not stat.S_ISSOCK(st.st_mode):
            raise RuntimeError(
                f"Refusing to overwrite non-socket file at {socket_path}"
            )
        os.unlink(socket_path)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="VPSAgent v2 Host Runtime Bridge")
    parser.add_argument(
        "--socket",
        default=os.environ.get(
            "VPSAGENT_RUNTIME_SOCKET", "/var/lib/vpsagent/run/runtime.sock"
        ),
        help="Unix domain socket path to bind.",
    )
    parser.add_argument(
        "--tcp",
        default="",
        help="Optional loopback host:port (e.g. 127.0.0.1:0) for local testing.",
    )
    parser.add_argument(
        "--apps-root",
        default=os.environ.get("VPSAGENT_APPS_ROOT", "/var/lib/vpsagent/apps"),
    )
    parser.add_argument(
        "--caddy-apps-dir",
        default=os.environ.get(
            "VPSAGENT_CADDY_APPS_DIR", "/var/lib/vpsagent/caddy/apps.d"
        ),
    )
    parser.add_argument(
        "--caddy-core-dir",
        default=os.environ.get("VPSAGENT_CADDY_CORE_DIR", ""),
    )
    parser.add_argument(
        "--caddy-container",
        default=os.environ.get("VPSAGENT_CADDY_CONTAINER", "vpsagent-caddy"),
    )
    parser.add_argument(
        "--docker-bin",
        default=os.environ.get("VPSAGENT_DOCKER_BIN", "docker"),
    )
    parser.add_argument(
        "--git-bin",
        default=os.environ.get("VPSAGENT_GIT_BIN", "git"),
    )
    parser.add_argument(
        "--runtime-token",
        default=os.environ.get("VPSAGENT_RUNTIME_TOKEN", ""),
    )
    parser.add_argument(
        "--allow-unauthenticated",
        action="store_true",
        help="Allow starting without VPSAGENT_RUNTIME_TOKEN (tests only).",
    )
    parser.add_argument(
        "--status-deadline",
        type=float,
        default=float(
            os.environ.get("VPSAGENT_STATUS_DEADLINE_S", DEFAULT_STATUS_DEADLINE_S)
        ),
        help="Overall deadline in seconds for batch /v1/apps/statuses queries.",
    )
    parser.add_argument(
        "--health-interval",
        type=float,
        default=float(
            os.environ.get("VPSAGENT_HEALTH_INTERVAL_S", DEFAULT_HEALTH_INTERVAL_S)
        ),
        help="Interval in seconds for host-side recurring HTTP health probes.",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    token = (args.runtime_token or "").strip()
    if not args.allow_unauthenticated and (
        not token or token.startswith("replace-with-") or len(token) < 16
    ):
        sys.stderr.write(
            "Fatal: VPSAGENT_RUNTIME_TOKEN must be a non-placeholder secret of at least 16 chars.\n"
        )
        return 1

    service = RuntimeService(
        apps_root=args.apps_root,
        caddy_apps_dir=args.caddy_apps_dir,
        caddy_core_dir=args.caddy_core_dir or None,
        caddy_container=args.caddy_container,
        docker_bin=args.docker_bin,
        git_bin=args.git_bin,
        runtime_token=token or None,
        allow_unauthenticated=bool(args.allow_unauthenticated),
        status_deadline_s=args.status_deadline,
        health_interval_s=args.health_interval,
    )
    handler_cls = make_handler(service)

    server: socketserver.BaseServer
    if args.tcp:
        host, _, raw_port = args.tcp.rpartition(":")
        if host not in ("127.0.0.1", "localhost", "::1"):
            sys.stderr.write("Fatal: --tcp may only bind to loopback addresses.\n")
            return 1
        port = int(raw_port)
        server = ThreadingTcpHttpServer((host, port), handler_cls)
        actual_host, actual_port = server.server_address[:2]
        sys.stdout.write(f"LISTENING http://{actual_host}:{actual_port}\n")
        sys.stdout.flush()
    else:
        if not hasattr(socketserver, "UnixStreamServer"):
            sys.stderr.write(
                "Fatal: UnixStreamServer is not supported on this platform; pass --tcp 127.0.0.1:0 for tests.\n"
            )
            return 1
        prepare_unix_socket(args.socket)
        old_umask = os.umask(0o117)
        try:
            server = ThreadingUnixHttpServer(args.socket, handler_cls)
        finally:
            os.umask(old_umask)
        os.chmod(args.socket, 0o660)
        if hasattr(os, "geteuid") and os.geteuid() == 0:
            os.chown(args.socket, 0, 1000)
        sys.stdout.write(f"LISTENING unix://{args.socket}\n")
        sys.stdout.flush()

    def _shutdown(_signum: int, _frame: Any) -> None:
        threading.Thread(target=server.shutdown, daemon=True).start()

    signal.signal(signal.SIGTERM, _shutdown)
    signal.signal(signal.SIGINT, _shutdown)

    service.start_health_monitor()
    try:
        server.serve_forever()
    finally:
        service.stop_health_monitor()
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
